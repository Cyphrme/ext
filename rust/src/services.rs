//! External services: the services file (ES-21, ES-22), service URIs and the
//! request each one receives (ES-23).

use crate::cache::{Effect, StepExecutor};
use crate::digest::{Digest, Enc};
use crate::store::{Store, WriteLock, SERVICES};
use std::io;
use std::net::Ipv6Addr;

/// At most this many services are registered (ES-3).
pub const MAX_SERVICES: usize = 64;

/// A line longer than this many bytes is rejected (ES-21).
const MAX_LINE: usize = 2048;

const FILE_TMP: &str = "services.tmp";

/// A digest a service may be asked for (ES-2): full length for its algorithm,
/// and the algorithm is cryptographic and supported. `Digest` already carries
/// the first property, so this wrapper is the type a backend accepts and the
/// one place the rule is stated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetchable(Digest);

impl Fetchable {
    pub fn new(d: Digest) -> Fetchable {
        Fetchable(d)
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Https,
    Http,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Https => "https",
            Scheme::Http => "http",
        }
    }
}

/// A line of the services file in normal form (scheme and host lowercased).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceUri {
    normal: String,
    scheme: Scheme,
    /// Contains `{digest}` or `{hex}`, so ES-23 substitutes instead of appending.
    template: bool,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct UriError(pub String);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FileError {
    /// `line` is 1-based. A duplicate, a blank line, a missing final LF and
    /// the 65th service are all reported against their own line.
    #[error("services:{line}: {source}")]
    Line { line: usize, source: UriError },
}

fn err<T>(why: &str) -> Result<T, UriError> {
    Err(UriError(why.to_string()))
}

/// The pieces of an absolute `http`/`https` URI that the services grammar and
/// redirect targets share (ES-14, ES-21).
pub(crate) struct Parts<'a> {
    pub scheme: Scheme,
    /// As written; brackets kept for IPv6.
    pub host: &'a str,
    /// Including its leading `:`, or empty.
    pub port: &'a str,
    /// Everything after the authority. Its rules differ by use.
    pub rest: &'a str,
}

/// Splits an absolute URI and checks scheme, host and port against ES-21.
pub(crate) fn split(line: &str) -> Result<Parts<'_>, UriError> {
    if line.len() > MAX_LINE {
        return err("longer than 2048 bytes");
    }
    if let Some(b) = line.bytes().find(|b| !(0x21..=0x7e).contains(b)) {
        return Err(UriError(format!(
            "byte {} is not printable ASCII",
            crate::escape::terminal(&[b])
        )));
    }
    let Some((scheme, after)) = line.split_once("://") else {
        return err("not of the form scheme://host");
    };
    let scheme = if scheme.eq_ignore_ascii_case("https") {
        Scheme::Https
    } else if scheme.eq_ignore_ascii_case("http") {
        Scheme::Http
    } else {
        return err("the scheme is neither https nor http");
    };
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let (authority, rest) = after.split_at(end);
    if authority.contains('@') {
        return err("userinfo is not allowed");
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let Some((addr, tail)) = inner.split_once(']') else {
            return err("unclosed [ in the host");
        };
        if addr.parse::<Ipv6Addr>().is_err() {
            return err("not an IPv6 address inside [ ]");
        }
        (&authority[..addr.len() + 2], tail)
    } else {
        let at = authority.find(':').unwrap_or(authority.len());
        let host = &authority[..at];
        if host.is_empty() {
            return err("the host is empty");
        }
        if !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            return err("the host has a character outside letters, digits, - and .");
        }
        (host, &authority[at..])
    };
    if !port.is_empty() {
        let digits = port.strip_prefix(':').unwrap_or("");
        let ok = !digits.is_empty()
            && digits.len() <= 5
            && digits.bytes().all(|b| b.is_ascii_digit())
            && !digits.starts_with('0')
            && digits.parse::<u32>().is_ok_and(|p| p <= 65535);
        if !ok {
            return err("the port is not a number from 1 to 65535 without leading zeros");
        }
    }
    Ok(Parts {
        scheme,
        host,
        port,
        rest,
    })
}

/// RFC 3986 `pchar` minus `%`, which is checked as a whole escape.
fn plain_pchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&b)
}

/// Checks `s` as `*( "/" / pchar )`, plus `"?"` when `query` and the three
/// placeholders when `placeholders`. Returns whether `{digest}` or `{hex}`
/// occurs.
pub(crate) fn check_path(s: &str, query: bool, placeholders: bool) -> Result<bool, UriError> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut id = false;
    while i < b.len() {
        let c = b[i];
        if c == b'/' || plain_pchar(c) || (query && c == b'?') {
            i += 1;
        } else if c == b'%' {
            if b.len() < i + 3 || !b[i + 1].is_ascii_hexdigit() || !b[i + 2].is_ascii_hexdigit() {
                return err("% is not followed by two hex digits");
            }
            i += 3;
        } else if c == b'{' && placeholders {
            let tail = &s[i..];
            let Some(p) = ["{alg}", "{digest}", "{hex}"]
                .into_iter()
                .find(|p| tail.starts_with(p))
            else {
                return err("only {alg}, {digest} and {hex} are placeholders");
            };
            id |= p != "{alg}";
            i += p.len();
        } else if c == b'#' {
            return err("a fragment is not allowed");
        } else if c == b'?' {
            return err("a query is allowed only in a template");
        } else {
            return Err(UriError(format!(
                "{} is not allowed in a path",
                crate::escape::terminal(&[c])
            )));
        }
    }
    Ok(id)
}

impl ServiceUri {
    /// One line without its LF, per the ES-21 grammar.
    pub fn parse(line: &str) -> Result<ServiceUri, UriError> {
        let p = split(line)?;
        // A base is tried first: it is the stricter form, and a line that is
        // one never needs substitution.
        let template = match check_path(p.rest, false, false) {
            Ok(_) => false,
            Err(base_err) => match check_path(p.rest, true, true) {
                Ok(true) => true,
                Ok(false) => return err("a template needs {digest} or {hex}"),
                Err(_) => return Err(base_err),
            },
        };
        Ok(ServiceUri {
            normal: format!(
                "{}://{}{}{}",
                p.scheme.as_str(),
                p.host.to_ascii_lowercase(),
                p.port,
                p.rest
            ),
            scheme: p.scheme,
            template,
        })
    }

    /// The normal form, which is what the services file stores.
    pub fn as_str(&self) -> &str {
        &self.normal
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The URL requested for `d` (ES-23). Every substituted character is a
    /// legal `pchar`, so nothing is escaped.
    pub fn request_url(&self, d: &Fetchable) -> String {
        let d = d.digest();
        let alg = d.alg().name();
        if self.template {
            self.normal
                .replace("{alg}", alg)
                .replace("{digest}", &d.encode(Enc::B64ut))
                .replace("{hex}", &d.encode(Enc::Hex))
        } else {
            format!(
                "{}/{alg}:{}",
                self.normal.trim_end_matches('/'),
                d.encode(Enc::B64ut)
            )
        }
    }
}

/// Parses the whole file: LF-terminated records, no blank lines, comments or
/// duplicates (after normalisation), at most [`MAX_SERVICES`].
pub fn parse_file(bytes: &[u8]) -> Result<Vec<ServiceUri>, FileError> {
    let fail = |line: usize, why: &str| FileError::Line {
        line,
        source: UriError(why.to_string()),
    };
    let mut out: Vec<ServiceUri> = Vec::new();
    if bytes.is_empty() {
        return Ok(out);
    }
    let complete = bytes.ends_with(b"\n");
    let body = if complete {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };
    let lines: Vec<&[u8]> = body.split(|b| *b == b'\n').collect();
    for (i, raw) in lines.iter().enumerate() {
        let n = i + 1;
        let text = std::str::from_utf8(raw).map_err(|_| fail(n, "not ASCII"))?;
        if text.is_empty() {
            return Err(fail(n, "blank line"));
        }
        let uri = ServiceUri::parse(text).map_err(|source| FileError::Line { line: n, source })?;
        if out.contains(&uri) {
            return Err(fail(n, "duplicate of an earlier line"));
        }
        if out.len() == MAX_SERVICES {
            return Err(fail(n, "more than 64 services"));
        }
        if !complete && n == lines.len() {
            return Err(fail(n, "the last line has no final LF"));
        }
        out.push(uri);
    }
    Ok(out)
}

pub fn render_file(services: &[ServiceUri]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in services {
        out.extend_from_slice(s.normal.as_bytes());
        out.push(b'\n');
    }
    out
}

/// Atomic replace of `<store>/services` through the executor (ES-22, F10).
/// The temporary has a fixed name: the lock is held, so one left behind is a
/// killed writer's and is cleared first.
pub fn write_file(
    store: &Store,
    lock: &WriteLock,
    ex: &mut dyn StepExecutor,
    services: &[ServiceUri],
) -> io::Result<()> {
    if !store.holds(lock) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the lock belongs to another store",
        ));
    }
    let tmp = store.path().join(FILE_TMP);
    if store.has_entry(FILE_TMP) {
        ex.step(&Effect::Unlink { path: tmp.clone() })?;
    }
    let result = (|| {
        ex.step(&Effect::Write {
            path: tmp.clone(),
            bytes: render_file(services),
        })?;
        ex.step(&Effect::Fsync { path: tmp.clone() })?;
        ex.step(&Effect::Rename {
            from: tmp.clone(),
            to: store.path().join(SERVICES),
        })
    })();
    if result.is_err() {
        // Best effort: the next write clears a leftover anyway.
        let _ = ex.step(&Effect::Unlink { path: tmp });
    }
    result
}
