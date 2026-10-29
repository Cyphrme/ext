//! Labelled digests: algorithms, encodings, parsing and formatting.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Alg {
    Sha256,
}

impl Alg {
    pub const ALL: &'static [Alg] = &[Alg::Sha256];

    pub fn name(self) -> &'static str {
        match self {
            Alg::Sha256 => "SHA-256",
        }
    }

    /// Exact and case-sensitive: `sha-256` is not an algorithm name.
    pub fn from_name(s: &str) -> Option<Alg> {
        Alg::ALL.iter().copied().find(|a| a.name() == s)
    }

    /// For the `hash://` authority only, which URI parsers lowercase.
    pub fn from_name_ignore_case(s: &str) -> Option<Alg> {
        Alg::ALL
            .iter()
            .copied()
            .find(|a| a.name().eq_ignore_ascii_case(s))
    }

    // Digest size in bytes; an algorithm has no "empty" state.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> usize {
        match self {
            Alg::Sha256 => 32,
        }
    }

    pub fn b64ut_len(self) -> usize {
        (self.len() * 8).div_ceil(6)
    }

    pub fn hex_len(self) -> usize {
        self.len() * 2
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enc {
    B64ut,
    Hex,
}

/// Invariant: `bytes.len() == alg.len()`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest {
    alg: Alg,
    bytes: Box<[u8]>,
}

impl Digest {
    pub fn from_bytes(alg: Alg, bytes: &[u8]) -> Result<Digest, DigestError> {
        if bytes.len() != alg.len() {
            return Err(DigestError::WrongByteLength {
                alg,
                got: bytes.len(),
            });
        }
        Ok(Digest {
            alg,
            bytes: bytes.into(),
        })
    }

    pub fn compute(alg: Alg, data: &[u8]) -> Digest {
        use sha2::Digest as _;
        let bytes: Box<[u8]> = match alg {
            Alg::Sha256 => sha2::Sha256::digest(data).as_slice().into(),
        };
        Digest { alg, bytes }
    }

    pub fn alg(&self) -> Alg {
        self.alg
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Value only, no label. Hex is uppercase so output has one spelling.
    pub fn encode(&self, enc: Enc) -> String {
        match enc {
            Enc::B64ut => data_encoding::BASE64URL_NOPAD.encode(&self.bytes),
            Enc::Hex => data_encoding::HEXUPPER.encode(&self.bytes),
        }
    }

    /// The canonical labelled form, `<value>:<alg>`.
    pub fn to_reverse(&self, enc: Enc) -> String {
        format!("{}:{}", self.encode(enc), self.alg.name())
    }

    /// The encoding is chosen by length alone, never by character set, so
    /// a value cannot be read two ways.
    pub fn decode_value(alg: Alg, s: &str) -> Result<Digest, DigestError> {
        Digest::decode_value_enc(alg, s).map(|(d, _)| d)
    }

    /// As [`Digest::decode_value`], also saying which encoding the length chose.
    pub fn decode_value_enc(alg: Alg, s: &str) -> Result<(Digest, Enc), DigestError> {
        let got = s.chars().count();
        let (bytes, enc) = if got == alg.b64ut_len() {
            (decode_b64ut(alg, s)?, Enc::B64ut)
        } else if got == alg.hex_len() {
            (decode_hex(s)?, Enc::Hex)
        } else {
            return Err(DigestError::WrongLength { alg, got });
        };
        Ok((Digest::from_bytes(alg, &bytes)?, enc))
    }

    /// Accepts `<value>:<alg>` and `<alg>:<value>`. An algorithm name is
    /// never a valid value, so the two orders cannot be confused.
    pub fn parse_labelled(s: &str) -> Result<Digest, DigestError> {
        Digest::parse_labelled_enc(s).map(|(d, _)| d)
    }

    fn parse_labelled_enc(s: &str) -> Result<(Digest, Enc), DigestError> {
        let (left, right) = s.split_once(':').ok_or(DigestError::Unlabelled)?;
        if right.contains(':') {
            return Err(DigestError::TooManyColons);
        }
        if let Some(alg) = Alg::from_name(right) {
            Digest::decode_value_enc(alg, left)
        } else if let Some(alg) = Alg::from_name(left) {
            Digest::decode_value_enc(alg, right)
        } else {
            // Reverse form is canonical, so blame the right-hand side.
            Err(DigestError::UnknownAlg(right.to_owned()))
        }
    }
}

/// What `resolve` looks up: a digest and, optionally, the filename that at
/// least one returned path must have.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub digest: Digest,
    /// A filename, extension included; never empty, never contains `/`.
    pub name: Option<Vec<u8>>,
    /// The encoding the digest was written in, for the config's input policy.
    pub enc: Enc,
}

impl Query {
    /// Accepts, in order of recognition:
    /// - `hash://<alg>/<digest>[tail]`, scheme and `alg` case-insensitive;
    /// - `<value>:<alg>` and `<alg>:<value>` (no name);
    /// - `<alg>:<value>:<name>`, `<value>:<alg>:<name>`,
    ///   `<name>:<alg>:<value>` and `<name>:<alg>:<value>.<ext>`.
    ///
    /// Names may contain `:`. The algorithm label and the fixed-length value
    /// beside it are located first and the rest is the name; in the
    /// name-first forms the last label wins, since the digest ends the
    /// argument. Outside `hash://` algorithm names are exact.
    pub fn parse(s: &str) -> Result<Query, DigestError> {
        if s.get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("hash://"))
        {
            return hash_uri(&s[7..]);
        }
        match s.matches(':').count() {
            0 => Err(DigestError::Unlabelled),
            1 => Digest::parse_labelled_enc(s).map(|(digest, enc)| Query {
                digest,
                name: None,
                enc,
            }),
            _ => name_form(s),
        }
    }
}

fn hash_uri(rest: &str) -> Result<Query, DigestError> {
    let (alg, rest) = rest.split_once('/').ok_or(DigestError::BadHashUri)?;
    let alg =
        Alg::from_name_ignore_case(alg).ok_or_else(|| DigestError::UnknownAlg(alg.to_owned()))?;
    // The tail starts at the first non-b64ut character; every b64ut
    // character is ASCII, so the prefix length is a char boundary.
    let end = rest
        .find(|c: char| b64ut_val(c).is_none())
        .unwrap_or(rest.len());
    let (digest, enc) = Digest::decode_value_enc(alg, &rest[..end])?;
    Ok(Query {
        digest,
        name: None,
        enc,
    })
}

/// Every value that decodes at the start of `b`, with its length. A hex
/// value's first 43 characters can also be a canonical b64ut value, so the
/// caller picks the candidate whose delimiter follows.
fn values_at(alg: Alg, b: &[u8]) -> impl Iterator<Item = (Digest, usize, Enc)> + '_ {
    [alg.b64ut_len(), alg.hex_len()]
        .into_iter()
        .filter_map(move |n| {
            let v = std::str::from_utf8(b.get(..n)?).ok()?;
            let (d, e) = Digest::decode_value_enc(alg, v).ok()?;
            Some((d, n, e))
        })
}

fn name_form(s: &str) -> Result<Query, DigestError> {
    let b = s.as_bytes();
    let found = Alg::ALL.iter().find_map(|&alg| {
        let label = alg.name().as_bytes();
        // <alg>:<value>:<name>
        if let Some(rest) = b.strip_prefix(label).and_then(|r| r.strip_prefix(b":")) {
            if let Some(hit) = values_at(alg, rest)
                .find_map(|(d, n, e)| Some((d, rest[n..].strip_prefix(b":")?.to_vec(), e)))
            {
                return Some(hit);
            }
        }
        // <value>:<alg>:<name>
        if let Some(hit) = values_at(alg, b).find_map(|(d, n, e)| {
            let tail = b[n..].strip_prefix(b":")?;
            let name = tail.strip_prefix(label)?.strip_prefix(b":")?;
            Some((d, name.to_vec(), e))
        }) {
            return Some(hit);
        }
        // <name>:<alg>:<value>[.<ext>], the rightmost label first
        let mut pat = vec![b':'];
        pat.extend_from_slice(label);
        pat.push(b':');
        let starts: Vec<usize> = (0..b.len()).filter(|&i| b[i..].starts_with(&pat)).collect();
        starts.into_iter().rev().find_map(|i| {
            let after = &b[i + pat.len()..];
            values_at(alg, after).find_map(|(d, n, e)| {
                let ext = &after[n..];
                let mut name = b[..i].to_vec();
                match ext {
                    [] => {}
                    [b'.', _, ..] => name.extend_from_slice(ext),
                    _ => return None,
                }
                Some((d, name, e))
            })
        })
    });
    let (digest, name, enc) = found.ok_or(DigestError::NoNameForm)?;
    if name.is_empty() || name.contains(&b'/') {
        return Err(DigestError::InvalidName);
    }
    Ok(Query {
        digest,
        name: Some(name),
        enc,
    })
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_reverse(Enc::B64ut))
    }
}

fn b64ut_val(c: char) -> Option<u8> {
    match c {
        'A'..='Z' => Some(c as u8 - b'A'),
        'a'..='z' => Some(c as u8 - b'a' + 26),
        '0'..='9' => Some(c as u8 - b'0' + 52),
        '-' => Some(62),
        '_' => Some(63),
        _ => None,
    }
}

// Hand-rolled so that canonicality is an explicit check rather than a
// property of whichever decoder happens to be linked.
fn decode_b64ut(alg: Alg, s: &str) -> Result<Vec<u8>, DigestError> {
    let mut out = Vec::with_capacity(alg.len());
    let (mut acc, mut nbits) = (0u32, 0u32);
    for (index, ch) in s.chars().enumerate() {
        let v = b64ut_val(ch).ok_or(DigestError::InvalidChar { index, ch })?;
        acc = (acc << 6) | u32::from(v);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    // Leftover bits are padding and must be zero, or two strings would
    // name the same digest.
    if acc != 0 {
        return Err(DigestError::NonCanonical);
    }
    Ok(out)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, DigestError> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut hi = None;
    for (index, ch) in s.chars().enumerate() {
        let v = ch
            .to_digit(16)
            .ok_or(DigestError::InvalidChar { index, ch })? as u8;
        match hi.take() {
            None => hi = Some(v),
            Some(h) => out.push((h << 4) | v),
        }
    }
    Ok(out)
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    #[error("digest has no ':' label")]
    Unlabelled,
    #[error("malformed hash:// URI: expected hash://<alg>/<digest>")]
    BadHashUri,
    #[error("no <alg>:<value> pair of a digest and a name found in the argument")]
    NoNameForm,
    #[error("a name is a filename: non-empty, without '/'")]
    InvalidName,
    #[error("digest has more than one ':'")]
    TooManyColons,
    #[error("unknown algorithm {0:?}")]
    UnknownAlg(String),
    #[error("{alg:?} value has wrong length {got}")]
    WrongLength { alg: Alg, got: usize },
    #[error("invalid character {ch:?} at index {index}")]
    /// `index` is a char offset into the value, not a byte offset.
    InvalidChar { index: usize, ch: char },
    #[error("non-canonical base64 trailing bits")]
    NonCanonical,
    #[error("{alg:?} digest has wrong byte length {got}")]
    WrongByteLength { alg: Alg, got: usize },
}
