//! Export and import of a store's records as TSV files (`registry`,
//! `source`, `timestamp`), the interchange format of the SQLite index.
//!
//! Formats (the spec's File Formats section, fields TSV-escaped):
//! - `registry`: `<path>`
//! - `source`: `<digest>:<alg>\t<path>`, digest in b64ut
//! - `timestamp`: `<path>\t<last_checked>\t<mtime>\t<ctime>\t<size>\t<inode>\t<dev>`
//!   with the times in nanoseconds; `<dev>` is this implementation's addition
//!   because an inode number means nothing without its device.
//!
//! Records are sorted by the raw (unescaped) bytes of their first field, with
//! the path breaking ties in `source`, so equal stores export equal bytes.

use crate::digest::{Alg, Digest, Enc};
use crate::escape::{escape, unescape};
use crate::index::{Entry, Index, Meta};
use crate::registry::{self, RegPath};
use crate::store::{Store, StoreError};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const FILES: [&str; 3] = ["registry", "source", "timestamp"];

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("{0}")]
    Store(#[from] StoreError),
    #[error("{what} {}: {source}", path.display())]
    Io {
        what: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("{file}:{line}: {why}")]
    Invalid {
        file: &'static str,
        line: usize,
        why: String,
    },
    #[error("refusing to import: the store's index is not empty")]
    NotEmpty,
}

fn invalid(file: &'static str, line: usize, why: impl Into<String>) -> TransferError {
    TransferError::Invalid {
        file,
        line,
        why: why.into(),
    }
}

fn join_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(b'\t');
        }
        out.extend_from_slice(&escape(f));
    }
    out.push(b'\n');
    out
}

/// Writes the three files into `dir`, each through a temp file in `dir`
/// renamed into place, so a reader sees an old file or a new one.
pub fn export(store: &Store, dir: &Path) -> Result<(), TransferError> {
    let io_err = |what, path: &Path| {
        let path = path.to_path_buf();
        move |source| TransferError::Io { what, path, source }
    };
    if !fs::metadata(dir)
        .map_err(io_err("cannot export to", dir))?
        .is_dir()
    {
        return Err(io_err("not a directory:", dir)(io::Error::from(
            io::ErrorKind::NotADirectory,
        )));
    }
    let mut roots = store.registry()?;
    roots.sort();
    let mut entries = Index::open(store)?.iter()?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let registry = registry::render(&roots);
    let mut src: Vec<(String, &[u8])> = entries
        .iter()
        .map(|e| (e.digest.to_reverse(Enc::B64ut), e.path.as_slice()))
        .collect();
    src.sort_by(|a, b| (a.0.as_bytes(), a.1).cmp(&(b.0.as_bytes(), b.1)));
    let source: Vec<u8> = src
        .iter()
        .flat_map(|(d, p)| join_fields(&[d.as_bytes(), p]))
        .collect();
    let timestamp: Vec<u8> = entries
        .iter()
        .flat_map(|e| {
            let n = |v: String| v.into_bytes();
            join_fields(&[
                &e.path,
                &n(e.last_checked_ns.to_string()),
                &n(e.meta.mtime_ns.to_string()),
                &n(e.meta.ctime_ns.to_string()),
                &n(e.meta.size.to_string()),
                &n(e.meta.ino.to_string()),
                &n(e.meta.dev.to_string()),
            ])
        })
        .collect();

    for (name, bytes) in FILES.iter().zip([&registry, &source, &timestamp]) {
        write_replacing(dir, name, bytes)?;
    }
    Ok(())
}

fn write_replacing(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), TransferError> {
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    let dest = dir.join(name);
    let result = (|| {
        // A leftover from a crashed run of this pid is not ours to keep.
        let _ = fs::remove_file(&tmp);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| (e, "create", &tmp))?;
        f.write_all(bytes).map_err(|e| (e, "write", &tmp))?;
        f.sync_all().map_err(|e| (e, "sync", &tmp))?;
        fs::rename(&tmp, &dest).map_err(|e| (e, "rename onto", &dest))
    })();
    result.map_err(
        |(source, what, path): (io::Error, &'static str, &PathBuf)| {
            let path = path.clone();
            let _ = fs::remove_file(&tmp);
            TransferError::Io { what, path, source }
        },
    )
}

/// Splits TSV text into records. A file must end in a newline, so a truncated file is an error
/// instead of a shorter store.
/// A record's 1-based line number and its unescaped fields.
type Record = (usize, Vec<Vec<u8>>);

fn records(file: &'static str, bytes: &[u8]) -> Result<Vec<Record>, TransferError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let Some(body) = bytes.strip_suffix(b"\n") else {
        let line = bytes.iter().filter(|&&b| b == b'\n').count() + 1;
        return Err(invalid(file, line, "missing final newline"));
    };
    body.split(|&b| b == b'\n')
        .enumerate()
        .map(|(i, line)| {
            let fields = line
                .split(|&b| b == b'\t')
                .map(|f| unescape(f).map_err(|e| invalid(file, i + 1, e.to_string())))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((i + 1, fields))
        })
        .collect()
}

fn fixed<const N: usize>(
    file: &'static str,
    line: usize,
    mut fields: Vec<Vec<u8>>,
) -> Result<[Vec<u8>; N], TransferError> {
    if fields.len() != N {
        return Err(invalid(
            file,
            line,
            format!("expected {N} fields, found {}", fields.len()),
        ));
    }
    Ok(std::array::from_fn(|i| std::mem::take(&mut fields[i])))
}

/// Canonical decimal only, so the file has one spelling per number.
fn number<T: std::str::FromStr + ToString>(
    file: &'static str,
    line: usize,
    what: &str,
    f: &[u8],
) -> Result<T, TransferError> {
    std::str::from_utf8(f)
        .ok()
        .and_then(|s| s.parse::<T>().ok().filter(|v| v.to_string() == s))
        .ok_or_else(|| invalid(file, line, format!("{what} is not a canonical number")))
}

fn under_a_root(roots: &[RegPath], path: &[u8]) -> bool {
    roots.iter().any(|r| {
        let r = r.as_bytes();
        path == r
            || r == b"/"
            || path
                .strip_prefix(r)
                .is_some_and(|rest| rest.first() == Some(&b'/'))
    })
}

fn path_field(
    file: &'static str,
    line: usize,
    roots: &[RegPath],
    p: &[u8],
) -> Result<Vec<u8>, TransferError> {
    let norm = RegPath::from_bytes(p)
        .ok()
        .filter(|n| n.as_bytes() == p)
        .ok_or_else(|| invalid(file, line, "path is not absolute and normalised"))?;
    if !under_a_root(roots, norm.as_bytes()) {
        return Err(invalid(file, line, "path is not under a registered root"));
    }
    Ok(p.to_vec())
}

fn digest_field(file: &'static str, line: usize, f: &[u8]) -> Result<Digest, TransferError> {
    let bad = |why: String| invalid(file, line, why);
    let s = std::str::from_utf8(f).map_err(|_| bad("digest is not text".into()))?;
    let (value, alg) = s
        .rsplit_once(':')
        .ok_or_else(|| bad("digest is not <value>:<alg>".into()))?;
    let alg = Alg::from_name(alg).ok_or_else(|| bad(format!("unknown algorithm {alg:?}")))?;
    Digest::decode_value(alg, value).map_err(|e| bad(format!("digest: {e}")))
}

/// Everything read and checked, nothing written yet.
struct Parsed {
    roots: Vec<RegPath>,
    entries: Vec<Entry>,
}

fn parse_all(dir: &Path) -> Result<Parsed, TransferError> {
    let read = |name: &'static str| {
        let path = dir.join(name);
        fs::read(&path).map_err(|source| TransferError::Io {
            what: "cannot read",
            path,
            source,
        })
    };
    let roots = registry::parse(&read("registry")?)
        .map_err(|(line, kind)| invalid("registry", line, format!("{kind:?}")))?;

    let mut sources: HashMap<Vec<u8>, (usize, Digest)> = HashMap::new();
    for (line, fields) in records("source", &read("source")?)? {
        let [d, p] = fixed::<2>("source", line, fields)?;
        let digest = digest_field("source", line, &d)?;
        let path = path_field("source", line, &roots, &p)?;
        if sources.insert(path, (line, digest)).is_some() {
            return Err(invalid("source", line, "duplicate path"));
        }
    }

    let mut entries = Vec::with_capacity(sources.len());
    for (line, fields) in records("timestamp", &read("timestamp")?)? {
        let [p, lc, mt, ct, size, ino, dev] = fixed::<7>("timestamp", line, fields)?;
        let path = path_field("timestamp", line, &roots, &p)?;
        let n = |what, f: &[u8]| number::<i64>("timestamp", line, what, f);
        let u = |what, f: &[u8]| number::<u64>("timestamp", line, what, f);
        let meta = Meta {
            size: u("size", &size)?,
            mtime_ns: n("mtime", &mt)?,
            ctime_ns: n("ctime", &ct)?,
            dev: u("dev", &dev)?,
            ino: u("inode", &ino)?,
        };
        let last_checked_ns = n("last_checked", &lc)?;
        let Some((_, digest)) = sources.remove(&path) else {
            return Err(invalid(
                "timestamp",
                line,
                "no source record for this path, or a duplicate",
            ));
        };
        entries.push(Entry {
            path,
            digest,
            meta,
            last_checked_ns,
        });
    }
    if let Some((line, _)) = sources.values().min_by_key(|(l, _)| *l) {
        return Err(invalid(
            "source",
            *line,
            "no timestamp record for this path",
        ));
    }
    Ok(Parsed { roots, entries })
}

/// Loads the files in `dir` into `store`, whose index must be empty, and
/// replaces its registry with theirs. The index rows go in one transaction
/// and the registry is swapped before it commits, so a failure in either
/// leaves the index empty.
pub fn import(store: &Store, dir: &Path) -> Result<(), TransferError> {
    let lock = store.lock()?;
    let idx = Index::open(store)?;
    if !idx.is_empty()? {
        return Err(TransferError::NotEmpty);
    }
    let Parsed { roots, entries } = parse_all(dir)?;
    idx.batch(|ix| {
        for e in &entries {
            ix.upsert(e)?;
        }
        store.edit_registry(&lock, |v| *v = roots)
    })?;
    Ok(())
}
