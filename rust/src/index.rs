//! SQLite index of path -> digest plus freshness metadata.

use crate::digest::{Alg, Digest};
use crate::registry::RegPath;
use crate::store::{wrap, Store, StoreError};
use rusqlite::config::DbConfig;
use rusqlite::types::Value;
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use std::collections::HashSet;
use std::time::Duration;

const SCHEMA_VERSION: i64 = 1;
const COLUMNS: &str = "path, alg, digest, size, mtime_ns, ctime_ns, dev, ino, last_checked_ns";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub dev: u64,
    pub ino: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: Vec<u8>,
    pub digest: Digest,
    pub meta: Meta,
    pub last_checked_ns: i64,
}

pub struct Index {
    conn: Connection,
}

/// SQLite integers are signed 64-bit; `u64` fields are stored as their
/// two's-complement bit pattern so every value round-trips.
fn to_sql(v: u64) -> i64 {
    v as i64
}

fn from_sql(v: i64) -> u64 {
    v as u64
}

/// Raw row; converted outside the rusqlite closure so decode failures keep
/// their own error type instead of being squeezed into `rusqlite::Error`.
struct RawRow {
    path: Vec<u8>,
    alg: String,
    digest: Vec<u8>,
    size: i64,
    mtime_ns: i64,
    ctime_ns: i64,
    dev: i64,
    ino: i64,
    last_checked_ns: i64,
}

impl RawRow {
    fn read(r: &Row<'_>) -> rusqlite::Result<RawRow> {
        Ok(RawRow {
            path: r.get(0)?,
            alg: r.get(1)?,
            digest: r.get(2)?,
            size: r.get(3)?,
            mtime_ns: r.get(4)?,
            ctime_ns: r.get(5)?,
            dev: r.get(6)?,
            ino: r.get(7)?,
            last_checked_ns: r.get(8)?,
        })
    }

    fn into_entry(self) -> Result<Entry, StoreError> {
        let corrupt = |why: String| {
            StoreError::Corrupt(format!("path {}: {why}", crate::escape::escape(&self.path)))
        };
        let alg = Alg::from_name(&self.alg)
            .ok_or_else(|| corrupt(format!("unknown algorithm {:?}", self.alg)))?;
        let digest =
            Digest::from_bytes(alg, &self.digest).map_err(|e| corrupt(format!("digest: {e}")))?;
        Ok(Entry {
            digest,
            meta: Meta {
                size: from_sql(self.size),
                mtime_ns: self.mtime_ns,
                ctime_ns: self.ctime_ns,
                dev: from_sql(self.dev),
                ino: from_sql(self.ino),
            },
            last_checked_ns: self.last_checked_ns,
            path: self.path,
        })
    }
}

/// Range bounds for "strictly below `root`": every key with prefix `root/`
/// lies in `[prefix, upper)`, so lookups use the primary-key index instead of
/// scanning. The prefix always ends in `/` (0x2F), so bumping it to `0` (0x30)
/// gives the exclusive upper bound.
fn below_bounds(root: &RegPath) -> (Vec<u8>, Vec<u8>) {
    let mut lo = root.as_bytes().to_vec();
    if lo != b"/" {
        lo.push(b'/');
    }
    let mut hi = lo.clone();
    if let Some(last) = hi.last_mut() {
        *last = b'0';
    }
    (lo, hi)
}

const UNDER: &str = "(path = ?1 OR (path >= ?2 AND path < ?3))";

impl Index {
    pub fn open(store: &Store) -> Result<Index, StoreError> {
        // SQLite opens by path, not through the store's dir fd, so the path
        // must still name the checked directory both before (nothing may be
        // created in a decoy) and after (narrowing, not closing, the window;
        // the ancestor check in `Store::open` is what closes it).
        store.check_unmoved()?;
        let db = store.path().join("index.db");
        let conn = Connection::open(&db).map_err(|e| wrap_db(e, &db))?;
        store.check_unmoved()?;
        conn.busy_timeout(Duration::from_millis(5000))?;
        // A hostile or damaged database must not run SQL functions through
        // its schema, nor have its shadow tables rewritten.
        conn.pragma_update(None, "trusted_schema", "OFF")?;
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        // Readers must not block the single writer or vice versa; the mode is
        // persisted in the file, so this is a no-op on later opens.
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get::<_, String>(0))?;
        let ix = Index { conn };
        ix.ensure_schema()?;
        Ok(ix)
    }

    /// Whether `SQLITE_DBCONFIG_DEFENSIVE` is set on this connection.
    #[doc(hidden)]
    pub fn db_config_defensive(&self) -> Result<bool, StoreError> {
        Ok(self.conn.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?)
    }

    /// Value of `PRAGMA <name>` on this index's own connection, as text.
    #[doc(hidden)]
    pub fn pragma(&self, name: &str) -> Result<String, StoreError> {
        // A pragma name cannot be a bound parameter, so it is restricted
        // instead.
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(StoreError::Corrupt(format!("invalid pragma name {name:?}")));
        }
        let v: Value = self
            .conn
            .query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))?;
        Ok(match v {
            Value::Integer(i) => i.to_string(),
            Value::Real(f) => f.to_string(),
            Value::Text(t) => t,
            Value::Blob(b) => crate::escape::escape(&b),
            Value::Null => String::new(),
        })
    }

    /// No migrations: an unknown version is refused rather than guessed at.
    fn ensure_schema(&self) -> Result<(), StoreError> {
        let tx = self.write_tx()?;
        let found: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        match found {
            0 => {
                tx.execute_batch(
                    "CREATE TABLE files (
                         path BLOB PRIMARY KEY,
                         alg TEXT NOT NULL,
                         digest BLOB NOT NULL,
                         size INTEGER NOT NULL,
                         mtime_ns INTEGER NOT NULL,
                         ctime_ns INTEGER NOT NULL,
                         dev INTEGER NOT NULL,
                         ino INTEGER NOT NULL,
                         last_checked_ns INTEGER NOT NULL
                     );
                     CREATE INDEX files_digest ON files(alg, digest);",
                )?;
                tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            }
            SCHEMA_VERSION => {}
            found => {
                return Err(StoreError::Schema {
                    found,
                    expected: SCHEMA_VERSION,
                })
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// IMMEDIATE so the write lock is taken up front: a deferred transaction
    /// that reads first can fail on upgrade with BUSY, which `busy_timeout`
    /// does not retry.
    fn write_tx(&self) -> Result<Transaction<'_>, StoreError> {
        Ok(Transaction::new_unchecked(
            &self.conn,
            TransactionBehavior::Immediate,
        )?)
    }

    pub fn get(&self, path: &[u8]) -> Result<Option<Entry>, StoreError> {
        let sql = format!("SELECT {COLUMNS} FROM files WHERE path = ?1");
        self.conn
            .query_row(&sql, [path], RawRow::read)
            .optional()?
            .map(RawRow::into_entry)
            .transpose()
    }

    /// Sorted by raw path bytes so `resolve` output is deterministic.
    pub fn by_digest(&self, digest: &Digest) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT path FROM files WHERE alg = ?1 AND digest = ?2 ORDER BY path",
        )?;
        let rows = stmt.query_map(params![digest.alg().name(), digest.bytes()], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn upsert(&self, e: &Entry) -> Result<(), StoreError> {
        let sql =
            format!("INSERT OR REPLACE INTO files ({COLUMNS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)");
        self.conn.prepare_cached(&sql)?.execute(params![
            e.path,
            e.digest.alg().name(),
            e.digest.bytes(),
            to_sql(e.meta.size),
            e.meta.mtime_ns,
            e.meta.ctime_ns,
            to_sql(e.meta.dev),
            to_sql(e.meta.ino),
            e.last_checked_ns,
        ])?;
        Ok(())
    }

    pub fn remove(&self, path: &[u8]) -> Result<(), StoreError> {
        self.conn
            .prepare_cached("DELETE FROM files WHERE path = ?1")?
            .execute([path])?;
        Ok(())
    }

    /// Removes `root` itself and everything below it; `/rx` is not below `/r`.
    pub fn remove_under(&self, root: &RegPath) -> Result<(), StoreError> {
        let (lo, hi) = below_bounds(root);
        self.conn
            .prepare_cached(&format!("DELETE FROM files WHERE {UNDER}"))?
            .execute(params![root.as_bytes(), lo, hi])?;
        Ok(())
    }

    pub fn paths_under(&self, root: &RegPath) -> Result<Vec<Vec<u8>>, StoreError> {
        let (lo, hi) = below_bounds(root);
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT path FROM files WHERE {UNDER} ORDER BY path"
        ))?;
        let rows = stmt.query_map(params![root.as_bytes(), lo, hi], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn iter(&self) -> Result<Vec<Entry>, StoreError> {
        let mut stmt = self
            .conn
            .prepare_cached(&format!("SELECT {COLUMNS} FROM files ORDER BY path"))?;
        let raw = stmt
            .query_map([], RawRow::read)?
            .collect::<Result<Vec<_>, _>>()?;
        raw.into_iter().map(RawRow::into_entry).collect()
    }

    /// Runs `f` in one `BEGIN IMMEDIATE` transaction: commit on `Ok`,
    /// rollback on `Err`.
    pub fn batch<T>(
        &self,
        _f: impl FnOnce(&Index) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        todo!("step 3")
    }

    /// Drops every entry not under one of `roots` (registry is authoritative).
    /// An entry is under a root when it equals it or lies below `root/`.
    pub fn reconcile(&self, roots: &[RegPath]) -> Result<(), StoreError> {
        let set: HashSet<&[u8]> = roots.iter().map(RegPath::as_bytes).collect();
        let keep = |p: &[u8]| {
            set.contains(p)
                || (set.contains(&b"/"[..]) && p.first() == Some(&b'/'))
                || p.iter()
                    .enumerate()
                    .any(|(i, &b)| b == b'/' && i > 0 && set.contains(&p[..i]))
        };
        let tx = self.write_tx()?;
        let stale: Vec<Vec<u8>> = {
            let mut stmt = tx.prepare("SELECT path FROM files")?;
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            let mut stale = Vec::new();
            for row in rows {
                let p = row?;
                if !keep(&p) {
                    stale.push(p);
                }
            }
            stale
        };
        {
            let mut del = tx.prepare("DELETE FROM files WHERE path = ?1")?;
            for p in &stale {
                del.execute([p])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

fn wrap_db(e: rusqlite::Error, path: &std::path::Path) -> StoreError {
    wrap(
        std::io::Error::other(e.to_string()),
        "open index database",
        path,
    )
}
