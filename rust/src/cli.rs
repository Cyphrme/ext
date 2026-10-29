//! Command-line surface (plan §5): argument parsing and the commands.
//!
//! Exit codes (plan §1): 0 ok, 1 `resolve` found nothing, 2 unaccepted
//! violation, 4 usage/config/store error, 5 incomplete scan. 3 is never used.

use crate::config::{Config, ConfigError};
use crate::digest::{Enc, Query};
use crate::escape::{display, escape};
use crate::index::Index;
use crate::registry::RegPath;
use crate::scan::{self, Opts, Report, ReportKind, Summary};
use crate::store::{self, Store, StoreError};
use clap::{Parser, Subcommand};
use std::io::{self, BufWriter, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const SYSTEM_STORE: &str = "/var/lib/ext";
const EXIT_NOT_FOUND: u8 = 1;
const EXIT_USAGE: u8 = 4;

#[derive(Parser, Debug)]
#[command(name = "ext", version)]
pub struct Cli {
    /// Store (or a directory whose `.ext/` is a store).
    #[arg(long = "d", global = true)]
    pub d: Option<PathBuf>,
    /// Hex (uppercase) instead of b64ut digests in output.
    #[arg(long, global = true)]
    pub hex: bool,
    /// NUL-terminated records with raw paths.
    #[arg(short = '0', global = true)]
    pub nul: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    Init {
        #[arg(conflicts_with = "bare")]
        dir: Option<PathBuf>,
        #[arg(long)]
        bare: Option<PathBuf>,
    },
    #[command(short_flag = 'r')]
    Register {
        path: PathBuf,
    },
    #[command(short_flag = 'u')]
    Unregister {
        path: PathBuf,
    },
    Resolve {
        digest: String,
    },
    List,
    Check {
        #[arg(long)]
        full: bool,
        #[arg(long)]
        accept: bool,
    },
    Rebuild,
    /// Write the registry, source and timestamp records as TSV into a directory.
    Export {
        dir: PathBuf,
    },
    /// Load an export into a store whose index is empty.
    Import {
        dir: PathBuf,
    },
}

/// Everything that ends a command early. All of these exit 4 (Display says
/// what failed and where).
#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Store(#[from] StoreError),
    #[error("{what} {}: {source}", path.display())]
    Io {
        what: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("cannot write output: {0}")]
    Out(#[from] io::Error),
    #[error("{0}")]
    Transfer(#[from] crate::transfer::TransferError),
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("{0}")]
    Digest(#[from] crate::digest::DigestError),
    #[error("not a valid registry root {}: {kind:?}", path.display())]
    BadRoot {
        path: PathBuf,
        kind: crate::registry::RegistryErrorKind,
    },
    #[error("--d names a store to open, but init creates one; give the location as an argument")]
    InitWithStoreFlag,
    #[error("not a directory: {}", .0.display())]
    NotADirectory(PathBuf),
    #[error("not a registry entry (unregister needs an exact match): {0}")]
    NotAnEntry(String),
    #[error("cannot determine the current directory: {0}")]
    Cwd(io::Error),
}

/// Output formatting shared by every record-producing command.
#[derive(Clone, Copy)]
struct Fmt {
    enc: Enc,
    nul: bool,
}

impl Fmt {
    /// Writes `head` fields, the path, then `tail` fields, tab-separated and
    /// terminated by NL (or NUL under `-0`). The path is escaped unless `-0`
    /// asked for raw bytes.
    fn record(
        self,
        w: &mut impl Write,
        head: &[&str],
        path: &[u8],
        tail: &[String],
    ) -> io::Result<()> {
        for h in head {
            w.write_all(h.as_bytes())?;
            w.write_all(b"\t")?;
        }
        if self.nul {
            w.write_all(path)?;
        } else {
            w.write_all(&escape(path))?;
        }
        for t in tail {
            w.write_all(b"\t")?;
            w.write_all(t.as_bytes())?;
        }
        w.write_all(if self.nul { b"\0" } else { b"\n" })
    }
}

/// The open store and its config, which every command that touches a store
/// applies: a bad config is an error for all of them, not just the ones that
/// happen to read the key.
fn open_store(cli: &Cli) -> Result<(Store, Config), CliError> {
    let cwd = std::env::current_dir().map_err(CliError::Cwd)?;
    let env = std::env::var_os("EXTANT_DIR");
    let (dir, _) = store::locate(
        cli.d.as_deref(),
        env.as_deref(),
        Path::new(SYSTEM_STORE),
        &cwd,
        store::is_elevated(),
    )?;
    let store = Store::open(&dir)?;
    // A malformed registry is a config error for every command, readers
    // included, not just for the ones that happen to scan.
    store.registry()?;
    let cfg = store.config()?;
    Ok((store, cfg))
}

/// `--hex` beats the config's `DefaultEnc`.
fn fmt_for(cli: &Cli, cfg: &Config) -> Fmt {
    Fmt {
        enc: if cli.hex { Enc::Hex } else { cfg.default_enc },
        nul: cli.nul,
    }
}

fn scan_opts(cfg: &Config) -> Opts {
    Opts {
        compare_ctime_inode: cfg.compare_ctime_inode,
        unregister_deleted: cfg.unregister_deleted,
        ..Opts::default()
    }
}

fn reg_path(p: &Path) -> Result<RegPath, CliError> {
    let abs = std::path::absolute(p).map_err(|source| CliError::Io {
        what: "resolve",
        path: p.to_path_buf(),
        source,
    })?;
    RegPath::from_bytes(abs.as_os_str().as_bytes())
        .map_err(|kind| CliError::BadRoot { path: abs, kind })
}

pub fn run(cli: &Cli) -> u8 {
    match dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ext: error: {e}");
            EXIT_USAGE
        }
    }
}

fn dispatch(cli: &Cli) -> Result<u8, CliError> {
    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    let result = command(cli, &mut w);
    // A reader that went away is a quiet stop, not a failure.
    let flushed = w.flush();
    match result {
        Err(CliError::Out(e)) if e.kind() == io::ErrorKind::BrokenPipe => Ok(0),
        Ok(code) => match flushed {
            Err(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(e.into()),
            _ => Ok(code),
        },
        Err(e) => Err(e),
    }
}

fn command(cli: &Cli, w: &mut impl Write) -> Result<u8, CliError> {
    let code = match &cli.cmd {
        Cmd::Init { dir, bare } => {
            if cli.d.is_some() {
                return Err(CliError::InitWithStoreFlag);
            }
            init(dir.as_deref(), bare.as_deref())?
        }
        Cmd::Register { path } => {
            let (store, cfg) = open_store(cli)?;
            register(&store, path, &cfg, fmt_for(cli, &cfg), w)?
        }
        Cmd::Unregister { path } => unregister(&open_store(cli)?.0, path)?,
        Cmd::Resolve { digest } => {
            let q = Query::parse(digest)?;
            let (store, cfg) = open_store(cli)?;
            cfg.check_input(q.enc)?;
            resolve(&store, &q, fmt_for(cli, &cfg), w)?
        }
        Cmd::List => {
            let (store, cfg) = open_store(cli)?;
            list(&store, fmt_for(cli, &cfg), w)?
        }
        Cmd::Check { full, accept } => {
            let (store, cfg) = open_store(cli)?;
            let opts = Opts {
                full: *full,
                accept: *accept,
                ..scan_opts(&cfg)
            };
            scan_locked(&store, &opts, false, fmt_for(cli, &cfg), w)?
        }
        Cmd::Export { dir } => {
            let (store, _cfg) = open_store(cli)?;
            // Writers hold this lock, so the registry and the index are read
            // with none between them.
            let _lock = store.lock()?;
            crate::transfer::export(&store, dir)?;
            0
        }
        Cmd::Import { dir } => {
            crate::transfer::import(&open_store(cli)?.0, dir)?;
            0
        }
        Cmd::Rebuild => {
            let (store, cfg) = open_store(cli)?;
            let opts = Opts {
                full: true,
                accept: true,
                ..scan_opts(&cfg)
            };
            scan_locked(&store, &opts, true, fmt_for(cli, &cfg), w)?
        }
    };
    Ok(code)
}

fn init(dir: Option<&Path>, bare: Option<&Path>) -> Result<u8, CliError> {
    match bare {
        Some(path) => Store::init_bare(path)?,
        None => {
            let cwd;
            let dir = match dir {
                Some(d) => d,
                None => {
                    cwd = std::env::current_dir().map_err(CliError::Cwd)?;
                    &cwd
                }
            };
            Store::init_extant(dir)?
        }
    };
    Ok(0)
}

fn register(
    store: &Store,
    path: &Path,
    cfg: &Config,
    fmt: Fmt,
    w: &mut impl Write,
) -> Result<u8, CliError> {
    let lock = store.lock()?;
    let canon = std::fs::canonicalize(path).map_err(|source| CliError::Io {
        what: "cannot register",
        path: path.to_path_buf(),
        source,
    })?;
    if !std::fs::metadata(&canon).is_ok_and(|m| m.is_dir()) {
        return Err(CliError::NotADirectory(path.to_path_buf()));
    }
    let root = RegPath::from_bytes(canon.as_os_str().as_bytes())
        .map_err(|kind| CliError::BadRoot { path: canon, kind })?;
    let already = store.registry()?.contains(&root);
    store.edit_registry(&lock, |v| {
        if !v.contains(&root) {
            v.push(root.clone());
        }
    })?;
    let idx = Index::open(store)?;
    // Re-registering is the operator vouching for the root's current
    // filesystem (its id can change legitimately, e.g. after a remount).
    if already {
        if let Ok(id) = crate::walk::root_id(&root) {
            idx.set_root_id(&root, id)?;
        }
    }
    let opts = Opts {
        only: Some(root),
        ..scan_opts(cfg)
    };
    report_scan(store, &lock, &idx, &opts, fmt, w)
}

fn unregister(store: &Store, path: &Path) -> Result<u8, CliError> {
    let lock = store.lock()?;
    let root = reg_path(path)?;
    if !store.registry()?.contains(&root) {
        return Err(CliError::NotAnEntry(display(root.as_bytes())));
    }
    let idx = Index::open(store)?;
    // Registry first: if we die between the two, the next run's reconcile
    // drops the orphaned entries.
    store.edit_registry(&lock, |v| v.retain(|r| *r != root))?;
    idx.remove_under(&root)?;
    Ok(0)
}

fn resolve(store: &Store, q: &Query, fmt: Fmt, w: &mut impl Write) -> Result<u8, CliError> {
    let mut paths = Index::open(store)?.by_digest(&q.digest)?;
    // A name is the filename: only paths ending in it are returned.
    if let Some(name) = &q.name {
        paths.retain(|p| p.rsplit(|&b| b == b'/').next() == Some(name.as_slice()));
    }
    if paths.is_empty() {
        return Ok(EXIT_NOT_FOUND);
    }
    paths.sort();
    for p in &paths {
        fmt.record(w, &[], p, &[])?;
    }
    Ok(0)
}

fn list(store: &Store, fmt: Fmt, w: &mut impl Write) -> Result<u8, CliError> {
    let entries = Index::open(store)?.iter()?;
    // The record's first field is the encoded text, so that is the sort key
    // (the same order `export` gives `source`).
    let mut rows: Vec<(String, &[u8])> = entries
        .iter()
        .map(|e| (e.digest.to_reverse(fmt.enc), e.path.as_slice()))
        .collect();
    rows.sort();
    for (d, p) in &rows {
        fmt.record(w, &[d], p, &[])?;
    }
    Ok(0)
}

/// `check` and `rebuild`: take the lock for the whole run.
fn scan_locked(
    store: &Store,
    opts: &Opts,
    clear: bool,
    fmt: Fmt,
    w: &mut impl Write,
) -> Result<u8, CliError> {
    let lock = store.lock()?;
    let idx = Index::open(store)?;
    if clear {
        // An explicit new baseline: nothing from the old index survives.
        idx.reconcile(&[])?;
    }
    report_scan(store, &lock, &idx, opts, fmt, w)
}

fn label(kind: ReportKind) -> &'static str {
    match kind {
        ReportKind::New => "NEW",
        ReportKind::Edited => "EDITED",
        ReportKind::Violation => "VIOLATION",
        ReportKind::Accepted => "ACCEPTED",
        ReportKind::Missing => "MISSING",
        ReportKind::Deleted => "DELETED",
        ReportKind::Excluded => "EXCLUDED",
        ReportKind::Unstable => "UNSTABLE",
        ReportKind::Error => "ERROR",
        ReportKind::Refused => "REFUSED",
        ReportKind::SubExtant => "SUBEXTANT",
        ReportKind::Mount => "MOUNT",
    }
}

fn report_scan(
    store: &Store,
    lock: &store::WriteLock,
    idx: &Index,
    opts: &Opts,
    fmt: Fmt,
    w: &mut impl Write,
) -> Result<u8, CliError> {
    // The callback cannot return an error; keep the first write failure and
    // stop printing, then surface it once the scan (which must finish its
    // index writes) returns.
    let mut write_err: Option<io::Error> = None;
    let summary = scan::run(store, lock, idx, opts, &mut |r: Report| {
        if write_err.is_some() {
            return;
        }
        let mut tail: Vec<String> = r
            .digests
            .iter()
            .flat_map(|(exp, act)| [exp.to_reverse(fmt.enc), act.to_reverse(fmt.enc)])
            .collect();
        // The cause is text from the OS; escape it like a path so it cannot
        // carry control bytes, and keep it a single tab-separated field.
        tail.extend(r.detail.iter().map(|d| display(d.as_bytes())));
        if let Err(e) = fmt.record(w, &[label(r.kind)], &r.path, &tail) {
            write_err = Some(e);
        }
    })?;
    let code = u8::try_from(summary.exit_code()).unwrap_or(EXIT_USAGE);
    let broken = |e: &io::Error| e.kind() == io::ErrorKind::BrokenPipe;
    // The scan finished and the index is written; only the report was cut
    // short. A vanished reader is a quiet stop with the summary's code.
    match write_err.map_or_else(|| w.flush(), Err) {
        Err(e) if broken(&e) => return Ok(code),
        Err(e) => return Err(e.into()),
        Ok(()) => {}
    }
    eprintln!("{}", summary_line(&summary));
    Ok(code)
}

fn summary_line(s: &Summary) -> String {
    format!(
        "new={} edited={} unchanged={} skipped={} violation={} accepted={} missing={} deleted={} \
         excluded={} unstable={} error={} refused={} subextant={} mount={} symlinks={} special={}",
        s.new,
        s.edited,
        s.unchanged,
        s.skipped,
        s.violation,
        s.accepted,
        s.missing,
        s.deleted,
        s.excluded,
        s.unstable,
        s.error,
        s.refused,
        s.subextant,
        s.mount,
        s.symlinks,
        s.special
    )
}
