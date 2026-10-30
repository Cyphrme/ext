//! Command-line surface (plan §5): argument parsing and the commands.
//!
//! Exit codes (plan §1): 0 ok, 1 `resolve` found nothing, 2 unaccepted
//! violation, 4 usage/config/store error, 5 incomplete scan. 3 is never used.
//! A lookup that reaches the services exits per ES-7.

use crate::cache::{Cache, CacheError, FsExecutor, Timestamp, Verified};
use crate::config::{Config, ConfigError};
use crate::digest::{Enc, Query};
use crate::escape::{display, escape, terminal};
use crate::https::{AddrTable, Client, HttpsConfig, SystemResolver};
use crate::index::Index;
use crate::lookup::{self, Attempt, Backend, EmitError, Limits, Outcome};
use crate::registry::RegPath;
use crate::scan::{self, Opts, Report, ReportKind, Summary};
use crate::services::{self, Fetchable, FileError, Scheme, ServiceUri, MAX_SERVICES};
use crate::store::{self, Store, StoreError};
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const SYSTEM_STORE: &str = "/var/lib/ext";
const EXIT_NOT_FOUND: u8 = 1;
const EXIT_USAGE: u8 = 4;
const EXIT_INCOMPLETE: u8 = 5;

/// ES-25: how long an admission waits for the store lock.
const ADMIT_LOCK_WAIT: Duration = Duration::from_secs(5);

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
    /// Register a root path, or a service URI (ES-22).
    #[command(short_flag = 'r')]
    Register {
        path: PathBuf,
    },
    /// Unregister a root path, or a service URI (ES-22).
    #[command(short_flag = 'u')]
    Unregister {
        path: PathBuf,
    },
    Resolve {
        /// Consult the local index and cache only (ES-32).
        #[arg(long)]
        offline: bool,
        digest: String,
    },
    /// Write the verified bytes of a blob to stdout (ES-11).
    Cat {
        #[arg(long)]
        offline: bool,
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
    #[error("cannot register {}: {why}", path.display())]
    InsideStore { path: PathBuf, why: &'static str },
    #[error("not a directory or regular file: {}", .0.display())]
    NotADirectoryOrFile(PathBuf),
    #[error("not a registry entry (unregister needs an exact match): {0}")]
    NotAnEntry(String),
    #[error("cannot determine the current directory: {0}")]
    Cwd(io::Error),
    #[error("{0}")]
    Services(#[from] FileError),
    #[error("{0}")]
    Cache(#[from] CacheError),
    #[error("{0}")]
    Service(String),
    #[error("cat takes <alg>:<digest> without a file name")]
    CatName,
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
            match e {
                // The blob may be indexed, so this is no usage error and no
                // "absent" either.
                CliError::Store(StoreError::IndexUnreadable { .. }) => EXIT_INCOMPLETE,
                _ => EXIT_USAGE,
            }
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
        Cmd::Register { path } if is_service(path) => {
            let (store, cfg) = open_store(cli)?;
            register_service(&store, &cfg, path)?
        }
        Cmd::Unregister { path } if is_service(path) => {
            unregister_service(&open_store(cli)?.0, path)?
        }
        Cmd::Register { path } => {
            let (store, cfg) = open_store(cli)?;
            register(&store, path, &cfg, fmt_for(cli, &cfg), w)?
        }
        Cmd::Unregister { path } => unregister(&open_store(cli)?.0, path)?,
        Cmd::Cat { offline, digest } => {
            let q = Query::parse(digest)?;
            if q.name.is_some() {
                return Err(CliError::CatName);
            }
            let (store, cfg) = open_store(cli)?;
            cfg.check_input(q.enc)?;
            cat(&store, &cfg, &Fetchable::new(q.digest), *offline, w)?
        }
        Cmd::Resolve { offline, digest } => {
            let q = Query::parse(digest)?;
            let (store, cfg) = open_store(cli)?;
            cfg.check_input(q.enc)?;
            resolve(&store, &cfg, &q, *offline, fmt_for(cli, &cfg), w)?
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
            let lock = store.lock()?;
            crate::transfer::export(&store, &lock, dir)?;
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
    let Some(md) = std::fs::metadata(&canon)
        .ok()
        .filter(|m| m.is_dir() || m.is_file())
    else {
        return Err(CliError::NotADirectoryOrFile(path.to_path_buf()));
    };
    let root = RegPath::from_bytes(canon.as_os_str().as_bytes())
        .map_err(|kind| CliError::BadRoot { path: canon, kind })?;
    let uid = std::os::unix::fs::MetadataExt::uid(&md);
    if let Some(why) =
        crate::walk::inside_store(&root, store.id(), uid).map_err(|source| CliError::Io {
            what: "cannot examine",
            path: path.to_path_buf(),
            source,
        })?
    {
        return Err(CliError::InsideStore {
            path: path.to_path_buf(),
            why,
        });
    }
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

/// ES-1 for `resolve`: the index, then the cache, then the services. A
/// query with a file name filters index paths only; the cache and the
/// services know no names, so they are not asked.
fn resolve(
    store: &Store,
    cfg: &Config,
    q: &Query,
    offline: bool,
    fmt: Fmt,
    w: &mut impl Write,
) -> Result<u8, CliError> {
    let mut paths = Index::open_for_lookup(store)?.by_digest(&q.digest)?;
    // A name is the filename: only paths ending in it are returned.
    if let Some(name) = &q.name {
        paths.retain(|p| p.rsplit(|&b| b == b'/').next() == Some(name.as_slice()));
    }
    if !paths.is_empty() {
        paths.sort();
        for p in &paths {
            fmt.record(w, &[], p, &[])?;
        }
        return Ok(0);
    }
    if q.name.is_some() {
        return Ok(EXIT_NOT_FOUND);
    }
    let cache = Cache::new(store, cfg.cache_capacity);
    cache.check()?;
    let d = Fetchable::new(q.digest.clone());
    if let Some(p) = cache.lookup(d.digest(), &mut FsExecutor { store })? {
        touch(&cache, &d);
        fmt.record(w, &[], p.as_os_str().as_bytes(), &[])?;
        return Ok(0);
    }
    if offline {
        return Ok(EXIT_NOT_FOUND);
    }
    let found = fetch(store, cfg, &cache, &d)?;
    let Some(v) = found.hit else {
        return Ok(lookup::exit_code(
            &found.outcomes,
            false,
            found.write_failed,
        ));
    };
    if let Err(e) = admit(store, &cache, v) {
        eprintln!("ext: error: {e}");
        return Ok(lookup::exit_code(&found.outcomes, false, true));
    }
    let p = store.path().join(Cache::relative_path(d.digest()));
    fmt.record(w, &[], p.as_os_str().as_bytes(), &[])?;
    Ok(0)
}

/// ES-11 for `cat`: every layer's blob is copied, hashed and only then
/// written; a layer whose copy fails verification is skipped.
fn cat(
    store: &Store,
    cfg: &Config,
    d: &Fetchable,
    offline: bool,
    w: &mut impl Write,
) -> Result<u8, CliError> {
    let cache = Cache::new(store, cfg.cache_capacity);
    cache.check()?;
    let mut index_failed = false;
    let mut paths = Index::open_for_lookup(store)?.by_digest(d.digest())?;
    paths.sort();
    for p in &paths {
        let path = Path::new(std::ffi::OsStr::from_bytes(p));
        let src = match open_regular(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "ext: cannot read indexed file {}: {}",
                    terminal(p),
                    terminal(e.to_string().as_bytes())
                );
                continue;
            }
        };
        match emit(&cache, src, d, w) {
            Emitted::Done => return Ok(0),
            Emitted::Mismatch => {
                eprintln!(
                    "ext: indexed file no longer matches its digest: {}",
                    terminal(p)
                );
                index_failed = true;
            }
            Emitted::ReadFailed(e) => {
                eprintln!(
                    "ext: cannot read indexed file {}: {}",
                    terminal(p),
                    terminal(e.to_string().as_bytes())
                );
            }
            Emitted::CopyFailed(e) => return Ok(copy_failed(&e, index_failed)),
            Emitted::OutFailed(e) => return Err(CliError::Out(e)),
        }
    }
    let mut ex = FsExecutor { store };
    if let Some(p) = cache.lookup(d.digest(), &mut ex)? {
        let rel = Cache::relative_path(d.digest());
        match store.open_nofollow(&rel) {
            Ok(src) => match emit(&cache, src, d, w) {
                Emitted::Done => {
                    touch(&cache, d);
                    return Ok(0);
                }
                Emitted::Mismatch => {
                    eprintln!(
                        "ext: cached file does not match its digest, discarded: {}",
                        terminal(p.as_os_str().as_bytes())
                    );
                    cache.discard_if_free(d.digest(), &mut ex);
                }
                Emitted::ReadFailed(e) => eprintln!(
                    "ext: cannot read cached file {}: {}",
                    terminal(p.as_os_str().as_bytes()),
                    terminal(e.to_string().as_bytes())
                ),
                Emitted::CopyFailed(e) => return Ok(copy_failed(&e, index_failed)),
                Emitted::OutFailed(e) => return Err(CliError::Out(e)),
            },
            Err(e) => eprintln!(
                "ext: cannot read cached file {}: {}",
                terminal(p.as_os_str().as_bytes()),
                terminal(e.to_string().as_bytes())
            ),
        }
    }
    if offline {
        return Ok(lookup::exit_code(&[], index_failed, false));
    }
    let found = fetch(store, cfg, &cache, d)?;
    let Some(v) = found.hit else {
        return Ok(lookup::exit_code(
            &found.outcomes,
            index_failed,
            found.write_failed,
        ));
    };
    // A second handle on the verified copy: admission renames the file, and
    // nothing is delivered unless it was admitted (ES-25).
    let mut copy = v.reopen().map_err(CliError::Out)?;
    if let Err(e) = admit(store, &cache, v) {
        eprintln!("ext: error: {e}");
        return Ok(lookup::exit_code(&found.outcomes, index_failed, true));
    }
    copy.seek(SeekFrom::Start(0)).map_err(CliError::Out)?;
    io::copy(&mut copy, w)?;
    Ok(0)
}

fn copy_failed(e: &io::Error, index_failed: bool) -> u8 {
    eprintln!(
        "ext: error: cannot make the private copy in cache/tmp (the blob may exist): {}",
        terminal(e.to_string().as_bytes())
    );
    lookup::exit_code(&[], index_failed, true)
}

/// Opens an indexed file for reading; anything but a regular file is a
/// read failure, and a FIFO cannot block the open.
fn open_regular(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(f)
}

enum Emitted {
    Done,
    Mismatch,
    ReadFailed(io::Error),
    CopyFailed(io::Error),
    OutFailed(io::Error),
}

/// Remembers whether the error came from this side, since `emit_verified`
/// reports source, copy and sink failures alike as I/O.
struct Side<T> {
    inner: T,
    failed: bool,
}

impl<T: Read> Read for Side<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).inspect_err(|_| self.failed = true)
    }
}

impl<T: Write> Write for Side<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf).inspect_err(|_| self.failed = true)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().inspect_err(|_| self.failed = true)
    }
}

fn emit(cache: &Cache, src: File, d: &Fetchable, w: &mut impl Write) -> Emitted {
    let tmp = match cache.create_tmp() {
        Ok(t) => t,
        Err(e) => return Emitted::CopyFailed(e),
    };
    let mut src = Side {
        inner: src,
        failed: false,
    };
    let mut out = Side {
        inner: w,
        failed: false,
    };
    match lookup::emit_verified(&mut src, tmp, d, &mut out) {
        Ok(_) => Emitted::Done,
        Err(EmitError::Mismatch) => Emitted::Mismatch,
        Err(EmitError::Io(e)) if src.failed => Emitted::ReadFailed(e),
        Err(EmitError::Io(e)) if out.failed => Emitted::OutFailed(e),
        Err(EmitError::Io(e)) => Emitted::CopyFailed(e),
    }
}

fn now_ns() -> Timestamp {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

/// ES-27: a hit never fails on its touch; a failure is only reported.
fn touch(cache: &Cache, d: &Fetchable) {
    if let Err(e) = cache.touch(d.digest(), now_ns()) {
        eprintln!(
            "ext: warning: cache hit not touched: {}",
            terminal(e.to_string().as_bytes())
        );
    }
}

fn admit(store: &Store, cache: &Cache, v: Verified) -> Result<(), String> {
    let lock = store
        .lock_within(ADMIT_LOCK_WAIT)
        .map_err(|e| format!("cannot admit the fetched blob: {e}"))?
        .ok_or("cannot admit the fetched blob: the store lock stayed busy for 5 s")?;
    cache
        .admit(&lock, &mut FsExecutor { store }, v, now_ns())
        .map_err(|e| {
            format!(
                "cannot admit the fetched blob: {}",
                terminal(e.to_string().as_bytes())
            )
        })
}

struct Fetch {
    outcomes: Vec<Outcome>,
    hit: Option<Verified>,
    write_failed: bool,
}

/// The services layer (ES-3 to ES-7). Each failure is reported on stderr as
/// it is recorded; `Missing` is silent.
fn fetch(store: &Store, cfg: &Config, cache: &Cache, d: &Fetchable) -> Result<Fetch, CliError> {
    let list = read_services(store)?;
    if list.is_empty() {
        return Ok(Fetch {
            outcomes: Vec::new(),
            hit: None,
            write_failed: false,
        });
    }
    let client = Client::new(
        HttpsConfig {
            allow_http: cfg.allow_http,
            allow_local: cfg.allow_local,
        },
        Box::new(SystemResolver),
        AddrTable::iana(),
    );
    let backends: Vec<_> = list.iter().map(|u| client.backend(u.clone())).collect();
    let services: Vec<(String, &dyn Backend)> = list
        .iter()
        .zip(&backends)
        .map(|(u, b)| (u.as_str().to_string(), b as &dyn Backend))
        .collect();
    let limits = Limits {
        max_size: cfg.service_max_size,
        idle: Duration::from_millis(cfg.service_idle_timeout_ms),
        total: Duration::from_millis(cfg.service_timeout_ms),
    };
    match lookup::run(&services, d, &limits, &mut || cache.create_tmp()) {
        Ok(found) => {
            for Attempt { service, outcome } in &found.attempts {
                match outcome {
                    Outcome::Error(e) => {
                        eprintln!(
                            "SERVICE {} ERROR {}",
                            terminal(service.as_bytes()),
                            terminal(e.as_bytes())
                        )
                    }
                    Outcome::Mismatch => {
                        eprintln!("SERVICE {} MISMATCH", terminal(service.as_bytes()))
                    }
                    Outcome::Hit | Outcome::Missing | Outcome::Skipped => {}
                }
            }
            Ok(Fetch {
                outcomes: found.attempts.into_iter().map(|a| a.outcome).collect(),
                hit: found.hit,
                write_failed: false,
            })
        }
        Err(e) => {
            eprintln!(
                "ext: error: cannot create a file for the fetch in cache/tmp (the blob may exist): {}",
                terminal(e.to_string().as_bytes())
            );
            Ok(Fetch {
                outcomes: Vec::new(),
                hit: None,
                write_failed: true,
            })
        }
    }
}

fn read_services(store: &Store) -> Result<Vec<ServiceUri>, CliError> {
    match store.services_bytes()? {
        Some(b) => Ok(services::parse_file(&b)?),
        None => Ok(Vec::new()),
    }
}

/// ES-22: a service when it starts like `scheme://`, otherwise a path.
fn is_service(arg: &Path) -> bool {
    let b = arg.as_os_str().as_bytes();
    let Some(at) = b.windows(3).position(|w| w == b"://") else {
        return false;
    };
    let scheme = &b[..at];
    scheme.first().is_some_and(u8::is_ascii_alphabetic)
        && scheme
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"+.-".contains(c))
}

fn parse_service_arg(arg: &Path) -> Result<ServiceUri, CliError> {
    let raw = arg.as_os_str().as_bytes();
    let text = std::str::from_utf8(raw)
        .map_err(|_| CliError::Service(format!("not a valid service URI: {}", terminal(raw))))?;
    ServiceUri::parse(text)
        .map_err(|e| CliError::Service(format!("not a valid service URI {}: {e}", terminal(raw))))
}

fn register_service(store: &Store, cfg: &Config, arg: &Path) -> Result<u8, CliError> {
    let uri = parse_service_arg(arg)?;
    if uri.scheme() == Scheme::Http && !cfg.allow_http {
        return Err(CliError::Service(format!(
            "{} is plain http, which needs AllowHTTP in the config",
            uri.as_str()
        )));
    }
    let lock = store.lock()?;
    let mut list = read_services(store)?;
    if list.contains(&uri) {
        return Ok(0);
    }
    if list.len() >= MAX_SERVICES {
        return Err(CliError::Service(format!(
            "cannot register {}: at most {MAX_SERVICES} services",
            uri.as_str()
        )));
    }
    list.push(uri);
    write_services(store, &lock, &list)
}

fn unregister_service(store: &Store, arg: &Path) -> Result<u8, CliError> {
    let uri = parse_service_arg(arg)?;
    let lock = store.lock()?;
    let mut list = read_services(store)?;
    let before = list.len();
    list.retain(|u| *u != uri);
    if list.len() == before {
        return Err(CliError::Service(format!(
            "not a registered service: {}",
            uri.as_str()
        )));
    }
    write_services(store, &lock, &list)
}

fn write_services(
    store: &Store,
    lock: &store::WriteLock,
    list: &[ServiceUri],
) -> Result<u8, CliError> {
    services::write_file(store, lock, &mut FsExecutor { store }, list).map_err(|source| {
        CliError::Io {
            what: "cannot write",
            path: store.path().join("services"),
            source,
        }
    })?;
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
