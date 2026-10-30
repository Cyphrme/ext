//! Shared harness for the external-services tests: the fake backend, a store
//! fixture around the real `ext` binary, and the independent hash oracle.
#![allow(dead_code)]

pub mod fb;

use ext::cache::{Cache, Record};
use ext::digest::{Alg, Digest};
use ext::services::Fetchable;
use ext::store::Store;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Boundary sizes every blob generator must hit (test plan, section 0).
pub const SIZES: &[usize] = &[0, 1, 55, 56, 63, 64, 65, 4095, 4096, 4097];

/// SHA-256 through the external `sha256sum`, never through the crate's own
/// hashing, so a bug in `ext::digest` cannot hide in both sides of an assert.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut c = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("sha256sum is installed");
    c.stdin.take().unwrap().write_all(data).unwrap();
    let out = c.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap()[..64].to_ascii_uppercase()
}

pub fn digest_of(data: &[u8]) -> Digest {
    let raw = data_encoding::HEXUPPER.decode(sha256_hex(data).as_bytes()).unwrap();
    Digest::from_bytes(Alg::Sha256, &raw).unwrap()
}

pub fn fetchable(data: &[u8]) -> Fetchable {
    Fetchable::new(digest_of(data))
}

/// `<b64ut>:SHA-256`, the argument form `cat` and `resolve` take.
pub fn label(data: &[u8]) -> String {
    digest_of(data).to_reverse(ext::digest::Enc::B64ut)
}

/// A deterministic blob of `n` bytes that is not all one value.
pub fn blob(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// The plan's mutation list. Each result differs from `b`.
pub fn mutations(b: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = vec![];
    let flip = |i: usize, bit: u8| {
        let mut m = b.to_vec();
        m[i] ^= bit;
        m
    };
    if !b.is_empty() {
        v.push(("flip-first", flip(0, 1)));
        v.push(("flip-last", flip(b.len() - 1, 0x80)));
        v.push(("flip-mid-bit", flip(b.len() / 2, 0x10)));
        v.push(("truncate-1", b[..b.len() - 1].to_vec()));
        v.push(("empty", vec![]));
        // Equal size, different content: passes any size-equality check.
        v.push(("subst", b.iter().map(|x| x.wrapping_add(1)).collect()));
    }
    let mut longer = b.to_vec();
    longer.push(0);
    v.push(("append-1", longer));
    v
}

pub struct Out {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub elapsed: Duration,
}

/// Runs a command to completion; a hang is killed at `limit` and reported as
/// code -1 so the assertion that follows names the failure.
pub fn run(mut cmd: Command, limit: Duration) -> Out {
    let t0 = Instant::now();
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn ext");
    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let t_out = std::thread::spawn(move || {
        let mut v = vec![];
        std::io::Read::read_to_end(&mut so, &mut v).ok();
        v
    });
    let t_err = std::thread::spawn(move || {
        let mut v = vec![];
        std::io::Read::read_to_end(&mut se, &mut v).ok();
        v
    });
    let code = loop {
        if let Some(s) = child.try_wait().unwrap() {
            // A signal death (a todo!() abort is a panic, code 101) has no code.
            break s.code().unwrap_or(-2);
        }
        if t0.elapsed() > limit {
            child.kill().ok();
            child.wait().ok();
            break -1;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    Out {
        code,
        stdout: t_out.join().unwrap(),
        stderr: String::from_utf8_lossy(&t_err.join().unwrap()).into_owned(),
        elapsed: t0.elapsed(),
    }
}

/// A bare store plus a work tree, driven through the real binary.
pub struct Env {
    pub _tmp: tempfile::TempDir,
    pub base: PathBuf,
    pub store: PathBuf,
    pub work: PathBuf,
}

const SCRUB: &[&str] = &[
    "EXTANT_DIR", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY",
    "all_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "HOSTALIASES",
];

impl Env {
    pub fn new() -> Env {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        let store = base.join("store");
        Store::init_bare(&store).unwrap();
        let work = base.join("work");
        fs::create_dir(&work).unwrap();
        Env { _tmp: t, base, store, work }
    }

    /// Runs `ext --d <store> args...` with proxies, trust and resolver
    /// variables scrubbed unless `env` sets them.
    pub fn command(&self, args: &[&str], env: &[(&str, &str)]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ext"));
        for k in SCRUB {
            c.env_remove(k);
        }
        c.envs(env.iter().copied()).arg("--d").arg(&self.store).args(args);
        c
    }

    pub fn ext_env(&self, args: &[&str], env: &[(&str, &str)], limit: Duration) -> Out {
        run(self.command(args, env), limit)
    }

    pub fn ext(&self, args: &[&str]) -> Out {
        self.ext_env(args, &[], Duration::from_secs(30))
    }

    fn put(&self, name: &str, bytes: &[u8]) {
        let p = self.store.join(name);
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Writes the store config. `AllowHTTP` and `AllowLocal` are on because
    /// the FBs speak plain http on loopback; `extra` adds more keys.
    pub fn config(&self, extra: &str) {
        self.put("config", format!("{{ AllowHTTP: true, AllowLocal: true, {extra} }}").as_bytes());
    }

    pub fn config_raw(&self, text: &str) {
        self.put("config", text.as_bytes());
    }

    /// Writes the services file directly (a fixture, not the registration path).
    pub fn services(&self, uris: &[String]) {
        let mut b = vec![];
        for u in uris {
            b.extend_from_slice(u.as_bytes());
            b.push(b'\n');
        }
        self.put("services", &b);
    }

    pub fn services_bytes(&self) -> Option<Vec<u8>> {
        fs::read(self.store.join("services")).ok()
    }

    /// Writes `work/<name>` and registers `work`, so the blob is in the index.
    pub fn index_file(&self, name: &str, content: &[u8]) -> PathBuf {
        let p = self.work.join(name);
        fs::write(&p, content).unwrap();
        let o = self.ext(&["-r", self.work.to_str().unwrap()]);
        assert_eq!(o.code, 0, "fixture: registering the work tree: {}", o.stderr);
        p
    }

    pub fn cache(&self) -> Cache<'static> {
        // The store must outlive the cache; tests are short-lived processes.
        let s: &'static Store = Box::leak(Box::new(Store::open(&self.store).unwrap()));
        Cache::new(s, 1 << 30)
    }

    pub fn records(&self) -> Vec<Record> {
        self.cache().records().expect("read the cache table")
    }

    /// Every file under `cache/` except `tmp/`, relative to `cache/`.
    pub fn cache_files(&self) -> Vec<PathBuf> {
        fn walk(dir: &Path, base: &Path, out: &mut Vec<PathBuf>) {
            let Ok(rd) = fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                if p.strip_prefix(base).unwrap() == Path::new("tmp") {
                    continue;
                }
                if e.file_type().unwrap().is_dir() {
                    walk(&p, base, out);
                } else {
                    out.push(p.strip_prefix(base).unwrap().to_path_buf());
                }
            }
        }
        let base = self.store.join("cache");
        let mut v = vec![];
        walk(&base, &base, &mut v);
        v.sort();
        v
    }

    pub fn tmp_files(&self) -> Vec<PathBuf> {
        match fs::read_dir(self.store.join("cache/tmp")) {
            Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
            Err(_) => vec![],
        }
    }
}

pub fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// Loud skip for tests whose violator is invisible to uid 0.
pub fn skip_if_root(why: &str) -> bool {
    if is_root() {
        eprintln!("SKIPPED (uid 0): {why}");
        return true;
    }
    false
}
