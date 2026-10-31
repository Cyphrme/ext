//! Step 4: end-to-end contract of the `ext` binary (plan §5, §1 exit codes,
//! D1-D3, amendments 26/26b/26c/26d). Scan internals are step 3; here only
//! the CLI's behaviour around them is pinned.
//!
//! Run: `cargo test --test cli`.
//!
//! Fixtures seed the index through the library (`Index::upsert`) wherever a
//! test is about `resolve`/`list`, so those fail only at the CLI. Tests that
//! need real scanning go through `ext check`, as a user would.
//!
//! Every invocation goes through `run`, which asserts the exit code is never
//! 3 (reserved, never produced in v1).

mod common;

use assert_cmd::Command;
use ext::digest::{Alg, Digest, Enc};
use ext::escape::{display, escape};
use ext::index::{Entry, Index, Meta};
use ext::registry::RegPath;
use ext::store::Store;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

impl Out {
    fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    fn lines(&self) -> Vec<Vec<u8>> {
        split(&self.stdout, b'\n')
    }
}

/// Splits on a terminator; a trailing terminator yields no empty tail.
fn split(b: &[u8], sep: u8) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = b.split(|&c| c == sep).map(<[u8]>::to_vec).collect();
    if v.last().is_some_and(Vec::is_empty) {
        v.pop();
    }
    v
}

fn cmd() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ext"));
    c.env_remove("EXTANT_DIR").timeout(Duration::from_secs(60));
    c
}

fn run(c: &mut Command) -> Out {
    let o = c.output().expect("ext spawns and finishes");
    let code = o.status.code().expect("ext exited by signal, not a status");
    assert_ne!(code, 3, "exit 3 is reserved and never produced in v1");
    Out {
        code,
        stdout: o.stdout,
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn dg(data: &[u8]) -> Digest {
    Digest::compute(Alg::Sha256, data)
}
fn rev(data: &[u8]) -> String {
    dg(data).to_reverse(Enc::B64ut)
}
fn rev_hex(data: &[u8]) -> String {
    dg(data).to_reverse(Enc::Hex)
}

fn p_bytes(p: &Path) -> Vec<u8> {
    p.as_os_str().as_bytes().to_vec()
}

struct Fx {
    _t: tempfile::TempDir,
    base: PathBuf,
    tree: PathBuf,
    store: PathBuf,
}

impl Fx {
    /// `<base>/tree` registered in a bare store at `<base>/store`.
    fn new() -> Fx {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        let tree = base.join("tree");
        fs::create_dir(&tree).unwrap();
        let store = base.join("store");
        let st = Store::init_bare(&store).unwrap();
        let lock = st.lock().unwrap();
        st.edit_registry(&lock, |v| {
            *v = vec![RegPath::from_bytes(&p_bytes(&tree)).unwrap()]
        })
        .unwrap();
        drop(lock);
        Fx {
            _t: t,
            base,
            tree,
            store,
        }
    }

    /// `ext` aimed at this fixture's store through EXTANT_DIR.
    fn ext(&self) -> Command {
        let mut c = cmd();
        c.env("EXTANT_DIR", &self.store);
        c
    }

    fn write(&self, rel: &str, data: &[u8]) -> PathBuf {
        let p = self.tree.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, data).unwrap();
        p
    }

    fn index(&self) -> Index {
        Index::open(&Store::open(&self.store).unwrap()).unwrap()
    }

    fn registry_text(&self) -> Vec<u8> {
        fs::read(self.store.join("registry")).unwrap()
    }

    /// Index an entry directly (no files needed): bogus but plausible meta.
    fn seed(&self, path: &[u8], content: &[u8]) {
        self.index()
            .upsert(&Entry {
                path: path.to_vec(),
                digest: dg(content),
                meta: Meta {
                    size: content.len() as u64,
                    mtime_ns: 1,
                    ctime_ns: 1,
                    dev: 1,
                    ino: 1,
                },
                last_checked_ns: 1_000_000_000_000,
            })
            .unwrap();
    }

    fn check(&self) -> Out {
        run(self.ext().arg("check"))
    }
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// The cwd-fallback and "no store" tests assume the host has no system store.
/// Tests never touch it; if one exists they cannot assert step 4 of the order.
fn system_store_present() -> bool {
    Path::new("/var/lib/ext/registry").exists()
}

fn tmp_dir() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = fs::canonicalize(t.path()).unwrap();
    (t, p)
}

fn status_lines(o: &Out, status: &str) -> Vec<Vec<Vec<u8>>> {
    o.lines()
        .into_iter()
        .map(|l| split(&l, b'\t'))
        .filter(|f| f.first().map(Vec::as_slice) == Some(status.as_bytes()))
        .collect()
}

// ---------------------------------------------------------------- help/usage

/// §1 exit table: 4 = usage.
#[test]
fn usage_errors_exit_4() {
    let fx = Fx::new();
    for args in [
        vec![],
        vec!["frobnicate"],
        vec!["check", "--bogus"],
        vec!["resolve"],
        vec!["register"],
        vec!["init", "--bare"],
    ] {
        let o = run(fx.ext().args(&args));
        assert_eq!(o.code, 4, "args {args:?}: stderr={}", o.stderr);
        assert!(!o.stderr.is_empty(), "args {args:?}: silent failure");
    }
    // A resolve argument that is not a labelled digest is a usage error, never
    // "not found" (1); the unlabelled case says why.
    let v = dg(b"c").encode(Enc::B64ut);
    let unlabelled = run(fx.ext().arg("resolve").arg(&v));
    assert_eq!(unlabelled.code, 4);
    assert!(
        unlabelled.stderr.to_lowercase().contains("label"),
        "{}",
        unlabelled.stderr
    );
    let bad_char = format!("{}$:SHA-256", &v[..42]);
    let o = run(fx.ext().arg("resolve").arg(&bad_char));
    assert_eq!((o.code, o.stdout.len()), (4, 0), "{}", o.stderr);
    // Asking for help or the version is success.
    for flag in ["--help", "--version"] {
        let o = run(fx.ext().arg(flag));
        assert_eq!(o.code, 0, "{flag}: {}", o.stderr);
        assert!(!o.stdout.is_empty(), "{flag}: nothing printed");
    }
}

// ---------------------------------------------------------------------- init

/// §5 "Its first `check` indexes the directory", through the cwd step (D2).
#[test]
fn init_then_check_indexes_the_directory() {
    if system_store_present() {
        return; // would shadow ./.ext at resolution step 3; see header
    }
    let (_t, base) = tmp_dir();
    fs::write(base.join("f"), b"hello").unwrap();
    assert_eq!(run(cmd().arg("init").current_dir(&base)).code, 0);
    // `init` with no argument registers the canonical working directory.
    let mut registered = p_bytes(&base);
    registered.push(b'\n');
    assert_eq!(fs::read(base.join(".ext/registry")).unwrap(), registered);
    let o = run(cmd().arg("check").current_dir(&base));
    assert_eq!(o.code, 0, "{}", o.stderr);
    let f = base.join("f");
    let new = status_lines(&o, "NEW");
    assert!(
        new.iter().any(|l| l[1] == escape(&p_bytes(&f))),
        "no NEW for {f:?} in {}",
        o.out()
    );
    let r = run(cmd().arg("resolve").arg(rev(b"hello")).current_dir(&base));
    assert_eq!(r.code, 0);
}

// ---------------------------------------------------------- store resolution

fn two_stores() -> (Fx, Fx) {
    let (a, b) = (Fx::new(), Fx::new());
    a.seed(b"/only/in/a", b"A");
    b.seed(b"/only/in/b", b"B");
    (a, b)
}

/// §1: an explicit path that is no store is an error; never falls through,
/// even though cwd holds a perfectly good ./.ext.
#[test]
fn explicit_missing_store_exits_4_without_fallthrough() {
    let (_t, base) = tmp_dir();
    assert_eq!(run(cmd().arg("init").arg(&base)).code, 0);
    let nope = base.join("nope");
    let o = run(cmd().arg("list").arg("--d").arg(&nope).current_dir(&base));
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains(nope.to_str().unwrap()), "{}", o.stderr);
    let o = run(cmd()
        .env("EXTANT_DIR", &nope)
        .arg("list")
        .current_dir(&base));
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains(nope.to_str().unwrap()), "{}", o.stderr);
    // a directory that exists but is not a store
    let plain = base.join("plain");
    fs::create_dir(&plain).unwrap();
    let o = run(cmd().arg("list").arg("--d").arg(&plain).current_dir(&base));
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains(plain.to_str().unwrap()), "{}", o.stderr);
}

// --------------------------------------------------------- foreign / unsafe

// ------------------------------------------------------------------ register

/// §5 register: add + limited check; then `resolve` finds the file.
#[test]
fn register_then_resolve_finds_the_file() {
    let fx = Fx::new();
    let other = fx.base.join("other");
    fs::create_dir(&other).unwrap();
    fs::write(other.join("f"), b"payload").unwrap();
    let o = run(fx.ext().arg("register").arg(&other));
    assert_eq!(o.code, 0, "{}", o.stderr);
    let r = run(fx.ext().arg("resolve").arg(rev(b"payload")));
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.out(), format!("{}\n", other.join("f").display()));
}

// ---------------------------------------------------------------- unregister

/// §5: "must match a registry entry exactly". Prefix or child -> exit 4,
/// nothing removed. (Exit 4 is an invented choice; see report.)
#[test]
fn unregister_requires_an_exact_entry() {
    let fx = Fx::new();
    fx.write("sub/f", b"keep");
    assert_eq!(fx.check().code, 0);
    let before = fx.registry_text();
    for p in [
        fx.base.clone(),
        fx.tree.join("sub"),
        fx.base.join("elsewhere"),
    ] {
        let o = run(fx.ext().arg("unregister").arg(&p));
        assert_eq!(o.code, 4, "{p:?}: {}", o.stderr);
        assert!(o.stderr.contains(p.to_str().unwrap()), "{}", o.stderr);
    }
    assert_eq!(fx.registry_text(), before);
    assert_eq!(run(fx.ext().arg("resolve").arg(rev(b"keep"))).code, 0);
}

// ------------------------------------------------------------------- resolve

// ---------------------------------------------------------------------- list

fn seeded_many(fx: &Fx) -> Vec<(Digest, Vec<u8>)> {
    let mut v = Vec::new();
    for i in 0..24u8 {
        let content = [i, 7];
        let path = format!("/p/{:02}", 23 - i).into_bytes();
        fx.seed(&path, &content);
        v.push((dg(&content), path));
    }
    // two paths sharing one digest, to exercise the path tiebreak
    fx.seed(b"/p/zz", &[0, 7]);
    fx.seed(b"/p/aa", &[0, 7]);
    v.push((dg(&[0, 7]), b"/p/zz".to_vec()));
    v.push((dg(&[0, 7]), b"/p/aa".to_vec()));
    v
}

/// §5 list: `<value>:<alg>\t<escaped path>`, sorted by (encoded digest text, path) bytes,
/// the order `export` gives `source`.
#[test]
fn list_format_and_order() {
    let fx = Fx::new();
    let mut want = seeded_many(&fx);
    let text = |d: &Digest| d.to_reverse(Enc::B64ut);
    let mut by_bytes = want.clone();
    by_bytes.sort_by(|a, b| (a.0.bytes(), &a.1).cmp(&(b.0.bytes(), &b.1)));
    want.sort_by(|a, b| (text(&a.0).as_bytes(), &a.1).cmp(&(text(&b.0).as_bytes(), &b.1)));
    assert_ne!(
        want.iter().map(|w| text(&w.0)).collect::<Vec<_>>(),
        by_bytes.iter().map(|w| text(&w.0)).collect::<Vec<_>>(),
        "fixture premise: text order must differ from digest-byte order"
    );
    let o = run(fx.ext().arg("list"));
    assert_eq!(o.code, 0, "{}", o.stderr);
    let expect: String = want
        .iter()
        .map(|(d, p)| format!("{}\t{}\n", d.to_reverse(Enc::B64ut), display(p)))
        .collect();
    assert_eq!(o.out(), expect);
    // --hex: uppercase hex, same shape, sorted by the hex text.
    want.sort_by(|a, b| {
        let h = |d: &Digest| d.to_reverse(Enc::Hex);
        (h(&a.0).as_bytes(), &a.1).cmp(&(h(&b.0).as_bytes(), &b.1))
    });
    let o = run(fx.ext().arg("--hex").arg("list"));
    let expect: String = want
        .iter()
        .map(|(d, p)| format!("{}\t{}\n", d.to_reverse(Enc::Hex), display(p)))
        .collect();
    assert_eq!(o.out(), expect);
}

// --------------------------------------------------------------------- check

/// Index a file, then forge a different digest under matching, non-racy
/// metadata. Returns the file path and the forged digest's source bytes.
fn tamper(fx: &Fx, f: &Path) {
    let ix = fx.index();
    let e = ix.get(&p_bytes(f)).unwrap().expect("indexed by check");
    ix.upsert(&Entry {
        digest: dg(b"FORGED"),
        // clear of the 2 s racy window without sleeping
        last_checked_ns: e.last_checked_ns + 10_000_000_000,
        ..e
    })
    .unwrap();
}

/// A1/§1: a file now under a new sub-extant is EXCLUDED and the subtree is
/// reported SUBEXTANT.
#[test]
fn check_excluded_and_subextant() {
    let fx = Fx::new();
    let f = fx.write("sub/f", b"inside");
    assert_eq!(fx.check().code, 0);
    Store::init_extant(&fx.tree.join("sub")).unwrap(); // only a real store makes a sub-extant
    let o = fx.check();
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(status_lines(&o, "EXCLUDED")[0][1], p_bytes(&f));
    assert_eq!(
        status_lines(&o, "SUBEXTANT")[0][1],
        p_bytes(&fx.tree.join("sub"))
    );
    assert!(fx.index().get(&p_bytes(&f)).unwrap().is_none());
}

/// §1 exit 5 + C8: unreadable file -> ERROR line, entry kept, exit 5.
#[test]
fn check_unreadable_file_exits_5() {
    if is_root() {
        return;
    }
    let fx = Fx::new();
    let f = fx.write("f", b"secret");
    assert_eq!(fx.check().code, 0);
    fs::write(&f, b"secret!").unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o000)).unwrap();
    let o = fx.check();
    assert_eq!(o.code, 5, "{}", o.stderr);
    assert_eq!(status_lines(&o, "ERROR")[0][1], p_bytes(&f));
    assert!(fx.index().get(&p_bytes(&f)).unwrap().is_some());
}

/// §5: symlinks and special files are counted on stderr, never listed on
/// stdout, never followed or opened.
#[test]
fn check_counts_symlinks_and_special_files_on_stderr() {
    let fx = Fx::new();
    fx.write("real", b"r");
    std::os::unix::fs::symlink("/etc/hostname", fx.tree.join("lnk")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        fx.tree.join("fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let o = fx.check();
    assert_eq!(o.code, 0, "{}", o.stderr);
    let e = o.stderr.to_lowercase();
    assert!(
        e.contains("symlink") && e.contains("special"),
        "{}",
        o.stderr
    );
    assert!(!o.out().contains("lnk") && !o.out().contains("fifo"));
}

/// §5 rebuild: clear + full re-hash accepting everything (new baseline).
#[test]
fn rebuild_resets_the_baseline() {
    let fx = Fx::new();
    let f = fx.write("f", b"truth");
    assert_eq!(fx.check().code, 0);
    tamper(&fx, &f);
    fx.seed(b"/stale/not/under/any/root", b"stale");
    let o = run(fx.ext().arg("rebuild"));
    assert_eq!(o.code, 0, "{}", o.stderr);
    let ix = fx.index();
    assert_eq!(ix.get(&p_bytes(&f)).unwrap().unwrap().digest, dg(b"truth"));
    assert_eq!(ix.iter().unwrap().len(), 1, "stale entries must be gone");
    assert_eq!(run(fx.ext().args(["check", "--full"])).code, 0);
}

// --------------------------------------------------------------- concurrency

/// §1 concurrency: readers take no lock; writers hold it for the whole run
/// and therefore wait for a held lock.
#[test]
fn readers_do_not_block_but_writers_wait_for_the_lock() {
    let fx = Fx::new();
    fx.seed(b"/x", b"r");
    let st = Store::open(&fx.store).unwrap();
    let held = st.lock().unwrap();

    let o = run(fx.ext().timeout(Duration::from_secs(20)).arg("list"));
    assert_eq!(o.code, 0, "reader blocked or failed: {}", o.stderr);

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_ext"))
        .env("EXTANT_DIR", &fx.store)
        .arg("check")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(700));
    let early = child.try_wait().unwrap();
    if early.is_none() {
        drop(held);
    }
    let status = child.wait().unwrap();
    assert!(
        early.is_none(),
        "writer finished ({early:?}) while the lock was held"
    );
    assert_eq!(status.code(), Some(0));
}

// ------------------------------------------------- store resolution wiring

/// §1 order, as far as the binary has to prove it: the semantics live in
/// store::precedence_table_all_combinations, here only that `--d` and
/// EXTANT_DIR are wired in the right order and the cwd step is `./.ext`.
#[test]
fn store_resolution_wiring() {
    let (a, b) = two_stores();
    let listed = |c: &mut Command| run(c.arg("list")).out();
    // --d beats EXTANT_DIR
    let o = run(cmd()
        .env("EXTANT_DIR", &b.store)
        .arg("list")
        .arg("--d")
        .arg(&a.store));
    assert!(o.out().contains("/only/in/a") && !o.out().contains("/only/in/b"));
    // EXTANT_DIR alone selects
    assert!(listed(cmd().env("EXTANT_DIR", &b.store)).contains("/only/in/b"));
    if system_store_present() {
        return; // would shadow ./.ext at resolution step 3
    }
    // ./.ext is the last resort, and an empty EXTANT_DIR counts as unset
    let (_t, base) = tmp_dir();
    assert_eq!(run(cmd().arg("init").arg(&base)).code, 0);
    for env in [None, Some("")] {
        let mut c = cmd();
        c.current_dir(&base);
        if let Some(v) = env {
            c.env("EXTANT_DIR", v);
        }
        let o = run(c.arg("list"));
        assert_eq!(o.code, 0, "EXTANT_DIR={env:?}: {}", o.stderr);
    }
}

// ----------------------------------------------------------- init, roots

/// R7: init never overwrites: exit 4, the path named, bytes untouched.
#[test]
fn init_never_overwrites() {
    let (_t, base) = tmp_dir();
    assert_eq!(run(cmd().arg("init").arg(&base)).code, 0);
    let before = fs::read(base.join(".ext/registry")).unwrap();
    let o = run(cmd().arg("init").arg(&base));
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains(base.to_str().unwrap()), "{}", o.stderr);
    assert_eq!(fs::read(base.join(".ext/registry")).unwrap(), before);

    let st = base.join("sys");
    fs::create_dir(&st).unwrap();
    fs::write(st.join("keep"), b"x").unwrap();
    let o = run(cmd().args(["init", "--bare"]).arg(&st));
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains(st.to_str().unwrap()), "{}", o.stderr);
    assert_eq!(fs::read(st.join("keep")).unwrap(), b"x");
}

/// S3: register, canonicalise, unregister, through the binary.
#[test]
fn roots() {
    let fx = Fx::new();
    let registry_lines = |fx: &Fx| split(&fx.registry_text(), b'\n');
    let other = fx.base.join("other");
    fs::create_dir_all(other.join("sub")).unwrap();
    fs::write(other.join("f"), b"payload").unwrap();

    // `-r`, through a messy path, twice: one canonical line.
    let messy = other.join("sub/..");
    for _ in 0..2 {
        let o = run(fx.ext().arg("-r").arg(&messy));
        assert_eq!(o.code, 0, "{}", o.stderr);
    }
    let hits = registry_lines(&fx)
        .iter()
        .filter(|l| **l == p_bytes(&other))
        .count();
    assert_eq!(hits, 1, "{}", String::from_utf8_lossy(&fx.registry_text()));
    assert!(!String::from_utf8_lossy(&fx.registry_text()).contains(".."));

    // Through a symlink: the real directory is recorded, not the link.
    let real = fx.base.join("real");
    fs::create_dir(&real).unwrap();
    let link = fx.base.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(run(fx.ext().arg("register").arg(&link)).code, 0);
    assert!(registry_lines(&fx).contains(&p_bytes(&real)));
    assert!(!registry_lines(&fx).contains(&p_bytes(&link)));

    // A path that does not exist: exit 4, named, registry unchanged.
    let ghost = fx.base.join("ghost");
    let before = fx.registry_text();
    let o = run(fx.ext().arg("register").arg(&ghost));
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains(ghost.to_str().unwrap()), "{}", o.stderr);
    assert_eq!(fx.registry_text(), before);

    // `-u` drops the line and the entries; the files are untouched.
    assert_eq!(run(fx.ext().arg("resolve").arg(rev(b"payload"))).code, 0);
    let o = run(fx.ext().arg("-u").arg(&other));
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(!registry_lines(&fx).contains(&p_bytes(&other)));
    assert_eq!(run(fx.ext().arg("resolve").arg(rev(b"payload"))).code, 1);
    assert!(other.join("f").exists());
}

// ------------------------------------------------- what e2e.rs does not say

/// Rows the lifecycle in e2e.rs lacks: resolve's accepted spellings and its
/// miss, `--hex` on check, and a deletion reported as MISSING.
#[test]
fn resolve_and_check_wiring() {
    let fx = Fx::new();
    fx.seed(b"/x/file", b"content");
    let d = dg(b"content");
    for form in [
        format!("{}:SHA-256", d.encode(Enc::Hex).to_lowercase()),
        format!("SHA-256:{}", d.encode(Enc::B64ut)),
    ] {
        let o = run(fx.ext().arg("resolve").arg(&form));
        assert_eq!(
            (o.code, o.out().as_str()),
            (0, "/x/file\n"),
            "{form}: {}",
            o.stderr
        );
    }
    let o = run(fx.ext().arg("resolve").arg(rev(b"absent")));
    assert_eq!((o.code, o.stdout.len()), (1, 0));

    let f = fx.write("f", b"before");
    assert_eq!(fx.check().code, 0);
    fs::write(&f, b"after, longer").unwrap();
    let o = run(fx.ext().args(["--hex", "check"]));
    assert_eq!(
        o.out(),
        format!(
            "EDITED\t{}\t{}\t{}\n",
            f.display(),
            rev_hex(b"before"),
            rev_hex(b"after, longer")
        )
    );
    fs::remove_file(&f).unwrap();
    let o = fx.check();
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.out(), format!("MISSING\t{}\n", f.display()));
    assert!(fx.index().get(&p_bytes(&f)).unwrap().is_none());
}

/// TSV escaping: tab and newline in names cannot split or forge a record;
/// every other byte (control, bidi, invalid UTF-8) is verbatim. `-0` gives
/// raw paths with NUL-terminated records.
#[test]
fn hostile_names() {
    let fx = Fx::new();
    let names: [&[u8]; 5] = [
        b"a\x1b[31m",
        b"n\nl",
        b"t\tb",
        "\u{202e}rtl".as_bytes(),
        b"\xffbad",
    ];
    let mut files: Vec<(Vec<u8>, String)> = Vec::new();
    for (i, n) in names.iter().enumerate() {
        let content = format!("content {i}");
        let p = fx.tree.join(OsStr::from_bytes(n));
        fs::write(&p, &content).unwrap();
        files.push((p_bytes(&p), content));
    }
    let sorted = |mut v: Vec<Vec<u8>>| {
        v.sort();
        v
    };
    let rec = |head: &str, p: &[u8]| [head.as_bytes(), b"\t", &escape(p)].concat();

    let o = fx.check();
    assert_eq!(o.code, 0, "{}", o.stderr);
    let lines = o.lines();
    assert!(
        lines.iter().all(|l| l.split(|&b| b == b'\t').count() == 2),
        "{lines:?}"
    );
    let want = files.iter().map(|(p, _)| rec("NEW", p)).collect();
    assert_eq!(sorted(lines), sorted(want));

    for (p, c) in &files {
        let o = run(fx.ext().arg("resolve").arg(rev(c.as_bytes())));
        assert_eq!(
            (o.code, o.stdout),
            (0, [escape(p), b"\n".to_vec()].concat())
        );
    }
    let o = run(fx.ext().arg("list"));
    let want = files
        .iter()
        .map(|(p, c)| rec(&rev(c.as_bytes()), p))
        .collect();
    assert_eq!(sorted(o.lines()), sorted(want));

    // -0: raw paths, NUL-terminated records.
    let nul_sorted = |o: &Out| {
        let mut v = split(&o.stdout, 0);
        v.sort();
        v
    };
    let raw_records = |prefix: &dyn Fn(&str) -> Vec<u8>| {
        let mut v: Vec<Vec<u8>> = files
            .iter()
            .map(|(p, c)| {
                let mut r = prefix(c);
                r.extend_from_slice(p);
                r
            })
            .collect();
        v.sort();
        v
    };
    let o = run(fx.ext().args(["-0", "rebuild"]));
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(nul_sorted(&o), raw_records(&|_| b"NEW\t".to_vec()));
    let o = run(fx.ext().args(["-0", "list"]));
    assert_eq!(
        nul_sorted(&o),
        raw_records(&|c| format!("{}\t", rev(c.as_bytes())).into_bytes())
    );
    for (p, c) in &files {
        let o = run(fx.ext().args(["-0", "resolve"]).arg(rev(c.as_bytes())));
        assert_eq!(o.stdout, [p.as_slice(), b"\0"].concat());
    }
}

// ----------------------------------------------- amendment 26f: CLI changes

/// Spawns `ext ARGS` against the fixture's store with piped output, so the
/// test can close the reading end.
fn spawn_piped(fx: &Fx, args: &[&str]) -> std::process::Child {
    use std::process::Stdio;
    std::process::Command::new(env!("CARGO_BIN_EXE_ext"))
        .env("EXTANT_DIR", &fx.store)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Well past a 64 KiB pipe, so the writer is still writing when the reader
/// goes away.
fn long_name_pad() -> String {
    "p".repeat(150)
}

/// A reader that goes away is a quiet stop, not an error:
/// `ext list | head -1` exits 0 with nothing on stderr.
#[test]
fn list_under_broken_pipe_exits_0_silently() {
    use std::io::BufRead;
    let fx = Fx::new();
    let pad = long_name_pad();
    fx.index()
        .batch(|ix| {
            (0..2000).try_for_each(|i: usize| {
                ix.upsert(&Entry {
                    path: format!("/seed/{pad}{i:05}").into_bytes(),
                    digest: dg(b"seed"),
                    meta: Meta {
                        size: 1,
                        mtime_ns: 1,
                        ctime_ns: 1,
                        dev: 1,
                        ino: i as u64,
                    },
                    last_checked_ns: 1_000_000_000_000,
                })
            })
        })
        .unwrap();
    let mut child = spawn_piped(&fx, &["list"]);
    let mut first = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap(); // the reader is dropped here
    assert!(first.starts_with(&rev(b"seed")), "{first}");
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert_eq!(err, "");
}

/// `check` whose reader went away still exits with the summary's code (2 for
/// a violation) and prints no error: the scan finished, only the report did
/// not.
#[test]
fn check_under_broken_pipe_exits_with_the_summary_code() {
    let fx = Fx::new();
    let f = fx.write("f", b"truth");
    assert_eq!(fx.check().code, 0);
    tamper(&fx, &f);
    let pad = long_name_pad();
    for i in 0..1500 {
        fx.write(&format!("{pad}{i:05}"), b"new");
    }
    let mut child = spawn_piped(&fx, &["check", "--full"]);
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(!err.contains("error") && !err.contains("pipe"), "{err}");
}

/// `--d` names a store to open; `init` creates one, so it is a usage error
/// that creates nothing.
#[test]
fn init_rejects_the_d_flag() {
    let (_t, base) = tmp_dir();
    let x = base.join("x");
    let o = run(cmd().arg("--d").arg(&x).arg("init").current_dir(&base));
    assert_eq!(o.code, 4, "{}", o.stderr);
    assert!(!x.exists() && !base.join(".ext").exists());
}

/// A positional dir contradicts `--bare`.
#[test]
fn init_rejects_dir_with_bare() {
    let (_t, base) = tmp_dir();
    let (p, dir) = (base.join("p"), base.join("dir"));
    fs::create_dir(&dir).unwrap();
    let o = run(cmd().arg("init").arg(&dir).arg("--bare").arg(&p));
    assert_eq!(o.code, 4, "{}", o.stderr);
    assert!(!p.exists() && !dir.join(".ext").exists());
}

/// `register` takes a directory or a regular file: anything else is refused
/// before anything is written.
#[test]
fn register_refuses_a_special_file() {
    let fx = Fx::new();
    let file = fx.base.join("afifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &file,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let before = fx.registry_text();
    let o = run(fx.ext().arg("register").arg(&file));
    assert_eq!(o.code, 4, "{}", o.stderr);
    assert!(o.stderr.contains(file.to_str().unwrap()), "{}", o.stderr);
    assert_eq!(fx.registry_text(), before);
}

/// ERROR and REFUSED lines say why: the cause follows the path as its own
/// tab-separated field.
fn assert_detail(o: &Out, status: &str) {
    let lines = status_lines(o, status);
    assert_eq!(lines.len(), 1, "{status}: {}", o.out());
    assert!(
        lines[0].len() >= 3 && !lines[0][2].is_empty(),
        "{status} line has no detail: {}",
        o.out()
    );
}

#[test]
fn refused_line_carries_the_detail() {
    let fx = Fx::new();
    let real = fx.base.join("real");
    fs::create_dir_all(real.join("r")).unwrap();
    let link = fx.base.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let st = Store::open(&fx.store).unwrap();
    let lock = st.lock().unwrap();
    let via = RegPath::from_bytes(&p_bytes(&link.join("r"))).unwrap();
    st.edit_registry(&lock, |v| v.push(via)).unwrap();
    drop(lock);
    let o = fx.check();
    assert_eq!(o.code, 5, "{}", o.stderr);
    assert_detail(&o, "REFUSED");
}

#[test]
fn error_line_carries_the_detail() {
    if is_root() {
        return;
    }
    let fx = Fx::new();
    let f = fx.write("locked", b"x");
    fs::set_permissions(&f, fs::Permissions::from_mode(0o000)).unwrap();
    let o = fx.check();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
    assert_detail(&o, "ERROR");
}

// -------------------------------------------- resolve: URIs and human names

fn resolved(fx: &Fx, arg: &str) -> (i32, String) {
    let o = run(fx.ext().arg("resolve").arg(arg));
    (o.code, o.out())
}

/// Three paths hold the content; the name filters by last component.
#[test]
fn resolve_hash_uri_and_names() {
    let fx = Fx::new();
    for p in [
        &b"/x/a/notes.txt"[..],
        b"/x/b/notes.txt",
        b"/x/c/xnotes.txt",
        b"/x/d/other",
        b"/x/notes.txt/inner",
    ] {
        fx.seed(p, b"hello");
    }
    let v = rev(b"hello");
    let v = v.strip_suffix(":SHA-256").unwrap();
    let all = "/x/a/notes.txt\n/x/b/notes.txt\n/x/c/xnotes.txt\n/x/d/other\n/x/notes.txt/inner\n";
    let notes = "/x/a/notes.txt\n/x/b/notes.txt\n";

    for arg in [
        format!("hash://SHA-256/{v}"),
        format!("hash://sha-256/{v}.png"),
        format!("HASH://SHA-256/{v}/tail"),
    ] {
        assert_eq!(resolved(&fx, &arg), (0, all.into()), "{arg}");
    }
    for arg in [
        format!("notes.txt:SHA-256:{v}"),
        format!("SHA-256:{v}:notes.txt"),
        format!("{v}:SHA-256:notes.txt"),
        format!("notes:SHA-256:{v}.txt"),
    ] {
        assert_eq!(resolved(&fx, &arg), (0, notes.into()), "{arg}");
    }
    // One match among several paths suffices; the others are not returned.
    assert_eq!(
        resolved(&fx, &format!("other:SHA-256:{v}")),
        (0, "/x/d/other\n".into())
    );
    // Hex input in any case, uppercase hex output under --hex is unchanged.
    let h = dg(b"hello").encode(Enc::Hex).to_lowercase();
    assert_eq!(
        resolved(&fx, &format!("notes.txt:SHA-256:{h}")),
        (0, notes.into())
    );
    // The digest exists but no path has that filename: not found.
    for arg in [
        format!("notes:SHA-256:{v}"),
        format!("nothing:SHA-256:{v}.txt"),
        format!("SHA-256:{v}:a"),
    ] {
        assert_eq!(resolved(&fx, &arg), (1, String::new()), "{arg}");
    }
    // A name never makes an absent digest present.
    let absent = rev(b"absent");
    let absent = absent.strip_suffix(":SHA-256").unwrap();
    assert_eq!(resolved(&fx, &format!("notes.txt:SHA-256:{absent}")).0, 1);
    // Malformed arguments are usage errors.
    for arg in [
        format!("hash://SHA-256/{}", &v[..40]),
        format!("a/b:SHA-256:{v}"),
        format!("x:sha-256:{v}"),
    ] {
        assert_eq!(resolved(&fx, &arg).0, 4, "{arg}");
    }
}

/// Filenames compare as raw bytes, so a name with a tab matches and the
/// path prints escaped.
#[test]
fn resolve_name_matches_raw_bytes() {
    let fx = Fx::new();
    fx.seed(b"/x/t\tb", b"hello");
    let v = rev(b"hello");
    let v = v.strip_suffix(":SHA-256").unwrap();
    assert_eq!(
        resolved(&fx, &format!("t\tb:SHA-256:{v}")),
        (0, "/x/t\\tb\n".into())
    );
}
