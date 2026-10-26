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
use ext::escape::escape;
use ext::index::{Entry, Index, Meta};
use ext::registry::RegPath;
use ext::store::Store;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const ESC_NAME: &[u8] = b"a\x1bb";

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
}

// ---------------------------------------------------------------------- init

/// §5 `init [dir]`; §1 init layout (0700 dir, 0600 files); D3.
#[test]
fn init_creates_extant_store_registering_the_dir() {
    let (_t, base) = tmp_dir();
    let dir = base.join("proj");
    fs::create_dir(&dir).unwrap();
    let o = run(cmd().arg("init").arg(&dir));
    assert_eq!(o.code, 0, "{}", o.stderr);
    let st = dir.join(".ext");
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&st), 0o700);
    for f in ["registry", "index.db", "lock"] {
        assert_eq!(mode(&st.join(f)), 0o600, "{f}");
    }
    let mut want = p_bytes(&dir);
    want.push(b'\n');
    assert_eq!(fs::read(st.join("registry")).unwrap(), want);
}

/// §5: dir defaults to cwd.
#[test]
fn init_without_dir_uses_cwd() {
    let (_t, base) = tmp_dir();
    let o = run(cmd().arg("init").current_dir(&base));
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(base.join(".ext/registry").is_file());
}

/// R7 + §1: never overwrite; error names the path; exit 4.
#[test]
fn init_over_existing_store_exits_4_and_names_path() {
    let (_t, base) = tmp_dir();
    assert_eq!(run(cmd().arg("init").arg(&base)).code, 0);
    let before = fs::read(base.join(".ext/registry")).unwrap();
    let o = run(cmd().arg("init").arg(&base));
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains(base.to_str().unwrap()), "{}", o.stderr);
    assert_eq!(fs::read(base.join(".ext/registry")).unwrap(), before);
}

/// §5 "Its first `check` indexes the directory", through the cwd step (D2).
#[test]
fn init_then_check_indexes_the_directory() {
    if system_store_present() {
        return; // would shadow ./.ext at resolution step 3; see header
    }
    let (_t, base) = tmp_dir();
    fs::write(base.join("f"), b"hello").unwrap();
    assert_eq!(run(cmd().arg("init").current_dir(&base)).code, 0);
    let o = run(cmd().arg("check").current_dir(&base));
    assert_eq!(o.code, 0, "{}", o.stderr);
    let f = base.join("f");
    let new = status_lines(&o, "NEW");
    assert!(
        new.iter()
            .any(|l| l[1] == escape(&p_bytes(&f)).into_bytes()),
        "no NEW for {f:?} in {}",
        o.out()
    );
    let r = run(cmd().arg("resolve").arg(rev(b"hello")).current_dir(&base));
    assert_eq!(r.code, 0);
}

/// §5 `init --bare <path>`: flat store, empty registry (D3).
#[test]
fn init_bare_creates_flat_store_with_empty_registry() {
    let (_t, base) = tmp_dir();
    let st = base.join("sys");
    let o = run(cmd().args(["init", "--bare"]).arg(&st));
    assert_eq!(o.code, 0, "{}", o.stderr);
    for f in ["registry", "index.db", "lock"] {
        assert!(st.join(f).is_file(), "missing {f}");
    }
    assert!(!st.join(".ext").exists(), "bare store must be flat");
    assert_eq!(fs::read(st.join("registry")).unwrap(), b"");
    assert_eq!(
        fs::metadata(&st).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // and it is usable
    let l = run(cmd().arg("list").arg("--d").arg(&st));
    assert_eq!((l.code, l.stdout.len()), (0, 0), "{}", l.stderr);
}

/// R7: init_bare never overwrites.
#[test]
fn init_bare_over_existing_path_exits_4() {
    let (_t, base) = tmp_dir();
    let st = base.join("sys");
    fs::create_dir(&st).unwrap();
    fs::write(st.join("keep"), b"x").unwrap();
    let o = run(cmd().args(["init", "--bare"]).arg(&st));
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains(st.to_str().unwrap()), "{}", o.stderr);
    assert_eq!(fs::read(st.join("keep")).unwrap(), b"x");
}

// ---------------------------------------------------------- store resolution

fn two_stores() -> (Fx, Fx) {
    let (a, b) = (Fx::new(), Fx::new());
    a.seed(b"/only/in/a", b"A");
    b.seed(b"/only/in/b", b"B");
    (a, b)
}

/// §1 order step 1 beats step 2.
#[test]
fn flag_beats_env() {
    let (a, b) = two_stores();
    let o = run(cmd()
        .env("EXTANT_DIR", &b.store)
        .arg("list")
        .arg("--d")
        .arg(&a.store));
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.out().contains("/only/in/a") && !o.out().contains("/only/in/b"));
}

/// §1 step 2.
#[test]
fn env_selects_store_without_flag() {
    let (_a, b) = two_stores();
    let o = run(cmd().env("EXTANT_DIR", &b.store).arg("list"));
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.out().contains("/only/in/b"));
}

/// §1: for steps 1-2, `<p>` may be a directory whose `.ext/` is a store.
#[test]
fn flag_accepts_dir_containing_dot_ext() {
    let (_t, base) = tmp_dir();
    assert_eq!(run(cmd().arg("init").arg(&base)).code, 0);
    let o = run(cmd().arg("list").arg("--d").arg(&base));
    assert_eq!(o.code, 0, "{}", o.stderr);
    let o = run(cmd().env("EXTANT_DIR", &base).arg("list"));
    assert_eq!(o.code, 0, "{}", o.stderr);
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

/// §1 step 4 (D2: `./.ext/`), and "an empty value counts as unset".
#[test]
fn cwd_dot_ext_is_the_last_resort_and_empty_env_is_unset() {
    if system_store_present() {
        return;
    }
    let (_t, base) = tmp_dir();
    assert_eq!(run(cmd().arg("init").arg(&base)).code, 0);
    let o = run(cmd().arg("list").current_dir(&base));
    assert_eq!(o.code, 0, "{}", o.stderr);
    let o = run(cmd().env("EXTANT_DIR", "").arg("list").current_dir(&base));
    assert_eq!(
        o.code, 0,
        "empty EXTANT_DIR must count as unset: {}",
        o.stderr
    );
}

/// §1 step 5: otherwise error.
#[test]
fn no_store_anywhere_exits_4() {
    if system_store_present() {
        return;
    }
    let (_t, base) = tmp_dir();
    let o = run(cmd().arg("list").current_dir(&base));
    assert_eq!(o.code, 4);
    assert!(!o.stderr.is_empty());
}

// --------------------------------------------------------- foreign / unsafe

/// §1 open: group/other-writable store -> exit 4, path named.
#[test]
fn writable_store_dir_exits_4_naming_it() {
    let fx = Fx::new();
    fs::set_permissions(&fx.store, fs::Permissions::from_mode(0o770)).unwrap();
    for sub in ["list", "check"] {
        let o = run(fx.ext().arg(sub));
        assert_eq!(o.code, 4, "{sub}: {}", o.stderr);
        assert!(
            o.stderr.contains(fx.store.to_str().unwrap()),
            "{}",
            o.stderr
        );
    }
}

/// §1 open: the checks also cover `registry`.
#[test]
fn writable_registry_file_exits_4_naming_it() {
    let fx = Fx::new();
    let reg = fx.store.join("registry");
    fs::set_permissions(&reg, fs::Permissions::from_mode(0o666)).unwrap();
    let o = run(fx.ext().arg("list"));
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains(reg.to_str().unwrap()), "{}", o.stderr);
}

/// Amendment 26d: unsafe ancestor of the store.
#[test]
fn store_under_world_writable_ancestor_exits_4() {
    let fx = Fx::new();
    let parent = fx.base.join("shared");
    fs::create_dir(&parent).unwrap();
    let inner = parent.join("store");
    fs::rename(&fx.store, &inner).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    let o = run(cmd().env("EXTANT_DIR", &inner).arg("list"));
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains(parent.to_str().unwrap()), "{}", o.stderr);
}

/// §1 registry: parse error with a line number -> exit 4.
#[test]
fn malformed_registry_exits_4_with_line_number() {
    let fx = Fx::new();
    fs::write(fx.store.join("registry"), b"# c\nrelative/path\n").unwrap();
    let o = run(fx.ext().arg("list"));
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains('2'), "line number missing: {}", o.stderr);
}

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

/// §5 `-r` alias; §1 "register canonicalises its argument with realpath".
#[test]
fn register_short_flag_canonicalises_and_is_idempotent() {
    let fx = Fx::new();
    let other = fx.base.join("other");
    fs::create_dir_all(other.join("sub")).unwrap();
    let messy = other.join("sub/..");
    for _ in 0..2 {
        let o = run(fx.ext().arg("-r").arg(&messy));
        assert_eq!(o.code, 0, "{}", o.stderr);
    }
    let reg = fx.registry_text();
    let want = p_bytes(&other);
    let hits = split(&reg, b'\n').iter().filter(|l| **l == want).count();
    assert_eq!(hits, 1, "registry: {}", String::from_utf8_lossy(&reg));
    assert!(!String::from_utf8_lossy(&reg).contains(".."));
}

#[test]
fn register_nonexistent_path_exits_4_naming_it() {
    let fx = Fx::new();
    let ghost = fx.base.join("ghost");
    let before = fx.registry_text();
    let o = run(fx.ext().arg("register").arg(&ghost));
    assert_eq!(o.code, 4);
    assert!(o.stderr.contains(ghost.to_str().unwrap()), "{}", o.stderr);
    assert_eq!(fx.registry_text(), before);
}

/// §1: a registered root may not be named through a symlink; `register`
/// canonicalises, so registering via a link records the real directory.
#[test]
fn register_via_symlink_records_the_real_path() {
    let fx = Fx::new();
    let real = fx.base.join("real");
    fs::create_dir(&real).unwrap();
    let link = fx.base.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(run(fx.ext().arg("register").arg(&link)).code, 0);
    let reg = String::from_utf8_lossy(&fx.registry_text()).into_owned();
    assert!(reg.lines().any(|l| l == real.to_str().unwrap()), "{reg}");
    assert!(!reg.lines().any(|l| l == link.to_str().unwrap()), "{reg}");
}

// ---------------------------------------------------------------- unregister

/// §5 unregister: removes the registry line and the entries under it.
#[test]
fn unregister_removes_line_and_entries() {
    let fx = Fx::new();
    fx.write("f", b"gone-soon");
    assert_eq!(fx.check().code, 0);
    assert_eq!(run(fx.ext().arg("resolve").arg(rev(b"gone-soon"))).code, 0);
    let o = run(fx.ext().arg("unregister").arg(&fx.tree));
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(
        fx.registry_text().is_empty()
            || !String::from_utf8_lossy(&fx.registry_text()).contains("tree")
    );
    assert_eq!(run(fx.ext().arg("resolve").arg(rev(b"gone-soon"))).code, 1);
    assert!(run(fx.ext().arg("list")).stdout.is_empty());
    // the file itself is untouched
    assert!(fx.tree.join("f").exists());
}

/// §5 `-u` alias.
#[test]
fn unregister_short_flag() {
    let fx = Fx::new();
    let o = run(fx.ext().arg("-u").arg(&fx.tree));
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(!String::from_utf8_lossy(&fx.registry_text()).contains("tree"));
}

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

/// §5 + digest.rs: both labelled orders, both encodings, hex any case.
#[test]
fn resolve_accepts_both_labelled_orders_and_encodings() {
    let fx = Fx::new();
    fx.seed(b"/x/file", b"content");
    let d = dg(b"content");
    let b64 = d.encode(Enc::B64ut);
    let hex = d.encode(Enc::Hex);
    let forms = [
        format!("{b64}:SHA-256"),
        format!("SHA-256:{b64}"),
        format!("{hex}:SHA-256"),
        format!("SHA-256:{}", hex.to_lowercase()),
    ];
    for f in forms {
        let o = run(fx.ext().arg("resolve").arg(&f));
        assert_eq!(o.code, 0, "{f}: {}", o.stderr);
        assert_eq!(o.out(), "/x/file\n", "{f}");
    }
}

/// §5: one path per line, sorted by bytes.
#[test]
fn resolve_lists_every_path_sorted() {
    let fx = Fx::new();
    for p in ["/z/b", "/a/z", "/a/B", "/m"] {
        fx.seed(p.as_bytes(), b"same");
    }
    let o = run(fx.ext().arg("resolve").arg(rev(b"same")));
    assert_eq!(o.code, 0);
    assert_eq!(o.out(), "/a/B\n/a/z\n/m\n/z/b\n");
}

/// §1 exit 1: not found, nothing on stdout.
#[test]
fn resolve_unknown_digest_exits_1() {
    let fx = Fx::new();
    fx.seed(b"/x", b"present");
    let o = run(fx.ext().arg("resolve").arg(rev(b"absent")));
    assert_eq!(o.code, 1);
    assert!(o.stdout.is_empty());
}

/// §5 + digest.rs: unlabelled, `hash://`, unknown algorithm, wrong length,
/// bad chars -> exit 4 (usage), never 1, with an explanation.
#[test]
fn resolve_rejects_unlabelled_and_malformed_input_with_exit_4() {
    let fx = Fx::new();
    fx.seed(b"/x", b"c");
    let v = dg(b"c").encode(Enc::B64ut);
    for bad in [
        v.clone(),                        // unlabelled
        dg(b"c").encode(Enc::Hex),        // unlabelled hex
        format!("hash://sha256/{v}"),     // hash:// URI
        format!("{v}:sha-256"),           // case-sensitive algorithm
        format!("{v}:MD5"),               // unknown algorithm
        format!("{}:SHA-256", &v[..42]),  // wrong length
        format!("{}$:SHA-256", &v[..42]), // bad character
        String::new(),
    ] {
        let o = run(fx.ext().arg("resolve").arg(&bad));
        assert_eq!(o.code, 4, "input {bad:?}: {}", o.stderr);
        assert!(o.stdout.is_empty(), "input {bad:?}");
        assert!(!o.stderr.is_empty(), "input {bad:?}: no message");
    }
    let o = run(fx.ext().arg("resolve").arg(&v));
    assert!(
        o.stderr.to_lowercase().contains("label"),
        "unlabelled input must say it is unlabelled: {}",
        o.stderr
    );
}

/// §2.2 + §5: control, bidi and invalid-UTF-8 bytes in a path never reach
/// the terminal raw.
#[test]
fn resolve_escapes_hostile_paths() {
    let fx = Fx::new();
    let path = b"/x/a\x1b[31m\xe2\x80\xaeb\xff\\c\td".to_vec();
    fx.seed(&path, b"evil");
    let o = run(fx.ext().arg("resolve").arg(rev(b"evil")));
    assert_eq!(o.code, 0, "{}", o.stderr);
    for raw in [0x1bu8, 0xff, b'\t'] {
        assert!(!o.stdout.contains(&raw), "raw byte {raw:#x} in output");
    }
    assert!(!o.out().contains('\u{202e}'));
    let want = format!("{}\n", escape(&path));
    assert_eq!(o.out(), want);
    assert!(want.contains("\\x1B") && want.contains("\\xE2\\x80\\xAE"));
    assert!(want.contains("\\xFF") && want.contains("\\\\c"));
}

/// §5 `-0`: raw paths, NUL-terminated; a newline-bearing name round-trips.
#[test]
fn resolve_nul_mode_round_trips_raw_paths() {
    let fx = Fx::new();
    let paths: [&[u8]; 3] = [b"/x/plain", b"/x/new\nline", b"/x/\xff\x1b"];
    for p in paths {
        fx.seed(p, b"nul");
    }
    for o in [
        run(fx.ext().arg("-0").arg("resolve").arg(rev(b"nul"))),
        run(fx.ext().arg("resolve").arg("-0").arg(rev(b"nul"))),
    ] {
        assert_eq!(o.code, 0, "{}", o.stderr);
        let mut want: Vec<Vec<u8>> = paths.iter().map(|p| p.to_vec()).collect();
        want.sort();
        assert_eq!(split(&o.stdout, 0), want);
        assert!(o.stdout.ends_with(&[0]));
    }
}

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

/// §5 list: `<value>:<alg>\t<escaped path>`, sorted by (digest, path) bytes.
#[test]
fn list_format_and_order() {
    let fx = Fx::new();
    let mut want = seeded_many(&fx);
    want.sort_by(|a, b| (a.0.bytes(), &a.1).cmp(&(b.0.bytes(), &b.1)));
    let by_text = {
        let mut t: Vec<String> = want.iter().map(|(d, _)| d.to_reverse(Enc::B64ut)).collect();
        t.sort();
        t
    };
    let in_byte_order: Vec<String> = want.iter().map(|(d, _)| d.to_reverse(Enc::B64ut)).collect();
    assert_ne!(
        by_text, in_byte_order,
        "fixture premise: text order must differ from digest-byte order"
    );
    let o = run(fx.ext().arg("list"));
    assert_eq!(o.code, 0, "{}", o.stderr);
    let expect: String = want
        .iter()
        .map(|(d, p)| format!("{}\t{}\n", d.to_reverse(Enc::B64ut), escape(p)))
        .collect();
    assert_eq!(o.out(), expect);
}

/// §5 `--hex`: uppercase hex, same `<value>:<alg>` shape (L125).
#[test]
fn list_hex_is_uppercase() {
    let fx = Fx::new();
    fx.seed(b"/h", b"hexme");
    let o = run(fx.ext().arg("--hex").arg("list"));
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.out(), format!("{}\t/h\n", rev_hex(b"hexme")));
    let (val, alg) = o
        .out()
        .split_once(':')
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
        .unwrap();
    assert_eq!(val.len(), 64);
    assert!(val
        .bytes()
        .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c)));
    assert!(alg.starts_with("SHA-256\t"));
}

/// §5 `-0`: NUL-terminated records, raw path, tab-separated fields.
#[test]
fn list_nul_mode() {
    let fx = Fx::new();
    let path = b"/x/ta\tb\nc\xff".to_vec();
    fx.seed(&path, b"nl");
    let o = run(fx.ext().arg("list").arg("-0"));
    assert_eq!(o.code, 0, "{}", o.stderr);
    let mut want = rev(b"nl").into_bytes();
    want.push(b'\t');
    want.extend_from_slice(&path);
    want.push(0);
    assert_eq!(o.stdout, want);
}

#[test]
fn list_empty_store_is_silent_success() {
    let fx = Fx::new();
    let o = run(fx.ext().arg("list"));
    assert_eq!((o.code, o.stdout.len()), (0, 0));
}

// --------------------------------------------------------------------- check

/// §5 check: `NEW\t<escaped path>`; unchanged is not printed; counts on
/// stderr; index written.
#[test]
fn check_reports_new_then_goes_quiet() {
    let fx = Fx::new();
    let f = fx.write("f", b"one");
    let o = fx.check();
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.out(), format!("NEW\t{}\n", f.display()));
    assert!(!o.stderr.is_empty(), "counts belong on stderr");
    assert!(fx.index().get(&p_bytes(&f)).unwrap().is_some());
    let o2 = fx.check();
    assert_eq!(o2.code, 0);
    assert!(
        o2.stdout.is_empty(),
        "unchanged must not print: {}",
        o2.out()
    );
}

/// §5 + C3: EDITED carries expected (stored) and actual digests.
#[test]
fn check_edited_prints_expected_and_actual() {
    let fx = Fx::new();
    let f = fx.write("f", b"before");
    assert_eq!(fx.check().code, 0);
    fs::write(&f, b"after, longer").unwrap();
    let o = fx.check();
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(
        o.out(),
        format!(
            "EDITED\t{}\t{}\t{}\n",
            f.display(),
            rev(b"before"),
            rev(b"after, longer")
        )
    );
    let o = run(fx.ext().arg("resolve").arg(rev(b"after, longer")));
    assert_eq!(o.code, 0);
    // --hex reaches check's digests too
    fs::write(&f, b"third").unwrap();
    let o = run(fx.ext().args(["--hex", "check"]));
    assert_eq!(
        o.out(),
        format!(
            "EDITED\t{}\t{}\t{}\n",
            f.display(),
            rev_hex(b"after, longer"),
            rev_hex(b"third")
        )
    );
}

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

/// D1: VIOLATION only under --full; exit 2; path, expected, actual shown;
/// index NOT written. Without --full the skip rule applies (metamorphic).
#[test]
fn check_full_reports_violation_exit_2_and_does_not_write() {
    let fx = Fx::new();
    let f = fx.write("f", b"truth");
    assert_eq!(fx.check().code, 0);
    tamper(&fx, &f);

    let plain = fx.check();
    assert_eq!(
        (plain.code, plain.stdout.len()),
        (0, 0),
        "skip rule: {}",
        plain.stderr
    );

    let o = run(fx.ext().args(["check", "--full"]));
    assert_eq!(o.code, 2, "{}", o.stderr);
    assert_eq!(
        o.out(),
        format!(
            "VIOLATION\t{}\t{}\t{}\n",
            f.display(),
            rev(b"FORGED"),
            rev(b"truth")
        )
    );
    let e = fx.index().get(&p_bytes(&f)).unwrap().unwrap();
    assert_eq!(
        e.digest,
        dg(b"FORGED"),
        "violation was written without --accept"
    );
    // and it keeps being reported
    assert_eq!(run(fx.ext().args(["check", "--full"])).code, 2);
}

/// D1 / C5: --accept writes it, exits 0, still visible.
#[test]
fn check_full_accept_writes_and_exits_0() {
    let fx = Fx::new();
    let f = fx.write("f", b"truth");
    assert_eq!(fx.check().code, 0);
    tamper(&fx, &f);
    let o = run(fx.ext().args(["check", "--full", "--accept"]));
    assert_eq!(o.code, 0, "{}", o.stderr);
    let acc = status_lines(&o, "ACCEPTED");
    assert_eq!(acc.len(), 1, "{}", o.out());
    assert_eq!(acc[0][1], p_bytes(&f));
    assert_eq!(acc[0][2], rev(b"FORGED").into_bytes());
    assert_eq!(acc[0][3], rev(b"truth").into_bytes());
    assert_eq!(
        fx.index().get(&p_bytes(&f)).unwrap().unwrap().digest,
        dg(b"truth")
    );
    assert_eq!(run(fx.ext().args(["check", "--full"])).code, 0);
}

/// `--accept` alone changes nothing when there is no violation.
#[test]
fn check_accept_without_violation_is_a_no_op() {
    let fx = Fx::new();
    fx.write("f", b"x");
    assert_eq!(fx.check().code, 0);
    let o = run(fx.ext().args(["check", "--accept"]));
    assert_eq!((o.code, o.stdout.len()), (0, 0), "{}", o.stderr);
}

/// C4: MISSING reported, entry removed, exit 0.
#[test]
fn check_missing_removes_entry_exit_0() {
    let fx = Fx::new();
    let f = fx.write("f", b"bye");
    assert_eq!(fx.check().code, 0);
    fs::remove_file(&f).unwrap();
    let o = fx.check();
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.out(), format!("MISSING\t{}\n", f.display()));
    assert!(fx.index().get(&p_bytes(&f)).unwrap().is_none());
}

/// A1/§1: a file now under a new sub-extant is EXCLUDED and the subtree is
/// reported SUBEXTANT.
#[test]
fn check_excluded_and_subextant() {
    let fx = Fx::new();
    let f = fx.write("sub/f", b"inside");
    assert_eq!(fx.check().code, 0);
    fs::create_dir(fx.tree.join("sub/.ext")).unwrap();
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

/// §1 exit 5 + C8: root behind a symlink -> REFUSED, entries kept, exit 5.
#[test]
fn check_refused_root_exits_5() {
    let fx = Fx::new();
    let real = fx.base.join("real");
    fs::create_dir_all(real.join("r")).unwrap();
    fs::write(real.join("r/f"), b"x").unwrap();
    let link = fx.base.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let root = link.join("r");
    let st = Store::open(&fx.store).unwrap();
    let lock = st.lock().unwrap();
    st.edit_registry(&lock, |v| {
        *v = vec![RegPath::from_bytes(&p_bytes(&root)).unwrap()]
    })
    .unwrap();
    drop(lock);
    fx.seed(&p_bytes(&root.join("f")), b"x");
    let o = fx.check();
    assert_eq!(o.code, 5, "{}", o.stderr);
    assert_eq!(status_lines(&o, "REFUSED")[0][1], p_bytes(&root));
    assert!(fx.index().get(&p_bytes(&root.join("f"))).unwrap().is_some());
}

/// §1 precedence: an unaccepted VIOLATION (2) outranks incomplete (5).
#[test]
fn violation_outranks_incomplete() {
    if is_root() {
        return;
    }
    let fx = Fx::new();
    let a = fx.write("a", b"truth");
    let b = fx.write("b", b"other");
    assert_eq!(fx.check().code, 0);
    tamper(&fx, &a);
    fs::set_permissions(&b, fs::Permissions::from_mode(0o000)).unwrap();
    let o = run(fx.ext().args(["check", "--full"]));
    assert_eq!(o.code, 2, "{}", o.stderr);
    assert_eq!(status_lines(&o, "VIOLATION").len(), 1);
    assert_eq!(status_lines(&o, "ERROR").len(), 1);
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

/// §2.2 on `check` output: an ESC in a file name is shown as `\x1B`.
#[test]
fn check_escapes_hostile_file_names() {
    let fx = Fx::new();
    let name = std::ffi::OsString::from_vec(ESC_NAME.to_vec());
    fs::write(fx.tree.join(&name), b"e").unwrap();
    let o = fx.check();
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(!o.stdout.contains(&0x1b));
    let mut raw = p_bytes(&fx.tree);
    raw.push(b'/');
    raw.extend_from_slice(ESC_NAME);
    assert_eq!(o.out(), format!("NEW\t{}\n", escape(&raw)));
    assert!(o.out().contains("a\\x1Bb"));
}

/// §5 `-0` on check: NUL-terminated, raw path (newline and all), tab fields.
#[test]
fn check_nul_mode_round_trips() {
    let fx = Fx::new();
    let name = OsStr::from_bytes(b"n\nl");
    let f = fx.tree.join(name);
    fs::write(&f, b"v1").unwrap();
    let o = run(fx.ext().args(["check", "-0"]));
    assert_eq!(o.code, 0, "{}", o.stderr);
    let mut want = b"NEW\t".to_vec();
    want.extend_from_slice(&p_bytes(&f));
    want.push(0);
    assert_eq!(o.stdout, want);

    fs::write(&f, b"version two").unwrap();
    let o = run(fx.ext().arg("-0").arg("check"));
    let mut want = b"EDITED\t".to_vec();
    want.extend_from_slice(&p_bytes(&f));
    want.extend_from_slice(format!("\t{}\t{}", rev(b"v1"), rev(b"version two")).as_bytes());
    want.push(0);
    assert_eq!(o.stdout, want);
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

#[test]
fn check_with_empty_registry_succeeds() {
    let (_t, base) = tmp_dir();
    let st = base.join("sys");
    assert_eq!(run(cmd().args(["init", "--bare"]).arg(&st)).code, 0);
    let o = run(cmd().arg("check").arg("--d").arg(&st));
    assert_eq!((o.code, o.stdout.len()), (0, 0), "{}", o.stderr);
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
