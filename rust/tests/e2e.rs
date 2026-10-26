//! Black-box stories: only the `ext` binary and real files, no `ext::` setup.
//!
//! Run: `cargo test --test e2e`.

use assert_cmd::Command;
use sha2::{Digest as _, Sha256};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread::sleep;
use std::time::{Duration, Instant};

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    /// Tab-split stdout records.
    fn records(&self) -> Vec<Vec<&str>> {
        self.stdout
            .lines()
            .map(|l| l.split('\t').collect())
            .collect()
    }
    fn of(&self, status: &str) -> Vec<Vec<&str>> {
        self.records()
            .into_iter()
            .filter(|r| r[0] == status)
            .collect()
    }
}

/// `ext` run in `cwd`, store found the way a user's shell would find it.
fn ext(cwd: &Path, args: &[&str]) -> Out {
    let o = Command::new(env!("CARGO_BIN_EXE_ext"))
        .env_remove("EXTANT_DIR")
        .current_dir(cwd)
        .args(args)
        .timeout(Duration::from_secs(120))
        .output()
        .expect("ext runs");
    Out {
        code: o.status.code().expect("ext exited by status, not signal"),
        stdout: String::from_utf8(o.stdout).expect("stdout is utf-8 for these names"),
        stderr: String::from_utf8(o.stderr).unwrap(),
    }
}

fn label(data: &[u8]) -> String {
    format!(
        "{}:SHA-256",
        data_encoding::BASE64URL_NOPAD.encode(&Sha256::digest(data))
    )
}

fn tree() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = fs::canonicalize(t.path()).unwrap();
    (t, p)
}

fn path_str(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Catches: a skip decision that is only ever unit-tested; here the real
/// clock, real mtimes and a real index must agree across five invocations.
#[test]
fn lifecycle_init_check_edit_resolve_unregister() {
    let (_t, dir) = tree();
    fs::write(dir.join("a.txt"), b"alpha").unwrap();
    fs::write(dir.join("b.txt"), b"bravo").unwrap();

    let o = ext(&dir, &["init", path_str(&dir)]);
    assert_eq!((o.code, o.stdout.as_str()), (0, ""), "{}", o.stderr);

    // First check: everything NEW, nothing else.
    let o = ext(&dir, &["check"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let mut new: Vec<_> = o.of("NEW").iter().map(|r| r[1].to_owned()).collect();
    new.sort();
    assert_eq!(
        new,
        [path_str(&dir.join("a.txt")), path_str(&dir.join("b.txt"))]
    );
    assert_eq!(
        o.records().len(),
        2,
        "unexpected extra output: {}",
        o.stdout
    );
    assert!(o.stderr.contains("new=2 "), "{}", o.stderr);

    // Past the racy window the first re-check rehashes (the stored times were
    // still racy); the one after it must really skip.
    sleep(Duration::from_millis(2100));
    let o = ext(&dir, &["check"]);
    assert_eq!((o.code, o.stdout.as_str()), (0, ""), "{}", o.stderr);
    assert!(o.stderr.contains("unchanged=2 "), "{}", o.stderr);
    let o = ext(&dir, &["check"]);
    assert_eq!((o.code, o.stdout.as_str()), (0, ""), "{}", o.stderr);
    assert!(
        o.stderr.contains("skipped=2 "),
        "never skipped: {}",
        o.stderr
    );

    // Edit: EDITED carries old then new digest.
    fs::write(dir.join("a.txt"), b"alpha, revised").unwrap();
    let o = ext(&dir, &["check"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(
        o.records(),
        [vec![
            "EDITED",
            path_str(&dir.join("a.txt")),
            &label(b"alpha"),
            &label(b"alpha, revised")
        ]]
    );

    // The old digest no longer resolves; the new one and the untouched one do.
    let o = ext(&dir, &["resolve", &label(b"alpha")]);
    assert_eq!((o.code, o.stdout.as_str()), (1, ""), "{}", o.stderr);
    let o = ext(&dir, &["resolve", &label(b"alpha, revised")]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.stdout, format!("{}\n", dir.join("a.txt").display()));
    let o = ext(&dir, &["resolve", &label(b"bravo")]);
    assert_eq!(o.stdout, format!("{}\n", dir.join("b.txt").display()));

    // Unregister drops everything the root contributed.
    let o = ext(&dir, &["-u", path_str(&dir)]);
    assert_eq!((o.code, o.stdout.as_str()), (0, ""), "{}", o.stderr);
    let o = ext(&dir, &["list"]);
    assert_eq!((o.code, o.stdout.as_str()), (0, ""), "{}", o.stderr);
}

/// Catches: content changes that hide behind unchanged size and mtime, and
/// the full-verify/accept path, which cli.rs only reaches via a seeded index.
#[test]
fn hidden_changes_are_found_and_accept_rebaselines() {
    let (_t, dir) = tree();
    let f = dir.join("data.bin");
    fs::write(&f, b"AAAAAAAA").unwrap();
    ext(&dir, &["init", path_str(&dir)]);
    assert_eq!(ext(&dir, &["check"]).code, 0);
    sleep(Duration::from_millis(2100));
    assert_eq!(ext(&dir, &["check"]).code, 0); // refresh last_checked past the window
    let mtime = fs::metadata(&f).unwrap().modified().unwrap();

    // Same size, mtime restored: ctime still moves, so a plain check must
    // notice rather than skip.
    fs::write(&f, b"BBBBBBBB").unwrap();
    File::options()
        .write(true)
        .open(&f)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    let o = ext(&dir, &["check"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(
        o.records(),
        [vec![
            "EDITED",
            path_str(&f),
            &label(b"AAAAAAAA"),
            &label(b"BBBBBBBB")
        ]],
        "same-size/same-mtime rewrite slipped past a plain check"
    );

    // Simulated bit rot: the file changes with no metadata change at all.
    // Userspace cannot do that, so flip the stored digest instead; observably
    // identical (metadata agrees, content disagrees).
    sleep(Duration::from_millis(2100));
    assert_eq!(ext(&dir, &["check"]).code, 0);
    assert_eq!(ext(&dir, &["check"]).code, 0);
    let db = rusqlite::Connection::open(dir.join(".ext/index.db")).unwrap();
    let n = db
        .execute("UPDATE files SET digest = zeroblob(length(digest))", [])
        .unwrap();
    assert_eq!(n, 1);
    drop(db);

    let o = ext(&dir, &["check"]);
    assert!(o.stderr.contains("skipped=1 "), "{}", o.stderr);
    assert_eq!(
        (o.code, o.stdout.as_str()),
        (0, ""),
        "plain check should trust metadata"
    );

    for _ in 0..2 {
        // Reporting a violation must not repair it.
        let o = ext(&dir, &["check", "--full"]);
        assert_eq!(o.code, 2, "{}", o.stderr);
        let v = o.of("VIOLATION");
        assert_eq!(v.len(), 1, "{}", o.stdout);
        assert_eq!(v[0][1], path_str(&f));
        assert_eq!(v[0][3], label(b"BBBBBBBB"), "actual digest");
    }

    let o = ext(&dir, &["check", "--full", "--accept"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.of("ACCEPTED").len(), 1, "{}", o.stdout);
    let o = ext(&dir, &["check", "--full"]);
    assert_eq!((o.code, o.stdout.as_str()), (0, ""), "{}", o.stderr);
    let o = ext(&dir, &["resolve", &label(b"BBBBBBBB")]);
    assert_eq!(o.code, 0, "{}", o.stderr);
}

fn content(i: u32) -> Vec<u8> {
    // Distinct per file, 16 KiB so hashing takes real time.
    format!("file number {i}\n").repeat(1024).into_bytes()
}

/// Catches: a SIGKILL mid-scan leaving the index torn, duplicated or stale;
/// unit tests never kill a real process between real commits.
#[test]
fn sigkill_during_check_then_recheck_is_exact() {
    const N: u32 = 3000;
    let (_t, dir) = tree();
    for i in 0..N {
        let sub = dir.join(format!("d{}", i % 10));
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join(format!("f{i}")), content(i)).unwrap();
    }
    assert_eq!(ext(&dir, &["init", path_str(&dir)]).code, 0);
    let idx = dir.join(".ext/index.db");
    let size_of = |suffix: &str| {
        fs::metadata(format!("{}{suffix}", idx.display()))
            .map(|m| m.len())
            .unwrap_or(0)
    };
    let before = size_of("") + size_of("-wal") + size_of("-journal");

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_ext"))
        .env_remove("EXTANT_DIR")
        .current_dir(&dir)
        .arg("check")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Kill once the first batch has hit the index, while most files remain.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        assert!(Instant::now() < deadline, "check never wrote to the index");
        if let Some(st) = child.try_wait().unwrap() {
            panic!("check finished ({st}) before it could be killed; enlarge the tree");
        }
        if size_of("") + size_of("-wal") + size_of("-journal") > before {
            break;
        }
        sleep(Duration::from_millis(2));
    }
    child.kill().unwrap();
    let st = child.wait().unwrap();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&st),
        Some(9),
        "check completed before the kill landed: {st}"
    );

    let o = ext(&dir, &["check"]);
    assert_eq!(o.code, 0, "recheck after kill: {}", o.stderr);

    let o = ext(&dir, &["list"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let mut got: Vec<(String, String)> = o
        .records()
        .iter()
        .map(|r| (r[1].to_owned(), r[0].to_owned()))
        .collect();
    got.sort();
    let mut want: Vec<(String, String)> = (0..N)
        .map(|i| {
            let p = dir.join(format!("d{}", i % 10)).join(format!("f{i}"));
            (p.to_str().unwrap().to_owned(), label(&content(i)))
        })
        .collect();
    want.sort();
    assert_eq!(got.len(), want.len(), "entry count");
    assert!(got == want, "index differs from the files on disk");

    // And it is stable: a further check finds nothing to say.
    let o = ext(&dir, &["check", "--full"]);
    assert_eq!((o.code, o.stdout.as_str()), (0, ""), "{}", o.stderr);
}

/// Catches: a nested store's files leaking into the parent's index, or the
/// parent swallowing the child's own bookkeeping, across two real stores.
#[test]
fn nested_store_is_excluded_from_parent_and_indexes_itself() {
    let (_t, dir) = tree();
    let child = dir.join("child");
    fs::create_dir(&child).unwrap();
    fs::write(dir.join("top.txt"), b"top").unwrap();
    fs::write(child.join("inner.txt"), b"inner").unwrap();
    assert_eq!(ext(&dir, &["init", path_str(&dir)]).code, 0);
    assert_eq!(ext(&dir, &["init", path_str(&child)]).code, 0);

    let o = ext(&dir, &["check"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.of("NEW").len(), 1, "{}", o.stdout);
    assert_eq!(o.of("NEW")[0][1], path_str(&dir.join("top.txt")));
    let sub = o.of("SUBEXTANT");
    assert_eq!(sub.len(), 1, "{}", o.stdout);
    assert_eq!(sub[0][1], path_str(&child));
    assert_eq!(o.records().len(), 2, "{}", o.stdout);

    let o = ext(&dir, &["list"]);
    assert_eq!(
        o.stdout,
        format!("{}\t{}\n", label(b"top"), dir.join("top.txt").display())
    );

    // The child, addressed from inside it, owns its files.
    let o = ext(&child, &["check"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.of("NEW").len(), 1, "{}", o.stdout);
    let o = ext(&child, &["list"]);
    assert_eq!(
        o.stdout,
        format!(
            "{}\t{}\n",
            label(b"inner"),
            child.join("inner.txt").display()
        )
    );
    // The parent's index is still unaware of it.
    let o = ext(&dir, &["resolve", &label(b"inner")]);
    assert_eq!(o.code, 1, "{}", o.stdout);
}
