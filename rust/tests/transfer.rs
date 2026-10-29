//! `ext export <dir>` / `ext import <dir>`: the registry, Source and
//! Timestamp records as TSV files, and the way back into an empty index.

mod common;

use assert_cmd::Command;
use common::rp;
use ext::digest::{Alg, Digest, Enc};
use ext::index::{Entry, Index, Meta};
use ext::registry::RegPath;
use ext::store::Store;
use proptest::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn ext(store: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ext"));
    c.env_remove("EXTANT_DIR")
        .env("EXTANT_DIR", store)
        .timeout(Duration::from_secs(60));
    c
}

fn entry(path: &[u8], content: &[u8], n: i64) -> Entry {
    Entry {
        path: path.to_vec(),
        digest: Digest::compute(Alg::Sha256, content),
        meta: Meta {
            size: content.len() as u64,
            mtime_ns: 1_000 + n,
            ctime_ns: 2_000 + n,
            dev: 7,
            ino: 100 + n as u64,
        },
        last_checked_ns: 9_000 + n,
    }
}

/// A bare store under `base/name` with the given roots and entries.
fn mk_store(base: &Path, name: &str, roots: &[&[u8]], entries: &[Entry]) -> PathBuf {
    let dir = base.join(name);
    let st = Store::init_bare(&dir).unwrap();
    let lock = st.lock().unwrap();
    let roots: Vec<RegPath> = roots.iter().map(|r| rp(r)).collect();
    st.edit_registry(&lock, |v| *v = roots).unwrap();
    drop(lock);
    let idx = Index::open(&st).unwrap();
    for e in entries {
        idx.upsert(e).unwrap();
    }
    dir
}

fn tsv(fields: &[&str]) -> String {
    format!("{}\n", fields.join("\t"))
}

#[test]
fn export_format_order_and_files() {
    let t = tempfile::tempdir().unwrap();
    let a = entry(b"/r/b.txt", b"one", 1);
    let b = entry(b"/r/a\tb\nc\\d", b"two", 2);
    let c = entry(b"/r/z", b"one", 3); // same digest as `a`
    let store = mk_store(
        t.path(),
        "s",
        &[b"/r", b"/q/a b"],
        &[a.clone(), b.clone(), c.clone()],
    );
    let out = t.path().join("out");
    fs::create_dir(&out).unwrap();
    let o = ext(&store).arg("export").arg(&out).output().unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );

    let mut names: Vec<_> = fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["registry", "source", "timestamp"],
        "no temp files remain"
    );

    assert_eq!(
        fs::read_to_string(out.join("registry")).unwrap(),
        "/q/a b\n/r\n"
    );

    let d = |e: &Entry| e.digest.to_reverse(Enc::B64ut);
    let mut src = vec![
        (d(&a), "/r/b.txt".to_string()),
        (d(&b), "/r/a\\tb\\nc\\\\d".to_string()),
        (d(&c), "/r/z".to_string()),
    ];
    // First field's text, then path, as raw bytes.
    src.sort_by(|x, y| x.0.as_bytes().cmp(y.0.as_bytes()).then(x.1.cmp(&y.1)));
    let want: String = src.iter().map(|(d, p)| tsv(&[d, p])).collect();
    assert_eq!(fs::read_to_string(out.join("source")).unwrap(), want);

    // Path order is by the unescaped bytes: "/r/a\tb..." < "/r/b.txt" < "/r/z".
    let ts = |p: &str, e: &Entry| {
        tsv(&[
            p,
            &e.last_checked_ns.to_string(),
            &e.meta.mtime_ns.to_string(),
            &e.meta.ctime_ns.to_string(),
            &e.meta.size.to_string(),
            &e.meta.ino.to_string(),
            &e.meta.dev.to_string(),
        ])
    };
    let want = ts("/r/a\\tb\\nc\\\\d", &b) + &ts("/r/b.txt", &a) + &ts("/r/z", &c);
    assert_eq!(fs::read_to_string(out.join("timestamp")).unwrap(), want);
}

#[test]
fn export_replaces_existing_files_and_needs_a_directory() {
    let t = tempfile::tempdir().unwrap();
    let store = mk_store(t.path(), "s", &[b"/r"], &[entry(b"/r/f", b"x", 1)]);
    let out = t.path().join("out");
    fs::create_dir(&out).unwrap();
    for f in ["registry", "source", "timestamp"] {
        fs::write(out.join(f), "stale\n").unwrap();
    }
    assert_eq!(
        ext(&store)
            .arg("export")
            .arg(&out)
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    assert_eq!(fs::read_to_string(out.join("registry")).unwrap(), "/r\n");
    assert!(!fs::read_to_string(out.join("source"))
        .unwrap()
        .contains("stale"));

    let o = ext(&store)
        .arg("export")
        .arg(t.path().join("absent"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(4));
}

/// Export, import into a store with an empty index, export again: the two
/// export directories are byte-identical.
fn roundtrip(entries: &[Entry], roots: &[&[u8]]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let t = tempfile::tempdir().unwrap();
    let a = mk_store(t.path(), "a", roots, entries);
    let b = mk_store(t.path(), "b", &[b"/unrelated"], &[]);
    let (o1, o2) = (t.path().join("o1"), t.path().join("o2"));
    fs::create_dir(&o1).unwrap();
    fs::create_dir(&o2).unwrap();
    assert_eq!(
        ext(&a)
            .arg("export")
            .arg(&o1)
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let imp = ext(&b).arg("import").arg(&o1).output().unwrap();
    assert_eq!(
        imp.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&imp.stderr)
    );
    assert_eq!(
        ext(&b)
            .arg("export")
            .arg(&o2)
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    let read = |d: &Path| {
        ["registry", "source", "timestamp"]
            .map(|f| fs::read(d.join(f)).unwrap())
            .to_vec()
    };
    // The imported store holds exactly the exported records.
    let st = Store::open(&b).unwrap();
    let got = Index::open(&st).unwrap().iter().unwrap();
    assert_eq!(got.len(), entries.len());
    for e in entries {
        assert_eq!(
            Index::open(&st).unwrap().get(&e.path).unwrap().as_ref(),
            Some(e)
        );
    }
    (read(&o1), read(&o2))
}

#[test]
fn roundtrip_is_byte_identical() {
    let es = [
        entry(b"/r/a", b"1", 1),
        entry(b"/r/t\tn\n\\", b"2", 2),
        entry(b"/r/\xff\x1b", b"1", 3),
        entry(b"/q/z", b"3", 4),
    ];
    let (x, y) = roundtrip(&es, &[b"/r", b"/q"]);
    assert_eq!(x, y);
    // Empty store too.
    let (x, y) = roundtrip(&[], &[b"/r"]);
    assert_eq!(x, y);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn roundtrip_property(
        files in prop::collection::btree_map(
            prop::collection::vec(any::<u8>().prop_filter("no NUL or /", |b| *b != 0 && *b != b'/'), 1..6)
                .prop_filter("not dots", |s| s != b"." && s != b".."),
            (prop::collection::vec(any::<u8>(), 0..4), any::<i64>(), any::<i64>(), any::<u64>(), any::<u64>(), any::<u64>(), any::<i64>()),
            0..8,
        )
    ) {
        let es: Vec<Entry> = files.iter().map(|(name, (content, m, c, size, dev, ino, lc))| {
            let mut path = b"/r/".to_vec();
            path.extend_from_slice(name);
            Entry {
                path,
                digest: Digest::compute(Alg::Sha256, content),
                meta: Meta { size: *size, mtime_ns: *m, ctime_ns: *c, dev: *dev, ino: *ino },
                last_checked_ns: *lc,
            }
        }).collect();
        let (x, y) = roundtrip(&es, &[b"/r"]);
        prop_assert_eq!(x, y);
    }
}

fn good_export(base: &Path) -> PathBuf {
    let es = [entry(b"/r/a", b"1", 1), entry(b"/r/b", b"2", 2)];
    let a = mk_store(base, "src", &[b"/r"], &es);
    let out = base.join("good");
    fs::create_dir(&out).unwrap();
    assert_eq!(
        ext(&a)
            .arg("export")
            .arg(&out)
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    out
}

#[test]
fn import_refuses_a_store_with_an_index() {
    let t = tempfile::tempdir().unwrap();
    let out = good_export(t.path());
    let keep = entry(b"/k/f", b"k", 9);
    let dst = mk_store(t.path(), "dst", &[b"/k"], &[keep.clone()]);
    let o = ext(&dst).arg("import").arg(&out).output().unwrap();
    assert_eq!(o.status.code(), Some(4));
    let st = Store::open(&dst).unwrap();
    assert_eq!(Index::open(&st).unwrap().iter().unwrap(), vec![keep]);
    assert_eq!(st.registry().unwrap(), vec![rp(b"/k")]);
}

/// Each corruption aborts the import with nothing written, and the message
/// names the file and line.
#[test]
fn import_rejects_invalid_records() {
    let t = tempfile::tempdir().unwrap();
    let good = good_export(t.path());
    let src_text = fs::read_to_string(good.join("source")).unwrap();
    let ts_text = fs::read_to_string(good.join("timestamp")).unwrap();
    let src_l: Vec<&str> = src_text.lines().collect();
    let ts_l: Vec<&str> = ts_text.lines().collect();
    let fields = |l: &str| l.split('\t').map(str::to_owned).collect::<Vec<_>>();
    let with = |l: &[String], i: usize, v: &str| {
        let mut l = l.to_vec();
        l[i] = v.to_owned();
        l.join("\t")
    };
    let s1 = fields(src_l[1]);
    let t1 = fields(ts_l[1]);
    let join = |ls: &[String]| ls.join("\n") + "\n";

    // (file, replacement for line 2 (1-based), expected line number in message)
    let mut cases: Vec<(&str, String, usize)> = vec![
        ("source", with(&s1, 0, "short:SHA-256"), 2),
        (
            "source",
            with(&s1, 0, &s1[0].replace("SHA-256", "SHA-999")),
            2,
        ),
        ("source", with(&s1, 0, &s1[0].replace(":SHA-256", "")), 2),
        ("source", with(&s1, 1, "relative/path"), 2),
        ("source", with(&s1, 1, "/outside/root"), 2),
        ("source", with(&s1, 1, "/r/bad\\q"), 2),
        ("source", with(&s1, 1, "/r/a/../b"), 2),
        ("source", s1[0].clone(), 2),
        ("source", format!("{}\textra", s1.join("\t")), 2),
        ("timestamp", with(&t1, 1, "12x"), 2),
        ("timestamp", with(&t1, 2, "+5"), 2),
        ("timestamp", with(&t1, 3, "007"), 2),
        ("timestamp", with(&t1, 4, "-1"), 2),
        ("timestamp", with(&t1, 5, "18446744073709551616"), 2),
        ("timestamp", with(&t1, 6, ""), 2),
        ("timestamp", with(&t1, 0, "/outside/root"), 2),
        ("timestamp", t1[..6].join("\t"), 2),
        ("registry", "relative".to_string(), 2),
        ("registry", "/r/../x".to_string(), 2),
        ("registry", "/bad\\q".to_string(), 2),
    ];
    // A blank line is a record with no fields, not something to skip.
    cases.push(("source", String::new(), 2));
    for (file, line, lineno) in cases {
        let bad = t.path().join("bad");
        let _ = fs::remove_dir_all(&bad);
        fs::create_dir(&bad).unwrap();
        for f in ["registry", "source", "timestamp"] {
            fs::copy(good.join(f), bad.join(f)).unwrap();
        }
        let text = fs::read_to_string(good.join(file)).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if file == "registry" {
            lines.push(line.clone());
        } else {
            lines[1] = line.clone();
        }
        let lineno = if file == "registry" { 2 } else { lineno };
        fs::write(bad.join(file), join(&lines)).unwrap();

        let dst = mk_store(t.path(), "dst", &[b"/keep"], &[]);
        let o = ext(&dst).arg("import").arg(&bad).output().unwrap();
        let err = String::from_utf8_lossy(&o.stderr).into_owned();
        assert_eq!(o.status.code(), Some(4), "{file}: {line:?}: {err}");
        assert!(
            err.contains(&format!("{file}:{lineno}")),
            "{file}: {line:?}: {err}"
        );
        let st = Store::open(&dst).unwrap();
        assert!(
            Index::open(&st).unwrap().iter().unwrap().is_empty(),
            "{file}: {line:?}"
        );
        assert_eq!(
            st.registry().unwrap(),
            vec![rp(b"/keep")],
            "{file}: {line:?}"
        );
        fs::remove_dir_all(&dst).unwrap();
    }
}

#[test]
fn import_rejects_unpaired_records_and_missing_files() {
    let t = tempfile::tempdir().unwrap();
    let good = good_export(t.path());
    let run = |dir: &Path| {
        let dst = mk_store(t.path(), "dst", &[b"/keep"], &[]);
        let o = ext(&dst).arg("import").arg(dir).output().unwrap();
        let st = Store::open(&dst).unwrap();
        let empty = Index::open(&st).unwrap().iter().unwrap().is_empty();
        fs::remove_dir_all(&dst).unwrap();
        (
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
            empty,
        )
    };
    // A source record without a timestamp record, and the reverse.
    for file in ["source", "timestamp"] {
        let bad = t.path().join("bad");
        let _ = fs::remove_dir_all(&bad);
        fs::create_dir(&bad).unwrap();
        for f in ["registry", "source", "timestamp"] {
            fs::copy(good.join(f), bad.join(f)).unwrap();
        }
        let text = fs::read_to_string(good.join(file)).unwrap();
        let first = text.lines().next().unwrap();
        fs::write(bad.join(file), text.replacen(&format!("{first}\n"), "", 1)).unwrap();
        let (code, err, empty) = run(&bad);
        assert_eq!((code, empty), (Some(4), true), "{file}: {err}");
    }
    // Duplicate path in the timestamp file.
    let bad = t.path().join("dup");
    fs::create_dir(&bad).unwrap();
    for f in ["registry", "source", "timestamp"] {
        fs::copy(good.join(f), bad.join(f)).unwrap();
    }
    let ts = fs::read_to_string(good.join("timestamp")).unwrap();
    let first = ts.lines().next().unwrap();
    fs::write(bad.join("timestamp"), format!("{ts}{first}\n")).unwrap();
    let (code, err, empty) = run(&bad);
    assert_eq!((code, empty), (Some(4), true), "{err}");
    assert!(err.contains("timestamp:3"), "{err}");
    // Missing file.
    fs::remove_file(bad.join("registry")).unwrap();
    let (code, err, empty) = run(&bad);
    assert_eq!((code, empty), (Some(4), true), "{err}");
    assert!(err.contains("registry"), "{err}");
}
