//! Plan §1 "Traversal" and §4 `walk.rs` (A1, A4, #9, R9, T5).

mod support;
use ext::store::Store;
use ext::walk::{walk, Event};
use rustix::fs::{mknodat, FileType, Mode, CWD};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use support::{b, canon_tmp, rp};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ev {
    File(Vec<u8>),
    Symlink(Vec<u8>),
    Special(Vec<u8>),
    Mount(Vec<u8>),
    SubExtant(Vec<u8>),
    Refused(Vec<u8>),
    Error(Vec<u8>),
}

fn run_walk(root: &Path, store_id: (u64, u64)) -> Vec<Ev> {
    let root = rp(root);
    let (tx, rx) = mpsc::channel();
    // A walk that opens a FIFO blocks forever; a watchdog turns that hang
    // into a failure instead of a stuck test run.
    thread::spawn(move || {
        let mut v = Vec::new();
        walk(&root, store_id, &mut |e| {
            v.push(match e {
                Event::File { path, .. } => Ev::File(path),
                Event::Symlink(p) => Ev::Symlink(p),
                Event::Special(p) => Ev::Special(p),
                Event::Mount(p) => Ev::Mount(p),
                Event::SubExtant(p) => Ev::SubExtant(p),
                Event::Refused(p, _) => Ev::Refused(p),
                Event::Error(p, _) => Ev::Error(p),
            })
        });
        v.sort();
        let _ = tx.send(v);
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("walk hung or panicked")
}

fn no_store() -> (u64, u64) {
    (u64::MAX, u64::MAX)
}

fn files(v: &[Ev]) -> Vec<&[u8]> {
    v.iter()
        .filter_map(|e| {
            if let Ev::File(p) = e {
                Some(p.as_slice())
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn regular_files_are_visited_with_meta_and_sampled_clock() {
    let (_t, d) = canon_tmp();
    let root = d.join("r");
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("a"), b"aaaa").unwrap();
    fs::write(root.join("sub/b"), b"bb").unwrap();
    let t0 = support::now_ns();
    let mut seen = Vec::new();
    walk(&rp(&root), no_store(), &mut |e| {
        if let Event::File {
            path,
            mut file,
            meta,
            last_checked_ns,
        } = e
        {
            use std::io::Read;
            let mut s = Vec::new();
            file.read_to_end(&mut s).unwrap();
            let md = fs::metadata(String::from_utf8(path.clone()).unwrap()).unwrap();
            assert_eq!(
                (meta.ino, meta.dev, meta.size),
                (md.ino(), md.dev(), md.len())
            );
            assert_eq!(s.len() as u64, meta.size);
            seen.push((path, last_checked_ns));
        }
    });
    let t1 = support::now_ns();
    seen.sort();
    assert_eq!(
        seen.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>(),
        vec![b(&root.join("a")), b(&root.join("sub/b"))]
    );
    // PR #12: last_checked is sampled from the real clock, before the statx.
    for (_, lc) in seen {
        assert!(t0 <= lc && lc <= t1, "{t0} <= {lc} <= {t1}");
    }
}

#[test]
fn symlinks_are_reported_and_never_followed() {
    let (_t, d) = canon_tmp();
    let (root, out) = (d.join("r"), d.join("outside"));
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("secret"), b"s").unwrap();
    symlink(out.join("secret"), root.join("flink")).unwrap();
    symlink(&out, root.join("dlink")).unwrap();
    symlink("nowhere", root.join("dangling")).unwrap();
    fs::write(root.join("real"), b"r").unwrap();
    let ev = run_walk(&root, no_store());
    assert_eq!(files(&ev), vec![b(&root.join("real")).as_slice()]);
    for n in ["flink", "dlink", "dangling"] {
        assert!(ev.contains(&Ev::Symlink(b(&root.join(n)))), "{n}: {ev:?}");
    }
}

#[test]
fn fifo_and_socket_are_skipped_without_blocking() {
    let (_t, d) = canon_tmp();
    let root = d.join("r");
    fs::create_dir_all(&root).unwrap();
    mknodat(
        CWD,
        root.join("fifo"),
        FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let _sock = UnixListener::bind(root.join("sock")).unwrap();
    fs::write(root.join("f"), b"x").unwrap();
    let ev = run_walk(&root, no_store());
    assert_eq!(files(&ev), vec![b(&root.join("f")).as_slice()]);
    assert!(ev.contains(&Ev::Special(b(&root.join("fifo")))), "{ev:?}");
    assert!(ev.contains(&Ev::Special(b(&root.join("sock")))), "{ev:?}");
}

// A4: the root itself and any parent component may not be a symlink.
#[test]
fn symlinked_root_is_refused() {
    let (_t, d) = canon_tmp();
    fs::create_dir_all(d.join("real/root")).unwrap();
    fs::write(d.join("real/root/f"), b"x").unwrap();
    symlink(d.join("real"), d.join("link")).unwrap();
    symlink(d.join("real/root"), d.join("root")).unwrap();
    // A symlink as a parent component, and as the root itself.
    for root in [d.join("link/root"), d.join("root")] {
        let ev = run_walk(&root, no_store());
        assert_eq!(ev, vec![Ev::Refused(b(&root))], "{root:?}");
    }
}

// A1: a directory containing `.ext/` is a sub-extant and is skipped whole.
#[test]
fn subextant_is_skipped_whole_and_reported() {
    let (_t, d) = canon_tmp();
    let root = d.join("r");
    fs::create_dir_all(root.join("sub/.ext")).unwrap();
    fs::create_dir_all(root.join("sub/deeper")).unwrap();
    fs::write(root.join("sub/content"), b"c").unwrap();
    fs::write(root.join("sub/deeper/content"), b"c").unwrap();
    fs::write(root.join("sub/.ext/registry"), b"").unwrap();
    fs::write(root.join("top"), b"t").unwrap();
    let ev = run_walk(&root, no_store());
    assert_eq!(files(&ev), vec![b(&root.join("top")).as_slice()]);
    assert!(ev.contains(&Ev::SubExtant(b(&root.join("sub")))), "{ev:?}");
}

// A1 exception: the store's own extant root is walked; only `.ext` is skipped.
#[test]
fn own_extant_root_is_walked_but_not_its_store() {
    let (_t, d) = canon_tmp();
    let root = d.join("r");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("f"), b"x").unwrap();
    let st = Store::init_extant(&root).unwrap();
    let ev = run_walk(&root, st.id());
    assert_eq!(files(&ev), vec![b(&root.join("f")).as_slice()]);
    assert!(!ev.iter().any(|e| matches!(e, Ev::SubExtant(_))), "{ev:?}");
}

// R9: the store is excluded by (dev, ino), wherever it sits and whatever it
// is called.
#[test]
fn store_inside_root_is_excluded_by_identity() {
    let (_t, d) = canon_tmp();
    let root = d.join("r");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("f"), b"x").unwrap();
    let st = Store::init_bare(&root.join("not-called-dot-ext")).unwrap();
    let ev = run_walk(&root, st.id());
    assert_eq!(files(&ev), vec![b(&root.join("f")).as_slice()], "{ev:?}");
    // Control: with a different identity the same tree does yield store files,
    // so the exclusion above is the identity check and not an accident.
    let ev = run_walk(&root, no_store());
    assert!(files(&ev).len() > 1, "{ev:?}");
}

/// T5: the mount rule on a real mount. A tmpfs inside the root is reported
/// and never entered (verified on a mutant that returns a constant mount
/// key: the tmpfs content then leaks into the listing).
#[test]
fn real_mount_boundary_is_not_entered() {
    let script = r#"
mkdir -p "$J/work/root/mnt"
echo x > "$J/work/root/f"
mount -t tmpfs tmpfs "$J/work/root/mnt" || exit 77
echo y > "$J/work/root/mnt/inside"
x init --bare /work/store || exit 1
x --d /work/store register /work/root
echo "CODE=$?"
"#;
    let Some(o) = support::in_jail(script) else {
        eprintln!("skipped: no unprivileged user+mount namespace");
        return;
    };
    assert!(o.stdout.contains("CODE=0"), "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("NEW\t/work/root/f\n"), "{}", o.stdout);
    assert!(o.stdout.contains("MOUNT\t/work/root/mnt\n"), "{}", o.stdout);
    assert!(!o.stdout.contains("inside"), "entered the mount: {}", o.stdout);
}
