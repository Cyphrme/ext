//! Registered roots against mounts and each other (amendments 26f, S3).
//! The jail scenarios run the binary in a private user+mount namespace
//! (`support::in_jail`) and skip, loudly, where one is unavailable.

mod support;
use ext::index::Index;
use ext::scan::{run, Opts, ReportKind as K};
use std::fs;
use support::{b, canon_tmp, store_with_roots};

/// Lines of `out` that start with `label` and a tab.
fn lines<'a>(out: &'a str, label: &str) -> Vec<&'a str> {
    out.lines()
        .filter(|l| l.starts_with(&format!("{label}\t")))
        .collect()
}

fn jail(args: &[&str], script: &str) -> Option<support::JailOut> {
    let o = support::in_jail_with(args, script);
    if o.is_none() {
        eprintln!("skipped: no unprivileged user+mount namespace");
    }
    o
}

// A root nested inside another across a mount is the nested root's own
// business: the outer walk stops at the mount without disowning the inner
// root's entries, so an edit under it is EDITED, not EXCLUDED then NEW.
#[test]
fn nested_root_across_a_mount_keeps_its_own_entries() {
    let script = r#"
mkdir -p "$J/work/outer/inner"
echo o > "$J/work/outer/o"
mount -t tmpfs tmpfs "$J/work/outer/inner" || exit 77
echo i > "$J/work/outer/inner/i"
x init --bare /work/store || exit 1
x --d /work/store register /work/outer > /dev/null 2>&1 || exit 1
x --d /work/store register /work/outer/inner > /dev/null 2>&1 || exit 1
echo "i, edited and longer" > "$J/work/outer/inner/i"
x --d /work/store check
echo "CODE=$?"
"#;
    let Some(o) = jail(&["-Urm"], script) else {
        return;
    };
    assert!(o.stdout.contains("CODE=0"), "{}{}", o.stdout, o.stderr);
    assert_eq!(lines(&o.stdout, "EDITED").len(), 1, "{}", o.stdout);
    assert!(
        o.stdout.contains("EDITED\t/work/outer/inner/i\t"),
        "{}",
        o.stdout
    );
    for bad in ["EXCLUDED", "NEW", "MISSING"] {
        assert!(lines(&o.stdout, bad).is_empty(), "{bad}: {}", o.stdout);
    }
}

// Roots nested on one filesystem are each scanned, but a file under both is
// one file: indexed once, reported once.
#[test]
fn nested_roots_on_one_filesystem_report_a_file_once() {
    let (_t, base) = canon_tmp();
    let (outer, sub) = (base.join("outer"), base.join("outer/sub"));
    fs::create_dir_all(&sub).unwrap();
    fs::write(outer.join("o"), b"o").unwrap();
    fs::write(sub.join("f"), b"first").unwrap();
    let st = store_with_roots(&base, &[&outer, &sub]);
    let ix = Index::open(&st).unwrap();
    let scan = |ix: &Index| {
        let lock = st.lock().unwrap();
        let mut reps = Vec::new();
        run(&st, &lock, ix, &Opts::default(), &mut |r| reps.push(r)).unwrap();
        reps
    };
    let new: Vec<_> = scan(&ix)
        .into_iter()
        .filter(|r| r.kind == K::New)
        .map(|r| r.path)
        .collect();
    assert_eq!(
        new.iter().filter(|p| **p == b(&sub.join("f"))).count(),
        1,
        "{new:?}"
    );
    fs::write(sub.join("f"), b"second, longer").unwrap();
    let edited: Vec<_> = scan(&ix)
        .into_iter()
        .filter(|r| r.kind == K::Edited)
        .map(|r| r.path)
        .collect();
    assert_eq!(edited, vec![b(&sub.join("f"))]);
}

// A root refused for a changed filesystem identity is accepted again by
// re-registering it (the identity can change legitimately, e.g. an XFS
// fsid after a re-mount): exit 0, entries kept and reconciled rather than
// re-reported as NEW, and the next check is no longer refused.
#[test]
fn reregistering_a_refused_root_rerecords_its_identity() {
    let script = r#"
mkdir -p "$J/work/root"
echo data > "$J/work/root/f"
x init --bare /work/store || exit 1
x --d /work/store register /work/root > /dev/null 2>&1 || exit 1
# Same content on a different filesystem.
mkdir "$J/work/stash" && cp -a "$J/work/root/f" "$J/work/stash/f" || exit 1
mount -t tmpfs tmpfs "$J/work/root" || exit 77
cp -a "$J/work/stash/f" "$J/work/root/f" || exit 1
x --d /work/store check
echo "CHECK1=$?"
echo "--register"
x --d /work/store register /work/root
echo "REGISTER=$?"
echo "--check"
x --d /work/store check
echo "CHECK2=$?"
"#;
    let Some(o) = jail(&["-Urm"], script) else {
        return;
    };
    let (first, rest) = o.stdout.split_once("--register\n").unwrap();
    let (reg, second) = rest.split_once("--check\n").unwrap();
    assert!(
        first.contains("CHECK1=5") && first.contains("REFUSED\t/work/root"),
        "{first}"
    );
    assert!(reg.contains("REGISTER=0"), "{reg}{}", o.stderr);
    for bad in ["NEW", "MISSING", "REFUSED"] {
        assert!(lines(reg, bad).is_empty(), "register printed {bad}: {reg}");
    }
    assert!(
        second.contains("CHECK2=0") && !second.contains("REFUSED"),
        "{second}"
    );
}

// The recorded identity belongs to the registration: after `unregister`, the
// same path registered on another filesystem is a new root, not a refusal.
#[test]
fn unregistering_forgets_the_recorded_identity() {
    let script = r#"
mkdir -p "$J/work/root"
echo data > "$J/work/root/f"
x init --bare /work/store || exit 1
x --d /work/store register /work/root > /dev/null 2>&1 || exit 1
x --d /work/store -u /work/root || exit 1
mount -t tmpfs tmpfs "$J/work/root" || exit 77
echo other > "$J/work/root/g"
x --d /work/store register /work/root
echo "CODE=$?"
"#;
    let Some(o) = jail(&["-Urm"], script) else {
        return;
    };
    assert!(o.stdout.contains("CODE=0"), "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("NEW\t/work/root/g"), "{}", o.stdout);
    assert!(lines(&o.stdout, "REFUSED").is_empty(), "{}", o.stdout);
}

// A `.ext` whose files belong to another user is not our store: it is walked,
// and cannot be planted to hide a subtree.
#[test]
fn dot_ext_files_owned_by_another_uid_do_not_exclude() {
    let script = r#"
mkdir -p "$J/work/root/sub/.ext"
echo f > "$J/work/root/sub/f"
for f in registry index.db lock; do
  : > "$J/work/root/sub/.ext/$f"
  chmod 644 "$J/work/root/sub/.ext/$f"
  chown 1:1 "$J/work/root/sub/.ext/$f" || exit 77
done
x init --bare /work/store || exit 1
x --d /work/store register /work/root
echo "CODE=$?"
"#;
    let Some(o) = jail(&["-m", "--map-auto", "--map-root-user"], script) else {
        return;
    };
    assert!(o.stdout.contains("CODE=0"), "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("NEW\t/work/root/sub/f"), "{}", o.stdout);
    assert!(lines(&o.stdout, "SUBEXTANT").is_empty(), "{}", o.stdout);
}

// ---- docs/traversal.md, Mounts: real mounts are entered, virtual are not.

/// A directory on the build tree's filesystem, holding `files`, to bind into
/// the jail as a real (non-virtual) mount. `None` when that filesystem is
/// itself tmpfs, where no real source exists.
fn real_source(files: &[&str]) -> Option<(tempfile::TempDir, std::path::PathBuf)> {
    let t = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let dir = fs::canonicalize(t.path()).unwrap();
    const TMPFS_MAGIC: i64 = 0x0102_1994;
    if rustix::fs::statfs(&dir).unwrap().f_type as i64 == TMPFS_MAGIC {
        eprintln!("skipped: the build tree is on tmpfs, so no real mount source exists");
        return None;
    }
    for f in files {
        fs::create_dir_all(dir.join(f).parent().unwrap()).unwrap();
        fs::write(dir.join(f), f.as_bytes()).unwrap();
    }
    Some((t, dir))
}

fn with_sources(script: &str, srcs: &[&std::path::Path]) -> String {
    let mut s = script.to_owned();
    for (i, p) in srcs.iter().enumerate() {
        s = s.replace(&format!("@SRC{i}@"), p.to_str().unwrap());
    }
    s
}

#[test]
fn real_mount_inside_a_root_is_entered() {
    let Some((_t, src)) = real_source(&["inside"]) else {
        return;
    };
    let script = with_sources(
        r#"
mkdir -p "$J/work/root/mnt"
echo x > "$J/work/root/f"
mount --bind "@SRC0@" "$J/work/root/mnt" || exit 77
x init --bare /work/store || exit 1
x --d /work/store register /work/root
echo "CODE=$?"
"#,
        &[&src],
    );
    let Some(o) = jail(&["-Urm"], &script) else {
        return;
    };
    assert!(o.stdout.contains("CODE=0"), "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("NEW\t/work/root/f\n"), "{}", o.stdout);
    assert!(o.stdout.contains("NEW\t/work/root/mnt/inside\n"), "{}", o.stdout);
    assert!(lines(&o.stdout, "MOUNT").is_empty(), "{}", o.stdout);
}

// The boundary is judged against the directory's parent mount, not the
// root's: a mount inside a mount is one more crossing, and its files are
// reached, while a directory inside an entered mount is not a crossing.
#[test]
fn real_mounts_nest() {
    let Some((_a, a)) = real_source(&["a-file", "sub/.keep"]) else {
        return;
    };
    let Some((_b, b)) = real_source(&["b-file"]) else {
        return;
    };
    let script = with_sources(
        r#"
mkdir -p "$J/work/root/a"
mount --bind "@SRC0@" "$J/work/root/a" || exit 77
mount --bind "@SRC1@" "$J/work/root/a/sub" || exit 77
x init --bare /work/store || exit 1
x --d /work/store register /work/root
echo "CODE=$?"
"#,
        &[&a, &b],
    );
    let Some(o) = jail(&["-Urm"], &script) else {
        return;
    };
    assert!(o.stdout.contains("CODE=0"), "{}{}", o.stdout, o.stderr);
    for f in ["a/a-file", "a/sub/b-file"] {
        assert!(o.stdout.contains(&format!("NEW\t/work/root/{f}\n")), "{f}: {}", o.stdout);
    }
    assert!(lines(&o.stdout, "MOUNT").is_empty(), "{}", o.stdout);
}

#[test]
fn virtual_mount_inside_a_real_mount_is_reported_and_skipped() {
    let Some((_t, src)) = real_source(&["real", "tmp/.keep"]) else {
        return;
    };
    let script = with_sources(
        r#"
mkdir -p "$J/work/root/a"
mount --bind "@SRC0@" "$J/work/root/a" || exit 77
mount -t tmpfs tmpfs "$J/work/root/a/tmp" || exit 77
echo hidden > "$J/work/root/a/tmp/hidden"
x init --bare /work/store || exit 1
x --d /work/store register /work/root
echo "CODE=$?"
"#,
        &[&src],
    );
    let Some(o) = jail(&["-Urm"], &script) else {
        return;
    };
    assert!(o.stdout.contains("CODE=0"), "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("NEW\t/work/root/a/real\n"), "{}", o.stdout);
    assert!(o.stdout.contains("MOUNT\t/work/root/a/tmp\n"), "{}", o.stdout);
    assert!(!o.stdout.contains("hidden"), "entered tmpfs: {}", o.stdout);
}

// A root that is itself on a virtual filesystem is walked; only a virtual
// filesystem mounted below it is skipped.
#[test]
fn a_root_on_a_virtual_filesystem_is_walked() {
    let script = r#"
mkdir -p "$J/work/root"
mount -t tmpfs tmpfs "$J/work/root" || exit 77
echo r > "$J/work/root/f"
mkdir "$J/work/root/sub" "$J/work/root/mnt"
echo s > "$J/work/root/sub/g"
mount -t tmpfs tmpfs "$J/work/root/mnt" || exit 77
echo hidden > "$J/work/root/mnt/hidden"
x init --bare /work/store || exit 1
x --d /work/store register /work/root
echo "CODE=$?"
"#;
    let Some(o) = jail(&["-Urm"], script) else {
        return;
    };
    assert!(o.stdout.contains("CODE=0"), "{}{}", o.stdout, o.stderr);
    for f in ["f", "sub/g"] {
        assert!(o.stdout.contains(&format!("NEW\t/work/root/{f}\n")), "{f}: {}", o.stdout);
    }
    assert!(o.stdout.contains("MOUNT\t/work/root/mnt\n"), "{}", o.stdout);
    assert!(!o.stdout.contains("hidden"), "{}", o.stdout);
}
