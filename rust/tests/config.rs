//! `<store>/config` (README, Config Flags): JSON5, optional, applied by every
//! command that opens the store. Black-box through the binary.

use assert_cmd::Command;
use ext::digest::{Alg, Digest, Enc};
use ext::index::{Entry, Index, Meta};
use ext::store::Store;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

struct Fx {
    _t: tempfile::TempDir,
    store: PathBuf,
}

const CONTENT: &[u8] = b"content";

impl Fx {
    /// A bare store holding one seeded entry for `CONTENT`.
    fn new() -> Fx {
        let t = tempfile::tempdir().unwrap();
        let store = fs::canonicalize(t.path()).unwrap().join("store");
        let st = Store::init_bare(&store).unwrap();
        Index::open(&st)
            .unwrap()
            .upsert(&Entry {
                path: b"/x/file".to_vec(),
                digest: Digest::compute(Alg::Sha256, CONTENT),
                meta: Meta {
                    size: 7,
                    mtime_ns: 1,
                    ctime_ns: 1,
                    dev: 1,
                    ino: 1,
                },
                last_checked_ns: 1,
            })
            .unwrap();
        Fx { _t: t, store }
    }

    fn config(&self, text: &str) {
        let p = self.store.join("config");
        let _ = fs::remove_file(&p);
        fs::write(&p, text).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn ext(&self, args: &[&str]) -> (i32, String, String) {
        let o = Command::new(env!("CARGO_BIN_EXE_ext"))
            .env("EXTANT_DIR", &self.store)
            .timeout(Duration::from_secs(60))
            .args(args)
            .output()
            .unwrap();
        (
            o.status.code().unwrap(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    }
}

fn digest(enc: Enc) -> String {
    Digest::compute(Alg::Sha256, CONTENT).to_reverse(enc)
}

#[test]
fn absent_config_means_defaults() {
    let fx = Fx::new();
    let (code, out, _) = fx.ext(&["list"]);
    assert_eq!(
        (code, out),
        (0, format!("{}\t/x/file\n", digest(Enc::B64ut)))
    );
}

#[test]
fn json5_syntax_and_default_values_are_accepted() {
    let fx = Fx::new();
    fx.config(
        "// comments, unquoted keys, single quotes and trailing commas are JSON5\n\
         { Aware: true, Base64: true, Hex: true, DefaultEnc: 'B64', IndexEnc: \"B64\",\n\
           Truncation: false, Unlabeled: false, Hash: 'SHA-256', Directory: 'CWD',\n\
           CompareCtimeInode: true, UnregisterDeleted: true, }\n",
    );
    assert_eq!(fx.ext(&["list"]).0, 0);
}

#[test]
fn default_enc_sets_the_output_and_the_flag_still_overrides() {
    let fx = Fx::new();
    fx.config("{ DefaultEnc: 'Hex' }");
    let want = format!("{}\t/x/file\n", digest(Enc::Hex));
    assert_eq!(fx.ext(&["list"]).1, want);
    fx.config("{ DefaultEnc: 'B64' }");
    assert_eq!(fx.ext(&["--hex", "list"]).1, want);
}

#[test]
fn disabled_input_encodings_are_refused_and_named() {
    let fx = Fx::new();
    let (b64, hex) = (digest(Enc::B64ut), digest(Enc::Hex));
    fx.config("{ Hex: false }");
    let (code, _, err) = fx.ext(&["resolve", &hex]);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("Hex"), "{err}");
    assert_eq!(fx.ext(&["resolve", &b64]).0, 0);
    fx.config("{ Base64: false }");
    let (code, _, err) = fx.ext(&["resolve", &b64]);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("Base64"), "{err}");
    assert_eq!(fx.ext(&["resolve", &hex]).0, 0);
}

#[test]
fn unsupported_non_default_values_are_configuration_errors_naming_the_key() {
    let fx = Fx::new();
    for (text, key) in [
        ("{ Truncation: true }", "Truncation"),
        ("{ Unlabeled: true }", "Unlabeled"),
        ("{ Aware: false }", "Aware"),
        ("{ Hash: 'SHA-512' }", "Hash"),
        ("{ IndexEnc: 'Hex' }", "IndexEnc"),
        ("{ Directory: '/srv' }", "Directory"),
        ("{ DefaultEnc: 'Base32' }", "DefaultEnc"),
        ("{ Frobnicate: 1 }", "Frobnicate"),
        ("{ Hex: 'yes' }", "Hex"),
    ] {
        fx.config(text);
        let (code, out, err) = fx.ext(&["list"]);
        assert_eq!(code, 4, "{text}: {err}");
        assert!(out.is_empty(), "{text}: {out}");
        assert!(err.contains(key), "{text}: {err}");
    }
}

#[test]
fn a_config_that_does_not_parse_is_an_error() {
    let fx = Fx::new();
    for text in ["", "{ Hex: ", "[]", "42"] {
        fx.config(text);
        let (code, _, err) = fx.ext(&["list"]);
        assert_eq!(code, 4, "{text:?}: {err}");
        assert!(err.contains("config"), "{text:?}: {err}");
    }
}

// The config is part of the store and is judged like the registry: a file
// others can write, or a symlink, is refused.
#[test]
fn a_config_others_can_write_or_a_symlink_is_refused() {
    let fx = Fx::new();
    fx.config("{}");
    let p = fx.store.join("config");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();
    let (code, _, err) = fx.ext(&["list"]);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("config"), "{err}");
    fs::remove_file(&p).unwrap();
    let real = fx.store.parent().unwrap().join("elsewhere");
    fs::write(&real, "{}").unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&real, &p).unwrap();
    let (code, _, err) = fx.ext(&["list"]);
    assert_eq!(code, 4, "{err}");
}

// `UnregisterDeleted: false` reaches the scan: a deleted root is reported
// and nothing changes.
#[test]
fn unregister_deleted_false_reaches_the_scan() {
    let fx = Fx::new();
    let tree = fx.store.parent().unwrap().join("tree");
    fs::create_dir(&tree).unwrap();
    fs::write(tree.join("f"), "x").unwrap();
    assert_eq!(fx.ext(&["register", tree.to_str().unwrap()]).0, 0);
    fx.config("{ UnregisterDeleted: false }");
    fs::remove_dir_all(&tree).unwrap();
    let (code, out, err) = fx.ext(&["check"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.starts_with(&format!("DELETED\t{}", tree.display())),
        "{out}"
    );
    assert!(fs::read_to_string(fx.store.join("registry"))
        .unwrap()
        .contains("tree"));
    fx.config("{}");
    let (code, out, err) = fx.ext(&["check"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains(&format!("DELETED\t{}", tree.display())),
        "{out}"
    );
    assert!(!fs::read_to_string(fx.store.join("registry"))
        .unwrap()
        .contains("tree"));
}

// Every query form is judged by the encoding it was written in, not just the
// labelled digest: hash:// and the name forms too.
#[test]
fn a_disabled_encoding_is_refused_in_every_query_form() {
    let fx = Fx::new();
    let (b64, hex) = (
        Digest::compute(Alg::Sha256, CONTENT).encode(Enc::B64ut),
        Digest::compute(Alg::Sha256, CONTENT).encode(Enc::Hex),
    );
    let forms = |v: &str| {
        vec![
            format!("hash://sha-256/{v}"),
            format!("hash://SHA-256/{v}/tail"),
            format!("{v}:SHA-256"),
            format!("SHA-256:{v}"),
            format!("SHA-256:{v}:file"),
            format!("file:SHA-256:{v}"),
        ]
    };
    fx.config("{ Hex: false }");
    for q in forms(&hex) {
        let (code, _, err) = fx.ext(&["resolve", &q]);
        assert_eq!(code, 4, "{q}: {err}");
        assert!(err.contains("Hex"), "{q}: {err}");
    }
    for q in forms(&b64) {
        assert_ne!(fx.ext(&["resolve", &q]).0, 4, "{q} still allowed");
    }
    fx.config("{ Base64: false }");
    for q in forms(&b64) {
        let (code, _, err) = fx.ext(&["resolve", &q]);
        assert_eq!(code, 4, "{q}: {err}");
        assert!(err.contains("Base64"), "{q}: {err}");
    }
    for q in forms(&hex) {
        assert_ne!(fx.ext(&["resolve", &q]).0, 4, "{q} still allowed");
    }
}

// export and import open the store like every command, so a bad config stops
// them too.
#[test]
fn export_and_import_apply_the_config() {
    let fx = Fx::new();
    fx.config("{ Truncation: true }");
    let out = fx.store.parent().unwrap().join("out");
    fs::create_dir(&out).unwrap();
    for cmd in ["export", "import"] {
        let (code, _, err) = fx.ext(&[cmd, out.to_str().unwrap()]);
        assert_eq!(code, 4, "{cmd}: {err}");
        assert!(err.contains("Truncation"), "{cmd}: {err}");
    }
}

// Imported roots carry no recorded filesystem identity. The first scan must
// record it, not refuse the root.
#[test]
fn export_import_then_check_records_identity_and_is_clean() {
    let fx = Fx::new();
    let tree = fx.store.parent().unwrap().join("tree");
    fs::create_dir(&tree).unwrap();
    fs::write(tree.join("f"), "x").unwrap();
    assert_eq!(fx.ext(&["register", tree.to_str().unwrap()]).0, 0);
    let out = fx.store.parent().unwrap().join("out");
    fs::create_dir(&out).unwrap();
    assert_eq!(fx.ext(&["export", out.to_str().unwrap()]).0, 0);

    let other = fx.store.parent().unwrap().join("store2");
    let st = Store::init_bare(&other).unwrap();
    drop(st);
    let run = |args: &[&str]| {
        let o = Command::new(env!("CARGO_BIN_EXE_ext"))
            .env("EXTANT_DIR", &other)
            .args(args)
            .output()
            .unwrap();
        (
            o.status.code().unwrap(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
        )
    };
    assert_eq!(run(&["import", out.to_str().unwrap()]).0, 0);
    let (code, stdout) = run(&["check"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(!stdout.contains("REFUSED"), "{stdout}");
    // The identity is now recorded: deleting the root is a deletion, not a
    // missing mount.
    fs::remove_dir_all(&tree).unwrap();
    let (code, stdout) = run(&["check"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(stdout.contains("DELETED\t"), "{stdout}");
}

// A FIFO planted as the config must fail the type check; opening it for
// reading would otherwise block until a writer appears.
#[test]
fn a_fifo_config_is_refused_without_blocking() {
    let fx = Fx::new();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        fx.store.join("config"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let (code, _, err) = fx.ext(&["list"]);
    assert_eq!(code, 4, "{err}");
}
