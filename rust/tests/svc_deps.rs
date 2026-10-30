//! ES-17: trust roots come from the platform, never from a list compiled into
//! `ext`. The deterministic evaluator is the resolved dependency graph: no
//! crate that ships a root list may be in it. Run: `cargo test --test svc_deps`.

use std::process::Command;

/// Violator: enabling a dependency feature that bundles Mozilla's roots (ureq's
/// `rustls` or `rustls-webpki-roots` pull in `webpki-roots`).
#[test]
fn no_compiled_in_root_list_is_in_the_dependency_tree() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    for krate in ["webpki-roots", "webpki-root-certs"] {
        let o = Command::new(&cargo)
            .args(["tree", "--offline", "-e", "normal,build", "-i", krate])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("run cargo tree");
        // A broken `cargo tree` also exits non-zero; only "no such package"
        // proves absence.
        assert!(
            !o.status.success()
                && String::from_utf8_lossy(&o.stderr).contains("did not match any packages"),
            "{krate} is in the dependency tree, or cargo tree failed:\n{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
    }
}

/// Removes the brace-delimited item that starts at `marker`, if present.
fn without_item(src: &str, marker: &str) -> String {
    let Some(at) = src.find(marker) else { return src.to_string() };
    let open = at + src[at..].find('{').expect("item has a body");
    let mut depth = 0;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return format!("{}{}", &src[..at], &src[open + i + 1..]);
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces after {marker}");
}

/// S5 (test plan): admit, evict, sweep and the services-file write perform no
/// filesystem effect except through the step executor, which is what lets a
/// test executor model a killed process. The scan covers `src/cache.rs` and
/// `src/services.rs` minus the three named exemptions (the executor
/// implementation, `TmpFile`'s drop-time cleanup and `create_tmp`). It is a
/// textual evaluator, so it checks the named effect calls and not every
/// possible spelling. Violator: a direct `std::fs::rename` (or any call
/// below) in `admit`, `evict`, `sweep` or `write_file`.
#[test]
fn cache_and_services_write_effects_go_through_the_executor() {
    const EFFECTS: &[&str] = &[
        "fs::rename", "fs::remove_file", "fs::remove_dir", "fs::write", "fs::create_dir",
        "fs::set_permissions", "fs::copy", "fs::hard_link", "fs::symlink", "File::create",
        "OpenOptions", "renameat", "unlinkat", "mkdirat", "fsync", "fdatasync", ".sync_all(",
        ".sync_data(", ".set_len(", ".write_all(", ".set_modified(", "ftruncate",
    ];
    let mut bad = vec![];
    for file in ["src/cache.rs", "src/services.rs"] {
        let raw = std::fs::read_to_string(format!("{}/{file}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let mut src: String = raw
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        if file == "src/cache.rs" {
            for m in ["impl StepExecutor for FsExecutor", "impl Drop for TmpFile", "pub fn create_tmp"] {
                src = without_item(&src, m);
            }
        }
        for e in EFFECTS {
            if src.contains(e) {
                bad.push(format!("{file}: direct `{e}` outside the executor"));
            }
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}
