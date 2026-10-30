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
        assert!(
            !o.status.success(),
            "{krate} is in the dependency tree:\n{}",
            String::from_utf8_lossy(&o.stdout)
        );
    }
}
