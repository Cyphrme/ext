//! A scan that finds nothing to report must change nothing: a second `check`
//! over an untouched tree prints nothing, exits 0, and leaves the entries,
//! the registry and the recorded root identities as they were. Only
//! `last_checked` may move, since a racy entry is re-hashed on purpose.

mod support;
use ext::index::{Entry, Index};
use ext::scan::{run, Opts, Report};
use ext::store::Store;
use proptest::prelude::*;
use std::fs;
use std::path::Path;
use support::{canon_tmp, rp, store_with_roots};

type State = (Vec<Entry>, Vec<Vec<u8>>, Option<u64>);

fn state(st: &Store, ix: &Index, root: &Path) -> State {
    let mut entries = ix.iter().unwrap();
    for e in &mut entries {
        e.last_checked_ns = 0;
    }
    let reg = st
        .registry()
        .unwrap()
        .iter()
        .map(|r| r.as_bytes().to_vec())
        .collect();
    let id = ix.root_id(&rp(root)).unwrap().map(|i| i.0);
    (entries, reg, id)
}

fn check(st: &Store, ix: &Index) -> (Vec<Report>, i32) {
    let lock = st.lock().unwrap();
    let mut reps = Vec::new();
    let s = run(st, &lock, ix, &Opts::default(), &mut |r| reps.push(r)).unwrap();
    (reps, s.exit_code())
}

fn segment() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec!["a", "b", "c", "d.txt"])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn second_check_of_an_untouched_tree_changes_nothing(
        files in prop::collection::vec(
            (prop::collection::vec(segment(), 1..4), prop::collection::vec(any::<u8>(), 0..40)),
            0..8,
        ),
        full in any::<bool>(),
    ) {
        let (_t, base) = canon_tmp();
        let root = base.join("root");
        fs::create_dir_all(&root).unwrap();
        for (segs, data) in &files {
            let p = segs.iter().fold(root.clone(), |p, s| p.join(s));
            // A name that is a directory in another case is simply skipped.
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&p, data);
        }
        let st = store_with_roots(&base, &[&root]);
        let ix = Index::open(&st).unwrap();
        check(&st, &ix);
        let before = state(&st, &ix, &root);
        for _ in 0..2 {
            let (reps, code) = check(&st, &ix);
            prop_assert!(reps.is_empty(), "reported {reps:?}");
            prop_assert_eq!(code, 0);
            prop_assert_eq!(&state(&st, &ix, &root), &before);
        }
        // --full ignores the metadata shortcut but must agree.
        if full {
            let lock = st.lock().unwrap();
            let mut reps = Vec::new();
            let opts = Opts { full: true, ..Opts::default() };
            run(&st, &lock, &ix, &opts, &mut |r| reps.push(r)).unwrap();
            prop_assert!(reps.is_empty(), "--full reported {reps:?}");
            prop_assert_eq!(&state(&st, &ix, &root), &before);
        }
    }
}
