//! The deleted-root verdict as a pure function of what was observed. A root
//! is deleted only if every observation agrees; any doubt keeps the index.
//! The walk reports a root as gone only on ENOENT, so that first observation
//! is not a parameter.

use ext::index::RootId;
use ext::scan::{judge_gone, Gone, Probe};
use std::io;

#[test]
fn deleted_only_when_the_reprobe_saw_it_absent_and_the_ancestor_is_the_recorded_filesystem() {
    let a = RootId(1);
    let recorded = [None, Some(a)];
    let ancestors: [fn() -> io::Result<RootId>; 3] = [
        || Ok(RootId(1)),
        || Ok(RootId(2)),
        || Err(io::Error::other("unreadable")),
    ];
    let probes = [Probe::Absent, Probe::Present];
    let mut deleted = 0;
    let mut cases = 0;
    for rec in recorded {
        for anc in ancestors {
            for again in probes {
                cases += 1;
                let want = again == Probe::Absent && rec == Some(a) && anc().ok() == Some(a);
                let got = judge_gone(rec, anc(), again);
                assert_eq!(
                    got == Gone::Deleted,
                    want,
                    "recorded={rec:?} ancestor={:?} again={again:?}: {got:?}",
                    anc().ok()
                );
                if let Gone::MissingMount(why) = &got {
                    assert!(!why.is_empty(), "a refusal must say why");
                }
                deleted += usize::from(want);
            }
        }
    }
    // 2 * 3 * 2 combinations, exactly one of which is a deletion.
    assert_eq!((cases, deleted), (12, 1));
}
