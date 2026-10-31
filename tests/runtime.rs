use pathward::runtime::{commit_generation, ready};
#[test]
fn transaction_edges_and_failure_states() {
    for current in [0, 1, 2, u64::MAX - 1, u64::MAX] {
        for expected in [0, 1, 2, u64::MAX - 1, u64::MAX] {
            for mask in 0..16 {
                let (p, i, s, d) = (mask & 1 != 0, mask & 2 != 0, mask & 4 != 0, mask & 8 != 0);
                let next = commit_generation(current, expected, p, i, s, d);
                if next != current {
                    assert!(p && i && s && !d && current == expected);
                    assert_eq!(Some(next), current.checked_add(1));
                } else {
                    assert!(!p || !i || !s || d || current != expected || current == u64::MAX);
                }
                assert_eq!(ready(d, p, i, s), !d && p && (!i || s));
            }
        }
    }
}
