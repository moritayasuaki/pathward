use pathward::tls::*;
#[test]
fn identity_requires_nonempty_exact_sni_and_host() {
    assert!(identity_allowed(b"a.test", b"a.test", b"a.test"));
    for (s, h, c) in [
        (b"".as_slice(), b"".as_slice(), b"".as_slice()),
        (b"a.test", b"b.test", b"b.test"),
        (b"A.test", b"a.test", b"a.test"),
        (b"a.test", b"a.test", b"b.test"),
    ] {
        assert!(!identity_allowed(s, h, c));
    }
}
#[test]
fn secret_metadata_and_lifecycle_edges() {
    let good = SecretFacts {
        regular: true,
        owner: 1000,
        mode: 0o600,
        links: 1,
        size: 1_048_576,
        device: 1,
        inode: 2,
    };
    assert!(secret_allowed(&good, &good, 1000));
    for bad in [
        SecretFacts {
            regular: false,
            ..good
        },
        SecretFacts { owner: 0, ..good },
        SecretFacts {
            mode: 0o644,
            ..good
        },
        SecretFacts {
            mode: 0o4600,
            ..good
        },
        SecretFacts { links: 2, ..good },
        SecretFacts {
            size: 1_048_577,
            ..good
        },
        SecretFacts { device: 2, ..good },
        SecretFacts { inode: 3, ..good },
    ] {
        assert!(!secret_allowed(&good, &bad, 1000));
        assert!(!secret_allowed(&bad, &good, 1000));
    }
    let samples = [
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        9,
        10,
        30,
        60,
        90,
        u64::MAX - 2,
        u64::MAX - 1,
        u64::MAX,
    ];
    for b in samples {
        for e in samples {
            for n in samples {
                let expected = n < b
                    || n >= e
                    || (u128::from(e) - u128::from(n)) <= (u128::from(e) - u128::from(b)) / 3;
                assert_eq!(renewal_due(b, e, n), expected);
                assert_eq!(activate(b, e, n, true, true, true), b <= n && n < e);
                assert!(!activate(b, e, n, true, true, false));
                assert!(!activate(b, e, n, false, true, true));
                assert!(!activate(b, e, n, true, false, true));
            }
        }
    }
    assert!(!renewal_due(0, 90, 59));
    assert!(renewal_due(0, 90, 60));
}
