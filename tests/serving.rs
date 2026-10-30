use pathward::{rules::Publication, serving::*};

#[test]
fn raw_path_is_an_unchanged_prefix_and_queries_do_not_grant_more() {
    for (target, expected) in [
        (b"/".as_slice(), b"/".as_slice()),
        (b"/a.css?v=1&x=%2f", b"/a.css"),
        (b"/a?", b"/a"),
        (b"/a?one?two", b"/a"),
    ] {
        let result = request_path(target).unwrap();
        assert_eq!(result, expected);
        assert_eq!(result.as_ptr(), target.as_ptr());
        assert_eq!(path_length(target), expected.len());
    }
    for target in [
        b"".as_slice(),
        b"?q",
        b"http://example.com/a",
        b"//a",
        b"/../a",
        b"/%61",
        b"/a#x",
        b"/a?q#x",
        b"/a?x y",
        b"/a?\xff",
        b"/a?\r\n",
        b"/a\\b",
    ] {
        assert!(request_path(target).is_none(), "{target:?}");
    }
    let exact = format!("/a?{}", "x".repeat(8189));
    assert!(request_path(exact.as_bytes()).is_some());
    assert!(request_path(format!("{exact}x").as_bytes()).is_none());
}

#[test]
fn methods_hosts_and_publications_all_gate_the_grant() {
    let rules = [Publication {
        path: b"/",
        target: b"index.html",
    }];
    for method in [b"GET".as_slice(), b"HEAD"] {
        let grant = authorize(method, b"example.com", b"example.com", b"/?q=1", &rules).unwrap();
        assert_eq!(grant.target, b"index.html");
        assert_eq!(grant.send_body, method == b"GET");
        assert!(authorize(method, b"other.example", b"example.com", b"/", &rules).is_none());
        assert!(
            authorize(
                method,
                b"example.com",
                b"example.com",
                b"/index.html",
                &rules
            )
            .is_none()
        );
    }
    for method in [
        b"get".as_slice(),
        b"HEAD ",
        b"POST",
        b"CONNECT",
        b"",
        b"GET\0",
    ] {
        assert!(authorize(method, b"example.com", b"example.com", b"/", &rules).is_none());
    }
    let bad = [Publication {
        path: b"/",
        target: b"../secret",
    }];
    assert!(authorize(b"GET", b"example.com", b"example.com", b"/", &bad).is_none());
}

#[test]
fn metadata_admission_requires_regular_single_link_same_bounded_inode() {
    let good = FileFacts {
        regular: true,
        links: 1,
        size: 10,
        device: 1,
        inode: 42,
    };
    assert!(file_allowed(&good, &good));
    for bad in [
        FileFacts {
            regular: false,
            ..good
        },
        FileFacts { links: 0, ..good },
        FileFacts { links: 2, ..good },
        FileFacts {
            size: MAX_FILE_BYTES + 1,
            ..good
        },
        FileFacts { size: 11, ..good },
        FileFacts { device: 2, ..good },
        FileFacts { inode: 43, ..good },
    ] {
        assert!(!file_allowed(&good, &bad));
        assert!(!file_allowed(&bad, &good));
    }
    let boundary = FileFacts {
        size: MAX_FILE_BYTES,
        ..good
    };
    assert!(file_allowed(&boundary, &boundary));
}

#[test]
fn arbitrary_target_samples_match_an_independent_specification() {
    let alphabet = b"aA0/._-%?# =\\\r\n\x00\xff";
    let mut seed = 7u32;
    for length in 0..256 {
        for _ in 0..32 {
            let bytes: Vec<_> = (0..length)
                .map(|_| {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    alphabet[seed as usize % alphabet.len()]
                })
                .collect();
            let split = bytes.iter().position(|b| *b == b'?').unwrap_or(bytes.len());
            let path = &bytes[..split];
            let query = &bytes[split..];
            let expected = if pathward::valid_path(path)
                && query.iter().all(|b| b.is_ascii_graphic() && *b != b'#')
            {
                Some(path)
            } else {
                None
            };
            assert_eq!(request_path(&bytes), expected);
            assert_eq!(path_length(&bytes), split);
        }
    }
}
