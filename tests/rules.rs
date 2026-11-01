use pathward::rules::{Publication, compile, lookup, valid_target};

#[test]
fn compilation_preserves_mapping_and_order() {
    let declarations = [
        Publication {
            path: b"/",
            target: b"index.html",
        },
        Publication {
            path: b"/style.css",
            target: b"assets/site.css",
        },
    ];
    let compiled = compile(&declarations).unwrap();
    assert!(std::ptr::eq(compiled, declarations.as_slice()));
    assert_eq!(lookup(b"/", compiled), Some(b"index.html".as_slice()));
    assert_eq!(
        lookup(b"/style.css", compiled),
        Some(b"assets/site.css".as_slice())
    );
    for denied in [
        b"/assets/site.css".as_slice(),
        b"/style.css.bak",
        b"/STYLE.css",
        b"/style.css/",
        b"/%73tyle.css",
    ] {
        assert_eq!(lookup(denied, compiled), None);
    }
}

#[test]
fn invalid_or_ambiguous_declarations_reject_the_whole_table() {
    let good = Publication {
        path: b"/",
        target: b"index.html",
    };
    for bad in [
        Publication {
            path: b"/../private",
            target: b"safe",
        },
        Publication {
            path: b"/file",
            target: b"../private",
        },
        Publication {
            path: b"/file",
            target: b"/private",
        },
        Publication {
            path: b"/file",
            target: b".secret",
        },
        Publication {
            path: b"/file",
            target: b"",
        },
        Publication {
            path: b"/",
            target: b"different.html",
        },
        good,
    ] {
        assert!(compile(&[good, bad]).is_none());
    }
    assert!(compile(&[]).is_none());
}

#[test]
fn uncompiled_input_cannot_return_a_dangerous_target() {
    for target in [
        b"/etc/passwd".as_slice(),
        b"../secret",
        b"a/./b",
        b"a//b",
        b"a/",
        b"a.",
        b"a\\b",
        b"%2e%2e",
        b"a\0b",
    ] {
        assert!(!valid_target(target));
        assert_eq!(
            lookup(
                b"/ok",
                &[Publication {
                    path: b"/ok",
                    target
                }]
            ),
            None
        );
    }
}

#[test]
fn target_and_table_limits_are_exact() {
    assert!(valid_target(&vec![b'a'; 4095]));
    assert!(!valid_target(&vec![b'a'; 4096]));
    let names: Vec<_> = (0..4097).map(|i| format!("/file{i}")).collect();
    let declarations: Vec<_> = names
        .iter()
        .map(|p| Publication {
            path: p.as_bytes(),
            target: b"file",
        })
        .collect();
    assert!(compile(&declarations[..4096]).is_some());
    assert_eq!(
        lookup(b"/file4095", &declarations[..4096]),
        Some(b"file".as_slice())
    );
    assert!(compile(&declarations).is_none());
    assert_eq!(lookup(b"/file0", &declarations), None);
}

#[test]
fn target_validation_matches_an_independent_component_grammar() {
    fn reference(bytes: &[u8]) -> bool {
        let name = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
        !bytes.is_empty()
            && bytes.len() <= 4095
            && bytes.split(|&b| b == b'/').all(|s| {
                !s.is_empty()
                    && name(s[0])
                    && name(s[s.len() - 1])
                    && s.iter().all(|&b| name(b) || b == b'.')
            })
    }
    let alphabet = [b'a', b'0', b'_', b'-', b'.', b'/', b'%', b'\\', 0, 255];
    for len in 0..=5 {
        for mut n in 0..alphabet.len().pow(len) {
            let mut bytes = vec![0; len as usize];
            for byte in &mut bytes {
                *byte = alphabet[n % alphabet.len()];
                n /= alphabet.len();
            }
            assert_eq!(valid_target(&bytes), reference(&bytes), "{bytes:?}");
        }
    }
}
