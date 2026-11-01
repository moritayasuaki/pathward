use pathward::{State, accepting, is_public, same_path, step, valid_path};

fn grammar(path: &[u8]) -> bool {
    if path.is_empty() || path.len() > 4096 || path[0] != b'/' {
        return false;
    }
    path == b"/"
        || path[1..]
            .strip_suffix(b"/")
            .unwrap_or(&path[1..])
            .split(|b| *b == b'/')
            .all(|part| {
                !part.is_empty()
                    && part[0] != b'.'
                    && part[part.len() - 1] != b'.'
                    && part
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-' | b'.'))
            })
}

#[test]
fn accepts_canonical_paths_without_changing_bytes() {
    for path in [
        b"/".as_slice(),
        b"/index.html",
        b"/assets/main-v2.js",
        b"/a/",
        b"/A_0-b/file..txt",
    ] {
        assert!(valid_path(path));
        assert!(is_public(path, &[path]));
        assert!(!is_public(path, &[]));
    }
}

#[test]
fn denies_attack_corpus_even_if_explicitly_published() {
    let paths: &[&[u8]] = &[
        b"",
        b"index.html",
        b"//host",
        b"/a//b",
        b"/.",
        b"/..",
        b"/a/../secret",
        b"/a/./b",
        b"/.git/config",
        b"/a/.env",
        b"/a.",
        b"/a./b",
        b"/%2e%2e/secret",
        b"/%252e%252e/secret",
        b"/a%2fb",
        b"/a%5cb",
        b"/a%00",
        b"/a%",
        b"/a\\b",
        b"/a\0b",
        b"/a\rb",
        b"/a\nb",
        b"/a\tb",
        b"/a b",
        b"/a?x=1",
        b"/a#x",
        b"/a:b",
        b"/a;b",
        b"http://host/a",
        b"/\xff",
        "/資料".as_bytes(),
    ];
    for path in paths {
        assert!(!valid_path(path), "accepted: {path:?}");
        assert!(!is_public(path, paths), "published: {path:?}");
    }
}

#[test]
fn exact_case_sensitive_match_not_prefix() {
    let allow: &[&[u8]] = &[b"/", b"/index.html", b"/assets/main.js"];
    for denied in [
        b"/index".as_slice(),
        b"/index.html.bak",
        b"/INDEX.html",
        b"/assets",
    ] {
        assert!(!is_public(denied, allow));
    }
    assert!(is_public(b"/index.html", allow));
    assert!(is_public(b"/index.html", &[b"/index.html", b"/index.html"]));
    assert!(!is_public(b"/index.html", &[b"/index.htm"]));
}

#[test]
fn length_boundary() {
    let mut path = vec![b'a'; 4096];
    path[0] = b'/';
    assert!(valid_path(&path));
    path.push(b'a');
    assert!(!valid_path(&path));
    assert!(!is_public(&path, &[&path]));
}

#[test]
fn publication_count_boundary() {
    let allowed = [b"/".as_slice(); 4096];
    assert!(is_public(b"/", &allowed));
    let too_many = [b"/".as_slice(); 4097];
    assert!(!is_public(b"/", &too_many));
    let mut last = [b"/no".as_slice(); 4096];
    last[4095] = b"/yes";
    assert!(is_public(b"/yes", &last));
    assert!(!is_public(b"/absent", &last));
}

#[test]
fn exhaustive_single_byte_and_absorbing_rejection() {
    assert!(!accepting(State::Start));
    for byte in 0..=255 {
        assert_eq!(step(State::Reject, byte), State::Reject);
        assert_eq!(valid_path(&[byte]), byte == b'/');
        assert_eq!(valid_path(&[b'/', byte]), grammar(&[b'/', byte]));
    }
}

#[test]
fn exhaustive_short_inputs_match_independent_grammar() {
    // Every short word over representatives of all relevant byte classes.
    let alphabet = [
        b'/', b'.', b'a', b'Z', b'9', b'_', b'-', b'%', b'\\', 0, 255,
    ];
    let mut words = vec![Vec::new()];
    for _ in 0..=5 {
        let mut next = Vec::new();
        for word in &words {
            assert_eq!(valid_path(word), grammar(word), "{word:?}");
            if word.len() < 5 {
                for byte in alphabet {
                    let mut child = word.clone();
                    child.push(byte);
                    next.push(child);
                }
            }
        }
        words = next;
    }
}

#[test]
fn comparison_and_authorization_match_reference() {
    let allow: &[&[u8]] = &[b"/", b"/a", b"/a/b.txt", b"/.secret", b"/a%2fb"];
    let mut seed = 0x6a09e667f3bcc909_u64;
    for length in 0..80 {
        for _ in 0..100 {
            let mut bytes = Vec::new();
            for _ in 0..length {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                bytes.push(seed as u8);
            }
            assert_eq!(valid_path(&bytes), grammar(&bytes));
            assert_eq!(
                is_public(&bytes, allow),
                grammar(&bytes) && allow.contains(&bytes.as_slice())
            );
            assert!(same_path(&bytes, &bytes));
            for other in allow {
                assert_eq!(same_path(&bytes, other), bytes.as_slice() == *other);
            }
        }
    }
}
