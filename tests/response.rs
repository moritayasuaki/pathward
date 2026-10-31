use pathward::response::*;
#[test]
fn redirects_and_header_boundaries() {
    assert!(redirect_allowed(
        b"example.com",
        b"example.com",
        b"/new?q=%20",
        308
    ));
    for host in [
        b"evil.test".as_slice(),
        b"example.com:443",
        b"example.com@evil.test",
        b"example.com\r\nX: y",
    ] {
        assert!(!redirect_allowed(host, b"example.com", b"/", 308));
    }
    for target in [
        b"//evil.test".as_slice(),
        b"/../x",
        b"/x\r\nY:z",
        b"/x#y",
        b"/x?q=\n",
    ] {
        assert!(!redirect_allowed(
            b"example.com",
            b"example.com",
            target,
            308
        ));
    }
    assert!(!redirect_allowed(b"example.com", b"example.com", b"/", 302));
    assert!(route_matches(b"/old/x", b"/old", true));
    assert!(!route_matches(b"/older", b"/old", true));
    assert!(!route_matches(b"/old/x", b"/old", false));
    assert!(header_allowed(
        b"content-security-policy",
        b"default-src 'none'"
    ));
    for name in [
        b"content-length".as_slice(),
        b"transfer-encoding",
        b"connection",
        b"location",
        b"Content-Security-Policy",
    ] {
        assert!(!header_allowed(name, b"anything"));
    }
    for byte in 0..=255 {
        assert_eq!(
            header_allowed(b"link", &[byte]),
            (0x20..=0x7e).contains(&byte)
        );
    }
}
#[test]
fn manifest_correspondence_and_activation() {
    assert!(pathward::release::generated_rule(
        b"/a.txt", b"a.txt", b"a.txt", false
    ));
    assert!(!pathward::release::generated_rule(
        b"/a.txt", b"b.txt", b"a.txt", false
    ));
    assert!(!pathward::release::generated_rule(
        b"/extra", b"a.txt", b"a.txt", false
    ));
    assert!(pathward::release::generated_rule(
        b"/",
        b"index.html",
        b"index.html",
        true
    ));
    assert!(!pathward::release::generated_rule(
        b"/",
        b"index.html",
        b"index.html",
        false
    ));
    assert!(!pathward::release::commit_allowed(
        &[b'a'; 64],
        &[b'b'; 64],
        true,
        true,
        false
    ));
    for mask in 0..8 {
        let (p, s, d) = (mask & 1 != 0, mask & 2 != 0, mask & 4 != 0);
        assert_eq!(
            pathward::release::commit_allowed(&[b'a'; 64], &[b'a'; 64], p, s, d),
            p && s && !d
        );
    }
}
