use futures_lite::future::block_on;
use rustls_acme::https_helper::{HttpsClient, read_response};
#[test]
fn discovered_urls_cannot_change_origin() {
    let client = HttpsClient::new(
        "https://acme.example.test/directory",
        pathward_server::acme::public_client_config().unwrap(),
    )
    .unwrap();
    assert!(
        client
            .check_url("https://acme.example.test/order/123")
            .is_ok()
    );
    for url in [
        "http://acme.example.test/order",
        "https://evil.test/",
        "https://acme.example.test.evil/",
        "https://acme.example.test:444/",
        "https://user@acme.example.test/",
        "https://acme.example.test/path#fragment",
        "//acme.example.test/x",
        "https://acme.example.test/\r\nHost:evil",
    ] {
        assert!(client.check_url(url).is_err(), "{url}");
    }
}
#[test]
fn bounded_response_framing() {
    for (wire, body) in [
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            "{}",
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
            "{}",
        ),
        (b"HTTP/1.1 200 OK\r\n\r\n{}", "{}"),
    ] {
        assert_eq!(
            block_on(read_response(&mut &*wire, false)).unwrap().body(),
            body
        );
    }
    for wire in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100001\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
    ] {
        assert!(block_on(read_response(&mut &*wire, false)).is_err());
    }
    let huge = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(9000));
    assert!(block_on(read_response(&mut huge.as_bytes(), false)).is_err());
    let chunk = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
    assert_eq!(
        block_on(read_response(&mut &chunk[..], true))
            .unwrap()
            .body(),
        ""
    );
}
