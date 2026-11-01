use pathward_server::http::{MAX_HEAD_BYTES, MAX_HEADERS, parse};

fn request(extra: &str) -> String {
    format!("GET /asset.css?v=1 HTTP/1.1\r\nHost: example.com\r\n{extra}\r\n")
}

#[test]
fn preserves_raw_target_and_canonicalizes_only_authority() {
    let text = "HEAD /asset.css?v=%2e HTTP/1.1\r\nHost: EXAMPLE.COM:8080\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
    let req = parse(text.as_bytes(), 8080).unwrap();
    assert_eq!(req.method, b"HEAD");
    assert_eq!(req.target, b"/asset.css?v=%2e");
    assert_eq!(req.host, "example.com");
    assert!(
        text.as_bytes()
            .windows(req.target.len())
            .any(|w| w.as_ptr() == req.target.as_ptr())
    );
}

#[test]
fn ambiguous_framing_and_authority_are_rejected() {
    for extra in [
        "Host: example.com\r\n",
        "hOsT: other.example\r\n",
        "Content-Length: 1\r\n",
        "Content-Length: 00\r\n",
        "Content-Length: +0\r\n",
        "Content-Length: 0\r\ncontent-length: 0\r\n",
        "Content-Length: 0, 0\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Transfer-Encoding: identity\r\n",
        "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n",
        "Expect: 100-continue\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Host\r\n",
        "Trailer: X-Anything\r\n",
        " Folded: header\r\n",
        "X-A: value\r\n\tcontinued\r\n",
        "Host : other.example\r\n",
        "X: a\0b\r\n",
    ] {
        assert!(
            parse(request(extra).as_bytes(), 8080).is_err(),
            "accepted {extra:?}"
        );
    }
    for host in [
        "",
        "example.com:0",
        "example.com:08080",
        "example.com:9999",
        "example.com:65536",
        "example.com:8080:8080",
        "example.com.",
        "a..b",
        "*.example.com",
        "example.com@evil",
        "example.com, evil",
        "[::1]",
        "a-.example",
        "-a.example",
        "example%2ecom",
    ] {
        let text = request("").replace("example.com", host);
        assert!(parse(text.as_bytes(), 8080).is_err(), "accepted {host:?}");
    }
    assert!(parse(b"GET / HTTP/1.1\r\n\r\n", 8080).is_err());
}

#[test]
fn explicit_external_port_is_checked_without_trusting_forwarded_headers() {
    for (expected, port, accepted) in [
        (443, 443, true),
        (443, 8443, false),
        (443, 80, false),
        (80, 80, true),
        (80, 8080, false),
        (80, 443, false),
        (8080, 8080, true),
        (8080, 80, false),
    ] {
        let text = format!(
            "GET / HTTP/1.1\r\nHost: example.com:{port}\r\nForwarded: host=example.com:{expected};proto=https\r\nX-Forwarded-Port: {expected}\r\n\r\n"
        );
        assert_eq!(parse(text.as_bytes(), expected).is_ok(), accepted);
    }
    assert!(parse(request("").as_bytes(), 0).is_err());
}

#[test]
fn strict_request_line_crlf_and_single_request() {
    for text in [
        "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
        "GET / HTTP/2.0\r\nHost: example.com\r\n\r\n",
        "GET  / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET\t/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET / HTTP/1.1\nHost: example.com\n\n",
        "GET / HTTP/1.1\r\nHost: example.com\n\r\n",
        "\r\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY",
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ] {
        assert!(parse(text.as_bytes(), 8080).is_err(), "accepted {text:?}");
    }
}

#[test]
fn header_limits_and_malformed_bytes_do_not_panic() {
    let exact = request(&"X: a\r\n".repeat(MAX_HEADERS - 1));
    assert!(parse(exact.as_bytes(), 8080).is_ok());
    let too_many = request(&"X: a\r\n".repeat(MAX_HEADERS));
    assert_eq!(parse(too_many.as_bytes(), 8080).err().unwrap().0, 431);
    let oversized = request(&format!("X: {}\r\n", "a".repeat(MAX_HEAD_BYTES)));
    assert_eq!(parse(oversized.as_bytes(), 8080).err().unwrap().0, 431);
    for byte in 0u8..=255 {
        for pos in 0..request("").len() {
            let mut text = request("").into_bytes();
            text[pos] = byte;
            if let Ok(req) = parse(&text, 8080) {
                assert!(req.host.is_ascii());
                assert!(req.target.starts_with(b"/"));
            }
        }
    }
}

#[test]
fn header_deadline_is_total_not_reset_by_slow_progress() {
    use std::{
        io::Write,
        net::{TcpListener, TcpStream},
        time::{Duration, Instant},
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::scope(|scope| {
        let server = scope.spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let start = Instant::now();
            let result =
                pathward_server::http::read_head(&mut stream, start + Duration::from_millis(250));
            assert!(result.is_err());
            assert!(start.elapsed() < Duration::from_secs(1));
        });
        let mut client = TcpStream::connect(address).unwrap();
        for _ in 0..10 {
            if client.write_all(b"G").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(60));
        }
        server.join().unwrap();
    });
}
