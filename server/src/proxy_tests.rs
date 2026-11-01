use crate::Server;
use pathward_config::ParsedConfig;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

fn config(upstream: SocketAddr, marker: &str) -> ParsedConfig {
    ParsedConfig::parse(&format!("site \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{upstream}\"\nheader \"*\" \"x-robots-tag\" \"{marker}\"\nheader \"*\" \"x-frame-options\" \"DENY\"\nheader \"*\" \"strict-transport-security\" \"max-age=60\"\n}}\n")).unwrap()
}
fn with_proxy(upstream: SocketAddr, test: impl FnOnce(SocketAddr, &Server)) {
    let config = config(upstream, "version-a");
    with_config(&config, test);
}
fn with_config(config: &ParsedConfig, test: impl FnOnce(SocketAddr, &Server)) {
    let server = Server::new(&config.compile().unwrap()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        let serving = s.spawn(|| server.serve(listener, &stop));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(addr, &server)));
        stop.store(true, Ordering::Release);
        serving.join().unwrap().unwrap();
        if let Err(e) = result {
            std::panic::resume_unwind(e)
        }
    });
}
fn exchange(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(request).unwrap();
    let mut output = Vec::new();
    if let Err(e) = s.read_to_end(&mut output) {
        assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset);
    }
    output
}
fn read_request(mut s: &TcpStream) -> Vec<u8> {
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut data = Vec::new();
    let mut b = [0; 2048];
    loop {
        let n = s.read(&mut b).unwrap();
        assert!(n > 0);
        data.extend_from_slice(&b[..n]);
        assert!(data.len() < 2 * 1024 * 1024);
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = std::str::from_utf8(&data[..end]).unwrap();
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .unwrap()
                .parse::<usize>()
                .unwrap();
            if data.len() >= end + 4 + length {
                assert_eq!(data.len(), end + 4 + length);
                return data;
            }
        }
    }
}
fn one_response(reply: &[u8], request: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = upstream.local_addr().unwrap();
    std::thread::scope(|s| {
        let origin = s.spawn(|| {
            let (mut stream, _) = upstream.accept().unwrap();
            let req = read_request(&stream);
            stream.write_all(reply).unwrap();
            req
        });
        let mut response = Vec::new();
        with_proxy(address, |addr, _| response = exchange(addr, request));
        (response, origin.join().unwrap())
    })
}
const GET: &[u8] = b"GET /api/ HTTP/1.1\r\nHost: app.example\r\n\r\n";

#[test]
fn explicit_nondefault_authority_reaches_origin_checks() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    with_proxy(upstream.local_addr().unwrap(), |addr, _| {
        std::thread::scope(|scope| {
            let origin = scope.spawn(|| {
                let (mut socket, _) = upstream.accept().unwrap();
                let wire = String::from_utf8(read_request(&socket))
                    .unwrap()
                    .to_ascii_lowercase();
                let authority = format!("app.example:{}", addr.port());
                let accepted = wire.contains(&format!("\r\nhost: {authority}\r\n"))
                    && wire.contains(&format!("\r\nx-forwarded-host: {authority}\r\n"))
                    && wire.contains(&format!("\r\norigin: http://{authority}\r\n"));
                socket
                    .write_all(if accepted {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
                    } else {
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nNO"
                    })
                    .unwrap();
            });
            let reply = exchange(addr, format!(
                "GET / HTTP/1.1\r\nHost: APP.EXAMPLE:{}\r\nOrigin: http://app.example:{}\r\nX-Forwarded-Host: attacker.example:9000\r\n\r\n",
                addr.port(), addr.port()
            ).as_bytes());
            origin.join().unwrap();
            assert!(
                reply.starts_with(b"HTTP/1.1 200 "),
                "{}",
                String::from_utf8_lossy(&reply)
            );
        });
    });
}

#[test]
fn post_preserves_raw_target_and_binary_body_and_rebuilds_authority_and_forwarding() {
    let body = b"a\0b\r\nGET /admin HTTP/1.1\r\n";
    let mut request=format!("POST /api/%E6%97%A5/?q=%2f HTTP/1.1\r\nHost: APP.EXAMPLE\r\nContent-Length: {}\r\nAuthorization: Bearer test-only\r\nCookie: session=test-only\r\nForwarded: host=evil;proto=https\r\nX-Forwarded-For: 203.0.113.8\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Host: evil.example\r\nX-Forwarded-Port: 443\r\nX-Forwarded-Client-Cert: forged\r\nX-Real-IP: forged\r\nProxy: http://evil.example\r\nProxy-Authorization: secret\r\nTE: trailers\r\nConnection: keep-alive\r\n\r\n",body.len()).into_bytes();
    request.extend_from_slice(body);
    let (response,wire)=one_response(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nSet-Cookie: a=1; Secure\r\nSet-Cookie: b=2; HttpOnly\r\nX-Frame-Options: SAMEORIGIN\r\nStrict-Transport-Security: max-age=999\r\nServer: internal\r\nAlt-Svc: h3=\":9090\"\r\nConnection: close, X-Internal\r\nX-Internal: secret\r\n\r\nOK",&request);
    let end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let h = String::from_utf8(wire[..end].to_vec())
        .unwrap()
        .to_ascii_lowercase();
    assert!(h.starts_with("post /api/%e6%97%a5/?q=%2f http/1.1\r\n"));
    assert!(h.contains("host: app.example\r\n"));
    assert!(h.contains("authorization: bearer test-only\r\n"));
    assert!(h.contains("cookie: session=test-only\r\n"));
    assert!(h.contains("x-forwarded-for: 127.0.0.1\r\n"));
    assert!(h.contains("x-forwarded-proto: http\r\n"));
    assert!(h.contains("x-forwarded-host: app.example\r\n"));
    assert!(h.contains("via: 1.1 pathward\r\n"));
    assert!(h.contains("connection: close\r\n"));
    for forbidden in [
        "evil",
        "203.0.113.8",
        "forged",
        "proxy:",
        "proxy-authorization:",
        "\r\nte:",
        "keep-alive",
    ] {
        assert!(!h.contains(forbidden), "{h}");
    }
    assert_eq!(&wire[end..], body);
    let text = String::from_utf8(response).unwrap();
    assert!(text.starts_with("HTTP/1.1 201 "));
    assert!(text.ends_with("\r\n\r\nOK"));
    assert!(text.contains("set-cookie: a=1; Secure\r\nset-cookie: b=2; HttpOnly\r\n"));
    assert!(text.contains("x-frame-options: DENY\r\n"));
    for forbidden in [
        "SAMEORIGIN",
        "strict-transport-security:",
        "internal",
        "alt-svc:",
        "Server:",
        "x-internal:",
    ] {
        assert!(!text.contains(forbidden), "{text}");
    }
}
#[test]
fn finite_chunked_and_close_delimited_responses_are_reframed_once() {
    for upstream in [
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n"
            .as_slice(),
        b"HTTP/1.0 200 OK\r\n\r\nhello",
    ] {
        let (r, _) = one_response(upstream, GET);
        let s = String::from_utf8(r).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 "));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\nhello"));
        assert!(!s.to_lowercase().contains("transfer-encoding"));
    }
}
#[test]
fn bad_upstream_framing_never_commits_a_partial_success() {
    let cases: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 8388609\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 01\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n800001\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;ext=value\r\nx\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Late: value\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTrailer: X-Late\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
        b"HTTP/1.1 103 Early Hints\r\n\r\n",
        b"HTTP/1.1 999 Surprise\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-A: a\0b\r\n\r\n",
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 205 Reset Content\r\nContent-Length: 1\r\n\r\nx",
    ];
    for reply in cases {
        let (r, _) = one_response(reply, GET);
        assert!(r.starts_with(b"HTTP/1.1 502 "), "{r:?}");
        assert!(r.ends_with(b"\r\n\r\n"));
    }
}
#[test]
fn head_and_conditional_responses_never_copy_a_body() {
    for (response, req, expected) in [
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n".as_slice(),
            b"HEAD / HTTP/1.1\r\nHost: app.example\r\n\r\n".as_slice(),
            200,
        ),
        (
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1234\r\nETag: \"v1\"\r\n\r\n",
            GET,
            304,
        ),
        (b"HTTP/1.1 204 No Content\r\n\r\n", GET, 204),
    ] {
        let (r, _) = one_response(response, req);
        let text = String::from_utf8(r).unwrap();
        assert!(text.starts_with(&format!("HTTP/1.1 {expected} ")));
        assert!(text.ends_with("\r\n\r\n"));
        if expected != 204 {
            assert!(text.contains("Content-Length: 1234\r\n"));
        } else {
            assert!(!text.contains("Content-Length:"));
        }
    }
}
#[test]
fn rejected_requests_do_not_contact_an_upstream() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    with_proxy(listener.local_addr().unwrap(), |addr, _| {
        for (method, path, host, extra, status) in [
            (
                "POST",
                "/",
                "app.example",
                "Content-Length: 1048577\r\n",
                413,
            ),
            (
                "POST",
                "/",
                "app.example",
                "Content-Length: 0\r\nContent-Length: 0\r\n",
                400,
            ),
            (
                "POST",
                "/",
                "app.example",
                "Transfer-Encoding: chunked\r\n",
                400,
            ),
            ("POST", "/", "app.example", "Expect: 100-continue\r\n", 417),
            ("GET", "/", "app.example", "Connection: X-Secret\r\n", 400),
            ("GET", "/", "app.example", "Upgrade: websocket\r\n", 400),
            ("CONNECT", "/", "app.example", "", 405),
            ("TRACE", "/", "app.example", "", 405),
            ("GET", "//evil.example/", "app.example", "", 400),
            ("GET", "/a\\b", "app.example", "", 400),
            ("GET", "/a#b", "app.example", "", 400),
            ("GET", "/", "unknown.example", "", 421),
            ("GET", "/", "app.example", "Via: 1.1 pathward\r\n", 508),
            ("GET", "/", "app.example", "X-A: 1\r\nx-a: 2\r\n", 400),
            (
                "GET",
                "/",
                "app.example",
                "Content-Length: 0\r\n\r\nGET /second HTTP/1.1\r\n",
                400,
            ),
        ] {
            let r = exchange(
                addr,
                format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n").as_bytes(),
            );
            assert!(
                r.starts_with(format!("HTTP/1.1 {status} ").as_bytes()),
                "{method} {extra:?}: {r:?}"
            );
            assert!(
                listener.accept().is_err(),
                "upstream contacted for a rejected request"
            );
            std::thread::sleep(Duration::from_millis(130));
        }
    });
}
#[test]
fn reload_pins_one_upstream_and_header_generation_for_each_request() {
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let baddr = b.local_addr().unwrap();
    with_proxy(a.local_addr().unwrap(), |addr, server| {
        std::thread::scope(|scope| {
            let pending = scope.spawn(|| exchange(addr, GET));
            let (mut old, _) = a.accept().unwrap();
            let _ = read_request(&old);
            let newer = config(baddr, "version-b");
            server
                .reload(&newer.compile().unwrap(), &AtomicBool::new(false))
                .unwrap();
            let fresh = scope.spawn(|| exchange(addr, GET));
            let (mut new, _) = b.accept().unwrap();
            let _ = read_request(&new);
            new.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB")
                .unwrap();
            drop(new);
            let r = String::from_utf8(fresh.join().unwrap()).unwrap();
            assert!(r.ends_with("\r\n\r\nB") && r.contains("x-robots-tag: version-b\r\n"));
            old.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA")
                .unwrap();
            drop(old);
            let r = String::from_utf8(pending.join().unwrap()).unwrap();
            assert!(r.ends_with("\r\n\r\nA") && r.contains("x-robots-tag: version-a\r\n"));
        })
    });
}
#[test]
fn split_request_body_and_options_max_forwards() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    with_proxy(upstream.local_addr().unwrap(), |addr, _| {
        std::thread::scope(|s| {
            let client = s.spawn(|| {
                let mut c = TcpStream::connect(addr).unwrap();
                c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                c.write_all(
                    b"PATCH /api/ HTTP/1.1\r\nHost: app.example\r\nContent-Length: 4\r\n\r\nab",
                )
                .unwrap();
                std::thread::sleep(Duration::from_millis(30));
                c.write_all(b"cd").unwrap();
                let mut out = Vec::new();
                c.read_to_end(&mut out).unwrap();
                out
            });
            let (mut backend, _) = upstream.accept().unwrap();
            let req = read_request(&backend);
            assert!(req.ends_with(b"\r\n\r\nabcd"));
            backend
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .unwrap();
            drop(backend);
            assert!(client.join().unwrap().starts_with(b"HTTP/1.1 204 "));
            upstream.set_nonblocking(true).unwrap();
            let r = exchange(
                addr,
                b"OPTIONS /api HTTP/1.1\r\nHost: app.example\r\nMax-Forwards: 0\r\n\r\n",
            );
            assert!(r.starts_with(b"HTTP/1.1 204 "));
            assert!(upstream.accept().is_err());
        })
    });
}
#[test]
fn unavailable_upstream_is_a_generic_bad_gateway() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    with_proxy(address, |addr, _| {
        let r = exchange(addr, GET);
        assert!(r.starts_with(b"HTTP/1.1 502 "));
        assert!(r.ends_with(b"\r\n\r\n"));
    });
}

#[test]
fn real_tls_sets_trusted_forwarding_and_plaintext_only_redirects_proxy_targets() {
    use crate::tls::{Certificate, Identity, TlsServer};
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName,
    };
    use std::sync::Arc;
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let parsed = config(backend.local_addr().unwrap(), "tls-proxy");
    let server = Server::new(&parsed.compile().unwrap()).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["app.example".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pem = format!("{}{}", key.serialize_pem(), cert.pem());
    let names = vec!["app.example".to_owned()];
    let identity = Arc::new(Identity::new(
        names.clone(),
        Some(Certificate::parse(pem.as_bytes(), &names).unwrap()),
    ));
    let tls = TlsServer::new(identity).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let mut client =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client = Arc::new(client);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
    let plain = redirect.local_addr().unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let worker =
            scope.spawn(|| server.serve_tls_with_redirect(listener, redirect, &stop, &tls));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let upstream=scope.spawn(||{
                let (mut s,_)=backend.accept().unwrap();let req=read_request(&s);
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nStrict-Transport-Security: max-age=999\r\n\r\nOK").unwrap();req
            });
            let mut s = TcpStream::connect(address).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let conn =
                ClientConnection::new(client.clone(), ServerName::try_from("app.example").unwrap())
                    .unwrap();
            let mut tls_client = StreamOwned::new(conn, &mut s);
            tls_client.write_all(b"POST /api/ HTTP/1.1\r\nHost: app.example:443\r\nContent-Length: 2\r\nX-Forwarded-Proto: http\r\n\r\nok").unwrap();
            let mut response = Vec::new();
            tls_client.read_to_end(&mut response).unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200 ") && response.ends_with(b"OK"));
            let text = String::from_utf8(response).unwrap();
            assert!(text.contains("strict-transport-security: max-age=60\r\n"));
            assert!(!text.contains("max-age=999"));
            let req = String::from_utf8(upstream.join().unwrap()).unwrap();
            assert!(
                req.contains("X-Forwarded-Proto: https\r\n")
                    && req.contains("X-Forwarded-Port: 443\r\n")
                    && req.contains("X-Forwarded-For: 127.0.0.1\r\n")
            );
            for (host, status) in [
                ("unknown.example".to_owned(), 421),
                (format!("app.example:{}", address.port()), 400),
            ] {
                let socket = TcpStream::connect(address).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let conn = ClientConnection::new(
                    client.clone(),
                    ServerName::try_from("app.example").unwrap(),
                )
                .unwrap();
                let mut tls_client = StreamOwned::new(conn, socket);
                tls_client
                    .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
                    .unwrap();
                let mut out = Vec::new();
                tls_client.read_to_end(&mut out).unwrap();
                assert!(out.starts_with(format!("HTTP/1.1 {status} ").as_bytes()));
            }
            let out=exchange(plain,b"POST /api/%2f/?q=a%20b HTTP/1.1\r\nHost: app.example:80\r\nContent-Length: 0\r\n\r\n");
            let out = String::from_utf8(out).unwrap();
            assert!(out.starts_with("HTTP/1.1 308 "));
            assert!(out.contains("Location: https://app.example/api/%2f/?q=a%20b\r\n"));
            assert!(!out.contains("strict-transport-security:"));
            backend.set_nonblocking(true).unwrap();
            assert!(backend.accept().is_err());
        }));
        stop.store(true, Ordering::Release);
        worker.join().unwrap().unwrap();
        if let Err(error) = result {
            std::panic::resume_unwind(error)
        }
    });
}

use super::{failure, receive};
use crate::http::Rejection;
use std::time::Instant;
#[test]
fn a_slow_upstream_body_cannot_reset_the_total_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    std::thread::scope(|scope| {
        let peer = scope.spawn(|| {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n")
                .unwrap();
            for _ in 0..20 {
                if socket.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        });
        let start = Instant::now();
        let error = receive(
            client,
            false,
            start + Duration::from_millis(150),
            start + Duration::from_millis(150),
            pathward_config::ProxyLimits::default(),
            None,
        )
        .err()
        .unwrap();
        assert_eq!(failure(error), Rejection(504));
        assert!(start.elapsed() < Duration::from_millis(600));
        peer.join().unwrap();
    });
}

fn configured(upstream: SocketAddr, extra: &str) -> ParsedConfig {
    ParsedConfig::parse(&format!(
        "site \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{upstream}\"\n{extra}\n}}\n"
    ))
    .unwrap()
}

#[test]
fn subtree_denials_scoped_proxy_and_redirects_never_fall_through() {
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    backend.set_nonblocking(true).unwrap();
    let parsed = configured(
        backend.local_addr().unwrap(),
        "deny \"/api/private\"\nproxy-path \"/api\"\nredirect \"/old\" \"app.example\" \"/new\" \"308\"",
    );
    with_config(&parsed, |address, _| {
        for path in [
            "/api/private",
            "/api/private/",
            "/api/private/item",
            "/api/%70rivate",
            "/api//private",
            "/api/a/../private",
            "/api/.env",
            "/api/private;other",
            "/api2",
            "/other",
            "/old/",
        ] {
            let response = exchange(
                address,
                format!("GET {path} HTTP/1.1\r\nHost: app.example\r\n\r\n").as_bytes(),
            );
            assert!(
                response.starts_with(b"HTTP/1.1 404 "),
                "{path}: {response:?}"
            );
            assert!(backend.accept().is_err());
            std::thread::sleep(Duration::from_millis(130));
        }
        let response = exchange(
            address,
            b"GET /old?q=kept HTTP/1.1\r\nHost: app.example\r\n\r\n",
        );
        assert!(
            response.starts_with(b"HTTP/1.1 308 ")
                && response
                    .windows(b"Location: https://app.example/new?q=kept\r\n".len())
                    .any(|w| w == b"Location: https://app.example/new?q=kept\r\n")
        );
        assert!(backend.accept().is_err());
        backend.set_nonblocking(false).unwrap();
        std::thread::scope(|scope| {
            let origin = scope.spawn(|| {
                let (mut s, _) = backend.accept().unwrap();
                let req = read_request(&s);
                assert!(req.starts_with(b"GET /api/public/?q=%2f HTTP/1.1\r\n"));
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    .unwrap();
            });
            assert!(
                exchange(
                    address,
                    b"GET /api/public/?q=%2f HTTP/1.1\r\nHost: app.example\r\n\r\n"
                )
                .ends_with(b"OK")
            );
            origin.join().unwrap();
        });
    });
}

#[test]
fn custom_body_limits_cover_fixed_chunked_close_delimited_and_rejected_uploads() {
    for response in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nFAIL"[..],
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\n\r\nFAIL"[..],
    ] {
        let backend = TcpListener::bind("127.0.0.1:0").unwrap();
        let parsed = configured(
            backend.local_addr().unwrap(),
            "proxy-limit \"request-body\" \"4B\"\nproxy-limit \"response-body\" \"3B\"",
        );
        with_config(&parsed, |addr, _| {
            backend.set_nonblocking(true).unwrap();
            let r = exchange(
                addr,
                b"POST /api/ HTTP/1.1\r\nHost: app.example\r\nContent-Length: 5\r\n\r\n12345",
            );
            assert!(r.starts_with(b"HTTP/1.1 413 "));
            assert!(backend.accept().is_err());
            backend.set_nonblocking(false).unwrap();
            std::thread::scope(|scope| {
                let origin = scope.spawn(|| {
                    let (mut s, _) = backend.accept().unwrap();
                    assert!(read_request(&s).ends_with(b"1234"));
                    s.write_all(response).unwrap();
                });
                let r = exchange(
                    addr,
                    b"POST /api/ HTTP/1.1\r\nHost: app.example\r\nContent-Length: 4\r\n\r\n1234",
                );
                assert!(r.starts_with(b"HTTP/1.1 502 ") && r.ends_with(b"\r\n\r\n"));
                origin.join().unwrap();
            });
        });
    }
}

#[test]
fn configured_request_and_upstream_head_timeouts_are_independent_absolute_budgets() {
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    backend.set_nonblocking(true).unwrap();
    let settings = "proxy-timeout \"request-body\" \"200ms\"\nproxy-timeout \"connect\" \"100ms\"\nproxy-timeout \"response-head\" \"150ms\"\nproxy-timeout \"total\" \"1s\"";
    let parsed = configured(backend.local_addr().unwrap(), settings);
    with_config(&parsed, |addr, _| {
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: app.example\r\nContent-Length: 2\r\n\r\nx")
            .unwrap();
        let start = Instant::now();
        let mut r = Vec::new();
        client.read_to_end(&mut r).unwrap();
        assert!(r.starts_with(b"HTTP/1.1 408 ") && start.elapsed() < Duration::from_secs(1));
        assert!(backend.accept().is_err());
        backend.set_nonblocking(false).unwrap();
        std::thread::scope(|scope| {
            let origin = scope.spawn(|| {
                let (mut s, _) = backend.accept().unwrap();
                read_request(&s);
                std::thread::sleep(Duration::from_millis(400));
                let _ = s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n");
            });
            let start = Instant::now();
            let r = exchange(addr, GET);
            assert!(
                r.starts_with(b"HTTP/1.1 504 ") && start.elapsed() < Duration::from_millis(800)
            );
            origin.join().unwrap();
        });
        std::thread::scope(|scope| {
            let origin = scope.spawn(|| {
                let (mut s, _) = backend.accept().unwrap();
                read_request(&s);
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
                    .unwrap();
                std::thread::sleep(Duration::from_millis(300));
                s.write_all(b"OK").unwrap();
            });
            let r = exchange(addr, GET);
            assert!(r.starts_with(b"HTTP/1.1 200 ") && r.ends_with(b"OK"));
            origin.join().unwrap();
        });
    });
}

#[test]
fn live_connection_cap_is_shared_across_snapshots_and_only_installed_at_commit() {
    use crate::runtime::Snapshot;
    let a = configured(
        "127.0.0.1:3000".parse().unwrap(),
        "proxy-limit \"connections\" \"2\"",
    );
    let b = configured(
        "127.0.0.1:3001".parse().unwrap(),
        "proxy-limit \"connections\" \"1\"",
    );
    let old = Snapshot::prepare(&a.compile().unwrap(), None).unwrap();
    let mut new = Snapshot::prepare(&b.compile().unwrap(), None).unwrap();
    new.inherit_budgets(&old);
    let active = old.sites[0].acquire().unwrap();
    // Preparing a candidate does not change the live budget.
    drop(old.sites[0].acquire().unwrap());
    new.install_limits();
    assert!(old.sites[0].acquire().is_none());
    assert!(new.sites[0].acquire().is_none());
    drop(active);
    let pending_old = old.sites[0].acquire().unwrap();
    assert!(new.sites[0].acquire().is_none());
    drop(pending_old);
    let one = new.sites[0].acquire().unwrap();
    let mut restored = Snapshot::prepare(&a.compile().unwrap(), None).unwrap();
    restored.inherit_budgets(&new);
    restored.install_limits();
    // A captured tighter policy cannot borrow the raised live limit.
    assert!(new.sites[0].acquire().is_none());
    drop(restored.sites[0].acquire().unwrap());
    drop(one);
}

#[test]
fn reload_cannot_reset_an_active_service_limit_and_overload_never_contacts_upstream() {
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let parsed = configured(a.local_addr().unwrap(), "proxy-limit \"connections\" \"1\"");
    with_config(&parsed, |addr, server| {
        std::thread::scope(|scope| {
            let pending = scope.spawn(|| exchange(addr, GET));
            let (mut old, _) = a.accept().unwrap();
            read_request(&old);
            let new = configured(b.local_addr().unwrap(), "proxy-limit \"connections\" \"1\"");
            server
                .reload(&new.compile().unwrap(), &AtomicBool::new(false))
                .unwrap();
            b.set_nonblocking(true).unwrap();
            assert!(exchange(addr, GET).starts_with(b"HTTP/1.1 503 "));
            assert!(b.accept().is_err());
            old.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOLD")
                .unwrap();
            drop(old);
            assert!(pending.join().unwrap().ends_with(b"OLD"));
            b.set_nonblocking(false).unwrap();
            let fresh = scope.spawn(|| exchange(addr, GET));
            let (mut next, _) = b.accept().unwrap();
            read_request(&next);
            next.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nNEW")
                .unwrap();
            drop(next);
            assert!(fresh.join().unwrap().ends_with(b"NEW"));
        })
    });
}

#[test]
fn a_prefetched_body_does_not_bypass_the_service_request_deadline() {
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    backend.set_nonblocking(true).unwrap();
    let parsed = configured(
        backend.local_addr().unwrap(),
        "proxy-timeout \"request-body\" \"100ms\"",
    );
    with_config(&parsed, |addr, _| {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(b"POST / HTTP/1.1\r\nHost: app.example\r\nContent-Length: 2\r\n")
            .unwrap();
        std::thread::sleep(Duration::from_millis(250));
        s.write_all(b"\r\nok").unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        assert!(out.starts_with(b"HTTP/1.1 408 "));
        assert!(backend.accept().is_err());
    });
}

#[test]
fn configured_sizes_can_exceed_old_defaults_without_dropping_the_new_ceiling() {
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let parsed = configured(
        backend.local_addr().unwrap(),
        "proxy-limit \"request-body\" \"2MiB\"\nproxy-limit \"response-body\" \"16MiB\"",
    );
    with_config(&parsed, |addr, _| {
        std::thread::scope(|scope| {
            let origin = scope.spawn(|| {
                let (mut socket, _) = backend.accept().unwrap();
                let req = read_request(&socket);
                let end = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                assert_eq!(req.len() - end, 1048577);
                assert!(req[end..].iter().all(|b| *b == b'x'));
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8388609\r\n\r\n")
                    .unwrap();
                socket.write_all(&vec![b'y'; 8388609]).unwrap();
            });
            let mut request =
                b"POST /api/ HTTP/1.1\r\nHost: app.example\r\nContent-Length: 1048577\r\n\r\n"
                    .to_vec();
            request.extend(vec![b'x'; 1048577]);
            let out = exchange(addr, &request);
            assert!(out.starts_with(b"HTTP/1.1 200 "));
            let end = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            assert_eq!(out.len() - end, 8388609);
            assert!(out[end..].iter().all(|b| *b == b'y'));
            origin.join().unwrap();
        })
    });
}

#[test]
fn independent_hosts_keep_independent_service_capacity() {
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let one = configured(a.local_addr().unwrap(), "proxy-limit \"connections\" \"1\"");
    let two = configured(b.local_addr().unwrap(), "proxy-limit \"connections\" \"1\"");
    let text = format!(
        "{}{}",
        one.compile().unwrap().source(),
        two.compile()
            .unwrap()
            .source()
            .replace("app.example", "other.example")
    );
    let parsed = ParsedConfig::parse(&text).unwrap();
    with_config(&parsed, |addr, _| {
        std::thread::scope(|scope| {
            let pending = scope.spawn(|| exchange(addr, GET));
            let (mut old, _) = a.accept().unwrap();
            read_request(&old);
            assert!(exchange(addr, GET).starts_with(b"HTTP/1.1 503 "));
            let other =
                scope.spawn(|| exchange(addr, b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n"));
            let (mut socket, _) = b.accept().unwrap();
            read_request(&socket);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB")
                .unwrap();
            drop(socket);
            assert!(other.join().unwrap().ends_with(b"B"));
            old.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA")
                .unwrap();
            drop(old);
            assert!(pending.join().unwrap().ends_with(b"A"));
        })
    });
}

fn bounded_accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let end = std::time::Instant::now() + Duration::from_secs(4);
    loop {
        match listener.accept() {
            Ok((s, _)) => return s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(std::time::Instant::now() < end, "missing upstream exchange");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("{e}"),
        }
    }
}
fn discovery_config(a: SocketAddr, b: SocketAddr, extra: &str) -> ParsedConfig {
    configured(
        a,
        &format!("proxy-resource \"/v1/rooms\" \"12\" \"{a},{b}\"\n{extra}"),
    )
}
#[test]
fn discovery_is_anonymous_and_mutation_is_sent_once_even_if_final_response_is_404() {
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = discovery_config(
        a.local_addr().unwrap(),
        b.local_addr().unwrap(),
        "header-prefix \"/v1\" \"x-robots-tag\" \"noindex\"",
    );
    with_config(&config, |addr, server| {
        std::thread::scope(|scope| {
            let client=scope.spawn(|| exchange(addr,format!("POST /v1/rooms/abcdef012345/join?private=yes HTTP/1.1\r\nHost: app.example:{}\r\nContent-Length: 4\r\nAuthorization: Bearer private\r\nCookie: session=private\r\n\r\nBODY",addr.port()).as_bytes()));
            let mut first = bounded_accept(&a);
            let probe = String::from_utf8(read_request(&first)).unwrap();
            assert!(probe.starts_with("GET /v1/rooms/abcdef012345 HTTP/1.1\r\n"));
            assert!(probe.contains(&format!("\r\nHost: app.example:{}\r\n", addr.port())));
            assert!(probe.contains(&format!(
                "\r\nX-Forwarded-Host: app.example:{}\r\n",
                addr.port()
            )));
            for secret in ["private", "BODY", "Authorization", "Cookie", "join"] {
                assert!(!probe.contains(secret));
            }
            // Reload while discovery is pending: the request must keep its captured routes.
            let replacement = ParsedConfig::parse(&format!(
                "site \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{}\"\n}}",
                a.local_addr().unwrap()
            ))
            .unwrap();
            server
                .reload(&replacement.compile().unwrap(), &AtomicBool::new(false))
                .unwrap();
            first
                .write_all(b"HTTP/1.1 404 Missing\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            drop(first);
            let mut second = bounded_accept(&b);
            assert_eq!(read_request(&second), probe.as_bytes());
            second
                .write_all(b"HTTP/1.1 401 Auth\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            drop(second);
            let mut original = bounded_accept(&b);
            let original_req = read_request(&original);
            assert!(original_req.starts_with(b"POST /v1/rooms/abcdef012345/join?private=yes "));
            assert!(original_req.ends_with(b"BODY"));
            assert!(
                String::from_utf8_lossy(&original_req)
                    .contains("authorization: Bearer private\r\n")
            );
            original
                .write_all(b"HTTP/1.1 404 Missing\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            drop(original);
            let response = String::from_utf8(client.join().unwrap()).unwrap();
            assert!(response.starts_with("HTTP/1.1 404 "));
            assert!(response.contains("x-robots-tag: noindex\r\n"));
            assert!(a.accept().is_err());
            assert!(b.accept().is_err());
        })
    });
}
#[test]
fn discovery_failure_and_absence_never_send_original_body() {
    for status in [404, 500, 429, 302] {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let b = TcpListener::bind("127.0.0.1:0").unwrap();
        b.set_nonblocking(true).unwrap();
        let config = discovery_config(a.local_addr().unwrap(), b.local_addr().unwrap(), "");
        with_config(&config, |addr, _| {
            std::thread::scope(|scope| {
                let c=scope.spawn(|| exchange(addr,b"POST /v1/rooms/abcdef012345/join HTTP/1.1\r\nHost: app.example\r\nContent-Length: 4\r\n\r\nBODY"));
                let mut first = bounded_accept(&a);
                assert!(!read_request(&first).ends_with(b"BODY"));
                first
                    .write_all(
                        format!("HTTP/1.1 {status} Probe\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                    )
                    .unwrap();
                drop(first);
                if status == 404 {
                    let mut second = bounded_accept(&b);
                    assert!(!read_request(&second).ends_with(b"BODY"));
                    second
                        .write_all(b"HTTP/1.1 404 Missing\r\nContent-Length: 0\r\n\r\n")
                        .unwrap();
                }
                let response = c.join().unwrap();
                assert!(response.starts_with(if status == 404 {
                    b"HTTP/1.1 404 "
                } else {
                    b"HTTP/1.1 502 "
                }));
                assert!(a.accept().is_err());
                assert!(b.accept().is_err());
            })
        });
    }
}
#[test]
fn fixed_route_and_query_headers_preserve_component_boundaries() {
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    a.set_nonblocking(true).unwrap();
    let config = configured(
        a.local_addr().unwrap(),
        &format!(
            "proxy-route \"/v1/feedback\" \"{}\"\nheader \"*\" \"x-robots-tag\" \"index\"\nheader-prefix \"/v1\" \"x-robots-tag\" \"prefix\"\nheader-query \"room\" \"x-robots-tag\" \"noindex\"",
            b.local_addr().unwrap()
        ),
    );
    with_config(&config, |addr, _| {
        std::thread::scope(|scope| {
            let c = scope.spawn(|| {
                exchange(
                    addr,
                    b"GET /v1/feedback?%72oom=one HTTP/1.1\r\nHost: app.example\r\n\r\n",
                )
            });
            let mut origin = bounded_accept(&b);
            read_request(&origin);
            origin
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Robots-Tag: upstream\r\n\r\n",
                )
                .unwrap();
            drop(origin);
            let out = String::from_utf8(c.join().unwrap()).unwrap();
            assert!(out.contains("x-robots-tag: noindex\r\n"));
            assert_eq!(out.matches("x-robots-tag:").count(), 1);
            assert!(a.accept().is_err());
            let c = scope.spawn(|| {
                exchange(
                    addr,
                    b"GET /v1/feedbacker?x=room HTTP/1.1\r\nHost: app.example\r\n\r\n",
                )
            });
            let mut origin = bounded_accept(&a);
            read_request(&origin);
            origin
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            drop(origin);
            let out = String::from_utf8(c.join().unwrap()).unwrap();
            assert!(out.contains("x-robots-tag: prefix\r\n"));
            assert!(b.accept().is_err());
        })
    });
}
