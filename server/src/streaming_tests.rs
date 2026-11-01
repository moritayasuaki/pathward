use super::*;
#[test]
fn handshake_known_answer_and_canonical_key() {
    assert!(key_valid(b"dGhlIHNhbXBsZSBub25jZQ=="));
    assert!(!key_valid(b"dGhlIHNhbXBsZSBub25jZR=="));
    assert_eq!(
        accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
}

use crate::Server;
use pathward_config::ParsedConfig;
use std::{
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
};
const WS: &[u8] = b"GET /chat HTTP/1.1\r\nHost: app.example\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat, binary\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";
const SWITCH: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: chat\r\n\r\n";
const GET: &[u8] = b"GET /events HTTP/1.1\r\nHost: app.example\r\nLast-Event-ID: 42\r\n\r\n";
fn configured(upstream: SocketAddr, options: &str) -> ParsedConfig {
    ParsedConfig::parse(&format!(
        "site \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{upstream}\"\n{options}\n}}\n"
    ))
    .unwrap()
}
fn listener() -> TcpListener {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    l
}
fn accept(l: &TcpListener) -> TcpStream {
    let start = Instant::now();
    loop {
        match l.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false).unwrap();
                s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                s.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
                return s;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                assert!(start.elapsed() < Duration::from_secs(3), "accept timeout");
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("{e}"),
        }
    }
}
fn head(s: &mut impl Read) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0];
    while !out.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).unwrap();
        out.push(b[0]);
        assert!(out.len() < 32768);
    }
    out
}
fn tail(s: &mut impl Read) -> Vec<u8> {
    let mut out = Vec::new();
    if let Err(e) = s.read_to_end(&mut out) {
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
            ),
            "{e}"
        );
    }
    out
}
fn connect(addr: SocketAddr, request: &[u8]) -> TcpStream {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(request).unwrap();
    s
}
fn with_server(
    upstream: SocketAddr,
    options: &str,
    test: impl FnOnce(SocketAddr, &Server, &AtomicBool),
) {
    let parsed = configured(upstream, options);
    let server = Server::new(&parsed.compile().unwrap()).unwrap();
    let l = listener();
    let addr = l.local_addr().unwrap();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let worker = scope.spawn(|| server.serve(l, &stop));
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(addr, &server, &stop)));
        stop.store(true, Ordering::Release);
        worker.join().unwrap().unwrap();
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    });
}
#[test]
fn websocket_validates_upgrade_and_relays_prefetched_frames_both_directions() {
    let upstream = listener();
    with_server(
        upstream.local_addr().unwrap(),
        "proxy-stream \"websocket\"",
        |addr, _, _| {
            thread::scope(|scope| {
                let upstream = &upstream;
                let origin = scope.spawn(move || {
                    let mut s = accept(upstream);
                    let request = String::from_utf8(head(&mut s)).unwrap();
                    assert!(request.contains("Connection: Upgrade\r\nUpgrade: websocket\r\n"));
                    assert!(request.contains("Sec-WebSocket-Protocol: chat, binary\r\n"));
                    assert!(!request.to_lowercase().contains("sec-websocket-extensions"));
                    let mut response = SWITCH.to_vec();
                    response.extend_from_slice(b"\x81\x02hi");
                    s.write_all(&response).unwrap();
                    let mut frame = [0; 8];
                    s.read_exact(&mut frame).unwrap();
                    assert_eq!(&frame, b"\x81\x82\0\0\0\0OK");
                    s.write_all(b"\x8a\x01x\x88\x02\x03\xe8").unwrap();
                });
                let mut client = connect(addr, WS);
                let h = String::from_utf8(head(&mut client)).unwrap();
                assert!(
                    h.starts_with("HTTP/1.1 101 ")
                        && h.contains("Sec-WebSocket-Protocol: chat\r\n")
                );
                assert!(
                    !h.contains("Content-Length:")
                        && !h.contains("Transfer-Encoding:")
                        && !h.contains("Connection: close")
                );
                let mut frame = [0; 4];
                client.read_exact(&mut frame).unwrap();
                assert_eq!(&frame, b"\x81\x02hi");
                client.write_all(b"\x81\x82\0\0\0\0OK").unwrap();
                assert_eq!(tail(&mut client), b"\x8a\x01x\x88\x02\x03\xe8");
                origin.join().unwrap();
            })
        },
    );
}
#[test]
fn invalid_or_disabled_websocket_requests_never_contact_upstream() {
    let upstream = listener();
    let base = std::str::from_utf8(WS).unwrap();
    let cases = [
        (base.to_owned(), "", 400),
        (
            base.replace("13\r\n", "12\r\n"),
            "proxy-stream \"websocket\"",
            400,
        ),
        (
            base.replace("ZQ==", "ZR=="),
            "proxy-stream \"websocket\"",
            400,
        ),
        (
            base.replace("GET ", "POST "),
            "proxy-stream \"websocket\"",
            400,
        ),
        (
            base.replace("\r\n\r\n", "\r\nOrigin: https://evil.example\r\n\r\n"),
            "proxy-stream \"websocket\"",
            403,
        ),
        (
            base.replace("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\nx"),
            "proxy-stream \"websocket\"",
            400,
        ),
        (
            format!("{base}early-frame"),
            "proxy-stream \"websocket\"",
            400,
        ),
        (
            base.replace("keep-alive, Upgrade", "Upgrade, Host"),
            "proxy-stream \"websocket\"",
            400,
        ),
        (
            base.to_owned(),
            "proxy-stream \"websocket\"\ndeny \"/chat\"",
            404,
        ),
    ];
    for (request, options, status) in cases {
        with_server(upstream.local_addr().unwrap(), options, |addr, _, _| {
            let mut client = connect(addr, request.as_bytes());
            assert!(
                tail(&mut client).starts_with(format!("HTTP/1.1 {status} ").as_bytes()),
                "{request}"
            );
            assert!(upstream.accept().is_err());
        });
    }
}
#[test]
fn upstream_cannot_forge_accept_extensions_subprotocol_or_framing() {
    let upstream = listener();
    let base = std::str::from_utf8(SWITCH).unwrap();
    let cases = [
        base.replace("s3pPL", "WRONG"),
        base.replace("chat\r\n", "unoffered\r\n"),
        base.replace("\r\n\r\n", "\r\nContent-Length: 0\r\n\r\n"),
        base.replace("\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n"),
        base.replace(
            "\r\n\r\n",
            "\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
        ),
        base.replace("Connection: Upgrade", "Connection: Upgrade, Authorization"),
    ];
    for response in cases {
        with_server(
            upstream.local_addr().unwrap(),
            "proxy-stream \"websocket\"",
            |addr, _, _| {
                thread::scope(|scope| {
                    let upstream = &upstream;
                    let origin = scope.spawn(move || {
                        let mut s = accept(upstream);
                        head(&mut s);
                        s.write_all(response.as_bytes()).unwrap();
                    });
                    let mut client = connect(addr, WS);
                    assert!(tail(&mut client).starts_with(b"HTTP/1.1 502 "));
                    origin.join().unwrap();
                })
            },
        );
    }
    with_server(
        upstream.local_addr().unwrap(),
        "proxy-stream \"websocket\"",
        |addr, _, _| {
            thread::scope(|scope| {
                let upstream = &upstream;
                let origin = scope.spawn(move || {
                    let mut s = accept(upstream);
                    head(&mut s);
                    s.write_all(SWITCH).unwrap();
                });
                let mut client = connect(addr, GET);
                assert!(tail(&mut client).starts_with(b"HTTP/1.1 502 "));
                origin.join().unwrap();
            })
        },
    );
}
#[test]
fn sse_arrives_before_upstream_finishes_and_preserves_reconnect_id() {
    let upstream = listener();
    with_server(
        upstream.local_addr().unwrap(),
        "proxy-stream \"sse\"",
        |addr, _, _| {
            thread::scope(|scope| {
                let (tx, rx) = mpsc::channel();
                let upstream = &upstream;
                let origin = scope.spawn(move || {
            let mut s = accept(upstream); let h = String::from_utf8(head(&mut s)).unwrap(); assert!(h.contains("last-event-id: 42\r\n"));
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n9\r\ndata: a\n\n\r\n").unwrap();
            rx.recv_timeout(Duration::from_secs(2)).unwrap();
            for b in b"9\r\ndata: b\n\n\r\n0\r\n\r\n" { s.write_all(&[*b]).unwrap(); }
        });
                let mut client = connect(addr, GET);
                let h = String::from_utf8(head(&mut client)).unwrap();
                assert!(h.contains("Transfer-Encoding: chunked\r\n"));
                assert!(!h.contains("Content-Length:"));
                let mut first = [0; 14];
                client.read_exact(&mut first).unwrap();
                assert_eq!(&first, b"9\r\ndata: a\n\n\r\n");
                tx.send(()).unwrap();
                let rest = tail(&mut client);
                assert!(rest.ends_with(b"0\r\n\r\n"));
                // Segmentation may change chunk boundaries; parse it before comparison.
                let mut d = Decoder::new(None, true, 1024);
                let mut pos = 0;
                let mut data = Vec::new();
                while pos < rest.len() {
                    let (n, bytes) = d.step(&rest[pos..]).unwrap();
                    data.extend_from_slice(bytes);
                    pos += n;
                }
                assert_eq!(data, b"data: b\n\n");
                assert!(d.done());
                origin.join().unwrap();
            })
        },
    );
}
#[test]
fn sse_caps_and_bad_chunks_close_without_a_second_http_response_or_success_terminator() {
    let upstream = listener();
    for ending in [
        b"3\r\nxyz\r\n0\r\n\r\n".as_slice(),
        b"X\r\n",
        b"0\r\nTrailer: no\r\n\r\n",
    ] {
        with_server(
            upstream.local_addr().unwrap(),
            "proxy-stream \"sse\"\nproxy-limit \"stream-download\" \"4B\"",
            |addr, _, _| {
                thread::scope(|scope| {
                    let (tx, rx) = mpsc::channel();
                    let upstream = &upstream;
                    let origin = scope.spawn(move || { let mut s = accept(upstream); head(&mut s); s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n").unwrap(); rx.recv_timeout(Duration::from_secs(2)).unwrap(); s.write_all(ending).unwrap(); });
                    let mut c = connect(addr, GET);
                    assert!(head(&mut c).starts_with(b"HTTP/1.1 200 "));
                    let mut first = [0; 7];
                    c.read_exact(&mut first).unwrap();
                    assert_eq!(&first, b"2\r\nok\r\n");
                    tx.send(()).unwrap();
                    let rest = tail(&mut c);
                    assert!(
                        !rest.ends_with(b"0\r\n\r\n") && !rest.windows(8).any(|w| w == b"HTTP/1.1")
                    );
                    origin.join().unwrap();
                })
            },
        );
    }
}
#[test]
fn sse_fixed_and_eof_bodies_stream_while_oversize_and_compression_fail_before_commit() {
    let upstream = listener();
    for (extra, body, status) in [
        ("Content-Length: 2\r\n", "ok", 200),
        ("", "ok", 200),
        ("Content-Length: 5\r\n", "", 502),
        ("Content-Encoding: gzip\r\n", "", 502),
    ] {
        with_server(
            upstream.local_addr().unwrap(),
            "proxy-stream \"sse\"\nproxy-limit \"stream-download\" \"4B\"",
            |addr, _, _| {
                thread::scope(|scope| {
                    let upstream = &upstream;
                    let origin=scope.spawn(||{let mut s=accept(upstream);head(&mut s);write!(s,"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n{extra}\r\n{body}").unwrap();});
                    let mut c = connect(addr, GET);
                    let r = tail(&mut c);
                    assert!(r.starts_with(format!("HTTP/1.1 {status} ").as_bytes()));
                    if status == 200 {
                        assert!(r.ends_with(b"2\r\nok\r\n0\r\n\r\n"));
                    }
                    origin.join().unwrap();
                })
            },
        );
    }
}
#[test]
fn idle_total_and_shutdown_bound_long_lived_connections() {
    let upstream = listener();
    for (heartbeat, stop_now) in [(false, false), (true, false), (false, true)] {
        with_server(
            upstream.local_addr().unwrap(),
            "proxy-stream \"sse\"\nproxy-timeout \"stream-idle\" \"200ms\"\nproxy-timeout \"stream-total\" \"500ms\"",
            |addr, server, _| {
                thread::scope(|scope| {
                    let (tx, rx) = mpsc::channel();
                    let upstream = &upstream;
                    let origin = scope.spawn(move || {
                        let mut s = accept(upstream);
                        head(&mut s);
                        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
                            .unwrap();
                        while matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                            if heartbeat && s.write_all(b": beat\n\n").is_err() {
                                break;
                            }
                            thread::sleep(Duration::from_millis(40));
                        }
                    });
                    let start = Instant::now();
                    let mut c = connect(addr, GET);
                    head(&mut c);
                    if stop_now {
                        server.begin_shutdown();
                    }
                    let _ = tail(&mut c);
                    assert!(start.elapsed() < Duration::from_secs(2));
                    if heartbeat {
                        assert!(start.elapsed() >= Duration::from_millis(400));
                    }
                    tx.send(()).ok();
                    origin.join().unwrap();
                })
            },
        );
    }
}
#[test]
fn stream_quota_is_shared_and_released_on_drop() {
    let q = Quota::default();
    let a = q.acquire(false).unwrap();
    let b = q.acquire(false).unwrap();
    assert!(q.acquire(false).is_none());
    drop(a);
    let c = q.acquire(false).unwrap();
    assert!(q.acquire(true).is_none());
    drop((b, c));
    assert!(q.acquire(false).is_some());
}
#[test]
fn websocket_reload_keeps_service_slot_and_shutdown_releases_it() {
    let upstream = listener();
    let options = "proxy-stream \"websocket\"\nproxy-limit \"connections\" \"1\"";
    with_server(
        upstream.local_addr().unwrap(),
        options,
        |addr, server, stop| {
            thread::scope(|scope| {
                let (tx, rx) = mpsc::channel();
                let upstream = &upstream;
                let origin = scope.spawn(move || {
                    let mut s = accept(upstream);
                    head(&mut s);
                    s.write_all(SWITCH).unwrap();
                    rx.recv_timeout(Duration::from_secs(2)).unwrap();
                });
                let mut c = connect(addr, WS);
                assert!(head(&mut c).starts_with(b"HTTP/1.1 101 "));
                let new = configured(
                    upstream.local_addr().unwrap(),
                    "proxy-limit \"connections\" \"1\"",
                );
                server.reload(&new.compile().unwrap(), stop).unwrap();
                let mut other = connect(addr, GET);
                assert!(tail(&mut other).starts_with(b"HTTP/1.1 503 "));
                assert!(upstream.accept().is_err());
                server.begin_shutdown();
                assert!(tail(&mut c).is_empty());
                tx.send(()).unwrap();
                origin.join().unwrap();
            })
        },
    );
}

#[test]
fn tls_websocket_keeps_partial_records_and_duplex_bytes_in_one_owner() {
    use crate::tls::{Certificate, Identity, TlsServer};
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName,
    };
    use std::sync::Arc;
    let upstream = listener();
    let parsed = configured(upstream.local_addr().unwrap(), "proxy-stream \"websocket\"");
    let server = Server::new(&parsed.compile().unwrap()).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["app.example".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pem = format!("{}{}", key.serialize_pem(), cert.pem());
    let identity = Arc::new(Identity::new(
        vec!["app.example".into()],
        Some(Certificate::parse(pem.as_bytes(), &["app.example".into()]).unwrap()),
    ));
    let tls = TlsServer::new(identity).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let l = listener();
    let addr = l.local_addr().unwrap();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let serving = scope.spawn(|| server.serve_tls(l, &stop, &tls));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            thread::scope(|scope| {
                let upstream = &upstream;
                let origin = scope.spawn(|| {
                    let mut s = accept(upstream);
                    let h = String::from_utf8(head(&mut s)).unwrap();
                    assert!(
                        h.contains("x-forwarded-proto: https")
                            || h.contains("X-Forwarded-Proto: https")
                    );
                    assert!(h.contains("origin: https://app.example"));
                    s.write_all(SWITCH).unwrap();
                    let mut upload = vec![0; 262144];
                    s.read_exact(&mut upload).unwrap();
                    assert!(upload.iter().all(|b| *b == 0x5a));
                    s.write_all(&vec![0xa5; 262144]).unwrap();
                });
                let socket = TcpStream::connect(addr).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let conn = ClientConnection::new(
                    Arc::new(config),
                    ServerName::try_from("app.example").unwrap(),
                )
                .unwrap();
                let mut c = StreamOwned::new(conn, socket);
                let request = std::str::from_utf8(WS)
                    .unwrap()
                    .replace("\r\n\r\n", "\r\nOrigin: https://app.example\r\n\r\n");
                c.write_all(request.as_bytes()).unwrap();
                assert!(head(&mut c).starts_with(b"HTTP/1.1 101 "));
                c.write_all(&vec![0x5a; 262144]).unwrap();
                c.flush().unwrap();
                let mut download = vec![0; 262144];
                c.read_exact(&mut download).unwrap();
                assert!(download.iter().all(|b| *b == 0xa5));
                origin.join().unwrap();
            })
        }));
        stop.store(true, Ordering::Release);
        serving.join().unwrap().unwrap();
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    });
}
#[test]
fn websocket_cumulative_upload_limit_is_enforced_before_forwarding_extra_bytes() {
    let upstream = listener();
    with_server(
        upstream.local_addr().unwrap(),
        "proxy-stream \"websocket\"\nproxy-limit \"stream-upload\" \"4B\"",
        |addr, _, _| {
            thread::scope(|scope| {
                let (tx, rx) = mpsc::channel();
                let upstream = &upstream;
                let origin = scope.spawn(move || {
                    let mut s = accept(upstream);
                    head(&mut s);
                    s.write_all(SWITCH).unwrap();
                    let mut first = [0; 4];
                    s.read_exact(&mut first).unwrap();
                    assert_eq!(&first, b"1234");
                    tx.send(()).unwrap();
                    let mut extra = [0];
                    assert_eq!(s.read(&mut extra).unwrap(), 0);
                });
                let mut c = connect(addr, WS);
                head(&mut c);
                c.write_all(b"1234").unwrap();
                rx.recv_timeout(Duration::from_secs(2)).unwrap();
                c.write_all(b"5").unwrap();
                assert!(tail(&mut c).is_empty());
                origin.join().unwrap();
            })
        },
    );
}
#[test]
fn pending_nonblocking_writes_and_flushes_never_duplicate_plaintext() {
    struct Sink {
        out: Vec<u8>,
        blocked: bool,
        flush_blocked: bool,
    }
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.blocked = !self.blocked;
            if self.blocked {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let n = b.len().min(3);
            self.out.extend_from_slice(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flush_blocked = !self.flush_blocked;
            if self.flush_blocked {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                Ok(())
            }
        }
    }
    let mut p = Pending {
        bytes: b"one copy only".to_vec(),
        offset: 0,
    };
    let mut sink = Sink {
        out: Vec::new(),
        blocked: false,
        flush_blocked: false,
    };
    for _ in 0..20 {
        p.write(&mut sink).unwrap();
        if p.empty() {
            break;
        }
    }
    assert!(p.empty());
    assert_eq!(sink.out, b"one copy only");
}

#[test]
fn downstream_backpressure_cannot_extend_the_idle_deadline() {
    struct Blocked;
    impl Read for Blocked {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
    impl Write for Blocked {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
    impl Transport for Blocked {
        fn nonblocking(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn deadline(&mut self, _: Instant) -> io::Result<()> {
            Ok(())
        }
        fn local_port(&self) -> io::Result<u16> {
            Ok(80)
        }
    }
    let l = listener();
    let socket = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let _peer = accept(&l);
    socket.set_nonblocking(true).unwrap();
    let limits = ProxyLimits {
        stream_idle_ms: 100,
        stream_total_ms: 1000,
        ..ProxyLimits::default()
    };
    let start = Instant::now();
    let error = relay(socket, vec![0; 16384], &mut Blocked, limits, start, &|| {
        false
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn occupied_stream_quota_rejects_before_upgrade_and_survives_reload() {
    struct Exchange {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Exchange {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Exchange {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.output.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Transport for Exchange {
        fn deadline(&mut self, _: Instant) -> io::Result<()> {
            Ok(())
        }
        fn local_port(&self) -> io::Result<u16> {
            Ok(80)
        }
    }
    let upstream = listener();
    let parsed = configured(upstream.local_addr().unwrap(), "proxy-stream \"websocket\"");
    let server = Server::new(&parsed.compile().unwrap()).unwrap();
    let a = server.stream_quota.acquire(false).unwrap();
    let b = server.stream_quota.acquire(false).unwrap();
    server
        .reload(&parsed.compile().unwrap(), &AtomicBool::new(false))
        .unwrap();
    thread::scope(|scope| {
        let origin = scope.spawn(|| {
            let mut s = accept(&upstream);
            head(&mut s);
            s.write_all(SWITCH).unwrap();
            let mut byte = [0];
            assert_eq!(s.read(&mut byte).unwrap(), 0);
        });
        let snapshot = server.state.read().unwrap().snapshot.clone();
        let mut client = Exchange {
            input: io::Cursor::new(WS.to_vec()),
            output: Vec::new(),
        };
        let result = Server::respond(
            &snapshot,
            &mut client,
            Instant::now(),
            None,
            false,
            &server.stream_quota,
            &|| false,
        )
        .unwrap();
        assert_eq!(result.0, 503);
        assert!(client.output.starts_with(b"HTTP/1.1 503 "));
        assert!(!client.output.windows(3).any(|s| s == b"101"));
        origin.join().unwrap();
    });
    drop((a, b));
    assert!(server.stream_quota.acquire(false).is_some());
}
#[test]
fn rejected_websocket_handshake_is_an_ordinary_bounded_http_response() {
    let upstream = listener();
    with_server(
        upstream.local_addr().unwrap(),
        "proxy-stream \"websocket\"",
        |addr, _, _| {
            thread::scope(|scope| {
                let origin = scope.spawn(|| {
                    let mut s = accept(&upstream);
                    head(&mut s);
                    s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nNO")
                        .unwrap();
                });
                let mut c = connect(addr, WS);
                let response = tail(&mut c);
                assert!(response.starts_with(b"HTTP/1.1 403 "));
                assert!(response.ends_with(b"NO"));
                assert!(!response.windows(8).any(|b| b == b"Upgrade:"));
                origin.join().unwrap();
            })
        },
    );
}
