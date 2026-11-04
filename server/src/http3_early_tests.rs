//! Real TLS resumption test: withhold the client's Finished/1-RTT packets.
use super::*;
use crate::http3::tests::{accept, configs};
use std::{
    io::Write,
    net::{SocketAddr, TcpListener},
    sync::atomic::AtomicUsize,
};

// QUIC v1 long-header lengths are public; header protection leaves packet type
// bits intact. Hold a coalesced datagram if any packet needs confirmation.
fn packet_types(mut b: &[u8]) -> (bool, bool) {
    fn var(b: &mut &[u8]) -> Option<usize> {
        let n = 1usize << (b.first()? >> 6);
        let raw = b.get(..n)?;
        let mut v = usize::from(raw[0] & 63);
        for x in &raw[1..] {
            v = v.checked_mul(256)?.checked_add(usize::from(*x))?;
        }
        *b = &b[n..];
        Some(v)
    }
    let mut early = false;
    while !b.is_empty() {
        if b[0] & 128 == 0 {
            return (true, early);
        }
        let kind = (b[0] >> 4) & 3;
        if kind == 2 || kind == 3 {
            return (true, early);
        }
        early |= kind == 1;
        let step = || -> Option<&[u8]> {
            let mut r = b.get(5..)?;
            r = r.get(1 + usize::from(*r.first()?)..)?;
            r = r.get(1 + usize::from(*r.first()?)..)?;
            if kind == 0 {
                let n = var(&mut r)?;
                r = r.get(n..)?;
            }
            let n = var(&mut r)?;
            r.get(n..)
        };
        let Some(next) = step() else {
            return (true, early);
        };
        b = next;
    }
    (false, early)
}
struct Gate {
    addr: SocketAddr,
    hold: Arc<AtomicBool>,
    held: Arc<AtomicUsize>,
    repeated: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Gate {
    fn new(server: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let hold = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let held = Arc::new(AtomicUsize::new(0));
        let repeated = Arc::new(AtomicUsize::new(0));
        let (h, s, n, r) = (hold.clone(), stop.clone(), held.clone(), repeated.clone());
        let worker = std::thread::spawn(move || {
            let mut client = None;
            let mut pending: Vec<Vec<u8>> = Vec::new();
            let mut buf = [0; 65536];
            while !s.load(Ordering::Acquire) {
                if !h.load(Ordering::Acquire) {
                    for bytes in pending.drain(..) {
                        socket.send_to(&bytes, server).unwrap();
                    }
                }
                match socket.recv_from(&mut buf) {
                    Ok((len, from)) if from == server => {
                        if let Some(to) = client {
                            socket.send_to(&buf[..len], to).unwrap();
                        }
                    }
                    Ok((len, from)) => {
                        client = Some(from);
                        let (confirmed, early) = packet_types(&buf[..len]);
                        if h.load(Ordering::Acquire) && confirmed {
                            assert!(pending.len() < 128, "bounded packet gate");
                            pending.push(buf[..len].to_vec());
                            n.fetch_add(1, Ordering::Relaxed);
                        } else {
                            socket.send_to(&buf[..len], server).unwrap();
                            // A duplicated captured 0-RTT datagram must not execute twice.
                            if h.load(Ordering::Acquire) && early {
                                socket.send_to(&buf[..len], server).unwrap();
                                r.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(e) => panic!("packet gate: {e}"),
                }
            }
        });
        Self {
            addr,
            hold,
            held,
            repeated,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn resumption_before_finished_denies_proxy_and_rechecks_publication() {
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    #[cfg(target_os = "linux")]
    let tree = {
        struct Tree(std::path::PathBuf);
        impl Drop for Tree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let p = std::env::temp_dir().join(format!(
            "pathward-early-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&p).unwrap();
        std::fs::write(p.join("index.txt"), b"PUBLIC EARLY").unwrap();
        Tree(p)
    };
    #[cfg(target_os = "linux")]
    let publication = format!(
        "root \"{}\"\npublish \"/\" \"index.txt\"\n",
        tree.0.display()
    );
    #[cfg(not(target_os = "linux"))]
    let publication = String::new();
    let source = format!(
        "capacity \"shared-nat\"\nsite \"app.example\" {{\ntls \"auto\"\n{publication}reverse-proxy \"{}\"\nproxy-path \"/api\"\n}}",
        backend.local_addr().unwrap()
    );
    let parsed = pathward_config::ParsedConfig::parse(&source).unwrap();
    let server = Server::new(&parsed.compile().unwrap()).unwrap();
    let (identity, client) = configs();
    let tls = tls::TlsServer::new(identity).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).unwrap();
    let gate = Gate::new(addr);
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let serving = scope.spawn(|| server.serve_tls_http3(tcp, None, udp, &stop, &tls));
        let origin = scope.spawn(|| {
            for path in [
                b"GET /api/seed ".as_slice(),
                b"POST /api/create ".as_slice(),
            ] {
                let mut s = accept(&backend);
                let head =
                    http::read_head(&mut s, Instant::now() + Duration::from_secs(3)).unwrap();
                assert!(
                    head.starts_with(path),
                    "unexpected upstream side effect: {:?}",
                    head
                );
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
            }
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    multiplex::bounded(Instant::now() + Duration::from_secs(12), async {
                        let mut endpoint =
                            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
                        endpoint.set_default_client_config(client);
                        let first = endpoint
                            .connect(gate.addr, "app.example")
                            .unwrap()
                            .await
                            .unwrap();
                        let (mut driver, mut client) =
                            h3::client::new(h3_quinn::Connection::new(first.clone()))
                                .await
                                .unwrap();
                        futures_lite::future::race(
                            async { panic!("seed driver: {}", driver.wait_idle().await) },
                            async {
                                let mut s = client
                                    .send_request(
                                        http_types::Request::builder()
                                            .uri("https://app.example/api/seed")
                                            .body(())
                                            .unwrap(),
                                    )
                                    .await
                                    .unwrap();
                                s.finish().await.unwrap();
                                assert_eq!(s.recv_response().await.unwrap().status(), 200);
                                tokio::time::sleep(Duration::from_millis(150)).await;
                            },
                        )
                        .await;
                        first.close(0u32.into(), b"resume");
                        drop(client);
                        drop(driver);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        gate.hold.store(true, Ordering::Release);
                        let (resumed, accepted) = endpoint
                            .connect(gate.addr, "app.example")
                            .unwrap()
                            .into_0rtt()
                            .expect("server supplied a resumable early-data ticket");
                        let (mut driver, mut client) =
                            h3::client::new(h3_quinn::Connection::new(resumed.clone()))
                                .await
                                .unwrap();
                        futures_lite::future::race(
                            async { panic!("early driver: {}", driver.wait_idle().await) },
                            async {
                                // Queue every early request before polling the endpoint driver:
                                // once ServerFinished arrives Quinn switches new sends to 1-RTT.
                                let mut cases =
                                    vec![("POST", "/api/create", 425), ("GET", "/api/create", 425)];
                                if cfg!(target_os = "linux") {
                                    cases.push(("GET", "/", 200));
                                    cases.push(("GET", "/?secret=value", 425));
                                }
                                let mut requests = Vec::new();
                                for (method, path, status) in cases {
                                    let mut s = client
                                        .send_request(
                                            http_types::Request::builder()
                                                .method(method)
                                                .uri(format!("https://app.example{path}"))
                                                .body(())
                                                .unwrap(),
                                        )
                                        .await
                                        .unwrap();
                                    s.finish().await.unwrap();
                                    requests.push((s, status));
                                }
                                for (mut s, status) in requests {
                                    assert_eq!(
                                        s.recv_response().await.unwrap().status(),
                                        status,
                                        "early publication gate"
                                    );
                                    let mut body = Vec::new();
                                    while let Some(mut b) = s.recv_data().await.unwrap() {
                                        body.extend_from_slice(&b.copy_to_bytes(b.remaining()));
                                    }
                                    if status == 200 {
                                        assert_eq!(body, b"PUBLIC EARLY");
                                    }
                                }
                                #[cfg(target_os = "linux")]
                                {
                                    let revoked = source.replace(
                                        "publish \"/\" \"index.txt\"\n",
                                        "publish \"/replacement\" \"index.txt\"\n",
                                    );
                                    let p = pathward_config::ParsedConfig::parse(&revoked).unwrap();
                                    server.reload(&p.compile().unwrap(), &stop).unwrap();
                                }
                                assert!(
                                    gate.held.load(Ordering::Relaxed) > 0,
                                    "client Finished was withheld"
                                );
                                assert!(
                                    gate.repeated.load(Ordering::Relaxed) > 0,
                                    "sent and duplicated actual 0-RTT packets"
                                );
                                gate.hold.store(false, Ordering::Release);
                                assert!(accepted.await, "TLS accepted early data");
                                tokio::time::sleep(Duration::from_millis(40)).await;
                                #[cfg(target_os = "linux")]
                                {
                                    let mut s = client
                                        .send_request(
                                            http_types::Request::builder()
                                                .uri("https://app.example/")
                                                .body(())
                                                .unwrap(),
                                        )
                                        .await
                                        .unwrap();
                                    s.finish().await.unwrap();
                                    assert_eq!(
                                        s.recv_response().await.unwrap().status(),
                                        404,
                                        "reused connection sees revoked publication"
                                    );
                                }
                                let mut s = client
                                    .send_request(
                                        http_types::Request::builder()
                                            .method("POST")
                                            .uri("https://app.example/api/create")
                                            .body(())
                                            .unwrap(),
                                    )
                                    .await
                                    .unwrap();
                                s.finish().await.unwrap();
                                assert_eq!(
                                    s.recv_response().await.unwrap().status(),
                                    200,
                                    "confirmed retry runs once"
                                );
                            },
                        )
                        .await;
                        resumed.close(0u32.into(), b"complete");
                        endpoint.close(0u32.into(), b"complete");
                    })
                    .await
                    .unwrap();
                });
        }));
        gate.hold.store(false, Ordering::Release);
        stop.store(true, Ordering::Release);
        serving.join().unwrap().unwrap();
        origin.join().unwrap();
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        backend.set_nonblocking(true).unwrap();
        assert!(backend.accept().is_err());
        #[cfg(target_os = "linux")]
        {
            assert_eq!(server.observe.early_static.load(Ordering::Relaxed), 1);
            assert_eq!(server.observe.early_rejected.load(Ordering::Relaxed), 3);
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(server.observe.early_rejected.load(Ordering::Relaxed), 2);
    });
}
