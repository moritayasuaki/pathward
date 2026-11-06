//! Explicit HTTP/3 transport, QUIC migration and replay-safe early responses.
use crate::{Server, admission, async_http, delivery, http, multiplex, tls};
use bytes::{Buf, Bytes};
use std::{
    cell::Cell,
    future::Future,
    io,
    net::UdpSocket,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
fn error<E>(_: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "HTTP/3 transport")
}
type Stream = h3::server::RequestStream<crate::quic_bounds::Bidi, Bytes>;
type Resolver = h3::server::RequestResolver<crate::quic_bounds::Connection, Bytes>;
#[allow(clippy::too_many_arguments)]
async fn exchange(
    server: &Server,
    resolver: Resolver,
    sni: &str,
    port: u16,
    peer: std::net::IpAddr,
    budget: &delivery::Budget,
    shutdown: &AtomicBool,
    waiting: multiplex::Pending<'_>,
    admission: &Arc<admission::Admission>,
    confirmed: &Cell<bool>,
    wire: &crate::quic_bounds::Budgets,
) {
    let began = Instant::now();
    let mut generation = server.generation();
    let result = async {
        let (req, mut stream) =
            multiplex::bounded(began + Duration::from_secs(5), resolver.resolve_request())
                .await?
                .map_err(error)?;
        let early = !confirmed.get();
        let marked = req.headers().contains_key("early-data");
        let _permit = match multiplex::admit(
            admission,
            peer,
            shutdown,
            began + delivery::QUEUE_BUDGET,
            waiting,
        )
        .await
        {
            Ok(p) => p,
            Err(reason) => {
                server.observe.admission_rejected(reason);
                stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
                return Err(io::ErrorKind::WouldBlock.into());
            }
        };
        let stream_id = stream.id();
        let result = async {
            let request = match multiplex::request_head(server, req.into_parts().0, sni, port) {
                Ok(r) => r,
                Err(status) => return send(multiplex::rejection(status), &mut stream).await,
            };
            generation = request.generation;
            if !wire.body(stream_id, request.length.unwrap_or(request.limit)) {
                return send(multiplex::rejection(431), &mut stream).await;
            }
            let Some(_input) = multiplex::input_lease(
                budget,
                peer,
                3 * request.length.unwrap_or(request.limit) + delivery::HEAD_BYTES as u64,
                shutdown,
                began + delivery::QUEUE_BUDGET,
            )
            .await
            else {
                return send(multiplex::rejection(503), &mut stream).await;
            };
            let mut body = Vec::with_capacity(request.length.unwrap_or(request.limit) as usize);
            let deadline = began + Duration::from_millis(request.body_ms);
            loop {
                let next = multiplex::bounded(deadline, stream.recv_data())
                    .await?
                    .map_err(error)?;
                let Some(mut chunk) = next else { break };
                if !pathward::routing::chunk_fits(
                    body.len() as u64,
                    chunk.remaining() as u64,
                    request.length.unwrap_or(request.limit),
                ) {
                    return send(multiplex::rejection(413), &mut stream).await;
                }
                body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            if multiplex::bounded(deadline, stream.recv_trailers())
                .await?
                .map_err(error)?
                .is_some()
                || request.length.is_some_and(|n| n != body.len() as u64)
            {
                return send(multiplex::rejection(400), &mut stream).await;
            }
            let response = multiplex::respond(
                server, request, body, sni, port, peer, budget, shutdown, early,
            )
            .await?;
            send(response, &mut stream).await
        }
        .await;
        wire.release(stream_id);
        if (early || marked)
            && let Ok((status, _)) = result
        {
            if status == 425 {
                server
                    .observe
                    .early_rejected
                    .fetch_add(1, Ordering::Relaxed);
            } else if matches!(status, 200 | 206 | 304) {
                server.observe.early_static.fetch_add(1, Ordering::Relaxed);
            }
        }
        if result.is_err() {
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        }
        result
    }
    .await;
    server.observe.request(generation, began.elapsed(), &result);
}
async fn send(mut response: multiplex::Response, stream: &mut Stream) -> io::Result<(u16, u64)> {
    multiplex::bounded(
        Instant::now() + Duration::from_secs(5),
        stream.send_response(response.head),
    )
    .await?
    .map_err(error)?;
    let mut total = 0;
    while let Some(bytes) = response.body.next().await? {
        let count = bytes.len();
        let deadline = response
            .body
            .deadline()
            .min(Instant::now() + Duration::from_secs(5));
        multiplex::bounded(deadline, stream.send_data(Bytes::from(bytes)))
            .await?
            .map_err(error)?;
        total += count as u64;
        response.body.sent();
    }
    multiplex::bounded(Instant::now() + Duration::from_secs(5), stream.finish())
        .await?
        .map_err(error)?;
    Ok((response.status, total))
}
#[allow(clippy::too_many_arguments)]
async fn connection(
    server: &Server,
    incoming: quinn::Incoming,
    port: u16,
    tls: &tls::TlsServer,
    admission: &Arc<admission::Admission>,
    budget: &delivery::Budget,
    shutdown: &AtomicBool,
    permit: admission::Permit,
) -> io::Result<()> {
    let accepted = Instant::now();
    let _active = server.observe.connection();
    // Admission ownership is immutable across migration: changing UDP paths
    // cannot reset rate credits or shed leases charged to the initial peer.
    let peer = permit.peer();
    let mut connecting = incoming.accept().map_err(error)?;
    let data = multiplex::bounded(
        accepted + tls::HANDSHAKE_BUDGET,
        connecting.handshake_data(),
    )
    .await?
    .map_err(error)?;
    let data = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(error)?;
    let sni = data.server_name.ok_or_else(|| error(()))?;
    if data.protocol.as_deref() != Some(b"h3") || !tls.current_identity(&sni) {
        return Err(error(()));
    }
    let (quic, mut confirmation) = connecting.into_0rtt().map_err(error)?;
    let confirmed = Cell::new(false);
    let mut address = quic.remote_address();
    let wire = crate::quic_bounds::Budgets::default();
    let mut h3 = multiplex::bounded(
        accepted + tls::HANDSHAKE_BUDGET,
        h3::server::builder()
            .max_field_section_size(http::MAX_HEAD_BYTES as u64)
            .send_grease(false)
            .enable_extended_connect(false)
            .enable_datagram(false)
            .enable_webtransport(false)
            .build(crate::quic_bounds::Connection::new(
                quic.clone(),
                wire.clone(),
            )),
    )
    .await?
    .map_err(error)?;
    let mut tasks: Vec<Pin<Box<dyn Future<Output = ()> + '_>>> = Vec::new();
    let mut seen = 0;
    let mut retirement = multiplex::Retirement::default();
    let mut idle = Instant::now();
    loop {
        if !confirmed.get() {
            if futures_lite::future::poll_once(&mut confirmation)
                .await
                .is_some()
            {
                // Quinn 0.11.12 forwards accepted_0rtt (a client-only flag),
                // which is false for successful server handshakes. Completion
                // is the signal; termination records close_reason before it.
                if quic.close_reason().is_some() {
                    return Err(error(()));
                }
                confirmed.set(true);
            }
            if !confirmed.get() && accepted.elapsed() >= tls::HANDSHAKE_BUDGET {
                return Err(io::ErrorKind::TimedOut.into());
            }
        }
        if quic.remote_address() != address {
            address = quic.remote_address();
            server
                .observe
                .quic_migrations
                .fetch_add(1, Ordering::Relaxed);
        }
        if quic.close_reason().is_some() {
            return Ok(());
        }
        if accepted.elapsed() >= multiplex::CONNECTION_CEILING {
            quic.close(0u32.into(), b"lifetime");
            return Err(io::ErrorKind::TimedOut.into());
        }
        let stopping =
            shutdown.load(Ordering::Acquire) || server.is_draining() || !tls.current_identity(&sni);
        if stopping {
            retirement.stopping();
        }
        if !retirement.retiring()
            && (stopping
                || seen >= 100
                || accepted.elapsed() >= Duration::from_secs(120)
                || (tasks.is_empty() && idle.elapsed() >= Duration::from_secs(5)))
        {
            let _ =
                multiplex::bounded(Instant::now() + Duration::from_secs(1), h3.shutdown(0)).await;
            retirement.begin();
        }
        if retirement.close(tasks.len(), false, idle) {
            quic.close(0u32.into(), b"draining");
            return Ok(());
        }
        match futures_lite::future::poll_once(h3.accept()).await {
            Some(Ok(Some(resolver))) => {
                let slot = pathward::delivery::multiplex_slot(
                    tasks.len() as u64,
                    seen,
                    accepted.elapsed().as_millis().min(u64::MAX as u128) as u64,
                    retirement.retiring(),
                );
                seen += 1;
                idle = Instant::now();
                let p = if slot {
                    multiplex::pending(server)
                } else {
                    None
                };
                match p {
                    Some(p) => tasks.push(Box::pin(exchange(
                        server, resolver, &sni, port, peer, budget, shutdown, p, admission,
                        &confirmed, &wire,
                    ))),
                    None => {
                        server
                            .observe
                            .admission_rejected(admission::Rejection::GlobalActive);
                        quic.close(
                            h3::error::Code::H3_EXCESSIVE_LOAD
                                .value()
                                .try_into()
                                .map_err(error)?,
                            b"capacity",
                        );
                        return Ok(());
                    }
                }
            }
            Some(Ok(None)) => return Ok(()),
            Some(Err(e)) => return Err(error(e)),
            None => {}
        }
        let mut i = 0;
        while i < tasks.len() {
            if futures_lite::future::poll_once(tasks[i].as_mut())
                .await
                .is_some()
            {
                drop(tasks.swap_remove(i));
                idle = Instant::now();
            } else {
                i += 1;
            }
        }
        async_http::pause().await;
    }
}
pub async fn serve(
    server: &Server,
    socket: UdpSocket,
    tls: &tls::TlsServer,
    admission: &Arc<admission::Admission>,
    budget: &delivery::Budget,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let port = socket.local_addr()?.port();
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(tls.quic_config()?),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    let mut tasks: Vec<Pin<Box<dyn Future<Output = ()> + '_>>> = Vec::new();
    let mut drain = None;
    loop {
        if shutdown.load(Ordering::Acquire) && drain.is_none() {
            drain = Some(Instant::now() + Duration::from_secs(5));
        }
        if drain.is_some_and(|d| Instant::now() >= d) || (drain.is_some() && tasks.is_empty()) {
            break;
        }
        if drain.is_none()
            && let Some(Some(incoming)) = futures_lite::future::poll_once(endpoint.accept()).await
        {
            if !incoming.remote_address_validated() {
                let _ = incoming.retry();
                continue;
            }
            match admission.acquire(incoming.remote_address().ip(), false) {
                Ok(permit) => {
                    server.observe.accepted.fetch_add(1, Ordering::Relaxed);
                    tasks.push(Box::pin(async {
                        if let Err(e) = connection(
                            server, incoming, port, tls, admission, budget, shutdown, permit,
                        )
                        .await
                        {
                            server
                                .observe
                                .request(server.generation(), Duration::ZERO, &Err(e));
                        }
                    }));
                }
                Err(reason) => {
                    server.observe.admission_rejected(reason);
                    incoming.refuse();
                }
            }
        }
        let mut i = 0;
        while i < tasks.len() {
            if futures_lite::future::poll_once(tasks[i].as_mut())
                .await
                .is_some()
            {
                drop(tasks.swap_remove(i));
            } else {
                i += 1;
            }
        }
        async_http::pause().await;
    }
    endpoint.close(0u32.into(), b"shutdown");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        net::{TcpListener, TcpStream},
    };
    pub(super) fn configs() -> (Arc<tls::Identity>, quinn::ClientConfig) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["app.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let bytes = format!("{}{}", key.serialize_pem(), cert.pem());
        let identity = Arc::new(tls::Identity::new(
            vec!["app.example".into()],
            Some(tls::Certificate::parse(bytes.as_bytes(), &["app.example".into()]).unwrap()),
        ));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client.alpn_protocols = vec![b"h3".to_vec()];
        client.enable_early_data = true;
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(client).unwrap();
        (identity, quinn::ClientConfig::new(Arc::new(quic)))
    }
    pub(super) fn accept(listener: &TcpListener) -> TcpStream {
        listener.set_nonblocking(true).unwrap();
        let until = Instant::now() + Duration::from_secs(8);
        loop {
            match listener.accept() {
                Ok((s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    return s;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < until, "missing backend request");
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("{e}"),
            }
        }
    }
    #[test]
    fn real_quic_migration_zstd_and_early_proxy_rejection() {
        let backend = TcpListener::bind("127.0.0.1:0").unwrap();
        let config=pathward_config::ParsedConfig::parse(&format!("capacity \"shared-nat\"\nsite \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{}\"\nencode \"gzip,zstd\"\n}}",backend.local_addr().unwrap())).unwrap();
        let server = Server::new(&config.compile().unwrap()).unwrap();
        let (identity, client) = configs();
        let tls = tls::TlsServer::new(identity).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(address).unwrap();
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let serving = scope.spawn(|| server.serve_tls_http3(tcp, None, udp, &stop, &tls));
            let origin=scope.spawn(||{for _ in 0..2 {let mut s=accept(&backend);let head=http::read_head(&mut s,Instant::now()+Duration::from_secs(3)).unwrap();assert!(String::from_utf8_lossy(&head).contains("X-Forwarded-For: 127.0.0.1\r\n"));assert!(head.starts_with(b"GET / "));s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8192\r\n\r\n").unwrap();s.write_all(&[b'z';8192]).unwrap();}});
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        multiplex::bounded(Instant::now() + Duration::from_secs(15), async {
                            let mut endpoint =
                                quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
                            endpoint.set_default_client_config(client);
                            let quic = endpoint
                                .connect(address, "app.example")
                                .unwrap()
                                .await
                                .unwrap();
                            let (mut driver, mut client) =
                                h3::client::new(h3_quinn::Connection::new(quic.clone()))
                                    .await
                                    .unwrap();
                            futures_lite::future::race(
                                async { panic!("early h3 close: {}", driver.wait_idle().await) },
                                async {
                                    for i in 0..2 {
                                        if i == 1 {
                                            #[cfg(target_os = "linux")]
                                            let moved = "127.0.0.2:0";
                                            #[cfg(not(target_os = "linux"))]
                                            let moved = "127.0.0.1:0";
                                            endpoint
                                                .rebind(UdpSocket::bind(moved).unwrap())
                                                .unwrap();
                                        }
                                        let mut stream = client
                                            .send_request(
                                                http_types::Request::builder()
                                                    .uri("https://app.example/")
                                                    .header("accept-encoding", "zstd")
                                                    .body(())
                                                    .unwrap(),
                                            )
                                            .await
                                            .unwrap();
                                        stream.finish().await.unwrap();
                                        let response = stream.recv_response().await.unwrap();
                                        assert_eq!(response.status(), 200);
                                        assert_eq!(
                                            response.headers()["alt-svc"],
                                            format!("h3=\":{}\"; ma=60", address.port())
                                        );
                                        assert_eq!(response.headers()["content-encoding"], "zstd");
                                        let mut data = Vec::new();
                                        while let Some(mut bytes) =
                                            stream.recv_data().await.unwrap()
                                        {
                                            data.extend_from_slice(
                                                &bytes.copy_to_bytes(bytes.remaining()),
                                            );
                                        }
                                        assert_eq!(
                                            zstd::stream::decode_all(data.as_slice()).unwrap(),
                                            vec![b'z'; 8192]
                                        );
                                    }
                                    let mut stream = client
                                        .send_request(
                                            http_types::Request::builder()
                                                .method("POST")
                                                .uri("https://app.example/create")
                                                .header("early-data", "1")
                                                .body(())
                                                .unwrap(),
                                        )
                                        .await
                                        .unwrap();
                                    stream.finish().await.unwrap();
                                    assert_eq!(stream.recv_response().await.unwrap().status(), 425);
                                },
                            )
                            .await;
                            quic.close(0u32.into(), b"test complete");
                            endpoint.close(0u32.into(), b"test complete");
                        })
                        .await
                        .unwrap();
                    });
            }));
            stop.store(true, Ordering::Release);
            serving.join().unwrap().unwrap();
            origin.join().unwrap();
            if let Err(p) = result {
                std::panic::resume_unwind(p);
            }
            assert!(server.observe.quic_migrations.load(Ordering::Relaxed) >= 1);
            assert_eq!(server.observe.early_rejected.load(Ordering::Relaxed), 1);
            backend.set_nonblocking(true).unwrap();
            assert!(backend.accept().is_err());
        });
    }
}

#[cfg(test)]
#[path = "http3_early_tests.rs"]
mod early_tests;
