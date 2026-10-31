use super::*;
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};
use std::{net::TcpListener, thread};
fn pem(domains: &[&str]) -> (Vec<u8>, rustls::pki_types::CertificateDer<'static>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert =
        rcgen::CertificateParams::new(domains.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
            .unwrap()
            .self_signed(&key)
            .unwrap();
    (
        format!("{}{}", key.serialize_pem(), cert.pem()).into_bytes(),
        cert.der().clone(),
    )
}
#[test]
fn candidates_require_matching_keys_and_exact_names_before_activation() {
    let (bytes, _) = pem(&["a.test"]);
    let domains = vec!["a.test".to_owned()];
    let cert = Certificate::parse(&bytes, &domains).unwrap();
    let identity = Identity::new(domains.clone(), None);
    assert!(identity.install(cert, false).is_err());
    assert!(identity.certificate.read().unwrap().is_none());
    identity
        .install(Certificate::parse(&bytes, &domains).unwrap(), true)
        .unwrap();
    assert!(Certificate::parse(&bytes, &["b.test".to_owned()]).is_err());
    let (more, _) = pem(&["a.test", "b.test"]);
    assert!(Certificate::parse(&more, &domains).is_err());
    let (other, _) = pem(&["a.test"]);
    let old = pem::parse_many(bytes).unwrap();
    let new = pem::parse_many(other).unwrap();
    let mixed = format!("{}{}", pem::encode(&new[0]), pem::encode(&old[1]));
    assert!(Certificate::parse(mixed.as_bytes(), &domains).is_err());
}
#[test]
fn real_tls_rejects_unknown_missing_sni_and_unsupported_alpn() {
    let (bytes, root) = pem(&["a.test"]);
    let identity = Arc::new(Identity::new(
        vec!["a.test".into()],
        Some(Certificate::parse(&bytes, &["a.test".into()]).unwrap()),
    ));
    let server = TlsServer::new(identity).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(root).unwrap();
    let base =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    for (name, sni, alpn, success) in [
        ("a.test", true, vec![b"http/1.1".to_vec()], true),
        ("unknown.test", true, vec![], false),
        ("a.test", false, vec![], false),
        ("a.test", true, vec![b"h2".to_vec()], false),
        (
            "a.test",
            true,
            vec![b"acme-tls/1".to_vec(), b"http/1.1".to_vec()],
            false,
        ),
        ("a.test", true, vec![b"acme-tls/1".to_vec()], false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let (s, _) = listener.accept().unwrap();
                let result = server.accept(s, Instant::now());
                if success {
                    let mut transport = result.unwrap().unwrap();
                    assert_eq!(transport.sni, "a.test");
                    transport
                        .deadline(Instant::now() + Duration::from_secs(1))
                        .unwrap();
                    transport.write_all(b"ok").unwrap();
                    transport.finish().unwrap();
                } else {
                    assert!(result.is_err());
                }
            });
            let mut cfg = base.clone();
            cfg.enable_sni = sni;
            cfg.alpn_protocols = alpn;
            let mut socket = TcpStream::connect(address).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut conn = ClientConnection::new(
                Arc::new(cfg),
                ServerName::try_from(name.to_owned()).unwrap(),
            )
            .unwrap();
            let handshake = (|| {
                while conn.is_handshaking() {
                    conn.complete_io(&mut socket)?;
                }
                Ok::<(), io::Error>(())
            })();
            if success {
                handshake.unwrap();
                let mut stream = StreamOwned::new(conn, socket);
                let mut out = String::new();
                stream.read_to_string(&mut out).unwrap();
                assert_eq!(out, "ok");
            } else {
                assert!(handshake.is_err());
            }
            worker.join().unwrap();
        });
    }
}
#[test]
fn stalled_clienthello_has_a_total_deadline() {
    let server = TlsServer::new(Arc::new(Identity::new(vec!["a.test".into()], None))).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, _) = listener.accept().unwrap();
    let start = Instant::now();
    assert!(
        server
            .accept(
                stream,
                start - HANDSHAKE_BUDGET + Duration::from_millis(200)
            )
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(client);
}
