#![cfg(target_os = "linux")]
use pathward_config::ParsedConfig;
use pathward_server::{Server, acme::Manager, tls::TlsServer};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName},
};
use std::{
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
fn client_config(path: &str) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for pem in pem::parse_many(fs::read(path).unwrap()).unwrap() {
        roots
            .add(CertificateDer::from(pem.into_contents()))
            .unwrap();
    }
    let mut cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}
fn fetch(
    port: u16,
    cfg: Arc<ClientConfig>,
    method: &str,
    host: &str,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let socket = TcpStream::connect(("127.0.0.1", port))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let conn = ClientConnection::new(cfg, ServerName::try_from("one.pathward.test").unwrap())
        .map_err(io::Error::other)?;
    let mut stream = StreamOwned::new(conn, socket);
    write!(
        stream,
        "{method} /?ignored=yes HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )?;
    stream.flush()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let cert = stream
        .conn
        .peer_certificates()
        .ok_or_else(|| io::Error::other("no certificate"))?[0]
        .to_vec();
    Ok((response, cert))
}
fn wait_for(port: u16, cfg: Arc<ClientConfig>, different: Option<&[u8]>) -> (Vec<u8>, Vec<u8>) {
    let deadline = Instant::now() + Duration::from_secs(80);
    loop {
        if let Ok(result) = fetch(port, cfg.clone(), "GET", "one.pathward.test")
            && result.0.ends_with(b"secretly-selected-public-file")
            && different != Some(result.1.as_slice())
        {
            return result;
        }
        assert!(
            Instant::now() < deadline,
            "certificate issuance/renewal timed out"
        );
        thread::sleep(Duration::from_millis(200));
    }
}
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::set_permissions(self.0.join("cache"), fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
#[ignore = "requires pinned disposable Pebble; run make acme-integration"]
fn real_acme_issue_renew_restart_and_fail_closed() {
    let port: u16 = std::env::var("PATHWARD_TEST_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let directory = std::env::var("PATHWARD_TEST_DIRECTORY").unwrap();
    let api = client_config(&std::env::var("PATHWARD_TEST_CA").unwrap());
    let issued = client_config(&std::env::var("PATHWARD_TEST_ISSUER").unwrap());
    let temp = Temp(std::env::temp_dir().join(format!("pathward-acme-{}", std::process::id())));
    fs::create_dir(&temp.0).unwrap();
    fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.0.join("public");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("index.html"), b"secretly-selected-public-file").unwrap();
    let text = format!(
        "site \"one.pathward.test\" {{\nroot \"{}\"\npublish \"/\" \"index.html\"\ntls \"auto\"\n}}\nsite \"two.pathward.test\" {{\nroot \"{}\"\npublish \"/\" \"index.html\"\ntls \"auto\"\n}}",
        root.display(),
        root.display()
    );
    let parsed = ParsedConfig::parse(&text).unwrap();
    let config = parsed.compile().unwrap();
    let server = Server::new(&config).unwrap();
    let domains = vec!["one.pathward.test".into(), "two.pathward.test".into()];
    let cache = temp.0.join("cache");
    let make_manager = || {
        Manager::new(
            domains.clone(),
            &[root.to_str().unwrap()],
            &cache,
            &directory,
            vec![],
            api.clone(),
        )
        .unwrap()
    };
    let manager = make_manager();
    let account = fs::read(cache.join(".account")).unwrap();
    let tls = TlsServer::new(manager.identity()).unwrap();
    let stop = AtomicBool::new(false);
    let renewed = thread::scope(|scope| {
        // Always stop background workers even when an assertion panics.
        struct Stop<'a>(&'a AtomicBool);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let _stop = Stop(&stop);
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_port = redirect.local_addr().unwrap().port();
        scope.spawn(|| {
            server
                .serve_tls_with_redirect(listener, redirect, &stop, &tls)
                .unwrap()
        });
        let mut plain = TcpStream::connect(("127.0.0.1", redirect_port)).unwrap();
        plain
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        plain
            .write_all(b"GET /?q=kept HTTP/1.1\r\nHost: one.pathward.test:80\r\n\r\n")
            .unwrap();
        let mut reply = String::new();
        plain.read_to_string(&mut reply).unwrap();
        assert!(reply.starts_with("HTTP/1.1 308"));
        assert!(reply.contains("Location: https://one.pathward.test/?q=kept\r\n"));
        scope.spawn(|| manager.run(&stop));
        let first = wait_for(port, issued.clone(), None);
        assert!(first.0.starts_with(b"HTTP/1.1 200"));
        for (authority, status) in [
            ("one.pathward.test:443".to_owned(), 200),
            (format!("one.pathward.test:{port}"), 400),
            ("one.pathward.test:80".to_owned(), 400),
        ] {
            let response = fetch(port, issued.clone(), "GET", &authority).unwrap().0;
            assert!(response.starts_with(format!("HTTP/1.1 {status}").as_bytes()));
        }
        let head = fetch(port, issued.clone(), "HEAD", "one.pathward.test")
            .unwrap()
            .0;
        assert!(head.ends_with(b"\r\n\r\n"));
        let front = fetch(port, issued.clone(), "GET", "two.pathward.test")
            .unwrap()
            .0;
        assert!(front.starts_with(b"HTTP/1.1 421"));
        let second = wait_for(port, issued.clone(), Some(&first.1));
        assert_ne!(first.1, second.1);
        assert_eq!(account, fs::read(cache.join(".account")).unwrap());
        second.1
    });
    drop(tls);
    drop(manager);
    let server = Server::new(&config).unwrap();
    // Restart uses durable account/certificate without polling or contacting ACME.
    let manager = make_manager();
    let tls = TlsServer::new(manager.identity()).unwrap();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        scope.spawn(|| server.serve_tls(listener, &stop, &tls).unwrap());
        struct Stop<'a>(&'a AtomicBool);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let _stop = Stop(&stop);
        assert_eq!(wait_for(port, issued.clone(), None).1, renewed);
        assert_eq!(account, fs::read(cache.join(".account")).unwrap());
        // Persistence failure during renewal must keep the previous certificate.
        let durable = fs::read(cache.join(".certificate")).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o500)).unwrap();
        scope.spawn(|| manager.run(&stop));
        let deadline = Instant::now() + Duration::from_secs(45);
        let mut unavailable = false;
        while Instant::now() < deadline {
            match fetch(port, issued.clone(), "GET", "one.pathward.test") {
                Ok((_, cert)) => assert_eq!(cert, renewed, "unpersisted certificate became active"),
                Err(_) => {
                    unavailable = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
        assert!(unavailable, "expired certificate remained available");
        assert_eq!(durable, fs::read(cache.join(".certificate")).unwrap());
    });
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
}
