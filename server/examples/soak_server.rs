//! Local-only integration driver; the production CLI keeps its fixed public CA origins.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use pathward_server::{Server, acme, control, deployment, tls};
    use std::{
        fs,
        net::TcpListener,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
    };
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 5 && args.len() != 7 {
        return Err(
            "expected CONTROL CACHE LOCAL_DIRECTORY CA_PEM TLS_PORT [HTTP_PORT MONITOR_PORT]"
                .into(),
        );
    }
    let directory = &args[2];
    let api_port: u16 = directory
        .strip_prefix("https://localhost:")
        .and_then(|s| s.strip_suffix("/dir"))
        .ok_or("local CA only")?
        .parse()?;
    if api_port == 0 {
        return Err("local CA port".into());
    }
    // Ephemeral test keys must not enter core dumps. Unlike the production CLI,
    // keep procfs readable so the unprivileged soak can measure descriptors.
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    let path = Path::new(&args[0]).join(".config");
    let parsed = control::read_config(&path)?;
    let config = parsed.compile()?;
    let cache = Path::new(&args[1]);
    let server = Server::new_with_cache(&config, Some(cache))?;
    server.protect_directory(Path::new(&args[0]))?;
    server.check_files()?;
    let managed = deployment::Managed::open(Path::new(&args[0]), &config, Some(cache))?;
    let mut roots = rustls::RootCertStore::empty();
    for item in pem::parse_many(fs::read(&args[3])?)? {
        roots.add(rustls::pki_types::CertificateDer::from(
            item.into_contents(),
        ))?;
    }
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut manager = acme::Manager::new(
        config.sites().iter().map(|s| s.host().to_owned()).collect(),
        &config
            .sites()
            .iter()
            .filter_map(|s| s.root())
            .collect::<Vec<_>>(),
        cache,
        directory,
        vec![],
        Arc::new(client),
    )?;
    manager.set_observability(server.observability());
    server.observability().enable_stderr()?;
    let signals = control::Signals::install()?;
    let identity = manager.identity();
    let tls = tls::TlsServer::new(identity.clone())?;
    let listener = TcpListener::bind(("127.0.0.1", args[4].parse::<u16>()?))?;
    let http_port = args
        .get(5)
        .map(|s| s.parse::<u16>())
        .transpose()?
        .unwrap_or(0);
    let monitor_port = args
        .get(6)
        .map(|s| s.parse::<u16>())
        .transpose()?
        .unwrap_or(0);
    let redirect = TcpListener::bind(("127.0.0.1", http_port))?;
    let monitor = TcpListener::bind(("127.0.0.1", monitor_port))?;
    println!(
        "{{\"pid\":{},\"tls\":{},\"http\":{},\"monitor\":{}}}",
        std::process::id(),
        listener.local_addr()?.port(),
        redirect.local_addr()?.port(),
        monitor.local_addr()?.port()
    );
    let done = AtomicBool::new(false);
    struct Stop<'a>(&'a AtomicBool, &'a AtomicBool);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
            self.1.store(true, Ordering::Release);
        }
    }
    thread::scope(|scope| -> std::io::Result<()> {
        let _guard = Stop(&signals.shutdown, &done);
        let acme = scope.spawn(|| manager.run(&signals.shutdown));
        let reload = scope.spawn(|| control::reload_loop(&server, &path, &signals));
        let deploy = scope.spawn(|| managed.run(&server, &signals.shutdown));
        let monitoring = scope.spawn(|| {
            control::monitor(monitor, &server, Some(&identity), &signals.shutdown, &done)
        });
        let result = if std::env::var("PATHWARD_TEST_HTTP3").as_deref() == Ok("1") {
            let udp = std::net::UdpSocket::bind(listener.local_addr()?)?;
            server.serve_tls_http3(listener, Some(redirect), udp, &signals.shutdown, &tls)
        } else {
            server.serve_tls_with_redirect(listener, redirect, &signals.shutdown, &tls)
        };
        signals.shutdown.store(true, Ordering::Release);
        done.store(true, Ordering::Release);
        acme.join()
            .map_err(|_| std::io::Error::other("ACME worker"))?;
        reload
            .join()
            .map_err(|_| std::io::Error::other("reload worker"))?;
        deploy
            .join()
            .map_err(|_| std::io::Error::other("deploy worker"))??;
        monitoring
            .join()
            .map_err(|_| std::io::Error::other("monitor worker"))??;
        result
    })?;
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("The soak driver requires Linux");
    std::process::exit(1);
}
