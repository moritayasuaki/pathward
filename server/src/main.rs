#![forbid(unsafe_code)]
use pathward_server::{Server, acme, control, tls};
use std::{
    env,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
    thread,
};
const HELP: &str = "pathward-server serve-http CONFIG [127.0.0.1:8080] [--monitor 127.0.0.1:9090]\npathward-server serve-tls CONFIG CACHE_DIRECTORY --accept-terms [--acme staging|production] [--listen 0.0.0.0:443] [--contact mailto:admin@example.com] [--monitor 127.0.0.1:9090]\nSIGHUP reloads roots/publications; SIGTERM/SIGINT drain active connections. Monitor is opt-in and loopback-only.\nLinux 5.6+ and trusted procfs required. TLS-ALPN-01 requires public TCP/443 forwarding.\nACME defaults to staging. --accept-terms accepts the selected CA's subscriber terms.";
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    let command = args.first().and_then(|s| s.to_str()).ok_or(HELP)?;
    match command {
        "serve-http" => {
            if args.len() < 2 {
                return Err(HELP.into());
            }
            let mut address: SocketAddr = "127.0.0.1:8080".parse()?;
            let mut monitor = None;
            let mut position = 2;
            if let Some(value) = args.get(position).and_then(|s| s.to_str())
                && !value.starts_with("--")
            {
                address = value.parse()?;
                position += 1;
            }
            if position < args.len() {
                if args[position] != "--monitor" || position + 2 != args.len() {
                    return Err(HELP.into());
                }
                monitor = Some(args[position + 1].to_str().ok_or(HELP)?.parse()?);
            }
            if !address.ip().is_loopback() {
                return Err("HTTP-only mode requires loopback".into());
            }
            let parsed = control::read_config(Path::new(&args[1]))?;
            let config = parsed.compile()?;
            let server = Server::new(&config)?;
            let listener = TcpListener::bind(address)?;
            let signals = control::Signals::install()?;
            run_service(
                &server,
                listener,
                Path::new(&args[1]),
                &signals,
                None,
                monitor,
            )?;
        }
        "serve-tls" => {
            if args.len() < 4 {
                return Err(HELP.into());
            }
            let cache = PathBuf::from(&args[2]);
            let mut accept = false;
            let mut address = "0.0.0.0:443";
            let mut directory = acme::STAGING;
            let mut contact = Vec::new();
            let mut monitor = None;
            let mut seen = std::collections::BTreeSet::new();
            let mut i = 3;
            while i < args.len() {
                let flag = args[i].to_str().ok_or(HELP)?;
                if !seen.insert(flag) {
                    return Err("duplicate CLI option".into());
                }
                if flag == "--accept-terms" {
                    accept = true;
                    i += 1;
                    continue;
                }
                let value = args.get(i + 1).and_then(|s| s.to_str()).ok_or(HELP)?;
                match flag {
                    "--acme" => {
                        directory = match value {
                            "staging" => acme::STAGING,
                            "production" => acme::PRODUCTION,
                            _ => return Err("ACME must be staging or production".into()),
                        }
                    }
                    "--listen" => address = value,
                    "--monitor" => monitor = Some(value.parse()?),
                    "--contact" => contact.push(value.to_owned()),
                    _ => return Err(HELP.into()),
                }
                i += 2;
            }
            if !accept {
                return Err("--accept-terms is required before contacting the selected CA".into());
            }
            let address: SocketAddr = address.parse()?;
            let parsed = control::read_config(Path::new(&args[1]))?;
            let config = parsed.compile()?;
            let server = Server::new_with_cache(&config, Some(&cache))?;
            let domains = config.sites().iter().map(|s| s.host().to_owned()).collect();
            let roots: Vec<_> = config.sites().iter().map(|s| s.root()).collect();
            #[cfg(target_os = "linux")]
            {
                rustix::process::set_dumpable_behavior(
                    rustix::process::DumpableBehavior::NotDumpable,
                )?;
                rustix::process::setrlimit(
                    rustix::process::Resource::Core,
                    rustix::process::Rlimit {
                        current: Some(0),
                        maximum: Some(0),
                    },
                )?;
            }
            let signals = control::Signals::install()?;
            let mut manager = acme::Manager::new(
                domains,
                &roots,
                &cache,
                directory,
                contact,
                acme::public_client_config()?,
            )?;
            manager.set_observability(server.observability());
            let listener = TcpListener::bind(address)?;
            run_service(
                &server,
                listener,
                Path::new(&args[1]),
                &signals,
                Some(&manager),
                monitor,
            )?;
        }
        _ => return Err(HELP.into()),
    }
    Ok(())
}
struct StopWorker<'a>(&'a AtomicBool);
impl Drop for StopWorker<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
fn run_service(
    server: &Server,
    listener: TcpListener,
    path: &Path,
    signals: &control::Signals,
    manager: Option<&acme::Manager>,
    monitor: Option<SocketAddr>,
) -> std::io::Result<()> {
    let monitor = monitor
        .map(|addr| {
            if !addr.ip().is_loopback() {
                return Err(std::io::Error::other("monitor requires loopback"));
            }
            TcpListener::bind(addr)
        })
        .transpose()?;
    let identity = manager.map(acme::Manager::identity);
    let tls = identity
        .as_ref()
        .map(|identity| tls::TlsServer::new(identity.clone()))
        .transpose()?;
    server.observability().enable_stderr()?;
    server.observability().listening(
        listener.local_addr()?.port(),
        monitor
            .as_ref()
            .map(|l| l.local_addr().map(|a| a.port()))
            .transpose()?,
        tls.is_some(),
    );
    let done = AtomicBool::new(false);
    thread::scope(|scope| {
        // Set both flags on every exit, including thread-spawn errors and panics,
        // before scope waits for background workers.
        struct Stop<'a>(&'a AtomicBool, &'a AtomicBool);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
                self.1.store(true, Ordering::Release);
            }
        }
        let _stop = Stop(&signals.shutdown, &done);
        let reload = thread::Builder::new()
            .name("pathward-reload".into())
            .spawn_scoped(scope, || {
                let _stop = StopWorker(&signals.shutdown);
                control::reload_loop(server, path, signals)
            })?;
        let monitor_worker = monitor
            .map(|listener| {
                thread::Builder::new()
                    .name("pathward-monitor".into())
                    .spawn_scoped(scope, || {
                        let _stop = StopWorker(&signals.shutdown);
                        let result = control::monitor(
                            listener,
                            server,
                            identity.as_deref(),
                            &signals.shutdown,
                            &done,
                        );
                        if result.is_err() {
                            signals.shutdown.store(true, Ordering::Release);
                        }
                        result
                    })
            })
            .transpose()?;
        let acme_worker = manager
            .map(|manager| {
                thread::Builder::new()
                    .name("pathward-acme".into())
                    .spawn_scoped(scope, || {
                        struct Stop<'a>(&'a AtomicBool);
                        impl Drop for Stop<'_> {
                            fn drop(&mut self) {
                                self.0.store(true, Ordering::Release);
                            }
                        }
                        let _stop = Stop(&signals.shutdown);
                        manager.run(&signals.shutdown);
                    })
            })
            .transpose()?;
        let result = match tls.as_ref() {
            Some(tls) => server.serve_tls(listener, &signals.shutdown, tls),
            None => server.serve(listener, &signals.shutdown),
        };
        signals.shutdown.store(true, Ordering::Release);
        done.store(true, Ordering::Release);
        reload
            .join()
            .map_err(|_| std::io::Error::other("reload worker failed"))?;
        if let Some(worker) = acme_worker {
            worker
                .join()
                .map_err(|_| std::io::Error::other("ACME worker failed"))?;
        }
        if let Some(worker) = monitor_worker {
            worker
                .join()
                .map_err(|_| std::io::Error::other("monitor worker failed"))??;
        }
        result
    })
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
