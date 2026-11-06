#![forbid(unsafe_code)]
mod cutover_policy;
use pathward_server::{Server, acme, control, deployment, tls};
use std::{
    env,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
    thread,
};
const HELP: &str = "pathward-server serve-http CONFIG [127.0.0.1:8080] [--monitor 127.0.0.1:9090]\npathward-server serve-tls CONFIG CACHE_DIRECTORY --accept-terms [--http-listen 0.0.0.0:80] [--experimental-http3] [--acme staging|production] [--listen 0.0.0.0:443] [--contact mailto:admin@example.com] [--monitor 127.0.0.1:9090]\npathward-server check CONFIG [--cache DIR]\npathward-server generate BASE SITE ROOT MANIFEST [--index FILE]\npathward-server init CONTROL_DIR CONFIG\npathward-server status --control-dir DIR\npathward-server activate --control-dir DIR --expect GENERATION:SHA256 CONFIG\npathward-server rollback --control-dir DIR --expect GENERATION:SHA256\npathward-server cutover-policy OP ARGS... (read-only; see docs/cutover-policy.md)\nServing modes accept --control-dir DIR with CONFIG=DIR/.config.\nSIGHUP reloads roots/publications; SIGTERM/SIGINT drain active connections. Monitor is opt-in and loopback-only.\nLinux 5.6+ and trusted procfs required. TLS-ALPN-01 requires public TCP/443 forwarding.\nACME defaults to staging. --accept-terms accepts the selected CA's subscriber terms.";
#[derive(Default)]
struct ServiceOptions {
    monitor: Option<SocketAddr>,
    http3: bool,
    http_listen: Option<SocketAddr>,
    control_dir: Option<PathBuf>,
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    let command = args.first().and_then(|s| s.to_str()).ok_or(HELP)?;
    match command {
        "cutover-policy" => {
            let allowed = cutover_policy::evaluate(&args[1..])?;
            println!("{}", if allowed { "ALLOW" } else { "DENY" });
        }
        "check" => {
            if args.len() != 2 && args.len() != 4 {
                return Err(HELP.into());
            }
            let cache = if args.len() == 4 {
                if args[2] != "--cache" {
                    return Err(HELP.into());
                }
                Some(Path::new(&args[3]))
            } else {
                None
            };
            let (revision, files) = deployment::check(Path::new(&args[1]), cache)?;
            println!("OK {revision} files={files}");
        }
        "generate" => {
            if args.len() != 5 && args.len() != 7 {
                return Err(HELP.into());
            }
            let parsed = control::read_config(Path::new(&args[1]))?;
            let config = parsed.compile()?;
            let host = args[2].to_str().ok_or(HELP)?;
            let root = args[3].to_str().ok_or(HELP)?;
            let manifest = bounded_text(Path::new(&args[4]))?;
            let index = if args.len() == 7 {
                if args[5] != "--index" {
                    return Err(HELP.into());
                }
                Some(args[6].to_str().ok_or(HELP)?)
            } else {
                None
            };
            print!(
                "{}",
                deployment::generate(&config, host, root, &manifest, index)?
            );
        }
        "init" => {
            if args.len() != 3 {
                return Err(HELP.into());
            }
            let parsed = control::read_config(Path::new(&args[2]))?;
            deployment::initialize(Path::new(&args[1]), &parsed.compile()?)?;
            println!("initialized");
        }
        "status" | "activate" | "rollback" => {
            let expected_len = match command {
                "status" => 3,
                "activate" => 6,
                _ => 5,
            };
            if args.len() != expected_len || args[1] != "--control-dir" {
                return Err(HELP.into());
            }
            let expected = if command != "status" {
                if args[3] != "--expect" {
                    return Err(HELP.into());
                }
                Some(args[4].to_str().ok_or(HELP)?)
            } else {
                None
            };
            let bytes = if command == "activate" {
                bounded_text(Path::new(&args[5]))?.into_bytes()
            } else {
                Vec::new()
            };
            let reply = deployment::command(
                Path::new(&args[2]),
                match command {
                    "status" => "STATUS",
                    "activate" => "APPLY",
                    _ => "ROLLBACK",
                },
                expected,
                &bytes,
            )?;
            let fields: Vec<_> = reply.split(' ').collect();
            if fields.len() != 3 {
                return Err("invalid control reply".into());
            }
            println!("{}:{}", fields[1], fields[2]);
        }
        "serve-http" => {
            if args.len() < 2 {
                return Err(HELP.into());
            }
            let mut address: SocketAddr = "127.0.0.1:8080".parse()?;
            let mut options = ServiceOptions::default();
            let mut position = 2;
            if let Some(value) = args.get(position).and_then(|s| s.to_str())
                && !value.starts_with("--")
            {
                address = value.parse()?;
                position += 1;
            }
            let mut seen = std::collections::BTreeSet::new();
            while position < args.len() {
                let flag = args[position].to_str().ok_or(HELP)?;
                if !seen.insert(flag) {
                    return Err("duplicate CLI option".into());
                }
                let value = args
                    .get(position + 1)
                    .and_then(|s| s.to_str())
                    .ok_or(HELP)?;
                match flag {
                    "--monitor" => options.monitor = Some(value.parse()?),
                    "--control-dir" => options.control_dir = Some(value.into()),
                    _ => return Err(HELP.into()),
                }
                position += 2;
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
                options,
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
            let mut options = ServiceOptions::default();
            let mut seen = std::collections::BTreeSet::new();
            let mut i = 3;
            while i < args.len() {
                let flag = args[i].to_str().ok_or(HELP)?;
                if !seen.insert(flag) {
                    return Err("duplicate CLI option".into());
                }
                if flag == "--experimental-http3" {
                    options.http3 = true;
                    i += 1;
                    continue;
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
                    "--monitor" => options.monitor = Some(value.parse()?),
                    "--http-listen" => options.http_listen = Some(value.parse()?),
                    "--control-dir" => options.control_dir = Some(value.into()),
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
            let roots: Vec<_> = config.sites().iter().filter_map(|s| s.root()).collect();
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
            if options
                .control_dir
                .as_ref()
                .is_some_and(|d| d.starts_with(&cache) || cache.starts_with(d))
            {
                return Err("control and ACME storage must be disjoint".into());
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
                options,
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
    options: ServiceOptions,
) -> std::io::Result<()> {
    let managed = if let Some(directory) = &options.control_dir {
        if path != directory.join(".config") {
            return Err(std::io::Error::other(
                "managed config must be CONTROL_DIR/.config",
            ));
        }
        server.protect_directory(directory)?;
        server.check_files()?;
        let parsed = control::read_config(path)?;
        if server.revision()
            != deployment::revision(
                parsed
                    .compile()
                    .map_err(|_| std::io::Error::other("config"))?
                    .source()
                    .as_bytes(),
            )
        {
            return Err(std::io::Error::other(
                "configuration changed during startup",
            ));
        }
        Some(deployment::Managed::open(
            directory,
            &parsed
                .compile()
                .map_err(|_| std::io::Error::other("config"))?,
            server.cache_path(),
        )?)
    } else {
        None
    };
    let monitor = options
        .monitor
        .map(|addr| {
            if !addr.ip().is_loopback() {
                return Err(std::io::Error::other("monitor requires loopback"));
            }
            TcpListener::bind(addr)
        })
        .transpose()?;
    let redirect = options.http_listen.map(TcpListener::bind).transpose()?;
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
        let deployment_worker = managed
            .as_ref()
            .map(|managed| {
                thread::Builder::new()
                    .name("pathward-deploy".into())
                    .spawn_scoped(scope, || {
                        let _stop = StopWorker(&signals.shutdown);
                        managed.run(server, &signals.shutdown)
                    })
            })
            .transpose()?;
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
            Some(tls) if options.http3 => {
                let udp = std::net::UdpSocket::bind(listener.local_addr()?)?;
                server.serve_tls_http3(listener, redirect, udp, &signals.shutdown, tls)
            }
            Some(tls) => match redirect {
                Some(redirect) => {
                    server.serve_tls_with_redirect(listener, redirect, &signals.shutdown, tls)
                }
                None => server.serve_tls(listener, &signals.shutdown, tls),
            },
            None => server.serve(listener, &signals.shutdown),
        };
        signals.shutdown.store(true, Ordering::Release);
        done.store(true, Ordering::Release);
        reload
            .join()
            .map_err(|_| std::io::Error::other("reload worker failed"))?;
        if let Some(worker) = deployment_worker {
            worker
                .join()
                .map_err(|_| std::io::Error::other("deployment worker failed"))??;
        }
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
fn bounded_text(path: &Path) -> std::io::Result<String> {
    let bytes = control::read_bytes(path)?;
    String::from_utf8(bytes).map_err(|_| std::io::Error::other("input must be UTF-8"))
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
