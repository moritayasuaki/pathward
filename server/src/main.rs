#![forbid(unsafe_code)]
use pathward_config::ParsedConfig;
use pathward_server::{Server, acme, tls};
use std::{
    env,
    fs::File,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
    thread,
};
const HELP: &str = "pathward-server serve-http CONFIG [127.0.0.1:8080]\npathward-server serve-tls CONFIG CACHE_DIRECTORY --accept-terms [--acme staging|production] [--listen 0.0.0.0:443] [--contact mailto:admin@example.com]\nLinux 5.6+ and trusted procfs required. TLS-ALPN-01 requires public TCP/443 forwarding.\nACME defaults to staging. --accept-terms accepts the selected CA's subscriber terms.";
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    let command = args.first().and_then(|s| s.to_str()).ok_or(HELP)?;
    match command {
        "serve-http" => {
            if args.len() != 2 && args.len() != 3 {
                return Err(HELP.into());
            }
            let address: SocketAddr = args
                .get(2)
                .map(|s| s.to_str().ok_or("invalid address"))
                .transpose()?
                .unwrap_or("127.0.0.1:8080")
                .parse()?;
            if !address.ip().is_loopback() {
                return Err("HTTP-only mode requires loopback".into());
            }
            let parsed = ParsedConfig::read(File::open(&args[1])?)?;
            let config = parsed.compile()?;
            let server = Server::new(&config)?;
            let listener = TcpListener::bind(address)?;
            eprintln!(
                "HTTP-only listening on {}; TLS auto is not active",
                listener.local_addr()?
            );
            server.serve(listener, &AtomicBool::new(false))?;
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
                    "--contact" => contact.push(value.to_owned()),
                    _ => return Err(HELP.into()),
                }
                i += 2;
            }
            if !accept {
                return Err("--accept-terms is required before contacting the selected CA".into());
            }
            let address: SocketAddr = address.parse()?;
            let parsed = ParsedConfig::read(File::open(&args[1])?)?;
            let config = parsed.compile()?;
            let server = Server::new(&config)?;
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
            let manager = acme::Manager::new(
                domains,
                &roots,
                &cache,
                directory,
                contact,
                acme::public_client_config()?,
            )?;
            let tls = tls::TlsServer::new(manager.identity())?;
            let listener = TcpListener::bind(address)?;
            eprintln!(
                "HTTPS listening on {}; ACME={}; cache is private; TLS-ALPN-01 requires external TCP/443",
                listener.local_addr()?,
                if directory == acme::STAGING {
                    "staging"
                } else {
                    "production"
                }
            );
            let shutdown = AtomicBool::new(false);
            thread::scope(|scope| -> std::io::Result<()> {
                let worker = thread::Builder::new()
                    .name("pathward-acme".into())
                    .spawn_scoped(scope, || {
                        struct Stop<'a>(&'a AtomicBool);
                        impl Drop for Stop<'_> {
                            fn drop(&mut self) {
                                self.0.store(true, Ordering::Release);
                            }
                        }
                        let _stop = Stop(&shutdown);
                        manager.run(&shutdown)
                    })?;
                let result = server.serve_tls(listener, &shutdown, &tls);
                shutdown.store(true, Ordering::Release);
                worker
                    .join()
                    .map_err(|_| std::io::Error::other("ACME worker failed"))?;
                result
            })?;
        }
        _ => return Err(HELP.into()),
    }
    Ok(())
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
