#![forbid(unsafe_code)]
use pathward_config::ParsedConfig;
use pathward_server::Server;
use std::{
    env,
    fs::File,
    net::{SocketAddr, TcpListener},
    process::ExitCode,
    sync::atomic::AtomicBool,
};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!(
            "pathward-server serve-http CONFIG [127.0.0.1:8080]\nLinux 5.6+ and procfs required. HTTP loopback only; TLS auto is not active."
        );
        return Ok(());
    }
    if !(args.len() == 2 || args.len() == 3) || args[0] != "serve-http" {
        return Err("usage: pathward-server serve-http CONFIG [127.0.0.1:8080]".into());
    }
    let address: SocketAddr = args
        .get(2)
        .map(|s| s.to_str().ok_or("address must be UTF-8"))
        .transpose()?
        .unwrap_or("127.0.0.1:8080")
        .parse()?;
    if !address.ip().is_loopback() {
        return Err("HTTP-only mode requires loopback; TLS is not implemented".into());
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
