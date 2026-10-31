//! CLI signals and a read-only loopback monitoring listener.
use crate::{Server, http, tls};
use pathward_config::ParsedConfig;
use std::{
    fs::File,
    io,
    net::TcpListener,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub struct Signals {
    pub shutdown: Arc<AtomicBool>,
    pub reload: Arc<AtomicBool>,
    ids: Vec<signal_hook::SigId>,
}
impl Signals {
    /// Install before starting any serving/ACME threads. Handlers only set flags.
    pub fn install() -> io::Result<Self> {
        let mut signals = Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            reload: Arc::new(AtomicBool::new(false)),
            ids: Vec::new(),
        };
        for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
            signals.ids.push(signal_hook::flag::register(
                signal,
                signals.shutdown.clone(),
            )?);
        }
        signals.ids.push(signal_hook::flag::register(
            signal_hook::consts::SIGHUP,
            signals.reload.clone(),
        )?);
        Ok(signals)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for id in &self.ids {
            signal_hook::low_level::unregister(*id);
        }
    }
}

/// A single descriptor pins each config read; nonregular files are refused.
/// Administrators must publish config using atomic rename, on a trusted local FS.
pub fn read_config(path: &Path) -> io::Result<ParsedConfig> {
    #[cfg(target_os = "linux")]
    let file = {
        use rustix::fs::{Mode, OFlags, open};
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        let pin = File::from(open(
            path,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let before = pin.metadata()?;
        if !before.is_file() || before.len() > 65_536 {
            return Err(io::Error::other("invalid configuration file"));
        }
        let fd_path = format!("/proc/self/fd/{}", pin.as_raw_fd());
        let readable = File::from(open(
            fd_path.as_str(),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let after = readable.metadata()?;
        if !after.is_file() || before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(io::Error::other("configuration identity changed"));
        }
        readable
    };
    #[cfg(not(target_os = "linux"))]
    let file = File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > 65_536 {
        return Err(io::Error::other("invalid configuration file"));
    }
    ParsedConfig::read(file).map_err(|_| io::Error::other("configuration parse rejected"))
}
pub fn reload_loop(server: &Server, path: &Path, signals: &Signals) {
    while !signals.shutdown.load(Ordering::Acquire) {
        if signals.reload.swap(false, Ordering::AcqRel) {
            match read_config(path) {
                Ok(parsed) => match parsed.compile() {
                    Ok(config) => {
                        let _ = server.reload(&config, &signals.shutdown);
                    }
                    Err(_) => server.observe.reload(false, server.generation()),
                },
                Err(_) => server.observe.reload(false, server.generation()),
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
}
pub fn monitor(
    listener: TcpListener,
    server: &Server,
    identity: Option<&tls::Identity>,
    shutdown: &AtomicBool,
    done: &AtomicBool,
) -> io::Result<()> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(io::Error::other("monitor requires loopback"));
    }
    listener.set_nonblocking(true)?;
    while !done.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false)?;
                let deadline = Instant::now() + Duration::from_millis(500);
                let result = (|| -> io::Result<()> {
                    let head = http::read_head(&mut stream, deadline)?;
                    let req = http::parse(&head, stream.local_addr()?.port())
                        .map_err(|_| io::Error::other("invalid monitor request"))?;
                    let draining = shutdown.load(Ordering::Acquire) || server.is_draining();
                    let cert = identity.and_then(tls::Identity::certificate_times);
                    let valid = cert
                        .zip(tls::unix_now().ok())
                        .is_some_and(|((b, e), n)| b <= n && n < e);
                    let ready = pathward::runtime::ready(
                        draining,
                        server.observe.serving.load(Ordering::Acquire),
                        identity.is_some(),
                        valid,
                    );
                    let (status, body) = if req.method != b"GET" {
                        (405, String::new())
                    } else {
                        match req.target {
                            b"/healthz" => (200, "ok\n".into()),
                            b"/readyz" => {
                                if ready {
                                    (200, "ready\n".into())
                                } else {
                                    (503, "unavailable\n".into())
                                }
                            }
                            b"/metrics" => (
                                200,
                                server.observe.metrics(
                                    server.generation(),
                                    ready,
                                    draining,
                                    identity.is_some(),
                                    cert,
                                ),
                            ),
                            _ => (404, String::new()),
                        }
                    };
                    http::write_all(
                        &mut stream,
                        http::response_head(
                            status,
                            body.len() as u64,
                            "text/plain; version=0.0.4; charset=utf-8",
                        )
                        .replace("Allow: GET, HEAD", "Allow: GET")
                        .as_bytes(),
                        deadline,
                    )?;
                    http::write_all(&mut stream, body.as_bytes(), deadline)
                })();
                let _ = result;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        fs,
        io::{Read, Write},
        net::TcpStream,
        time::{SystemTime, UNIX_EPOCH},
    };
    fn get(port: u16, path: &str) -> Vec<u8> {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut result = Vec::new();
        stream.read_to_end(&mut result).unwrap();
        result
    }
    #[test]
    fn monitoring_tracks_certificate_validity_and_drain_without_exposing_secrets() {
        let root = std::env::temp_dir().join(format!(
            "pathward-monitor-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        struct Tree(std::path::PathBuf);
        impl Drop for Tree {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _tree = Tree(root.clone());
        let parsed = ParsedConfig::parse(&format!(
            "site \"example.com\" {{\nroot \"{}\"\npublish \"/\" \"index.html\"\ntls \"auto\"\n}}",
            root.display()
        ))
        .unwrap();
        let server = Server::new(&parsed.compile().unwrap()).unwrap();
        let identity = tls::Identity::new(vec!["example.com".into()], None);
        let stop = AtomicBool::new(false);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::scope(|scope| {
            struct Stop<'a>(&'a AtomicBool);
            impl Drop for Stop<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Release);
                }
            }
            let _stop = Stop(&stop);
            scope.spawn(|| monitor(listener, &server, Some(&identity), &stop, &stop).unwrap());
            server.observe.serving.store(true, Ordering::Release);
            assert!(get(port, "/healthz").starts_with(b"HTTP/1.1 200"));
            assert!(get(port, "/readyz").starts_with(b"HTTP/1.1 503"));
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
            let pem = format!("{}{}", key_pair.serialize_pem(), cert.pem());
            let cert = tls::Certificate::parse(pem.as_bytes(), &["example.com".into()]).unwrap();
            identity.install(cert, true).unwrap();
            assert!(get(port, "/readyz").starts_with(b"HTTP/1.1 200"));
            let metrics = String::from_utf8(get(port, "/metrics")).unwrap();
            assert!(metrics.contains("pathward_certificate_present 1\n"));
            assert!(
                !metrics.contains("PRIVATE KEY")
                    && !metrics.contains("example.com")
                    && !metrics.contains(root.to_str().unwrap())
            );
            let mut expired =
                tls::Certificate::parse(pem.as_bytes(), &["example.com".into()]).unwrap();
            expired.not_after = 0; // Simulate the clock passing the active certificate's expiration.
            *identity.certificate.write().unwrap() = Some(Arc::new(expired));
            assert!(get(port, "/readyz").starts_with(b"HTTP/1.1 503"));
            server.begin_shutdown();
            assert!(
                get(port, "/metrics")
                    .windows(b"pathward_draining 1\n".len())
                    .any(|s| s == b"pathward_draining 1\n")
            );
            assert!(get(port, "/readyz").starts_with(b"HTTP/1.1 503"));
            stop.store(true, Ordering::Release);
        });
        let public = TcpListener::bind("0.0.0.0:0").unwrap();
        assert!(monitor(public, &server, None, &stop, &stop).is_err());
    }
}
