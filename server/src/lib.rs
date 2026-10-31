//! Minimal HTTP/1.1 serving on loopback, using the verified publication gate.
#![forbid(unsafe_code)]

pub mod acme;
pub mod files;
pub mod http;
pub mod secrets;
pub mod tls;

use files::DocumentRoot;
use pathward::serving::authorize;
use pathward_config::{CompiledConfig, CompiledSite};
use std::{
    io::{self, Read},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

pub const WORKERS: usize = 4;
pub const QUEUE_CAPACITY: usize = 8;

struct Site<'a> {
    config: &'a CompiledSite<'a>,
    root: DocumentRoot,
}

pub struct Server<'a> {
    sites: Vec<Site<'a>>,
}

impl<'a> Server<'a> {
    pub fn new(config: &'a CompiledConfig<'a>) -> io::Result<Self> {
        let mut sites = Vec::with_capacity(config.sites().len());
        for site in config.sites() {
            sites.push(Site {
                config: site,
                root: DocumentRoot::open(site.root())?,
            });
        }
        Ok(Self { sites })
    }

    fn reject(stream: &mut impl http::Transport, status: u16) -> io::Result<()> {
        // Error responses contain no reflected paths, hosts, or error details.
        http::write_all(
            stream,
            http::response_head(status, 0, "text/plain").as_bytes(),
            Instant::now() + Duration::from_secs(1),
        )
    }

    fn handle(
        &self,
        stream: &mut impl http::Transport,
        accepted: Instant,
        sni: Option<&str>,
    ) -> io::Result<()> {
        let head = match http::read_head(stream, accepted + http::READ_BUDGET) {
            Ok(head) => head,
            Err(e) => {
                return Self::reject(
                    stream,
                    match e.kind() {
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => 408,
                        io::ErrorKind::InvalidData => 431,
                        _ => 400,
                    },
                );
            }
        };
        let req = match http::parse(&head, stream.local_port()?) {
            Ok(req) => req,
            Err(http::Rejection(status)) => return Self::reject(stream, status),
        };
        if req.method != b"GET" && req.method != b"HEAD" {
            return Self::reject(stream, 405);
        }
        let Some(site) = self.sites.iter().find(|s| s.config.host() == req.host) else {
            return Self::reject(stream, 421);
        };
        if let Some(sni) = sni
            && !pathward::tls::identity_allowed(
                sni.as_bytes(),
                req.host.as_bytes(),
                site.config.host().as_bytes(),
            )
        {
            return Self::reject(stream, 421);
        }
        let Some(grant) = authorize(
            req.method,
            req.host.as_bytes(),
            site.config.host().as_bytes(),
            req.target,
            site.config.publications(),
        ) else {
            return Self::reject(stream, 404);
        };
        let target = std::str::from_utf8(grant.target)
            .map_err(|_| io::Error::other("invalid verified target"))?;
        // This is the only serving-file open. It is reachable only after a grant.
        let mut opened = match site.root.open_file(target) {
            Ok(file) => file,
            Err(_) => return Self::reject(stream, 404),
        };
        let deadline = Instant::now() + http::WRITE_BUDGET;
        http::write_all(
            stream,
            http::response_head(200, opened.length, http::content_type(target)).as_bytes(),
            deadline,
        )?;
        if grant.send_body {
            let mut left = opened.length;
            let mut buffer = [0u8; 16_384];
            while left > 0 {
                let size = buffer.len().min(left as usize);
                let n = opened.file.read(&mut buffer[..size])?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "file changed"));
                }
                http::write_all(stream, &buffer[..n], deadline)?;
                left -= n as u64;
            }
        }
        Ok(())
    }

    /// One request per connection. Fixed workers and bounded pending sockets.
    /// Shutdown is programmatic; CLI signal integration is a later milestone.
    pub fn serve(&self, listener: TcpListener, shutdown: &AtomicBool) -> io::Result<()> {
        if !listener.local_addr()?.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HTTP-only mode requires a loopback listener",
            ));
        }
        self.serve_transport(listener, shutdown, None)
    }
    pub fn serve_tls(
        &self,
        listener: TcpListener,
        shutdown: &AtomicBool,
        tls: &tls::TlsServer,
    ) -> io::Result<()> {
        self.serve_transport(listener, shutdown, Some(tls))
    }
    fn serve_transport(
        &self,
        listener: TcpListener,
        shutdown: &AtomicBool,
        tls: Option<&tls::TlsServer>,
    ) -> io::Result<()> {
        listener.set_nonblocking(true)?;
        thread::scope(|scope| {
            let (send, receive) = mpsc::sync_channel::<(TcpStream, Instant)>(QUEUE_CAPACITY);
            let receive = Arc::new(Mutex::new(receive));
            for i in 0..WORKERS {
                let receive = receive.clone();
                if let Err(e) = thread::Builder::new()
                    .name(format!("pathward-{i}"))
                    .spawn_scoped(scope, move || {
                        loop {
                            let job = match receive.lock() {
                                Ok(receiver) => receiver.recv(),
                                Err(_) => break,
                            };
                            let Ok((mut stream, accepted)) = job else {
                                break;
                            };
                            if !shutdown.load(Ordering::Acquire)
                                && stream.set_nonblocking(false).is_ok()
                            {
                                if let Some(tls) = tls {
                                    // Own the socket through the entire TLS exchange.
                                    if let Ok(Some(mut encrypted)) = tls.accept(stream, accepted) {
                                        let sni = encrypted.sni.clone();
                                        let _ =
                                            self.handle(&mut encrypted, Instant::now(), Some(&sni));
                                        let _ = encrypted.finish();
                                    }
                                    continue;
                                }
                                let _ = self.handle(&mut stream, accepted, None);
                            }
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                    })
                {
                    drop(send);
                    return Err(e);
                }
            }
            let result = loop {
                if shutdown.load(Ordering::Acquire) {
                    break Ok(());
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(e) = send.try_send((stream, Instant::now())) {
                            let (mpsc::TrySendError::Full((stream, _))
                            | mpsc::TrySendError::Disconnected((stream, _))) = e;
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => break Err(e),
                }
            };
            drop(send);
            result
        })
    }
}
