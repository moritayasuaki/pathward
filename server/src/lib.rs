//! Minimal HTTP/1.1 serving on loopback, using the verified publication gate.
#![forbid(unsafe_code)]

pub mod acme;
pub mod control;
pub mod files;
pub mod http;
pub mod observe;
mod runtime;
pub mod secrets;
pub mod tls;

use pathward::serving::authorize;
use pathward_config::CompiledConfig;
use runtime::Snapshot;
use std::path::{Path, PathBuf};
use std::{
    io::{self, Read},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

pub const WORKERS: usize = 4;
pub const QUEUE_CAPACITY: usize = 8;

struct State {
    generation: u64,
    draining: bool,
    snapshot: Arc<Snapshot>,
}

pub struct Server {
    state: RwLock<State>,
    reload_lock: Mutex<()>,
    cache: Option<PathBuf>,
    observe: Arc<observe::Observability>,
}

impl Server {
    pub fn new(config: &CompiledConfig<'_>) -> io::Result<Self> {
        Self::new_with_cache(config, None)
    }
    /// The cache path must be the same canonical absolute path passed to Manager.
    pub fn new_with_cache(config: &CompiledConfig<'_>, cache: Option<&Path>) -> io::Result<Self> {
        Ok(Self {
            state: RwLock::new(State {
                generation: 1,
                draining: false,
                snapshot: Arc::new(Snapshot::prepare(config, cache)?),
            }),
            reload_lock: Mutex::new(()),
            cache: cache.map(Path::to_owned),
            observe: Arc::new(observe::Observability::default()),
        })
    }
    pub fn observability(&self) -> Arc<observe::Observability> {
        self.observe.clone()
    }
    pub fn generation(&self) -> u64 {
        self.state.read().map(|s| s.generation).unwrap_or(0)
    }
    pub fn is_draining(&self) -> bool {
        self.state.read().map(|s| s.draining).unwrap_or(true)
    }
    pub(crate) fn begin_shutdown(&self) {
        if let Ok(mut state) = self.state.write() {
            state.draining = true;
        }
    }
    /// Serialize preparation to bound descriptors and memory under repeated reloads.
    /// No mutation of the active snapshot occurs until every candidate root is open.
    pub fn reload(&self, config: &CompiledConfig<'_>, shutdown: &AtomicBool) -> io::Result<u64> {
        let result = (|| {
            let _serial = self
                .reload_lock
                .lock()
                .map_err(|_| io::Error::other("reload lock"))?;
            let (expected, identity_matches) = {
                let state = self
                    .state
                    .read()
                    .map_err(|_| io::Error::other("state lock"))?;
                (state.generation, state.snapshot.same_hosts(config))
            };
            let isolated = Snapshot::isolated(config, self.cache.as_deref());
            if !identity_matches
                || !isolated
                || shutdown.load(Ordering::Acquire)
                || self.is_draining()
            {
                return Err(io::Error::other("reload policy rejected"));
            }
            let candidate = Arc::new(Snapshot::prepare(config, self.cache.as_deref())?);
            let mut state = self
                .state
                .write()
                .map_err(|_| io::Error::other("state lock"))?;
            let next = pathward::runtime::commit_generation(
                state.generation,
                expected,
                true,
                identity_matches,
                isolated,
                state.draining || shutdown.load(Ordering::Acquire),
            );
            if next == state.generation {
                return Err(io::Error::other("reload commit rejected"));
            }
            state.snapshot = candidate;
            state.generation = next;
            Ok(next)
        })();
        self.observe.reload(result.is_ok(), self.generation());
        result
    }

    fn reject(stream: &mut impl http::Transport, status: u16) -> io::Result<(u16, u64)> {
        // Error responses contain no reflected paths, hosts, or error details.
        http::write_all(
            stream,
            http::response_head(status, 0, "text/plain").as_bytes(),
            Instant::now() + Duration::from_secs(1),
        )?;
        Ok((status, 0))
    }

    fn respond(
        snapshot: &Snapshot,
        stream: &mut impl http::Transport,
        accepted: Instant,
        sni: Option<&str>,
    ) -> io::Result<(u16, u64)> {
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
        let Some(site) = snapshot.sites.iter().find(|s| s.host == req.host) else {
            return Self::reject(stream, 421);
        };
        if let Some(sni) = sni
            && !pathward::tls::identity_allowed(
                sni.as_bytes(),
                req.host.as_bytes(),
                site.host.as_bytes(),
            )
        {
            return Self::reject(stream, 421);
        }
        let publications = site.publications();
        let Some(grant) = authorize(
            req.method,
            req.host.as_bytes(),
            site.host.as_bytes(),
            req.target,
            &publications,
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
        Ok((200, if grant.send_body { opened.length } else { 0 }))
    }

    fn handle(
        &self,
        stream: &mut impl http::Transport,
        accepted: Instant,
        sni: Option<&str>,
    ) -> io::Result<()> {
        let (generation, snapshot) = {
            let state = self
                .state
                .read()
                .map_err(|_| io::Error::other("state lock"))?;
            (state.generation, state.snapshot.clone())
        };
        let start = Instant::now();
        let result = Self::respond(&snapshot, stream, accepted, sni);
        self.observe.request(generation, start.elapsed(), &result);
        result.map(|_| ())
    }

    /// One request per connection. Fixed workers and bounded pending sockets.
    /// Stop accepting, discard queued connections, and drain active bounded I/O.
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
        {
            let state = self
                .state
                .write()
                .map_err(|_| io::Error::other("state lock"))?;
            if state.draining || self.observe.serving.load(Ordering::Acquire) {
                return Err(io::Error::other("server already started or draining"));
            }
            self.observe.serving.store(true, Ordering::Release);
        }
        let result = thread::scope(|scope| {
            let (send, receive) = mpsc::sync_channel::<(TcpStream, Instant)>(QUEUE_CAPACITY);
            let receive = Arc::new(Mutex::new(receive));
            for i in 0..WORKERS {
                let receive = receive.clone();
                if let Err(e) = thread::Builder::new()
                    .name(format!("pathward-{i}"))
                    .spawn_scoped(scope, move || {
                        struct StopOnExit<'a>(&'a AtomicBool);
                        impl Drop for StopOnExit<'_> {
                            fn drop(&mut self) {
                                self.0.store(true, Ordering::Release);
                            }
                        }
                        let _stop = StopOnExit(shutdown);
                        loop {
                            let job = match receive.lock() {
                                Ok(receiver) => receiver.recv(),
                                Err(_) => break,
                            };
                            let Ok((mut stream, accepted)) = job else {
                                break;
                            };
                            let _active = self.observe.connection();
                            if !shutdown.load(Ordering::Acquire)
                                && stream.set_nonblocking(false).is_ok()
                            {
                                if let Some(tls) = tls {
                                    // Own the socket through the entire TLS exchange.
                                    match tls.accept(stream, accepted) {
                                        Ok(Some(mut encrypted)) => {
                                            let sni = encrypted.sni.clone();
                                            let _ = self.handle(
                                                &mut encrypted,
                                                Instant::now(),
                                                Some(&sni),
                                            );
                                            let _ = encrypted.finish();
                                        }
                                        Ok(None) => {}
                                        Err(_) => self.observe.tls_failed(),
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
                    self.begin_shutdown();
                    break Ok(());
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        self.observe.accepted.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = send.try_send((stream, Instant::now())) {
                            self.observe.overloaded.fetch_add(1, Ordering::Relaxed);
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
            shutdown.store(true, Ordering::Release);
            self.begin_shutdown();
            drop(listener);
            self.observe.serving.store(false, Ordering::Release);
            self.observe.event("draining", self.generation(), 0);
            drop(send);
            result
        });
        self.begin_shutdown();
        self.observe.serving.store(false, Ordering::Release);
        self.observe.event("stopped", self.generation(), 0);
        result
    }
}
