//! Minimal HTTP/1.1 serving on loopback, using the verified publication gate.
#![forbid(unsafe_code)]

pub mod acme;
mod admission;
pub mod control;
pub mod deployment;
pub mod files;
pub mod http;
pub mod observe;
mod proxy;
mod runtime;
pub mod secrets;
pub mod tls;
mod work;

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
    protected: RwLock<Vec<PathBuf>>,
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
            protected: RwLock::new(Vec::new()),
            observe: Arc::new(observe::Observability::default()),
        })
    }
    pub fn check_files(&self) -> io::Result<usize> {
        let snapshot = self
            .state
            .read()
            .map_err(|_| io::Error::other("state lock"))?
            .snapshot
            .clone();
        snapshot.check_files()
    }
    pub fn cache_path(&self) -> Option<&Path> {
        self.cache.as_deref()
    }
    pub fn observability(&self) -> Arc<observe::Observability> {
        self.observe.clone()
    }
    pub fn status(&self) -> (u64, String) {
        self.state
            .read()
            .map(|s| {
                (
                    s.generation,
                    crate::deployment::revision(s.snapshot.source.as_bytes()),
                )
            })
            .unwrap_or_default()
    }
    pub fn revision(&self) -> String {
        self.status().1
    }
    pub fn protect_directory(&self, path: &Path) -> io::Result<()> {
        let _serial = self
            .reload_lock
            .lock()
            .map_err(|_| io::Error::other("reload lock"))?;
        let state = self
            .state
            .read()
            .map_err(|_| io::Error::other("state lock"))?;
        let parsed = pathward_config::ParsedConfig::parse(&state.snapshot.source)
            .map_err(|_| io::Error::other("config"))?;
        let config = parsed.compile().map_err(|_| io::Error::other("config"))?;
        if !Snapshot::isolated(&config, Some(path)) {
            return Err(io::Error::other("private storage overlaps public root"));
        }
        let mut protected = self
            .protected
            .write()
            .map_err(|_| io::Error::other("private paths"))?;
        if !protected.is_empty() {
            return Err(io::Error::other("private directory already set"));
        }
        protected.push(path.to_owned());
        Ok(())
    }
    fn isolated(&self, config: &CompiledConfig<'_>) -> bool {
        Snapshot::isolated(config, self.cache.as_deref())
            && self
                .protected
                .read()
                .is_ok_and(|paths| paths.iter().all(|p| Snapshot::isolated(config, Some(p))))
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
        let _serial = self
            .reload_lock
            .lock()
            .map_err(|_| io::Error::other("reload lock"))?;
        let result = self.reload_inner(config, shutdown);
        self.observe.reload(result.is_ok(), self.generation());
        result
    }
    pub fn reload_file(&self, path: &Path, shutdown: &AtomicBool) -> io::Result<u64> {
        let _serial = self
            .reload_lock
            .lock()
            .map_err(|_| io::Error::other("reload lock"))?;
        let result = (|| {
            let parsed = control::read_config(path)?;
            let config = parsed
                .compile()
                .map_err(|_| io::Error::other("config rejected"))?;
            self.reload_inner(&config, shutdown)
        })();
        self.observe.reload(result.is_ok(), self.generation());
        result
    }
    fn reload_inner(&self, config: &CompiledConfig<'_>, shutdown: &AtomicBool) -> io::Result<u64> {
        let (expected, identity_matches) = {
            let state = self
                .state
                .read()
                .map_err(|_| io::Error::other("state lock"))?;
            (state.generation, state.snapshot.same_hosts(config))
        };
        let isolated = self.isolated(config);
        if !identity_matches || !isolated || shutdown.load(Ordering::Acquire) || self.is_draining()
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
        automatic_redirect: bool,
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
        let authority_port = pathward::response::authority_port(
            stream.local_port()?,
            sni.is_some(),
            automatic_redirect,
        );
        let boundary = head
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| io::Error::other("missing head"))?
            + 4;
        let (head, prefetched) = head.split_at(boundary);
        let req = match http::parse_framed(head, authority_port) {
            Ok(req) => req,
            Err(http::Rejection(status)) => return Self::reject(stream, status),
        };
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
        let path = if site.upstream.is_some() && pathward::proxy::target_allowed(req.target) {
            &req.target[..pathward::serving::path_length(req.target)]
        } else {
            pathward::serving::request_path(req.target).unwrap_or(b"")
        };
        let reject = |stream: &mut _, status| -> io::Result<(u16, u64)> {
            http::write_all(
                stream,
                site.head(status, 0, "text/plain", path, sni.is_some())
                    .as_bytes(),
                Instant::now() + Duration::from_secs(1),
            )?;
            Ok((status, 0))
        };
        if let Some(upstream) = site.upstream {
            if !pathward::proxy::method_allowed(req.method) {
                return reject(stream, 405);
            }
            if !pathward::proxy::target_allowed(req.target) {
                return reject(stream, 400);
            }
            if !pathward::proxy::request_framing(req.content_length, false, false) {
                return reject(stream, 413);
            }
            if automatic_redirect {
                let mut head = site.head(308, 0, "text/plain", path, false);
                head.truncate(head.len() - 2);
                head.push_str(&format!(
                    "Location: https://{}{}\r\n\r\n",
                    site.host,
                    std::str::from_utf8(req.target).map_err(|_| io::Error::other("target"))?
                ));
                http::write_all(
                    stream,
                    head.as_bytes(),
                    Instant::now() + Duration::from_secs(1),
                )?;
                return Ok((308, 0));
            }
            let response = match proxy::forward(
                upstream,
                &req,
                prefetched,
                stream,
                accepted,
                sni.is_some(),
                authority_port,
            ) {
                Ok(response) => response,
                Err(http::Rejection(status)) => return reject(stream, status),
            };
            let deadline = accepted + http::READ_BUDGET + http::WRITE_BUDGET;
            http::write_all(
                stream,
                site.proxy_head(&response, path, sni.is_some()).as_bytes(),
                deadline,
            )?;
            http::write_all(stream, &response.body, deadline)?;
            return Ok((response.status, response.body.len() as u64));
        }
        if req.content_length != 0 || !prefetched.is_empty() {
            return Self::reject(stream, 400);
        }
        if req.method != b"GET" && req.method != b"HEAD" {
            return Self::reject(stream, 405);
        }
        if let Some((status, location)) =
            site.redirect(req.target, &snapshot.sites, automatic_redirect)
        {
            let mut head = site.head(status, 0, "text/plain", path, sni.is_some());
            head.truncate(head.len() - 2);
            head.push_str("Location: ");
            head.push_str(&location);
            head.push_str("\r\n\r\n");
            http::write_all(
                stream,
                head.as_bytes(),
                Instant::now() + Duration::from_secs(1),
            )?;
            return Ok((status, 0));
        }
        if automatic_redirect {
            return reject(stream, 404);
        }
        let publications = site.publications();
        let Some(grant) = authorize(
            req.method,
            req.host.as_bytes(),
            site.host.as_bytes(),
            req.target,
            &publications,
        ) else {
            return reject(stream, 404);
        };
        let target = std::str::from_utf8(grant.target)
            .map_err(|_| io::Error::other("invalid verified target"))?;
        // This is the only serving-file open. It is reachable only after a grant.
        let Some(root) = site.root.as_ref() else {
            return reject(stream, 404);
        };
        let mut opened = match root.open_file(target) {
            Ok(file) => file,
            Err(_) => return reject(stream, 404),
        };
        let deadline = Instant::now() + http::WRITE_BUDGET;
        http::write_all(
            stream,
            site.head(
                200,
                opened.length,
                http::content_type(target),
                path,
                sni.is_some(),
            )
            .as_bytes(),
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
        let result = Self::respond(&snapshot, stream, accepted, sni, false);
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
        self.serve_transport(listener, None, shutdown, None)
    }
    pub fn serve_tls(
        &self,
        listener: TcpListener,
        shutdown: &AtomicBool,
        tls: &tls::TlsServer,
    ) -> io::Result<()> {
        self.serve_transport(listener, None, shutdown, Some(tls))
    }
    pub fn serve_tls_with_redirect(
        &self,
        listener: TcpListener,
        redirect: TcpListener,
        shutdown: &AtomicBool,
        tls: &tls::TlsServer,
    ) -> io::Result<()> {
        self.serve_transport(listener, Some(redirect), shutdown, Some(tls))
    }
    fn serve_transport(
        &self,
        listener: TcpListener,
        redirect: Option<TcpListener>,
        shutdown: &AtomicBool,
        tls: Option<&tls::TlsServer>,
    ) -> io::Result<()> {
        listener.set_nonblocking(true)?;
        if let Some(redirect) = &redirect {
            redirect.set_nonblocking(true)?;
        }
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
        let admission = Arc::new(admission::Admission::new());
        let result = thread::scope(|scope| {
            let receive = work::Queue::<(TcpStream, Instant, bool, admission::Permit)>::new();
            for i in 0..WORKERS {
                let worker_queue = receive.clone();
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
                            let Some(((mut stream, accepted, redirect_only, _permit), _running)) =
                                worker_queue.take(shutdown)
                            else {
                                break;
                            };
                            let _active = self.observe.connection();
                            if !shutdown.load(Ordering::Acquire)
                                && stream.set_nonblocking(false).is_ok()
                            {
                                if redirect_only {
                                    if let Ok(state) = self.state.read() {
                                        let snapshot = state.snapshot.clone();
                                        let generation = state.generation;
                                        drop(state);
                                        let start = Instant::now();
                                        let result = Self::respond(
                                            &snapshot,
                                            &mut stream,
                                            accepted,
                                            None,
                                            true,
                                        );
                                        self.observe.request(generation, start.elapsed(), &result);
                                    }
                                    let _ = stream.shutdown(Shutdown::Both);
                                    continue;
                                }
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
                    receive.close();
                    return Err(e);
                }
            }
            let result = 'accept: loop {
                if shutdown.load(Ordering::Acquire) {
                    break Ok(());
                }
                let mut accepted_any = false;
                for (listener, redirect_only) in
                    std::iter::once((&listener, false)).chain(redirect.iter().map(|l| (l, true)))
                {
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            accepted_any = true;
                            self.observe.accepted.fetch_add(1, Ordering::Relaxed);
                            let Some(permit) =
                                admission.acquire(peer.ip(), shutdown.load(Ordering::Acquire))
                            else {
                                self.observe
                                    .admission_rejected
                                    .fetch_add(1, Ordering::Relaxed);
                                let _ = stream.shutdown(Shutdown::Both);
                                continue;
                            };
                            if let Err((stream, _, _, _permit)) = receive.push(
                                permit.peer(),
                                (stream, Instant::now(), redirect_only, permit),
                            ) {
                                self.observe.overloaded.fetch_add(1, Ordering::Relaxed);
                                let _ = stream.shutdown(Shutdown::Both);
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) => {}
                        Err(e) => break 'accept Err(e),
                    }
                }
                if !accepted_any {
                    thread::sleep(Duration::from_millis(10));
                }
            };
            shutdown.store(true, Ordering::Release);
            self.begin_shutdown();
            drop(listener);
            drop(redirect);
            self.observe.serving.store(false, Ordering::Release);
            self.observe.event("draining", self.generation(), 0);
            receive.close();
            result
        });
        self.begin_shutdown();
        self.observe.serving.store(false, Ordering::Release);
        self.observe.event("stopped", self.generation(), 0);
        result
    }
}

#[cfg(all(test, target_os = "linux"))]
mod response_tests;
