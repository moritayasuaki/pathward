//! Minimal HTTP/1.1 serving on loopback, using the verified publication gate.
#![forbid(unsafe_code)]

#[cfg(test)]
mod browser_fixture;

pub mod acme;
mod admission;
mod async_http;
pub mod control;
mod delivery;
pub mod deployment;
mod encoding;
pub mod files;
pub mod http;
mod http3;
mod multiplex;
pub mod observe;
mod proxy;
mod quic_bounds;
mod runtime;
pub mod secrets;
mod static_files;
mod stream_pool;
mod streaming;
pub mod tls;
mod work;

use crate::http::Transport;
use pathward::serving::authorize;
use pathward_config::CompiledConfig;
use runtime::Snapshot;
use std::path::{Path, PathBuf};
use std::{
    io::{self, Read},
    net::{Shutdown, TcpListener},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub const WORKERS: usize = 4;
pub const QUEUE_CAPACITY: usize = 8;

enum Handoff {
    Stream(stream_pool::Prepared),
    Output(delivery::Prepared),
}
struct ResponseHandoff<'a> {
    prepared: Option<Handoff>,
    budget: &'a delivery::Budget,
    peer: std::net::IpAddr,
    reuse: bool,
    head_validated: bool,
    early: bool,
    http3_port: u16,
}
impl ResponseHandoff<'_> {
    fn advertise(&self, head: &mut String, tls: bool) {
        if tls && self.http3_port != 0 {
            head.truncate(head.len() - 2);
            head.push_str(&format!(
                "Alt-Svc: h3=\":{}\"; ma=60\r\n\r\n",
                self.http3_port
            ));
        }
    }
}

struct State {
    generation: u64,
    draining: bool,
    snapshot: Arc<Snapshot>,
}

pub struct Server {
    shared_nat: bool,
    http3_port: AtomicU16,
    pending_requests: AtomicU64,
    state: RwLock<State>,
    reload_lock: Mutex<()>,
    stream_quota: streaming::Quota,
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
            shared_nat: config.shared_nat(),
            http3_port: AtomicU16::new(0),
            pending_requests: AtomicU64::new(0),
            state: RwLock::new(State {
                generation: 1,
                draining: false,
                snapshot: Arc::new(Snapshot::prepare(config, cache)?),
            }),
            reload_lock: Mutex::new(()),
            stream_quota: streaming::Quota::default(),
            cache: cache.map(Path::to_owned),
            protected: RwLock::new(Vec::new()),
            observe: Arc::new(observe::Observability::for_capacity(config.shared_nat())),
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
        if !identity_matches
            || !pathward::release::capacity_reload_allowed(self.shared_nat, config.shared_nat())
            || !isolated
            || shutdown.load(Ordering::Acquire)
            || self.is_draining()
        {
            return Err(io::Error::other("reload policy rejected"));
        }
        let mut candidate = Snapshot::prepare(config, self.cache.as_deref())?;
        candidate.inherit_budgets(
            &self
                .state
                .read()
                .map_err(|_| io::Error::other("state lock"))?
                .snapshot,
        );
        let candidate = Arc::new(candidate);
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
        candidate.install_limits();
        state.snapshot = candidate;
        state.generation = next;
        Ok(next)
    }

    async fn reject(stream: &mut impl http::Transport, status: u16) -> io::Result<(u16, u64)> {
        // Error responses contain no reflected paths, hosts, or error details.
        async_http::write_all(
            stream,
            http::response_head(status, 0, "text/plain").as_bytes(),
            Instant::now() + Duration::from_secs(1),
        )
        .await?;
        Ok((status, 0))
    }

    #[allow(clippy::too_many_arguments)]
    async fn respond_async(
        snapshot: &Snapshot,
        stream: &mut impl http::Transport,
        accepted: Instant,
        sni: Option<&str>,
        automatic_redirect: bool,
        quota: &streaming::Quota,
        stopping: &dyn Fn() -> bool,
        mut handoff: Option<&mut ResponseHandoff<'_>>,
    ) -> io::Result<(u16, u64)> {
        let head_deadline = if handoff.as_ref().is_some_and(|h| h.head_validated) {
            Instant::now() + Duration::from_secs(1)
        } else {
            accepted + http::READ_BUDGET
        };
        let head = match async_http::read_head(stream, head_deadline).await {
            Ok(head) => head,
            Err(e) => {
                return Self::reject(
                    stream,
                    match e.kind() {
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => 408,
                        io::ErrorKind::InvalidData => 431,
                        _ => 400,
                    },
                )
                .await;
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
            Err(http::Rejection(status)) => return Self::reject(stream, status).await,
        };
        if let Some(out) = &mut handoff {
            out.reuse = !req.upgrade
                && req.headers.iter().any(|h| {
                    h.name.eq_ignore_ascii_case("connection")
                        && h.value.eq_ignore_ascii_case(b"keep-alive")
                });
        }
        let Some(site) = snapshot.sites.iter().find(|s| s.host == req.host) else {
            return Self::reject(stream, 421).await;
        };
        if let Some(sni) = sni
            && !pathward::tls::identity_allowed(
                sni.as_bytes(),
                req.host.as_bytes(),
                site.host.as_bytes(),
            )
        {
            return Self::reject(stream, 421).await;
        }
        if let Err(e) = encoding::validate(&req, site.encoding) {
            return Self::reject(stream, encoding::rejection(&e)).await;
        }
        let path = if site.upstream.is_some() && pathward::proxy::target_allowed(req.target) {
            &req.target[..pathward::serving::path_length(req.target)]
        } else {
            pathward::serving::request_path(req.target).unwrap_or(b"")
        };
        let reject = async |stream: &mut _, status| -> io::Result<(u16, u64)> {
            async_http::write_all(
                stream,
                site.head(status, 0, "text/plain", req.target, sni.is_some())
                    .as_bytes(),
                Instant::now() + Duration::from_secs(1),
            )
            .await?;
            Ok((status, 0))
        };
        let route = site.route(req.target);
        let mut early = handoff.as_ref().is_some_and(|h| h.early);
        for h in &req.headers {
            if h.name.eq_ignore_ascii_case("early-data") {
                if h.value != b"1" {
                    return reject(stream, 400).await;
                }
                early = true;
            }
        }
        if early {
            let publications = site.publications();
            let published = route == pathward::routing::Route::Static
                && authorize(
                    req.method,
                    req.host.as_bytes(),
                    site.host.as_bytes(),
                    req.target,
                    &publications,
                )
                .is_some();
            let sensitive = req.target.contains(&b'?')
                || req.headers.iter().any(|h| {
                    h.name.eq_ignore_ascii_case("cookie")
                        || h.name.eq_ignore_ascii_case("authorization")
                });
            if !pathward::delivery::early_allowed(
                false,
                req.method == b"GET" || req.method == b"HEAD",
                published,
                req.content_length,
                sensitive,
            ) {
                return reject(stream, 425).await;
            }
        }

        if route == pathward::routing::Route::Denied {
            // Preserve the whole-host proxy's malformed-target status; policy
            // denials and ambiguous spellings in routing sites remain generic 404.
            return reject(
                stream,
                if !pathward::proxy::target_allowed(req.target) && site.upstream.is_some() {
                    400
                } else {
                    404
                },
            )
            .await;
        }
        if route == pathward::routing::Route::Missing {
            return reject(stream, 404).await;
        }
        if route == pathward::routing::Route::Proxy {
            let upstream = site
                .upstream
                .ok_or_else(|| io::Error::other("proxy route without upstream"))?;
            if !pathward::proxy::method_allowed(req.method) {
                return reject(stream, 405).await;
            }
            if !pathward::proxy::target_allowed(req.target) {
                return reject(stream, 400).await;
            }
            if !pathward::routing::request_framing(
                req.content_length,
                site.limits.request_bytes,
                false,
                false,
            ) {
                return reject(stream, 413).await;
            }
            if automatic_redirect {
                let mut head = site.head(308, 0, "text/plain", req.target, false);
                head.truncate(head.len() - 2);
                head.push_str(&format!(
                    "Location: https://{}{}\r\n\r\n",
                    site.host,
                    std::str::from_utf8(req.target).map_err(|_| io::Error::other("target"))?
                ));
                async_http::write_all(
                    stream,
                    head.as_bytes(),
                    Instant::now() + Duration::from_secs(1),
                )
                .await?;
                return Ok((308, 0));
            }
            if req.upgrade
                && let Err(http::Rejection(status)) = streaming::request(
                    &req,
                    prefetched.len(),
                    site.limits.websocket,
                    site.limits.deflate,
                    &site.websocket_origins,
                    sni.is_some(),
                    authority_port,
                )
            {
                return reject(stream, status).await;
            }
            // Brief bursts wait cooperatively, before any upstream side effect.
            // Pending tasks/inputs already hold admission and byte reservations;
            // no request is retried, nor can waiting extend the service deadline.
            let capacity_deadline = (Instant::now() + Duration::from_secs(1))
                .min(accepted + Duration::from_millis(site.limits.total_ms));
            let (_permit, delivery_lease) = loop {
                if stopping() || Instant::now() >= capacity_deadline {
                    return reject(stream, 503).await;
                }
                if let Some(permit) = site.acquire() {
                    if let Some(out) = &handoff {
                        if let Some(lease) = out.budget.reserve(
                            out.peer,
                            req.content_length + delivery::HEAD_BYTES as u64,
                            stopping(),
                        ) {
                            break (permit, Some(lease));
                        }
                    } else {
                        break (permit, None);
                    }
                }
                async_http::pause().await;
            };
            // Reserve WS capacity before any upstream side effect. SSE is only
            // identified after its response head, before committing downstream.
            let reserve = || {
                quota
                    .acquire_for(stream.peer_ip(), stopping())
                    .zip(site.acquire_stream())
            };
            let mut leases = if req.upgrade {
                Some(match reserve() {
                    Some(p) => p,
                    None => return reject(stream, 503).await,
                })
            } else {
                None
            };
            let mut response = match proxy::forward_async(
                upstream,
                &req,
                prefetched,
                stream,
                accepted,
                sni.is_some(),
                authority_port,
                site.limits,
                &site.websocket_origins,
                &site.proxy_routes,
                handoff.as_ref().map(|out| proxy::ResponseBudget {
                    budget: out.budget,
                    peer: out.peer,
                    stopping,
                }),
            )
            .await
            {
                Ok(response) => response,
                Err(http::Rejection(status)) => return reject(stream, status).await,
            };
            // Release the request charge after forwarding. Ordinary responses
            // now carry their own framing-sized storage reservation. Local
            // bodyless OPTIONS retains the original small metadata charge.
            let delivery_lease = response.delivery_lease.take().or(delivery_lease);
            if response.live.is_some() && leases.is_none() {
                leases = match quota
                    .acquire_for(stream.peer_ip(), stopping())
                    .zip(site.acquire_stream())
                {
                    Some(p) => Some(p),
                    None => return reject(stream, 503).await,
                };
            }
            let deadline = accepted + Duration::from_millis(site.limits.total_ms);
            if response.live.is_none() {
                if let Some(out) = handoff {
                    let mut head = site.proxy_head(&response, req.target, sni.is_some());
                    if let Err(e) = encoding::apply(
                        site.encoding,
                        &req,
                        &mut head,
                        &mut response.body,
                        out.budget,
                        out.peer,
                        stopping(),
                    ) {
                        return reject(stream, encoding::rejection(&e)).await;
                    }
                    out.advertise(&mut head, sni.is_some());
                    let prepared = delivery::Prepared::buffered(
                        head,
                        response.body,
                        response.status,
                        deadline,
                        delivery_lease.ok_or_else(|| io::Error::other("delivery lease"))?,
                    )?;
                    out.prepared = Some(Handoff::Output(prepared));
                    return Ok((response.status, 0));
                }
                async_http::write_all(
                    stream,
                    site.proxy_head(&response, req.target, sni.is_some())
                        .as_bytes(),
                    deadline,
                )
                .await?;
                async_http::write_all(stream, &response.body, deadline).await?;
                return Ok((response.status, response.body.len() as u64));
            }
            async_http::write_all(
                stream,
                site.proxy_head(&response, req.target, sni.is_some())
                    .as_bytes(),
                deadline,
            )
            .await?;
            if let Some(live) = response.live.take() {
                let (global, service) = leases.ok_or_else(|| io::Error::other("stream leases"))?;
                let prepared = stream_pool::Prepared {
                    live,
                    limits: site.limits,
                    status: response.status,
                    _global: global,
                    _service: service,
                };
                // An established stream no longer occupies the ordinary service cap.
                drop(_permit);
                if let Some(out) = handoff {
                    out.prepared = Some(Handoff::Stream(prepared));
                    return Ok((response.status, 0));
                }
                return prepared
                    .live
                    .run(stream, site.limits, stopping)
                    .map(|bytes| (response.status, bytes));
            }
            async_http::write_all(stream, &response.body, deadline).await?;
            return Ok((response.status, response.body.len() as u64));
        }
        if req.upgrade || req.content_length != 0 || !prefetched.is_empty() {
            return Self::reject(stream, 400).await;
        }
        if req.method != b"GET" && req.method != b"HEAD" {
            return Self::reject(stream, 405).await;
        }
        if let Some((status, location)) = site.redirect(
            req.target,
            &snapshot.sites,
            automatic_redirect,
            route == pathward::routing::Route::Redirect,
        ) {
            let mut head = site.head(status, 0, "text/plain", req.target, sni.is_some());
            head.truncate(head.len() - 2);
            head.push_str("Location: ");
            head.push_str(&location);
            head.push_str("\r\n\r\n");
            async_http::write_all(
                stream,
                head.as_bytes(),
                Instant::now() + Duration::from_secs(1),
            )
            .await?;
            return Ok((status, 0));
        }
        if automatic_redirect || route == pathward::routing::Route::Redirect {
            return reject(stream, 404).await;
        }
        let publications = site.publications();
        let Some(grant) = authorize(
            req.method,
            req.host.as_bytes(),
            site.host.as_bytes(),
            req.target,
            &publications,
        ) else {
            return reject(stream, 404).await;
        };
        let target = std::str::from_utf8(grant.target)
            .map_err(|_| io::Error::other("invalid verified target"))?;
        // This is the only serving-file open. It is reachable only after a grant.
        let Some(root) = site.root.as_ref() else {
            return reject(stream, 404).await;
        };
        let mut opened = match root.open_file(target) {
            Ok(file) => file,
            Err(_) => return reject(stream, 404).await,
        };
        let plan = match static_files::plan(&req, &opened, site.cache_policy(path)) {
            Ok(plan) => plan,
            Err(http::Rejection(status)) => return reject(stream, status).await,
        };
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut head = site.head(
            plan.status,
            plan.count,
            http::content_type(target),
            req.target,
            sni.is_some(),
        );
        head = head.replace(
            "\r\nCache-Control: no-store\r\n",
            &format!("\r\nCache-Control: {}\r\n", plan.cache),
        );
        if plan.status == 304 {
            head = head.replace("\r\nContent-Length: 0\r\n", "\r\n");
        }
        head.truncate(head.len() - 2);
        head.push_str(&plan.fields);
        head.push_str("\r\n");
        if let Some(out) = handoff {
            out.advertise(&mut head, sni.is_some());
            let Some(lease) = out.budget.reserve(
                out.peer,
                (delivery::HEAD_BYTES + delivery::FILE_CHUNK) as u64,
                stopping(),
            ) else {
                return reject(stream, 503).await;
            };
            if site.encoding != 0 {
                head = encoding::vary(head);
                let selected = match encoding::candidate(site.encoding, &req, &head, plan.count) {
                    Ok(n) => n,
                    Err(e) => return reject(stream, encoding::rejection(&e)).await,
                };
                if selected != 0 {
                    if let Some(_workspace) =
                        out.budget
                            .reserve(out.peer, encoding::WORKSPACE, stopping())
                    {
                        let mut body = vec![0; plan.count as usize];
                        opened.file.read_exact(&mut body)?;
                        if let Err(e) =
                            encoding::transform(site.encoding, &req, &mut head, &mut body)
                        {
                            return reject(stream, encoding::rejection(&e)).await;
                        }
                        // This small representation needs a body reservation, not a file chunk.
                        drop(lease);
                        let Some(lease) = out.budget.reserve(
                            out.peer,
                            (delivery::HEAD_BYTES + body.len()) as u64,
                            stopping(),
                        ) else {
                            return reject(stream, 503).await;
                        };
                        if !grant.send_body {
                            body.clear();
                        }
                        out.prepared = Some(Handoff::Output(delivery::Prepared::buffered(
                            head,
                            body,
                            plan.status,
                            deadline,
                            lease,
                        )?));
                        return Ok((plan.status, 0));
                    }
                    if let Err(e) = encoding::identity(&req) {
                        return reject(stream, encoding::rejection(&e)).await;
                    }
                }
            }
            use std::io::{Seek, SeekFrom};
            opened.file.seek(SeekFrom::Start(plan.start))?;
            let prepared = delivery::Prepared::file(
                head,
                opened.file,
                if grant.send_body { plan.count } else { 0 },
                plan.status,
                deadline,
                lease,
            )?;
            out.prepared = Some(Handoff::Output(prepared));
            return Ok((plan.status, 0));
        }
        async_http::write_all(
            stream,
            head.as_bytes(),
            Instant::now() + Duration::from_secs(5),
        )
        .await?;
        if grant.send_body && plan.count > 0 {
            use std::io::{Seek, SeekFrom};
            opened.file.seek(SeekFrom::Start(plan.start))?;
            let mut left = plan.count;
            let mut buffer = [0u8; 16_384];
            let mut drain_deadline = None;
            while left > 0 {
                // Preserve the active response during graceful shutdown, but
                // do not let a large/slow transfer retain its full 120s budget.
                if stopping() && drain_deadline.is_none() {
                    drain_deadline = Some(Instant::now() + Duration::from_secs(5));
                }
                let size = buffer.len().min(left as usize);
                let n = opened.file.read(&mut buffer[..size])?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "file changed"));
                }
                async_http::write_all(
                    stream,
                    &buffer[..n],
                    deadline
                        .min(drain_deadline.unwrap_or(deadline))
                        .min(Instant::now() + Duration::from_secs(5)),
                )
                .await?;
                left -= n as u64;
            }
        }
        Ok((plan.status, if grant.send_body { plan.count } else { 0 }))
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn respond(
        snapshot: &Snapshot,
        stream: &mut impl http::Transport,
        accepted: Instant,
        sni: Option<&str>,
        automatic_redirect: bool,
        quota: &streaming::Quota,
        stopping: &dyn Fn() -> bool,
        handoff: Option<&mut ResponseHandoff<'_>>,
    ) -> io::Result<(u16, u64)> {
        futures_lite::future::block_on(Self::respond_async(
            snapshot,
            stream,
            accepted,
            sni,
            automatic_redirect,
            quota,
            stopping,
            handoff,
        ))
    }

    #[cfg(all(test, target_os = "linux"))]
    fn handle(
        &self,
        stream: &mut impl http::Transport,
        accepted: Instant,
        sni: Option<&str>,
        shutdown: &AtomicBool,
    ) -> io::Result<()> {
        let (generation, snapshot) = {
            let state = self
                .state
                .read()
                .map_err(|_| io::Error::other("state lock"))?;
            (state.generation, state.snapshot.clone())
        };
        let start = Instant::now();
        let result = Self::respond(
            &snapshot,
            stream,
            accepted,
            sni,
            false,
            &self.stream_quota,
            &|| shutdown.load(Ordering::Acquire) || self.is_draining(),
            None,
        );
        self.observe.request(generation, start.elapsed(), &result);
        result.map(|_| ())
    }

    async fn handle_owned(
        &self,
        mut input: delivery::Input,
        queued: Instant,
        shutdown: &AtomicBool,
        pool: &stream_pool::Pool,
        sink: &delivery::Sink,
        budget: &delivery::Budget,
    ) {
        let (generation, snapshot) = {
            let Ok(state) = self.state.read() else {
                input.client.finish();
                return;
            };
            (state.generation, state.snapshot.clone())
        };
        let started = Instant::now();
        // Preserve time spent receiving the head in existing service budgets;
        // exclude only the separately bounded ready-queue interval.
        let request_started = started
            .checked_sub(queued.saturating_duration_since(input.started))
            .unwrap_or(input.started);
        let peer = input.permit.peer();
        let mut handoff = ResponseHandoff {
            prepared: None,
            budget,
            peer,
            reuse: false,
            head_validated: false,
            early: false,
            http3_port: self.http3_port.load(Ordering::Acquire),
        };
        let queued_ms = queued.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let result = if !pathward::delivery::phase_live(
            queued_ms,
            delivery::QUEUE_BUDGET.as_millis() as u64,
            shutdown.load(Ordering::Acquire),
        ) {
            self.observe.overloaded.fetch_add(1, Ordering::Relaxed);
            handoff.prepared = Some(Handoff::Output(delivery::Prepared::rejection(503)));
            Ok((503, 0))
        } else if let Err(e) = input.client.nonblocking() {
            Err(e)
        } else {
            let sni = input.client.sni().map(str::to_owned);
            let mut replay = delivery::Replay::new(&mut input.client, &input.prefix);
            Self::respond_async(
                &snapshot,
                &mut replay,
                request_started,
                sni.as_deref(),
                input.redirect,
                &self.stream_quota,
                &|| shutdown.load(Ordering::Acquire) || self.is_draining(),
                Some(&mut handoff),
            )
            .await
        };
        match handoff.prepared {
            Some(Handoff::Stream(prepared)) => {
                if let Err(mut job) = pool.push(stream_pool::Job {
                    client: input.client,
                    prepared,
                    generation,
                    started,
                    _active: input.active,
                }) {
                    job.client.finish();
                    self.observe.request(
                        generation,
                        started.elapsed(),
                        &Err(io::ErrorKind::Interrupted.into()),
                    );
                }
            }
            Some(Handoff::Output(mut prepared)) => {
                prepared.reuse(pathward::delivery::reuse_allowed(
                    input.completed.saturating_add(1),
                    input.born.elapsed().as_millis().min(u64::MAX as u128) as u64,
                    handoff.reuse,
                    shutdown.load(Ordering::Acquire) || self.is_draining(),
                ));
                if let Err(e) = sink.output(delivery::Output {
                    client: input.client,
                    prepared,
                    generation,
                    started,
                    _permit: input.permit,
                    _active: input.active,
                    born: input.born,
                    completed: input.completed,
                    redirect: input.redirect,
                }) {
                    self.observe.request(generation, started.elapsed(), &Err(e));
                }
            }
            None => {
                self.observe.request(generation, started.elapsed(), &result);
                input.client.finish();
            }
        }
    }

    /// Bounded connections, cooperative request work and finite downstream delivery.
    /// Stop accepting, discard queued connections, and drain active bounded I/O.
    pub fn serve(&self, listener: TcpListener, shutdown: &AtomicBool) -> io::Result<()> {
        if !listener.local_addr()?.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HTTP-only mode requires a loopback listener",
            ));
        }
        self.serve_transport(listener, None, shutdown, None, None)
    }
    pub fn serve_tls(
        &self,
        listener: TcpListener,
        shutdown: &AtomicBool,
        tls: &tls::TlsServer,
    ) -> io::Result<()> {
        self.serve_transport(listener, None, shutdown, Some(tls), None)
    }
    pub fn serve_tls_with_redirect(
        &self,
        listener: TcpListener,
        redirect: TcpListener,
        shutdown: &AtomicBool,
        tls: &tls::TlsServer,
    ) -> io::Result<()> {
        self.serve_transport(listener, Some(redirect), shutdown, Some(tls), None)
    }
    /// Explicit experimental HTTP/3 listener; uses the same certificate and quotas.
    pub fn serve_tls_http3(
        &self,
        listener: TcpListener,
        redirect: Option<TcpListener>,
        udp: std::net::UdpSocket,
        shutdown: &AtomicBool,
        tls: &tls::TlsServer,
    ) -> io::Result<()> {
        if listener.local_addr()? != udp.local_addr()? {
            return Err(io::Error::other(
                "HTTP/3 must share the TLS address and port",
            ));
        }
        self.serve_transport(listener, redirect, shutdown, Some(tls), Some(udp))
    }
    fn serve_transport(
        &self,
        listener: TcpListener,
        redirect: Option<TcpListener>,
        shutdown: &AtomicBool,
        tls: Option<&tls::TlsServer>,
        udp: Option<std::net::UdpSocket>,
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
        self.http3_port.store(
            if udp.is_some() {
                listener.local_addr()?.port()
            } else {
                0
            },
            Ordering::Release,
        );
        let admission = Arc::new(admission::Admission::new(self.shared_nat));
        let result = thread::scope(|scope| {
            let _scope_stop = StopOnExit(shutdown);
            let receive = work::Queue::<delivery::Work>::new(self.shared_nat);
            let (sink, mut reactor) =
                delivery::channel(pathward::release::capacity_global(self.shared_nat) as usize);
            let budget = delivery::Budget::default();
            let quic = if let Some(udp) = udp {
                let admission = admission.clone();
                let budget = budget.clone();
                let tls = tls.ok_or_else(|| io::Error::other("HTTP/3 requires TLS"))?;
                Some(
                    thread::Builder::new()
                        .name("pathward-quic".into())
                        .spawn_scoped(scope, move || {
                            let _stop = StopOnExit(shutdown);
                            tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()?
                                .block_on(crate::http3::serve(
                                    self, udp, tls, &admission, &budget, shutdown,
                                ))
                        })?,
                )
            } else {
                None
            };
            let workers_done = Arc::new(AtomicBool::new(false));
            let io_done = workers_done.clone();
            let io_queue = receive.clone();
            let io_worker = thread::Builder::new()
                .name("pathward-io".into())
                .spawn_scoped(scope, move || {
                    let _stop = StopOnExit(shutdown);
                    reactor.run(&io_queue, &self.observe, shutdown, &io_done, &|| {
                        self.generation()
                    });
                })?;
            let mut workers = Vec::new();
            let streams = stream_pool::Pool::new();
            for i in 0..stream_pool::WORKERS {
                let pool = streams.clone();
                if let Err(e) = thread::Builder::new()
                    .name(format!("pathward-stream-{i}"))
                    .spawn_scoped(scope, move || {
                        let _stop = StopOnExit(shutdown);
                        while let Some(mut job) = pool.take(shutdown) {
                            let result = job
                                .prepared
                                .live
                                .run(&mut job.client, job.prepared.limits, &|| {
                                    shutdown.load(Ordering::Acquire) || self.is_draining()
                                })
                                .map(|bytes| (job.prepared.status, bytes));
                            job.client.finish();
                            self.observe
                                .request(job.generation, job.started.elapsed(), &result);
                        }
                    })
                {
                    shutdown.store(true, Ordering::Release);
                    streams.close();
                    receive.close();
                    workers_done.store(true, Ordering::Release);
                    let _ = io_worker.join();
                    return Err(e);
                }
            }
            for i in 0..WORKERS {
                let multiplex_admission = admission.clone();
                let worker_queue = receive.clone();
                let pool = streams.clone();
                let sink = sink.clone();
                let budget = budget.clone();
                match thread::Builder::new()
                    .name(format!("pathward-{i}"))
                    .spawn_scoped(scope, move || {
                        let _stop = StopOnExit(shutdown);
                        let mut tasks: Vec<
                            std::pin::Pin<Box<dyn std::future::Future<Output = ()> + '_>>,
                        > = Vec::new();
                        let mut drain = None;
                        loop {
                            let stopping = shutdown.load(Ordering::Acquire);
                            if stopping && drain.is_none() {
                                drain = Some(Instant::now() + Duration::from_secs(5));
                            }
                            if drain.is_some_and(|deadline| Instant::now() >= deadline) {
                                break;
                            }
                            if !stopping
                                && pathward::delivery::task_slot(tasks.len() as u64)
                                && let Some(job) = worker_queue.try_take()
                            {
                                tasks.push(Box::pin(async {
                                    match job {
                                        delivery::Work::Handshake {
                                            stream,
                                            accepted,
                                            permit,
                                            active,
                                        } => {
                                            let Some(tls) = tls else {
                                                return;
                                            };
                                            match tls.accept_async(stream, accepted).await {
                                                Ok(Some(encrypted)) => {
                                                    if encrypted.is_h2() {
                                                        let outcome = multiplex::serve_h2(
                                                            self,
                                                            encrypted,
                                                            accepted,
                                                            permit,
                                                            active,
                                                            &multiplex_admission,
                                                            &budget,
                                                            shutdown,
                                                        )
                                                        .await;
                                                        if let Err(e) = outcome {
                                                            self.observe.request(
                                                                self.generation(),
                                                                accepted.elapsed(),
                                                                &Err(observe::stage_error(e, observe::TransportStage::Connection)),
                                                            );
                                                        }
                                                        return;
                                                    }
                                                    if sink
                                                        .input(delivery::Input {
                                                            client: stream_pool::Connection::Tls(
                                                                Box::new(encrypted),
                                                            ),
                                                            prefix: Vec::new(),
                                                            started: Instant::now(),
                                                            redirect: false,
                                                            permit,
                                                            active,
                                                            born: accepted,
                                                            completed: 0,
                                                            idle: false,
                                                        })
                                                        .is_err()
                                                    {
                                                        self.observe.tls_failed();
                                                    }
                                                }
                                                Ok(None) => {}
                                                Err(e) => self.observe.tls_handshake_failed(accepted.elapsed(), &e),
                                            }
                                        }
                                        delivery::Work::Http { input, queued } => {
                                            self.handle_owned(
                                                input, queued, shutdown, &pool, &sink, &budget,
                                            )
                                            .await;
                                        }
                                    }
                                }));
                            }
                            let mut i = 0;
                            while i < tasks.len() {
                                if futures_lite::future::block_on(futures_lite::future::poll_once(
                                    tasks[i].as_mut(),
                                ))
                                .is_some()
                                {
                                    drop(tasks.swap_remove(i));
                                } else {
                                    i += 1;
                                }
                            }
                            if stopping && tasks.is_empty() {
                                break;
                            }
                            thread::sleep(Duration::from_millis(2));
                        }
                    }) {
                    Ok(worker) => workers.push(worker),
                    Err(e) => {
                        shutdown.store(true, Ordering::Release);
                        streams.close();
                        receive.close();
                        for worker in workers {
                            let _ = worker.join();
                        }
                        workers_done.store(true, Ordering::Release);
                        let _ = io_worker.join();
                        return Err(e);
                    }
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
                            let permit = match admission
                                .acquire(peer.ip(), shutdown.load(Ordering::Acquire))
                            {
                                Ok(permit) => permit,
                                Err(reason) => {
                                    self.observe.admission_rejected(reason);
                                    let _ = stream.shutdown(Shutdown::Both);
                                    continue;
                                }
                            };
                            let accepted = Instant::now();
                            let active = self.observe.connection();
                            let submitted = if tls.is_some() && !redirect_only {
                                receive
                                    .push(
                                        permit.peer(),
                                        delivery::Work::Handshake {
                                            stream,
                                            accepted,
                                            permit,
                                            active,
                                        },
                                    )
                                    .is_ok()
                            } else {
                                sink.input(delivery::Input {
                                    client: stream_pool::Connection::Plain(stream),
                                    prefix: Vec::new(),
                                    started: accepted,
                                    redirect: redirect_only,
                                    permit,
                                    active,
                                    born: accepted,
                                    completed: 0,
                                    idle: false,
                                })
                                .is_ok()
                            };
                            if !submitted {
                                self.observe.overloaded.fetch_add(1, Ordering::Relaxed);
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
            streams.close();
            receive.close();
            let mut worker_failed = false;
            if let Some(quic) = quic {
                worker_failed |= !matches!(quic.join(), Ok(Ok(())));
            }
            for worker in workers {
                worker_failed |= worker.join().is_err();
            }
            workers_done.store(true, Ordering::Release);
            worker_failed |= io_worker.join().is_err();
            if worker_failed {
                Err(io::Error::other("serving worker failed"))
            } else {
                result
            }
        });
        self.begin_shutdown();
        self.http3_port.store(0, Ordering::Release);
        self.observe.serving.store(false, Ordering::Release);
        self.observe.event("stopped", self.generation(), 0);
        result
    }
}

#[cfg(all(test, target_os = "linux"))]
mod response_tests;

struct StopOnExit<'a>(&'a AtomicBool);
impl Drop for StopOnExit<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
