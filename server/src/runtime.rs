//! Immutable owned configurations, prepared before the short commit lock.
use crate::files::DocumentRoot;
use pathward::rules::Publication;
use pathward_config::{CompiledConfig, ProxyLimits};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::{io, path::Path};

pub(crate) struct Site {
    pub encoding: u8,
    pub host: String,
    pub root: Option<DocumentRoot>,
    pub upstream: Option<SocketAddr>,
    pub proxy_routes: Vec<crate::proxy::UpstreamRoute>,
    pub limits: ProxyLimits,
    pub websocket_origins: Vec<String>,
    budget: Arc<ServiceBudget>,
    denies: Vec<String>,
    proxy_paths: Vec<String>,
    rules: Vec<(Vec<u8>, Vec<u8>)>,
    redirects: Vec<Redirect>,
    headers: Vec<Header>,
    cache: Vec<(String, bool, pathward_config::CachePolicy)>,
}
struct Redirect {
    from: String,
    host: String,
    to: String,
    status: u16,
    prefix: bool,
    fallback: bool,
}
struct Header {
    kind: pathward_config::HeaderScope,
    scope: String,
    name: String,
    value: String,
}
// (ordinary active, ordinary live cap, stream active, stream live cap).
struct ServiceBudget(Mutex<(u64, u64, u64, u64)>);
pub(crate) struct ServicePermit {
    budget: Arc<ServiceBudget>,
    stream: bool,
}
impl Drop for ServicePermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.budget.0.lock() {
            let active = if self.stream {
                &mut state.2
            } else {
                &mut state.0
            };
            *active = active.saturating_sub(1);
        }
    }
}
impl Site {
    pub fn cache_policy(&self, path: &[u8]) -> pathward_config::CachePolicy {
        self.cache
            .iter()
            .filter(|(scope, prefix, _)| {
                scope == "*"
                    || if *prefix {
                        pathward::routing::subtree(path, scope.as_bytes())
                    } else {
                        path == scope.as_bytes()
                    }
            })
            .max_by_key(|(s, p, _)| (s != "*", s.len(), !p))
            .map_or(pathward_config::CachePolicy::NoStore, |(_, _, c)| *c)
    }

    pub fn acquire(&self) -> Option<ServicePermit> {
        let mut state = self.budget.0.lock().ok()?;
        if !pathward::routing::service_admit(state.0, self.limits.connections, state.1) {
            return None;
        }
        state.0 += 1;
        Some(ServicePermit {
            budget: self.budget.clone(),
            stream: false,
        })
    }
    pub fn acquire_stream(&self) -> Option<ServicePermit> {
        let mut state = self.budget.0.lock().ok()?;
        if !pathward::streaming::service_admission(state.2, self.limits.streams, state.3) {
            return None;
        }
        state.2 += 1;
        Some(ServicePermit {
            budget: self.budget.clone(),
            stream: true,
        })
    }
    pub fn route(&self, target: &[u8]) -> pathward::routing::Route {
        let raw = &target[..pathward::serving::path_length(target)];
        let strict = !self.rules.is_empty()
            || !self.redirects.is_empty()
            || !self.denies.is_empty()
            || !self.proxy_paths.is_empty()
            || !self.proxy_routes.is_empty();
        let stem = pathward::routing::stem(raw);
        let path = stem.unwrap_or(b"");
        let transport_valid = if self.upstream.is_some() {
            pathward::proxy::target_allowed(target)
        } else {
            pathward::serving::request_path(target).is_some()
        };
        let valid = transport_valid && (!strict || stem.is_some());
        let denied = self
            .denies
            .iter()
            .any(|d| pathward::routing::subtree(path, d.as_bytes()));
        // Reserve slash variants for the local route, but authorize only exact URLs.
        // An unconfigured alias must never fall through to another backend.
        let trim = |p: &[u8]| {
            if p.len() > 1 && p.ends_with(b"/") {
                p.len() - 1
            } else {
                p.len()
            }
        };
        let published = self
            .rules
            .iter()
            .any(|(p, _)| p[..trim(p)] == path[..trim(path)]);
        let redirect = self.redirects.iter().any(|r| {
            r.fallback || pathward::response::route_matches(path, r.from.as_bytes(), r.prefix)
        });
        let proxy = self.upstream.is_some()
            && (self.proxy_paths.is_empty()
                || self
                    .proxy_paths
                    .iter()
                    .any(|p| pathward::routing::subtree(path, p.as_bytes())));
        pathward::routing::select(valid, denied, published, redirect, proxy)
    }
    pub fn head(
        &self,
        status: u16,
        length: u64,
        content_type: &str,
        path: &[u8],
        encrypted: bool,
    ) -> String {
        let mut out = crate::http::response_head(status, length, content_type);
        if self.upstream.is_some() && status == 405 {
            out = out.replace(
                "Allow: GET, HEAD\r\n",
                "Allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS\r\n",
            );
        }
        out.truncate(out.len() - 2);
        self.append_headers(&mut out, path, encrypted);
        out.push_str("\r\n");
        out
    }
    fn header_rank(&self, h: &Header, target: &[u8]) -> Option<(u8, usize)> {
        use pathward_config::HeaderScope;
        let n = pathward::serving::path_length(target);
        let path = &target[..n];
        match h.kind {
            HeaderScope::Exact if h.scope.as_bytes() == path => Some((2, h.scope.len())),
            HeaderScope::Exact if h.scope == "*" => Some((0, 0)),
            HeaderScope::Prefix if pathward::routing::subtree(path, h.scope.as_bytes()) => {
                Some((1, h.scope.len()))
            }
            HeaderScope::Query
                if n < target.len()
                    && target[n + 1..].split(|b| *b == b'&').any(|part| {
                        let key = part.split(|b| *b == b'=').next().unwrap_or(b"");
                        pathward::upstream::query_match(
                            key == h.scope.as_bytes(),
                            key.contains(&b'%') || key.contains(&b'+'),
                        )
                    }) =>
            {
                Some((3, 0))
            }
            _ => None,
        }
    }
    fn append_headers(&self, out: &mut String, target: &[u8], encrypted: bool) {
        for (index, h) in self.headers.iter().enumerate() {
            let Some(rank) = self.header_rank(h, target) else {
                continue;
            };
            let overridden = self.headers.iter().enumerate().any(|(i, other)| {
                other.name == h.name
                    && self
                        .header_rank(other, target)
                        .is_some_and(|r| (r, i) > (rank, index))
            });
            if !overridden
                && (encrypted || h.name != "strict-transport-security")
                && pathward::response::header_allowed(h.name.as_bytes(), h.value.as_bytes())
            {
                out.push_str(&h.name);
                out.push_str(": ");
                out.push_str(&h.value);
                out.push_str("\r\n");
            }
        }
    }
    pub fn proxy_head(
        &self,
        response: &crate::proxy::Response,
        path: &[u8],
        encrypted: bool,
    ) -> String {
        let mut out = format!(
            "HTTP/1.1 {} Upstream Response\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n",
            response.status
        );
        if let Some(live) = &response.live {
            match &live.mode {
                crate::streaming::Mode::WebSocket {
                    accept,
                    protocol,
                    deflate,
                } => {
                    out = format!(
                        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\nX-Content-Type-Options: nosniff\r\n"
                    );
                    if *deflate {
                        out.push_str(&format!(
                            "Sec-WebSocket-Extensions: {}\r\n",
                            crate::streaming::DEFLATE
                        ));
                    }
                    if let Some(p) = protocol {
                        out.push_str(&format!("Sec-WebSocket-Protocol: {p}\r\n"));
                    }
                }
                crate::streaming::Mode::Sse { .. } => {
                    out.push_str("Transfer-Encoding: chunked\r\n")
                }
            }
        }
        if let Some(length) = response.length {
            out.push_str(&format!("Content-Length: {length}\r\n"));
        }
        for (name, value) in &response.headers {
            let overridden = self
                .headers
                .iter()
                .any(|h| h.name == *name && self.header_rank(h, path).is_some());
            if name != "x-content-type-options"
                && !overridden
                && pathward::proxy::response_header(name.as_bytes(), value.as_bytes(), encrypted)
            {
                out.push_str(name);
                out.push_str(": ");
                out.push_str(value);
                out.push_str("\r\n");
            }
        }
        if !response.headers.iter().any(|(n, _)| n == "date") {
            out.push_str(&crate::http::date_header());
        }
        self.append_headers(&mut out, path, encrypted);
        out.push_str("\r\n");
        out
    }
    pub fn redirect(
        &self,
        target: &[u8],
        hosts: &[Site],
        automatic: bool,
    ) -> Option<(u16, String)> {
        let path = pathward::serving::request_path(target)?;
        let query = std::str::from_utf8(&target[path.len()..]).ok()?;
        let (host, destination, status) = if automatic {
            (&self.host, std::str::from_utf8(path).ok()?.to_owned(), 308)
        } else {
            let rule = self
                .redirects
                .iter()
                .filter(|r| {
                    r.fallback
                        || pathward::response::route_matches(path, r.from.as_bytes(), r.prefix)
                })
                .max_by_key(|r| (!r.fallback, r.from.len()))?;
            if rule.fallback {
                return Self::checked_redirect(
                    &rule.host,
                    std::str::from_utf8(target).ok()?,
                    rule.status,
                    hosts,
                );
            }
            let suffix = std::str::from_utf8(&path[rule.from.len()..]).ok()?;
            let destination = if rule.to == "/" && !suffix.is_empty() {
                suffix.to_owned()
            } else {
                format!("{}{suffix}", rule.to)
            };
            (&rule.host, destination, rule.status)
        };
        let target = format!("{destination}{query}");
        Self::checked_redirect(host, &target, status, hosts)
    }

    fn checked_redirect(
        host: &str,
        target: &str,
        status: u16,
        hosts: &[Site],
    ) -> Option<(u16, String)> {
        let configured = hosts.iter().find(|s| s.host == host)?;
        if !pathward::response::redirect_allowed(
            host.as_bytes(),
            configured.host.as_bytes(),
            target.as_bytes(),
            status,
        ) {
            return None;
        }
        Some((status, format!("https://{host}{target}")))
    }

    pub fn publications(&self) -> Vec<Publication<'_>> {
        self.rules
            .iter()
            .map(|(path, target)| Publication { path, target })
            .collect()
    }
}
pub(crate) struct Snapshot {
    pub sites: Vec<Site>,
    pub source: String,
}
impl Snapshot {
    /// Preparation never changes the active cap. Install only at the commit point.
    pub fn inherit_budgets(&mut self, old: &Snapshot) {
        for site in &mut self.sites {
            if let Some(previous) = old.sites.iter().find(|s| s.host == site.host) {
                site.budget = previous.budget.clone();
            }
        }
    }
    pub fn install_limits(&self) {
        for site in &self.sites {
            // A poisoned budget refuses admission. No I/O or fallible work follows
            // installation at either commit point.
            if let Ok(mut state) = site.budget.0.lock() {
                state.1 = if site.upstream.is_some() {
                    site.limits.connections
                } else {
                    0
                };
                state.3 = if site.upstream.is_some() && (site.limits.websocket || site.limits.sse) {
                    site.limits.streams
                } else {
                    0
                };
            }
        }
    }
    pub fn check_files(&self) -> io::Result<usize> {
        let mut count = 0;
        for site in &self.sites {
            for (_, target) in &site.rules {
                let _ = site
                    .root
                    .as_ref()
                    .ok_or_else(|| io::Error::other("publication without root"))?
                    .open_file(
                        std::str::from_utf8(target).map_err(|_| io::Error::other("target"))?,
                    )?;
                count += 1;
            }
        }
        Ok(count)
    }
    pub fn prepare(config: &CompiledConfig<'_>, cache: Option<&Path>) -> io::Result<Self> {
        if !Self::isolated(config, cache) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "public root overlaps private cache",
            ));
        }
        let sites = config
            .sites()
            .iter()
            .map(|site| {
                Ok(Site {
                    encoding: site.encoding(),
                    host: site.host().to_owned(),
                    root: site.root().map(DocumentRoot::open).transpose()?,
                    upstream: site.upstream(),
                    proxy_routes: site
                        .proxy_routes()
                        .iter()
                        .map(|r| crate::proxy::UpstreamRoute {
                            prefix: r.prefix.to_owned(),
                            width: r.width,
                            candidates: r.candidates.clone(),
                        })
                        .collect(),
                    limits: site.proxy_limits(),
                    websocket_origins: site
                        .websocket_origins()
                        .iter()
                        .map(|o| (*o).to_owned())
                        .collect(),
                    budget: Arc::new(ServiceBudget(Mutex::new((
                        0,
                        if site.upstream().is_some() {
                            site.proxy_limits().connections
                        } else {
                            0
                        },
                        0,
                        if site.upstream().is_some()
                            && (site.proxy_limits().websocket || site.proxy_limits().sse)
                        {
                            site.proxy_limits().streams
                        } else {
                            0
                        },
                    )))),
                    denies: site.denies().iter().map(|p| (*p).to_owned()).collect(),
                    proxy_paths: site.proxy_paths().iter().map(|p| (*p).to_owned()).collect(),
                    redirects: site
                        .redirects()
                        .iter()
                        .map(|r| Redirect {
                            from: r.from.into(),
                            host: r.host.into(),
                            to: r.to.into(),
                            status: r.status,
                            prefix: r.prefix,
                            fallback: r.fallback,
                        })
                        .collect(),
                    cache: site
                        .cache_rules()
                        .iter()
                        .map(|c| (c.scope.to_owned(), c.prefix, c.policy))
                        .collect(),
                    headers: site
                        .headers()
                        .iter()
                        .map(|h| Header {
                            kind: h.kind,
                            scope: h.scope.into(),
                            name: h.name.into(),
                            value: h.value.into(),
                        })
                        .collect(),
                    rules: site
                        .publications()
                        .iter()
                        .map(|p| (p.path.to_vec(), p.target.to_vec()))
                        .collect(),
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            sites,
            source: config.source().to_owned(),
        })
    }
    pub fn isolated(config: &CompiledConfig<'_>, cache: Option<&Path>) -> bool {
        cache.is_none_or(|cache| {
            config.sites().iter().all(|s| {
                s.root().is_none_or(|root| {
                    !cache.starts_with(root) && !Path::new(root).starts_with(cache)
                })
            })
        })
    }
    pub fn same_hosts(&self, config: &CompiledConfig<'_>) -> bool {
        self.sites.len() == config.sites().len()
            && self
                .sites
                .iter()
                .all(|s| config.sites().iter().any(|c| c.host() == s.host))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{Server, http};
    use pathward_config::ParsedConfig;
    use std::{
        fs,
        io::{Read, Write},
        sync::atomic::AtomicBool,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };
    struct Tree(std::path::PathBuf);
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tree() -> Tree {
        let path = std::env::temp_dir().join(format!(
            "pathward-runtime-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        for root in ["old", "new", "cache"] {
            fs::create_dir(path.join(root)).unwrap();
        }
        fs::write(path.join("old/old.txt"), "OLD").unwrap();
        fs::write(path.join("old/new.txt"), "MIXED").unwrap();
        fs::write(path.join("new/old.txt"), "MIXED").unwrap();
        fs::write(path.join("new/new.txt"), "NEW").unwrap();
        Tree(path)
    }
    fn config(path: &Path, host: &str, target: &str) -> ParsedConfig {
        ParsedConfig::parse(&format!(
            "site \"{host}\" {{\nroot \"{}\"\npublish \"/\" \"{target}\"\ntls \"auto\"\n}}",
            path.display()
        ))
        .unwrap()
    }
    struct Exchange<F: FnMut()> {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
        before_read: F,
    }
    impl<F: FnMut()> Read for Exchange<F> {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            (self.before_read)();
            self.input.read(b)
        }
    }
    impl<F: FnMut()> Write for Exchange<F> {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.output.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<F: FnMut()> http::Transport for Exchange<F> {
        fn deadline(&mut self, _: Instant) -> io::Result<()> {
            Ok(())
        }
        fn local_port(&self) -> io::Result<u16> {
            Ok(80)
        }
    }
    fn request(server: &Server, before_read: impl FnMut()) -> Vec<u8> {
        let mut stream = Exchange {
            input: io::Cursor::new(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()),
            output: Vec::new(),
            before_read,
        };
        server
            .handle(&mut stream, Instant::now(), None, &AtomicBool::new(false))
            .unwrap();
        stream.output
    }
    #[test]
    fn request_pins_rules_and_root_across_commit_and_rejections_retain_previous() {
        let tree = tree();
        let old = config(&tree.0.join("old"), "example.com", "old.txt");
        let new = config(&tree.0.join("new"), "example.com", "new.txt");
        let server =
            Server::new_with_cache(&old.compile().unwrap(), Some(&tree.0.join("cache"))).unwrap();
        let stop = AtomicBool::new(false);
        let mut once = true;
        let response = request(&server, || {
            if once {
                once = false;
                assert_eq!(server.reload(&new.compile().unwrap(), &stop).unwrap(), 2);
            }
        });
        assert!(response.ends_with(b"OLD"));
        assert!(request(&server, || {}).ends_with(b"NEW"));
        for (path, host) in [
            (tree.0.join("missing"), "example.com"),
            (tree.0.join("old"), "other.example"),
            (tree.0.join("cache"), "example.com"),
            (tree.0.clone(), "example.com"),
        ] {
            let bad = config(&path, host, "old.txt");
            assert!(server.reload(&bad.compile().unwrap(), &stop).is_err());
            assert_eq!(server.generation(), 2);
            assert!(request(&server, || {}).ends_with(b"NEW"));
        }
        std::os::unix::fs::symlink(tree.0.join("old"), tree.0.join("linked")).unwrap();
        let linked = config(&tree.0.join("linked"), "example.com", "old.txt");
        assert!(server.reload(&linked.compile().unwrap(), &stop).is_err());
        server.begin_shutdown();
        assert!(server.reload(&old.compile().unwrap(), &stop).is_err());
        assert_eq!(server.generation(), 2);
    }
    #[test]
    fn concurrent_requests_only_observe_complete_generations() {
        let tree = tree();
        let old = config(&tree.0.join("old"), "example.com", "old.txt");
        let new = config(&tree.0.join("new"), "example.com", "new.txt");
        let server = Server::new(&old.compile().unwrap()).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let server = &server;
                scope.spawn(move || {
                    for _ in 0..100 {
                        let r = request(server, || {});
                        assert!(r.ends_with(b"OLD") || r.ends_with(b"NEW"));
                    }
                });
            }
            for i in 0..50 {
                let config = if i % 2 == 0 { &new } else { &old };
                server
                    .reload(&config.compile().unwrap(), &AtomicBool::new(false))
                    .unwrap();
            }
        });
        assert_eq!(server.generation(), 51);
    }
    #[test]
    fn a_server_cannot_restart_after_draining() {
        let tree = tree();
        let parsed = config(&tree.0.join("old"), "example.com", "old.txt");
        let server = Server::new(&parsed.compile().unwrap()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        server.serve(listener, &AtomicBool::new(true)).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(server.serve(listener, &AtomicBool::new(false)).is_err());
    }
}
