//! KDL 2 parsing and a strict schema around the verified publication compiler.
//! Parsing, schema adaptation, hostname selection, and allocation are audited
//! and tested Rust, outside the Lean proof of `pathward::rules`.
#![forbid(unsafe_code)]

mod cache;
mod upstream;
pub use upstream::ProxyRoute;
mod surface;
pub use cache::{CachePolicy, CacheRule};

use kdl::{KdlDocument, KdlNode};
use pathward::rules::{self, Publication};
use std::fmt;
use std::io::Read;
use std::net::SocketAddr;

pub const MAX_CONFIG_BYTES: usize = 1_048_576;
pub const MAX_ROUTE_RULES: usize = 64;
pub const MAX_SITES: usize = 16;
pub const MAX_PUBLICATIONS: usize = 4096;
pub const MAX_REDIRECTS: usize = 512;
pub const MAX_HEADERS: usize = 32;

#[derive(Clone, Copy)]
pub struct Redirect<'a> {
    pub from: &'a str,
    pub host: &'a str,
    pub to: &'a str,
    pub status: u16,
    pub prefix: bool,
    pub fallback: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderScope {
    Exact,
    Prefix,
    Query,
}
impl HeaderScope {
    pub fn directive(self) -> &'static str {
        match self {
            Self::Exact => "header",
            Self::Prefix => "header-prefix",
            Self::Query => "header-query",
        }
    }
}
#[derive(Clone, Copy)]
pub struct Header<'a> {
    pub kind: HeaderScope,
    pub scope: &'a str,
    pub name: &'a str,
    pub value: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}

impl std::error::Error for ConfigError {}

fn error(source: &str, offset: usize, message: impl Into<String>) -> ConfigError {
    let mut offset = offset.min(source.len());
    while !source.is_char_boundary(offset) {
        offset -= 1;
    }
    let mut line = 1;
    let mut column = 1;
    let mut chars = source[..offset].chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\r' && chars.peek() == Some(&'\n') {
            chars.next();
        }
        if matches!(
            ch,
            '\r' | '\n' | '\u{85}' | '\u{b}' | '\u{c}' | '\u{2028}' | '\u{2029}'
        ) {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    ConfigError {
        line,
        column,
        message: message.into(),
    }
}

/// Holds the parsed document so compiled rules can borrow its decoded strings.
/// No partially compiled configuration is ever returned.
pub struct ParsedConfig {
    source: String,
    document: KdlDocument,
}

impl ParsedConfig {
    /// Bounded UTF-8 read: the limit is applied before allocating the full file.
    pub fn read(reader: impl Read) -> Result<Self, ConfigError> {
        let mut bytes = Vec::new();
        reader
            .take(MAX_CONFIG_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| error("", 0, "could not read configuration"))?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(error("", 0, "configuration exceeds 1048576 bytes"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| error("", 0, "configuration must be UTF-8"))?;
        Self::parse(text)
    }

    pub fn parse(source: &str) -> Result<Self, ConfigError> {
        if source.len() > MAX_CONFIG_BYTES {
            return Err(error(source, 0, "configuration exceeds 1048576 bytes"));
        }
        surface::check(source)?;
        let document = KdlDocument::parse_v2(source).map_err(|failure| {
            let offset = failure.diagnostics.first().map_or(0, |d| d.span.offset());
            error(source, offset, "invalid KDL 2 syntax")
        })?;
        Ok(Self {
            source: source.to_owned(),
            document,
        })
    }

    /// Interpret only the documented schema and call the extracted Rust
    /// compiler before returning each immutable site's publication table.
    pub fn compile(&self) -> Result<CompiledConfig<'_>, ConfigError> {
        let mut nodes = self.document.nodes();
        let mut shared_nat = false;
        if let Some(node) = nodes.first()
            && node.name().value() == "capacity"
        {
            if node.children().is_some() {
                return Err(self.at(node, "capacity cannot have children"));
            }
            shared_nat = match self.arguments(node, 1)?[0] {
                "standard" => false,
                "shared-nat" => true,
                _ => return Err(self.at(node, "capacity must be standard or shared-nat")),
            };
            nodes = &nodes[1..];
        }
        if nodes.is_empty() || nodes.len() > MAX_SITES {
            return Err(error(&self.source, 0, "expected 1 to 16 site blocks"));
        }
        let mut sites = Vec::with_capacity(nodes.len());
        for node in nodes {
            if node.name().value() != "site" {
                return Err(self.at(node, "only site blocks are allowed at the top level"));
            }
            let arguments = self.arguments(node, 1)?;
            let host = arguments[0];
            if !valid_host(host) {
                return Err(self.at(node, "site must be a lowercase ASCII hostname without a port, wildcard, or trailing dot"));
            }
            if sites
                .iter()
                .any(|site: &CompiledSite<'_>| site.host == host)
            {
                return Err(self.at(node, "duplicate site hostname"));
            }
            let children = node
                .children()
                .ok_or_else(|| self.at(node, "site requires a children block"))?;
            let mut root = None;
            let mut tls = None;
            let mut encoding = None;
            let mut upstream = None;
            let mut denies = Vec::new();
            let mut proxy_paths = Vec::new();
            let mut proxy_routes = Vec::new();
            let mut websocket_origins = Vec::new();
            let mut limits = ProxyLimits::default();
            let mut limit_names = std::collections::BTreeSet::new();
            let mut publications = Vec::new();
            let mut redirects = Vec::new();
            let mut headers = Vec::new();
            let mut cache = Vec::new();
            for child in children.nodes() {
                if child.children().is_some() {
                    return Err(self.at(child, "nested directive blocks are not supported"));
                }
                match child.name().value() {
                    "deny" | "proxy-path" => {
                        let value = self.arguments(child, 1)?[0];
                        let list = if child.name().value() == "deny" {
                            &mut denies
                        } else {
                            &mut proxy_paths
                        };
                        if !pathward::valid_path(value.as_bytes())
                            || (value.len() > 1 && value.ends_with('/'))
                            || list.len() == MAX_ROUTE_RULES
                            || list.contains(&value)
                        {
                            return Err(
                                self.at(child, "invalid, duplicate or excessive subtree rule")
                            );
                        }
                        list.push(value);
                    }
                    "websocket-origin" => {
                        let value = self.arguments(child, 1)?[0];
                        if !valid_origin(value)
                            || websocket_origins.len() == 16
                            || websocket_origins.contains(&value)
                        {
                            return Err(
                                self.at(child, "invalid, duplicate or excessive WebSocket origin")
                            );
                        }
                        websocket_origins.push(value);
                    }
                    "websocket-compression" => {
                        let value = self.arguments(child, 1)?[0];
                        if value != "permessage-deflate" || limits.deflate {
                            return Err(self.at(child, "expected one permessage-deflate setting"));
                        }
                        limits.deflate = true;
                    }
                    "proxy-stream" => {
                        let value = self.arguments(child, 1)?[0];
                        if !limit_names.insert(("proxy-stream", value)) {
                            return Err(self.at(child, "duplicate stream setting"));
                        }
                        match value {
                            "websocket" => limits.websocket = true,
                            "sse" => limits.sse = true,
                            _ => return Err(self.at(child, "expected websocket or sse")),
                        }
                    }
                    "proxy-limit" | "proxy-timeout" => {
                        let v = self.arguments(child, 2)?;
                        let kind = child.name().value();
                        if !limit_names.insert((kind, v[0])) || !limits.set(kind, v[0], v[1]) {
                            return Err(self.at(child, "invalid or duplicate proxy limit/timeout"));
                        }
                    }
                    "proxy-route" | "proxy-resource" => {
                        let resource = child.name().value() == "proxy-resource";
                        let v = self.arguments(child, if resource { 3 } else { 2 })?;
                        let route = ProxyRoute::parse(&v, resource).ok_or_else(|| {
                            self.at(child, "invalid loopback route or resource probe policy")
                        })?;
                        if proxy_routes.len() == MAX_ROUTE_RULES
                            || proxy_routes
                                .iter()
                                .any(|r: &ProxyRoute<'_>| r.prefix == route.prefix)
                        {
                            return Err(self.at(child, "duplicate or excessive proxy route"));
                        }
                        proxy_routes.push(route);
                    }
                    "reverse-proxy" => {
                        let values = self.arguments(child, 1)?;
                        let address = values[0].parse::<SocketAddr>().map_err(|_| {
                            self.at(child, "proxy requires a literal loopback IP:port")
                        })?;
                        if upstream.is_some()
                            || address.to_string() != values[0]
                            || !pathward::proxy::endpoint_allowed(
                                address.ip().to_string().as_bytes(),
                                address.port(),
                            )
                        {
                            return Err(self.at(child, "invalid or duplicate loopback upstream"));
                        }
                        upstream = Some(address);
                    }
                    "root" => {
                        let values = self.arguments(child, 1)?;
                        if root.is_some() {
                            return Err(self.at(child, "duplicate root directive"));
                        }
                        if !pathward::valid_path(values[0].as_bytes())
                            || (values[0].len() > 1 && values[0].ends_with('/'))
                        {
                            return Err(
                                self.at(child, "root must be an absolute canonical Unix path")
                            );
                        }
                        root = Some(values[0]);
                    }
                    "encode" => {
                        let value = self.arguments(child, 1)?[0];
                        let mode = match value {
                            "gzip" => 1,
                            "zstd" => 2,
                            "gzip,zstd" => 3,
                            _ => {
                                return Err(
                                    self.at(child, "encode must be gzip, zstd or gzip,zstd")
                                );
                            }
                        };
                        if encoding.replace(mode).is_some() {
                            return Err(self.at(child, "duplicate encode directive"));
                        }
                    }
                    "tls" => {
                        let values = self.arguments(child, 1)?;
                        if tls.is_some() {
                            return Err(self.at(child, "duplicate tls directive"));
                        }
                        if values[0] != "auto" {
                            return Err(
                                self.at(child, "the only currently supported TLS policy is auto")
                            );
                        }
                        tls = Some(TlsPolicy::Auto);
                    }
                    "publish" => {
                        let values = self.arguments(child, 2)?;
                        if publications.len() == MAX_PUBLICATIONS {
                            return Err(self.at(child, "a site may publish at most 4096 URLs"));
                        }
                        let publication = Publication {
                            path: values[0].as_bytes(),
                            target: values[1].as_bytes(),
                        };
                        // Give a precise location; the verified compiler repeats
                        // these checks over the complete table below.
                        if !pathward::valid_path(publication.path) {
                            return Err(
                                self.at(child, "publish URL is not a canonical absolute URL path")
                            );
                        }
                        if !rules::valid_target(publication.target) {
                            return Err(self.at(
                                child,
                                "publish file must be a nonempty canonical relative path",
                            ));
                        }
                        if publications
                            .iter()
                            .any(|old: &Publication<'_>| old.path == publication.path)
                        {
                            return Err(self.at(child, "duplicate publish URL"));
                        }
                        publications.push(publication);
                    }
                    "redirect" | "redirect-prefix" | "redirect-fallback" => {
                        let fallback = child.name().value() == "redirect-fallback";
                        let v = if fallback {
                            let v = self.arguments(child, 2)?;
                            vec!["/", v[0], "/", v[1]]
                        } else {
                            self.arguments(child, 4)?
                        };
                        let status = match v[3] {
                            "301" => 301,
                            "308" => 308,
                            _ => return Err(self.at(child, "redirect status must be 301 or 308")),
                        };
                        let prefix = child.name().value() == "redirect-prefix";
                        if redirects.len() == MAX_REDIRECTS
                            || !pathward::valid_path(v[0].as_bytes())
                            || !valid_host(v[1])
                            || !pathward::valid_path(v[2].as_bytes())
                            || (prefix
                                && (v[0] == "/"
                                    || v[0].ends_with('/')
                                    || (v[2] != "/" && v[2].ends_with('/'))))
                        {
                            return Err(self.at(child, "invalid or excessive redirect"));
                        }
                        if redirects.iter().any(|r: &Redirect<'_>| r.from == v[0])
                            || (host == v[1] && v[0] == v[2])
                        {
                            return Err(self.at(child, "duplicate or self redirect"));
                        }
                        redirects.push(Redirect {
                            from: v[0],
                            host: v[1],
                            to: v[2],
                            status,
                            prefix,
                            fallback,
                        });
                    }
                    "cache" | "cache-prefix" => {
                        let v = self.arguments(child, 2)?;
                        let prefix = child.name().value() == "cache-prefix";
                        if cache.len() == MAX_ROUTE_RULES
                            || (v[0] != "*" && !pathward::valid_path(v[0].as_bytes()))
                            || (prefix && (v[0] == "*" || (v[0] != "/" && v[0].ends_with('/'))))
                            || cache
                                .iter()
                                .any(|r: &CacheRule<'_>| r.scope == v[0] && r.prefix == prefix)
                        {
                            return Err(
                                self.at(child, "invalid, duplicate or excessive cache rule")
                            );
                        }
                        let policy = CachePolicy::parse(v[1])
                            .ok_or_else(|| self.at(child, "invalid cache policy"))?;
                        cache.push(CacheRule {
                            scope: v[0],
                            prefix,
                            policy,
                        });
                    }
                    "header" | "header-prefix" | "header-query" => {
                        let v = self.arguments(child, 3)?;
                        let kind = match child.name().value() {
                            "header-prefix" => HeaderScope::Prefix,
                            "header-query" => HeaderScope::Query,
                            _ => HeaderScope::Exact,
                        };
                        let scope_valid = match kind {
                            HeaderScope::Exact => {
                                v[0] == "*" || pathward::valid_path(v[0].as_bytes())
                            }
                            HeaderScope::Prefix => upstream::prefix(v[0]),
                            HeaderScope::Query => {
                                !v[0].is_empty()
                                    && v[0].len() <= 64
                                    && v[0].bytes().all(|b| {
                                        b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
                                    })
                            }
                        };
                        if headers.len() == MAX_HEADERS
                            || !scope_valid
                            || !pathward::response::header_allowed(v[1].as_bytes(), v[2].as_bytes())
                            || headers.iter().any(|h: &Header<'_>| {
                                h.scope == v[0] && h.name == v[1] && h.kind == kind
                            })
                        {
                            return Err(self.at(child, "invalid, duplicate or excessive header"));
                        }
                        headers.push(Header {
                            kind,
                            scope: v[0],
                            name: v[1],
                            value: v[2],
                        });
                    }
                    _ => {
                        return Err(self.at(
                            child,
                            "unknown site directive; expected root, publish, or tls",
                        ));
                    }
                }
            }
            let tls = tls.ok_or_else(|| self.at(node, "site is missing tls"))?;
            if upstream.is_some() && redirects.iter().any(|r| r.fallback) {
                return Err(self.at(node, "redirect fallback cannot coexist with a proxy"));
            }
            if !pathward::proxy::site_mode_allowed(
                root.is_some(),
                !publications.is_empty(),
                !redirects.is_empty(),
                upstream.is_some(),
            ) {
                return Err(self.at(
                    node,
                    "publications require a root; site requires publications, redirects or a proxy",
                ));
            }
            if (!limits.websocket && (limits.deflate || !websocket_origins.is_empty()))
                || (!limits.websocket
                    && !limits.sse
                    && limit_names
                        .iter()
                        .any(|(_, key)| key.starts_with("stream-") || *key == "streams"))
                || !limits.valid()
                || (upstream.is_none()
                    && (!proxy_paths.is_empty()
                        || !proxy_routes.is_empty()
                        || !limit_names.is_empty()))
            {
                return Err(self.at(
                    node,
                    "proxy settings require an upstream and bounded, consistent limits",
                ));
            }
            if (!publications.is_empty() && rules::compile(&publications).is_none())
                || (publications.is_empty() && redirects.is_empty() && upstream.is_none())
            {
                return Err(self.at(node, "site requires 1 to 4096 valid, distinct publish URLs"));
            }
            if publications.iter().any(|p| {
                redirects.iter().any(|r| {
                    !r.fallback
                        && pathward::response::route_matches(p.path, r.from.as_bytes(), r.prefix)
                })
            }) {
                return Err(self.at(node, "redirect overlaps a publication"));
            }
            if headers
                .iter()
                .map(|h| h.name.len() + h.value.len() + 4)
                .sum::<usize>()
                > 8192
            {
                return Err(self.at(node, "configured headers exceed 8192 bytes"));
            }
            if root.is_none() && !cache.is_empty() {
                return Err(self.at(node, "cache rules require a static root"));
            }
            // Moving the same vector preserves the byte-for-byte declarations
            // accepted by rules::compile; no expansion or additional rule occurs.
            sites.push(CompiledSite {
                encoding: encoding.unwrap_or(0),
                host,
                root,
                tls,
                upstream,
                denies,
                proxy_paths,
                proxy_routes,
                websocket_origins,
                limits,
                publications,
                redirects,
                headers,
                cache,
            });
        }
        for site in &sites {
            if site
                .redirects
                .iter()
                .any(|r| !sites.iter().any(|s| s.host == r.host))
            {
                return Err(error(
                    &self.source,
                    0,
                    "redirect destination must be a configured site",
                ));
            }
        }
        Ok(CompiledConfig {
            sites,
            source: &self.source,
            shared_nat,
        })
    }

    fn at(&self, node: &KdlNode, message: &str) -> ConfigError {
        error(&self.source, node.span().offset(), message)
    }

    fn arguments<'a>(&self, node: &'a KdlNode, count: usize) -> Result<Vec<&'a str>, ConfigError> {
        if node.ty().is_some() || node.entries().len() != count {
            return Err(self.at(node, "unexpected argument count or type annotation"));
        }
        node.entries()
            .iter()
            .map(|entry| {
                if entry.name().is_some() || entry.ty().is_some() {
                    return Err(self.at(node, "properties and type annotations are not supported"));
                }
                entry
                    .value()
                    .as_string()
                    .ok_or_else(|| self.at(node, "all directive arguments must be strings"))
            })
            .collect()
    }
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            let bytes = label.as_bytes();
            let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
            !bytes.is_empty()
                && bytes.len() <= 63
                && alnum(bytes[0])
                && alnum(bytes[bytes.len() - 1])
                && bytes.iter().all(|&b| alnum(b) || b == b'-')
        })
}

/// A declaration of intent; this configuration library performs no TLS or ACME.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsPolicy {
    Auto,
}

pub struct CompiledSite<'a> {
    encoding: u8,
    host: &'a str,
    root: Option<&'a str>,
    upstream: Option<SocketAddr>,
    denies: Vec<&'a str>,
    proxy_paths: Vec<&'a str>,
    proxy_routes: Vec<ProxyRoute<'a>>,
    websocket_origins: Vec<&'a str>,
    limits: ProxyLimits,
    tls: TlsPolicy,
    publications: Vec<Publication<'a>>,
    redirects: Vec<Redirect<'a>>,
    headers: Vec<Header<'a>>,
    cache: Vec<CacheRule<'a>>,
}

impl<'a> CompiledSite<'a> {
    pub fn encoding(&self) -> u8 {
        self.encoding
    }
    pub fn proxy_routes(&self) -> &[ProxyRoute<'a>] {
        &self.proxy_routes
    }
    pub fn cache_rules(&self) -> &[CacheRule<'a>] {
        &self.cache
    }
    pub fn websocket_origins(&self) -> &[&'a str] {
        &self.websocket_origins
    }
    pub fn denies(&self) -> &[&'a str] {
        &self.denies
    }
    pub fn proxy_paths(&self) -> &[&'a str] {
        &self.proxy_paths
    }
    pub fn proxy_limits(&self) -> ProxyLimits {
        self.limits
    }
    pub fn redirects(&self) -> &[Redirect<'a>] {
        &self.redirects
    }
    pub fn headers(&self) -> &[Header<'a>] {
        &self.headers
    }
    pub fn host(&self) -> &'a str {
        self.host
    }
    pub fn root(&self) -> Option<&'a str> {
        self.root
    }
    pub fn upstream(&self) -> Option<SocketAddr> {
        self.upstream
    }
    pub fn tls(&self) -> TlsPolicy {
        self.tls
    }
    pub fn publications(&self) -> &[Publication<'a>] {
        &self.publications
    }

    /// Exact raw-path lookup through the same Rust function checked by Lean.
    pub fn resolve(&self, raw_path: &[u8]) -> Option<&'a str> {
        let target = rules::lookup(raw_path, &self.publications)?;
        std::str::from_utf8(target).ok()
    }
}

pub struct CompiledConfig<'a> {
    sites: Vec<CompiledSite<'a>>,
    source: &'a str,
    shared_nat: bool,
}

impl<'a> CompiledConfig<'a> {
    pub fn shared_nat(&self) -> bool {
        self.shared_nat
    }
    pub fn source(&self) -> &'a str {
        self.source
    }
    pub fn sites(&self) -> &[CompiledSite<'a>] {
        &self.sites
    }

    /// Takes a canonical configured hostname, not an unvalidated HTTP authority.
    /// Unknown hosts have no fallback to another site's rules.
    pub fn site(&self, host: &str) -> Option<&CompiledSite<'a>> {
        self.sites.iter().find(|site| site.host == host)
    }
}

/// Per-host proxy service budgets. All durations are absolute milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyLimits {
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub body_ms: u64,
    pub connect_ms: u64,
    pub head_ms: u64,
    pub total_ms: u64,
    pub connections: u64,
    pub websocket: bool,
    pub deflate: bool,
    pub streams: u64,
    pub sse: bool,
    pub stream_upload_bytes: u64,
    pub stream_download_bytes: u64,
    pub stream_idle_ms: u64,
    pub stream_total_ms: u64,
}
impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            request_bytes: 1048576,
            response_bytes: 8388608,
            body_ms: 5000,
            connect_ms: 2000,
            head_ms: 10000,
            total_ms: 15000,
            connections: 2,
            websocket: false,
            deflate: false,
            streams: 8,
            sse: false,
            stream_upload_bytes: 16777216,
            stream_download_bytes: 67108864,
            stream_idle_ms: 30000,
            stream_total_ms: 300000,
        }
    }
}
fn quantity(s: &str, time: bool) -> Option<u64> {
    let units: &[(&str, u64)] = if time {
        &[("ms", 1), ("s", 1000)]
    } else {
        &[("KiB", 1024), ("MiB", 1048576), ("B", 1)]
    };
    for &(suffix, scale) in units {
        if let Some(n) = s.strip_suffix(suffix) {
            return number(n)?.checked_mul(scale);
        }
    }
    None
}
fn number(s: &str) -> Option<u64> {
    if s.is_empty()
        || s.len() > 20
        || (s.len() > 1 && s.starts_with('0'))
        || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    s.parse().ok()
}
impl ProxyLimits {
    pub fn valid(self) -> bool {
        pathward::routing::body_limit(self.request_bytes, false)
            && pathward::routing::body_limit(self.response_bytes, true)
            && pathward::routing::time_limits(
                self.body_ms,
                self.connect_ms,
                self.head_ms,
                self.total_ms,
            )
            && pathward::routing::connection_limit(self.connections)
            && pathward::streaming::service_limit(self.streams)
            && pathward::streaming::byte_limit(self.stream_upload_bytes)
            && pathward::streaming::byte_limit(self.stream_download_bytes)
            && pathward::streaming::time_limits(self.stream_idle_ms, self.stream_total_ms)
    }
    fn set(&mut self, kind: &str, key: &str, value: &str) -> bool {
        let (destination, parsed) = match (kind, key) {
            ("proxy-limit", "streams") => (&mut self.streams, number(value)),
            ("proxy-limit", "stream-upload") => {
                (&mut self.stream_upload_bytes, quantity(value, false))
            }
            ("proxy-limit", "stream-download") => {
                (&mut self.stream_download_bytes, quantity(value, false))
            }
            ("proxy-timeout", "stream-idle") => (&mut self.stream_idle_ms, quantity(value, true)),
            ("proxy-timeout", "stream-total") => (&mut self.stream_total_ms, quantity(value, true)),
            ("proxy-limit", "request-body") => (&mut self.request_bytes, quantity(value, false)),
            ("proxy-limit", "response-body") => (&mut self.response_bytes, quantity(value, false)),
            ("proxy-limit", "connections") => (&mut self.connections, number(value)),
            ("proxy-timeout", "request-body") => (&mut self.body_ms, quantity(value, true)),
            ("proxy-timeout", "connect") => (&mut self.connect_ms, quantity(value, true)),
            ("proxy-timeout", "response-head") => (&mut self.head_ms, quantity(value, true)),
            ("proxy-timeout", "total") => (&mut self.total_ms, quantity(value, true)),
            _ => return false,
        };
        if let Some(value) = parsed {
            *destination = value;
            true
        } else {
            false
        }
    }
}

/// Canonical serialized origin only: no URL parsing, decoding, wildcard or path.
pub fn valid_origin(value: &str) -> bool {
    let (host, default) = if let Some(host) = value.strip_prefix("https://") {
        (host, 443)
    } else if let Some(host) = value.strip_prefix("http://") {
        (host, 80)
    } else {
        return false;
    };
    if let Some((host, port)) = host.split_once(':') {
        valid_host(host) && number(port).is_some_and(|n| n > 0 && n <= 65535 && n != default)
    } else {
        valid_host(host)
    }
}
