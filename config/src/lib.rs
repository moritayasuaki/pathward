//! KDL 2 parsing and a strict schema around the verified publication compiler.
//! Parsing, schema adaptation, hostname selection, and allocation are audited
//! and tested Rust, outside the Lean proof of `pathward::rules`.
#![forbid(unsafe_code)]

mod surface;

use kdl::{KdlDocument, KdlNode};
use pathward::rules::{self, Publication};
use std::fmt;
use std::io::Read;

pub const MAX_CONFIG_BYTES: usize = 65_536;
pub const MAX_SITES: usize = 16;
pub const MAX_PUBLICATIONS: usize = 256;
pub const MAX_REDIRECTS: usize = 64;
pub const MAX_HEADERS: usize = 32;

#[derive(Clone, Copy)]
pub struct Redirect<'a> {
    pub from: &'a str,
    pub host: &'a str,
    pub to: &'a str,
    pub status: u16,
    pub prefix: bool,
}
#[derive(Clone, Copy)]
pub struct Header<'a> {
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
            return Err(error("", 0, "configuration exceeds 65536 bytes"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| error("", 0, "configuration must be UTF-8"))?;
        Self::parse(text)
    }

    pub fn parse(source: &str) -> Result<Self, ConfigError> {
        if source.len() > MAX_CONFIG_BYTES {
            return Err(error(source, 0, "configuration exceeds 65536 bytes"));
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
        let nodes = self.document.nodes();
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
            let mut publications = Vec::new();
            let mut redirects = Vec::new();
            let mut headers = Vec::new();
            for child in children.nodes() {
                if child.children().is_some() {
                    return Err(self.at(child, "nested directive blocks are not supported"));
                }
                match child.name().value() {
                    "root" => {
                        let values = self.arguments(child, 1)?;
                        if root.is_some() {
                            return Err(self.at(child, "duplicate root directive"));
                        }
                        if !pathward::valid_path(values[0].as_bytes()) {
                            return Err(
                                self.at(child, "root must be an absolute canonical Unix path")
                            );
                        }
                        root = Some(values[0]);
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
                            return Err(self.at(child, "a site may publish at most 256 URLs"));
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
                    "redirect" | "redirect-prefix" => {
                        let v = self.arguments(child, 4)?;
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
                            || (prefix && v[0] == "/")
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
                        });
                    }
                    "header" => {
                        let v = self.arguments(child, 3)?;
                        if headers.len() == MAX_HEADERS
                            || (v[0] != "*" && !pathward::valid_path(v[0].as_bytes()))
                            || !pathward::response::header_allowed(v[1].as_bytes(), v[2].as_bytes())
                            || headers
                                .iter()
                                .any(|h: &Header<'_>| h.scope == v[0] && h.name == v[1])
                        {
                            return Err(self.at(child, "invalid, duplicate or excessive header"));
                        }
                        headers.push(Header {
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
            let root = root.ok_or_else(|| self.at(node, "site is missing root"))?;
            let tls = tls.ok_or_else(|| self.at(node, "site is missing tls"))?;
            if (!publications.is_empty() && rules::compile(&publications).is_none())
                || (publications.is_empty() && redirects.is_empty())
            {
                return Err(self.at(node, "site requires 1 to 256 valid, distinct publish URLs"));
            }
            if publications.iter().any(|p| {
                redirects
                    .iter()
                    .any(|r| pathward::response::route_matches(p.path, r.from.as_bytes(), r.prefix))
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
            // Moving the same vector preserves the byte-for-byte declarations
            // accepted by rules::compile; no expansion or additional rule occurs.
            sites.push(CompiledSite {
                host,
                root,
                tls,
                publications,
                redirects,
                headers,
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
    host: &'a str,
    root: &'a str,
    tls: TlsPolicy,
    publications: Vec<Publication<'a>>,
    redirects: Vec<Redirect<'a>>,
    headers: Vec<Header<'a>>,
}

impl<'a> CompiledSite<'a> {
    pub fn redirects(&self) -> &[Redirect<'a>] {
        &self.redirects
    }
    pub fn headers(&self) -> &[Header<'a>] {
        &self.headers
    }
    pub fn host(&self) -> &'a str {
        self.host
    }
    pub fn root(&self) -> &'a str {
        self.root
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
}

impl<'a> CompiledConfig<'a> {
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
