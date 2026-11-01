use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct ProxyRoute<'a> {
    pub prefix: &'a str,
    /// Zero selects a fixed subtree route. Otherwise discover one hex resource.
    pub width: usize,
    pub candidates: Vec<SocketAddr>,
}
pub(crate) fn prefix(s: &str) -> bool {
    pathward::valid_path(s.as_bytes()) && (s == "/" || !s.ends_with('/'))
}
impl<'a> ProxyRoute<'a> {
    pub(crate) fn parse(v: &[&'a str], resource: bool) -> Option<Self> {
        if !prefix(v[0]) || (resource && v[0] == "/") {
            return None;
        }
        let width = if resource {
            let n: usize = v[1].parse().ok()?;
            if n == 0 || n > 64 || n.to_string() != v[1] {
                return None;
            }
            n
        } else {
            0
        };
        let mut candidates = Vec::new();
        for endpoint in v[if resource { 2 } else { 1 }].split(',') {
            let addr: SocketAddr = endpoint.parse().ok()?;
            if addr.to_string() != endpoint
                || !pathward::proxy::endpoint_allowed(addr.ip().to_string().as_bytes(), addr.port())
                || candidates.contains(&addr)
                || candidates.len() == 32
            {
                return None;
            }
            candidates.push(addr);
        }
        if !resource && candidates.len() != 1 {
            return None;
        }
        Some(Self {
            prefix: v[0],
            width,
            candidates,
        })
    }
}
