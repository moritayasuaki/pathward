//! Pure HTTP response policy; serialization and I/O stay in the adapter.
use crate::{same_path, serving::request_path, valid_path};

/// Public TLS/redirect modes use their fixed external ports, even behind DNAT.
/// Direct loopback HTTP uses its listening port. Forwarded headers are ignored.
pub fn authority_port(local: u16, encrypted: bool, redirect: bool) -> u16 {
    if encrypted {
        443
    } else if redirect {
        80
    } else {
        local
    }
}

/// An omitted port is accepted; an explicit port must match the trusted endpoint.
pub fn authority_port_allowed(explicit: Option<u16>, expected: u16) -> bool {
    if expected == 0 {
        return false;
    }
    match explicit {
        Some(port) => port == expected,
        None => true,
    }
}

#[allow(clippy::manual_range_contains)]
pub fn visible(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] < 0x20 || bytes[i] > 0x7e {
            return false;
        }
        i += 1;
    }
    true
}

pub fn header_name(name: &[u8]) -> bool {
    same_path(name, b"content-security-policy")
        || same_path(name, b"strict-transport-security")
        || same_path(name, b"referrer-policy")
        || same_path(name, b"permissions-policy")
        || same_path(name, b"x-frame-options")
        || same_path(name, b"x-robots-tag")
        || same_path(name, b"link")
}

pub fn header_allowed(name: &[u8], value: &[u8]) -> bool {
    header_name(name) && !value.is_empty() && value.len() <= 4096 && visible(value)
}

#[allow(clippy::manual_range_contains)]
pub fn host_bytes(host: &[u8]) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let mut i = 0;
    while i < host.len() {
        let b = host[i];
        if !((b >= b'a' && b <= b'z') || (b >= b'0' && b <= b'9') || b == b'.' || b == b'-') {
            return false;
        }
        i += 1;
    }
    true
}

/// The caller selects `configured_host` from the compiled site set.
/// It emits the literal https:// prefix, this host, then the checked target.
pub fn redirect_allowed(host: &[u8], configured_host: &[u8], target: &[u8], status: u16) -> bool {
    (status == 301 || status == 308)
        && same_path(host, configured_host)
        && host_bytes(host)
        && visible(target)
        && request_path(target).is_some()
}

/// Exact match, or a component-boundary prefix. '/' is exact only.
pub fn route_matches(path: &[u8], from: &[u8], prefix: bool) -> bool {
    if !valid_path(path) || !valid_path(from) || path.len() < from.len() {
        return false;
    }
    let (head, tail) = path.split_at(from.len());
    same_path(head, from) && (tail.is_empty() || (prefix && from.len() > 1 && tail[0] == b'/'))
}
