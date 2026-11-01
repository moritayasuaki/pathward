//! Decisions for explicitly delegated, whole-host HTTP proxy sites.
//! The upstream owns URL interpretation; static publication policy is unchanged.
use crate::{response::visible, same_path};

pub const MAX_REQUEST_BODY: u64 = 1024 * 1024;
pub const MAX_RESPONSE_BODY: u64 = 8 * 1024 * 1024;

/// Whole-site delegation is mutually exclusive with filesystem publication.
pub fn site_mode_allowed(root: bool, publications: bool, redirects: bool, proxy: bool) -> bool {
    if proxy {
        !root && !publications && !redirects
    } else {
        root && (publications || redirects)
    }
}

pub fn endpoint_allowed(address: &[u8], port: u16) -> bool {
    port > 0 && (same_path(address, b"127.0.0.1") || same_path(address, b"::1"))
}

pub fn method_allowed(method: &[u8]) -> bool {
    same_path(method, b"GET")
        || same_path(method, b"HEAD")
        || same_path(method, b"POST")
        || same_path(method, b"PUT")
        || same_path(method, b"PATCH")
        || same_path(method, b"DELETE")
        || same_path(method, b"OPTIONS")
}

#[allow(clippy::manual_range_contains)]
pub fn status_allowed(status: u16) -> bool {
    status >= 200 && status <= 599
}

/// Header/framing syntax and canonical decimal parsing remain adapter checks.
pub fn request_framing(length: u64, transfer_encoding: bool, duplicate_length: bool) -> bool {
    length <= MAX_REQUEST_BODY && !transfer_encoding && !duplicate_length
}

pub fn response_framing(length: Option<u64>, chunked: bool, duplicate_length: bool) -> bool {
    if duplicate_length {
        return false;
    }
    match length {
        Some(n) => n <= MAX_RESPONSE_BODY && !chunked,
        None => true,
    }
}

#[allow(clippy::manual_range_contains)]
fn target_bytes(target: &[u8]) -> bool {
    let mut i = 0;
    while i < target.len() {
        let b = target[i];
        if b < 0x21 || b > 0x7e || b == b'#' || b == b'\\' {
            return false;
        }
        i += 1;
    }
    true
}

/// A bounded raw origin-form target. Never decoded or used for file opening.
pub fn target_allowed(target: &[u8]) -> bool {
    !target.is_empty()
        && target.len() <= 8192
        && target[0] == b'/'
        && (target.len() == 1 || target[1] != b'/')
        && target_bytes(target)
}

pub fn hop_header(name: &[u8]) -> bool {
    same_path(name, b"connection")
        || same_path(name, b"keep-alive")
        || same_path(name, b"proxy-authenticate")
        || same_path(name, b"proxy-authorization")
        || same_path(name, b"proxy-connection")
        || same_path(name, b"te")
        || same_path(name, b"trailer")
        || same_path(name, b"transfer-encoding")
        || same_path(name, b"upgrade")
}

/// Names are parsed HTTP tokens, lowercased by the adapter. Connection-nominated
/// fields are removed by the adapter in addition to this fixed policy.
pub fn forwarding_header(name: &[u8]) -> bool {
    if same_path(name, b"forwarded")
        || same_path(name, b"x-real-ip")
        || same_path(name, b"x-original-url")
        || same_path(name, b"x-rewrite-url")
        || same_path(name, b"proxy")
    {
        true
    } else if name.len() >= 12 {
        let (prefix, _) = name.split_at(12);
        same_path(prefix, b"x-forwarded-")
    } else {
        false
    }
}

pub fn request_header(name: &[u8], value: &[u8]) -> bool {
    value.len() <= 4096
        && visible(value)
        && !hop_header(name)
        && !same_path(name, b"host")
        && !same_path(name, b"content-length")
        && !forwarding_header(name)
}

pub fn response_header(name: &[u8], value: &[u8], encrypted: bool) -> bool {
    value.len() <= 4096
        && visible(value)
        && !hop_header(name)
        && !same_path(name, b"content-length")
        && !same_path(name, b"server")
        && !same_path(name, b"alt-svc")
        && (encrypted || !same_path(name, b"strict-transport-security"))
}
