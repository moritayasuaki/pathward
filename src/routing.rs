//! Route precedence and capacity gates; no I/O, allocation or normalization.
use crate::{response, same_path, valid_path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Denied,
    Static,
    Redirect,
    Proxy,
    Missing,
}

/// Denial wins even if a publication or proxy also matches. A selected local
/// route is final: opening/serving failure must not try a lower-priority route.
pub fn select(valid: bool, denied: bool, published: bool, redirect: bool, proxy: bool) -> Route {
    if !valid || denied {
        Route::Denied
    } else if published {
        Route::Static
    } else if redirect {
        Route::Redirect
    } else if proxy {
        Route::Proxy
    } else {
        Route::Missing
    }
}

/// Routing sites require the exact canonical URL, including a directory slash.
/// No normalization: a routing path is never a filesystem grant.
pub fn stem(path: &[u8]) -> Option<&[u8]> {
    if valid_path(path) {
        return Some(path);
    }
    None
}

/// Subtree match with a segment boundary; '/' explicitly selects all paths.
pub fn subtree(path: &[u8], from: &[u8]) -> bool {
    valid_path(path) && (same_path(from, b"/") || response::route_matches(path, from, true))
}

#[allow(clippy::manual_range_contains)]
pub fn body_limit(limit: u64, response: bool) -> bool {
    if response {
        limit <= 67108864
    } else {
        limit <= 16777216
    }
}

pub fn body_fits(length: u64, limit: u64, response: bool) -> bool {
    body_limit(limit, response) && length <= limit
}

pub fn chunk_fits(used: u64, next: u64, limit: u64) -> bool {
    body_fits(used, limit, true) && next <= limit - used
}

#[allow(clippy::manual_range_contains)]
pub fn time_limits(body: u64, connect: u64, head: u64, total: u64) -> bool {
    body >= 100
        && body <= 30000
        && body <= total
        && connect >= 50
        && connect <= 10000
        && connect <= total
        && head >= 100
        && head <= total
        && total >= 100
        && total <= 120000
}

pub fn connection_limit(limit: u64) -> bool {
    limit > 0 && limit <= 3
}

/// Shared across generations; a captured old policy cannot exceed the live cap.
pub fn service_admit(active: u64, captured: u64, current: u64) -> bool {
    connection_limit(captured) && connection_limit(current) && active < captured && active < current
}

pub fn request_framing(length: u64, limit: u64, transfer: bool, duplicate: bool) -> bool {
    body_fits(length, limit, false) && !transfer && !duplicate
}
pub fn response_framing(length: Option<u64>, limit: u64, chunked: bool, duplicate: bool) -> bool {
    if duplicate || !body_limit(limit, true) {
        return false;
    }
    match length {
        Some(n) => body_fits(n, limit, true) && !chunked,
        None => true,
    }
}
