//! Gates for opt-in long-lived proxy exchanges. No protocol parsing or I/O.

#[allow(clippy::too_many_arguments)]
pub fn upgrade_request(
    enabled: bool,
    get: bool,
    length: u64,
    prefetched: u64,
    upgrade: bool,
    version: bool,
    key: bool,
    origin: bool,
) -> bool {
    enabled && get && length == 0 && prefetched == 0 && upgrade && version && key && origin
}

#[allow(clippy::too_many_arguments)]
pub fn upgrade_response(
    requested: bool,
    version: bool,
    status: u16,
    upgrade: bool,
    accept: bool,
    protocol: bool,
    extensions_valid: bool,
    length: bool,
    transfer: bool,
) -> bool {
    requested
        && version
        && status == 101
        && upgrade
        && accept
        && protocol
        && extensions_valid
        && !length
        && !transfer
}

pub fn sse_response(
    enabled: bool,
    head: bool,
    status: u16,
    event_type: bool,
    encoded: bool,
) -> bool {
    enabled && !head && status == 200 && event_type && !encoded
}

pub fn byte_limit(limit: u64) -> bool {
    limit > 0 && limit <= 1073741824
}
pub fn bytes_fit(used: u64, next: u64, limit: u64) -> bool {
    byte_limit(limit) && used <= limit && next <= limit - used
}

#[allow(clippy::manual_range_contains)]
pub fn time_limits(idle: u64, total: u64) -> bool {
    idle >= 100 && idle <= 300000 && idle <= total && total <= 3600000
}
pub fn running(stopped: bool, elapsed: u64, quiet: u64, idle: u64, total: u64) -> bool {
    !stopped && time_limits(idle, total) && elapsed < total && quiet < idle
}
pub fn admission(active: u64, stopped: bool) -> bool {
    !stopped && active < 16
}

pub fn peer_admission(active: u64, peer: u64, stopped: bool) -> bool {
    admission(active, stopped) && peer < 8
}
pub fn service_limit(limit: u64) -> bool {
    limit > 0 && limit <= 16
}
pub fn service_admission(active: u64, captured: u64, current: u64) -> bool {
    service_limit(captured) && service_limit(current) && active < captured && active < current
}
pub fn origin_allowed(present: bool, same: bool, listed: bool) -> bool {
    !present || same || listed
}
pub fn deflate_allowed(
    enabled: bool,
    offered: bool,
    selected: bool,
    server_reset: bool,
    client_reset: bool,
    parameters: bool,
) -> bool {
    !selected || (enabled && offered && server_reset && client_reset && parameters)
}
