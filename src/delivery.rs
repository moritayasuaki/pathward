//! Pure bounds for staged input and finite downstream delivery.
pub fn reserve_allowed(global: u64, peer: u64, amount: u64, draining: bool) -> bool {
    !draining
        && amount > 0
        && global <= 268435456
        && peer <= 201326592
        && amount <= 268435456 - global
        && amount <= 201326592 - peer
}

pub fn shrink_allowed(before: u64, after: u64) -> bool {
    after <= before
}

/// A buffered response reserves room for two body copies and bounded metadata.
/// The adapter checks this before allocating the body, after validating framing.
#[allow(clippy::manual_range_contains)]
pub fn response_storage(body: u64, credit: u64) -> bool {
    credit >= 262144 && credit <= 134479872 && body <= (credit - 262144) / 2
}

/// Phase deadlines never restart when another byte arrives.
pub fn phase_live(elapsed_ms: u64, budget_ms: u64, draining: bool) -> bool {
    !draining && budget_ms > 0 && budget_ms <= 120000 && elapsed_ms < budget_ms
}

/// Idle preconnections have no HTTP request to reject. Partial heads do.
pub fn input_timeout_status(bytes: u64) -> u16 {
    if bytes == 0 { 0 } else { 408 }
}

/// A completed, framed exchange may retain its admitted connection briefly.
pub fn reuse_allowed(completed: u64, age_ms: u64, requested: bool, draining: bool) -> bool {
    requested && !draining && completed > 0 && completed < 100 && age_ms < 120000
}

/// Reusing a socket must not bypass the global or peer request rate budget.
pub fn request_credit(global: u64, peer: u64, draining: bool) -> bool {
    !draining && global > 0 && peer > 0
}

/// Each of the four fixed executors holds at most 64 admitted tasks.
pub fn task_slot(running: u64) -> bool {
    running < 64
}

/// Compression is limited to small, complete, non-sensitive textual responses.
#[allow(clippy::too_many_arguments, clippy::manual_range_contains)]
pub fn encode_allowed(
    enabled: bool,
    size: u64,
    status: u16,
    safe_method: bool,
    sensitive: bool,
    range: bool,
    encoded: bool,
    no_transform: bool,
    text: bool,
) -> bool {
    enabled
        && size >= 1024
        && size <= 4194304
        && status == 200
        && safe_method
        && !sensitive
        && !range
        && !encoded
        && !no_transform
        && text
}

/// HTTP/2 and HTTP/3 share per-connection stream, request and new-admission age caps.
pub fn multiplex_slot(active: u64, seen: u64, age_ms: u64, draining: bool) -> bool {
    !draining && active < 32 && seen < 100 && age_ms < 120000
}

/// Unadmitted, cancelled heads have a separate finite work and age budget.
/// They never consume a successfully admitted request's reuse allowance.
pub fn cancel_slot(discarded: u64, age_ms: u64) -> bool {
    discarded < 256 && age_ms < 120000
}

/// A held head uses one slot of the same connection window as running tasks.
pub fn head_slot(active: u64, held: bool) -> bool {
    !held && active < 32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeldAction {
    Discard,
    Expire,
    TryAdmission,
}

/// Observed cancellation wins over both an expired deadline and free capacity.
/// The clock starts when this head is accepted and is never restarted by waits.
pub fn held_action(cancelled: bool, elapsed_ms: u64) -> HeldAction {
    if cancelled {
        HeldAction::Discard
    } else if elapsed_ms >= 5000 {
        HeldAction::Expire
    } else {
        HeldAction::TryAdmission
    }
}
/// Normal retirement must not discard accepted work. An explicit server stop
/// has its own non-renewable five-second drain limit. Normal idle time restarts
/// after each finished task. Both clocks must allow five seconds: quiet time
/// before retirement began cannot stand in for time to flush its GOAWAY.
pub fn retirement_close(
    retiring: bool,
    quiet_ms: u64,
    retired_ms: u64,
    active: u64,
    held: bool,
    stopping: bool,
    stopped_ms: u64,
) -> bool {
    (stopping && stopped_ms >= 5000)
        || (retiring && quiet_ms >= 5000 && retired_ms >= 5000 && active == 0 && !held)
}

/// Before handshake confirmation, only anonymous, exact static grants are safe.
pub fn early_allowed(
    confirmed: bool,
    read: bool,
    published: bool,
    body: u64,
    sensitive: bool,
) -> bool {
    confirmed || (read && published && body == 0 && !sensitive)
}

/// Includes HTTP/3 framing overhead; applied before library frame buffering.
pub fn wire_fits(used: u64, next: u64, limit: u64) -> bool {
    limit <= 134283264 && used <= limit && next <= limit - used
}
