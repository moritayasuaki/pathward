//! Pure gates for explicit, anonymous resource discovery before one exchange.

/// Discovery must not carry a client body, credentials, or a mutating method.
pub fn probe_allowed(
    get: bool,
    body: u64,
    credentials: bool,
    resource: bool,
    candidates: u64,
) -> bool {
    get && body == 0 && !credentials && resource && candidates > 0 && candidates <= 32
}

/// Only absence permits trying the next discovery endpoint. Authorization,
/// gone, overload, connection errors and server errors must never fall through.
pub fn probe_next(status: u16, remaining: u64) -> bool {
    status == 404 && remaining > 0 && remaining < 32
}

#[allow(clippy::manual_range_contains)] // scalar comparisons in the extracted model
pub fn probe_owned(status: u16) -> bool {
    (status >= 200 && status < 300) || status == 401 || status == 403 || status == 410
}

/// Query headers conservatively apply to encoded/ambiguous keys as well.
pub fn query_match(exact: bool, ambiguous: bool) -> bool {
    exact || ambiguous
}

/// Return the actual route member, never an address supplied by the request.
/// Zero is outside the encoding of a permitted loopback socket address.
pub fn pool_select(members: &[u32], index: usize, ready: bool, draining: bool, sent: bool) -> u32 {
    if ready && !draining && !sent && members.len() <= 32 && index < members.len() {
        members[index]
    } else {
        0
    }
}

/// Consume this request's only dispatch permission before its first socket write.
pub fn begin_dispatch(sent: &mut bool) -> bool {
    let allowed = !*sent;
    *sent = true;
    allowed
}

/// Monotonic nanoseconds in the pool's clock domain. Revision zero
/// denotes a cold member; an exhausted revision permanently refuses dispatch.
#[derive(Clone, Copy, Default)]
pub struct PoolHealth {
    pub revision: u64,
    pub at: u64,
    pub status: u16,
}

pub fn publish_health(old: PoolHealth, expected: u64, now: u64, status: u16) -> PoolHealth {
    if expected != old.revision || expected == u64::MAX || now < old.at {
        return old;
    }
    PoolHealth {
        revision: expected + 1,
        at: now,
        status,
    }
}

pub fn within_health_ttl(at: u64, now: u64) -> bool {
    now != u64::MAX && now >= at && now - at < 5_000_000_000
}

pub fn fresh_health(h: PoolHealth, now: u64) -> bool {
    h.revision != 0 && h.revision != u64::MAX && within_health_ttl(h.at, now)
}

/// An in-flight probe can be suspended even after its response has arrived.
/// Charge its entire lifetime against the TTL before publishing any result.
pub fn publish_probe(
    old: PoolHealth,
    expected: u64,
    started: u64,
    finished: u64,
    status: u16,
) -> PoolHealth {
    if within_health_ttl(started, finished) {
        publish_health(old, expected, started, status)
    } else {
        old
    }
}

/// The reserved maximum makes an unrepresentable or unavailable sample stale.
pub fn pool_tick(nanos: Option<u128>) -> u64 {
    match nanos {
        Some(n) if n < u64::MAX as u128 => n as u64,
        _ => u64::MAX,
    }
}

/// Resume an already-started write on its connected transport.
pub fn write_suffix(bytes: &[u8], accepted: usize) -> Option<&[u8]> {
    if accepted <= bytes.len() {
        Some(&bytes[accepted..])
    } else {
        None
    }
}

/// A retryable error accepted no bytes. Zero progress reported as success or
/// a count larger than the offered slice terminates the transfer.
pub fn remaining_after_write(bytes: &[u8], count: Option<usize>) -> Option<&[u8]> {
    match count {
        None => Some(bytes),
        Some(0) => None,
        Some(n) => write_suffix(bytes, n),
    }
}

#[allow(clippy::manual_range_contains)]
pub fn healthy_response(status: u16) -> bool {
    status >= 200 && status < 300
}

pub fn retire_pool(retired: &mut bool) {
    *retired = true;
}

pub struct FirstWriteGate {
    pub peer: u32,
    pub health: PoolHealth,
    pub now: u64,
    pub draining: bool,
    pub retired: bool,
}

pub fn first_write_allowed(
    members: &[u32],
    index: usize,
    gate: &FirstWriteGate,
    sent: bool,
) -> bool {
    let ready = fresh_health(gate.health, gate.now) && healthy_response(gate.health.status);
    gate.peer != 0
        && pool_select(members, index, ready, gate.draining || gate.retired, sent) == gate.peer
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirstIo {
    Wait,
    Written(usize),
    Failed,
}

/// Keep the original fatal error for the caller while spending the first-write
/// permission in the driver. Only a retryable error returns a wait event.
pub fn first_write_report<E>(report: Result<Option<usize>, E>) -> (FirstIo, Option<E>) {
    match report {
        Ok(Some(n)) => (FirstIo::Written(n), None),
        Ok(None) => (FirstIo::Wait, None),
        Err(e) => (FirstIo::Failed, Some(e)),
    }
}

/// The socket adapter implements this effect as one nonblocking write on the
/// same connected descriptor whose peer was checked. There is no reconnect here.
pub trait FirstWriter {
    fn write_once(&mut self) -> FirstIo;
}

pub fn guarded_first_write<W: FirstWriter>(
    members: &[u32],
    index: usize,
    gate: &FirstWriteGate,
    sent: &mut bool,
    writer: &mut W,
) -> Option<FirstIo> {
    if !first_write_allowed(members, index, gate, *sent) {
        return None;
    }
    let outcome = writer.write_once();
    if let FirstIo::Wait = outcome {
        return Some(FirstIo::Wait);
    }
    begin_dispatch(sent);
    Some(match outcome {
        FirstIo::Written(0) => FirstIo::Failed,
        other => other,
    })
}

/// The adapter reads the marker and file size under a lock. Only one awake byte
/// admits a reader or lets a supervisor start another sleep.
pub fn sleep_fence_awake(count: u64, first: u8) -> bool {
    count == 1 && first == b'A'
}
