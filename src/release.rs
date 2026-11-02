//! Manifest correspondence and durable release activation decisions.
use crate::{rules::valid_target, same_path, valid_path};

/// The adapter supplies one entry from the explicit manifest. No discovery.
pub fn generated_rule(url: &[u8], target: &[u8], entry: &[u8], root_alias: bool) -> bool {
    if url.is_empty() {
        return false;
    }
    let (_, suffix) = url.split_at(1);
    valid_path(url)
        && valid_target(target)
        && same_path(target, entry)
        && if root_alias {
            same_path(url, b"/")
        } else {
            same_path(suffix, target)
        }
}

/// Revision bytes are lowercase SHA-256 hex computed by the trusted adapter.
pub fn commit_allowed(
    current: &[u8],
    expected: &[u8],
    prepared: bool,
    persisted: bool,
    draining: bool,
) -> bool {
    current.len() == 64 && same_path(current, expected) && prepared && persisted && !draining
}

/// Admission is evaluated under one adapter lock, with monotonic time accounting.
pub fn admission_allowed(active: u64, per_peer: u64, tokens: u64, draining: bool) -> bool {
    !draining && active < 12 && per_peer < 6 && tokens > 0
}

/// Fixed diagnostic code for the same gate: 0 allows; 1 drains; 2/3 bound
/// global/peer occupancy; 4 requires credit. No client data enters the code.
pub fn admission_rejection(active: u64, per_peer: u64, tokens: u64, draining: bool) -> u64 {
    if draining {
        1
    } else if active >= 12 {
        2
    } else if per_peer >= 6 {
        3
    } else if tokens == 0 {
        4
    } else {
        0
    }
}

/// Separate running-work quota; queued connections still count toward admission.
pub fn dispatch_allowed(running: u64, peer_running: u64, draining: bool) -> bool {
    !draining && running < 4 && peer_running < 2
}

/// Explicit startup-only capacity profile; running workers and deadlines are unchanged.
pub fn capacity_global(shared_nat: bool) -> u64 {
    if shared_nat { 192 } else { 12 }
}
pub fn capacity_peer(shared_nat: bool) -> u64 {
    if shared_nat { 144 } else { 6 }
}
pub fn capacity_queue(shared_nat: bool) -> u64 {
    if shared_nat { 188 } else { 8 }
}
pub fn capacity_rate(shared_nat: bool, peer: bool) -> u64 {
    if shared_nat {
        if peer { 128 } else { 256 }
    } else if peer {
        8
    } else {
        64
    }
}
pub fn capacity_burst(shared_nat: bool, peer: bool) -> u64 {
    if shared_nat {
        if peer { 384 } else { 512 }
    } else if peer {
        16
    } else {
        128
    }
}
pub fn capacity_rejection(
    active: u64,
    per_peer: u64,
    tokens: u64,
    draining: bool,
    shared_nat: bool,
) -> u64 {
    if draining {
        1
    } else if active >= capacity_global(shared_nat) {
        2
    } else if per_peer >= capacity_peer(shared_nat) {
        3
    } else if tokens == 0 {
        4
    } else {
        0
    }
}
/// A reload/activation must never silently replace live admission accounting.
pub fn capacity_reload_allowed(current: bool, candidate: bool) -> bool {
    current == candidate
}

/// Staging handoff gate. The adapter hashes the inspected binaries, configuration,
/// explicit content manifest and listener plan, then rechecks immediately before
/// stopping the fallback. Evidence and the OS handoff remain trusted I/O.
pub fn migration_allowed(
    current: &[u8],
    inspected: &[u8],
    candidate_ready: bool,
    parity: bool,
    rollback_ready: bool,
    isolated: bool,
) -> bool {
    current.len() == 64
        && same_path(current, inspected)
        && candidate_ready
        && parity
        && rollback_ready
        && isolated
}
