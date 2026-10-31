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

/// Separate running-work quota; queued connections still count toward admission.
pub fn dispatch_allowed(running: u64, peer_running: u64, draining: bool) -> bool {
    !draining && running < 4 && peer_running < 2
}
