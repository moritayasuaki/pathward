//! Administrator decisions, independent of subprocesses and persistent storage.
//! Durability, observed service state, monotonic clocks and exclusive locking
//! are adapter obligations, not guarantees of these pure functions.

pub fn stop_old_allowed(pending: bool, armed: bool, preflight: bool, unchanged: bool) -> bool {
    pending && armed && preflight && unchanged
}

pub fn window_allowed(same_boot: bool, started_ns: u64, now_ns: u64) -> bool {
    same_boot && now_ns >= started_ns && now_ns - started_ns < 900_000_000_000
}

pub fn commit_allowed(awaiting: bool, verified: bool, in_window: bool, armed: bool) -> bool {
    awaiting && verified && in_window && armed
}

pub fn disarm_allowed(committed: bool, persisted_epoch: u64, current_epoch: u64) -> bool {
    committed && current_epoch > 0 && persisted_epoch == current_epoch
}

/// Unknown/nonterminal phases still request recovery. A durable commit,
/// untouched preparation, or completed restoration must not be undone.
pub fn watchdog_required(committed: bool, prepared: bool, restored: bool) -> bool {
    !committed && !prepared && !restored
}
