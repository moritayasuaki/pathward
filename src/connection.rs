//! Pure gates for one ACME request's bounded, staggered TCP attempts.
//! The adapter supplies elapsed time from the same start instant for DNS,
//! dialing, TLS and response handling; launches cannot reset that instant.

pub fn candidate_slot(used: u64) -> bool {
    used < 8
}

pub fn request_live(elapsed_ns: u64, budget_ns: u64) -> bool {
    budget_ns > 0 && budget_ns <= 30_000_000_000 && elapsed_ns < budget_ns
}

pub fn launch_allowed(
    total: u64,
    launched: u64,
    elapsed_ns: u64,
    budget_ns: u64,
    spaced: bool,
) -> bool {
    total > 0 && total <= 8 && launched < total && spaced && request_live(elapsed_ns, budget_ns)
}

/// A ready I/O result observed at or after the deadline is not a success.
pub fn success_allowed(elapsed_ns: u64, budget_ns: u64) -> bool {
    request_live(elapsed_ns, budget_ns)
}
