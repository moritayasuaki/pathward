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

/// Phase deadlines never restart when another byte arrives.
pub fn phase_live(elapsed_ms: u64, budget_ms: u64, draining: bool) -> bool {
    !draining && budget_ms > 0 && budget_ms <= 120000 && elapsed_ms < budget_ms
}

/// Idle preconnections have no HTTP request to reject. Partial heads do.
pub fn input_timeout_status(bytes: u64) -> u16 {
    if bytes == 0 { 0 } else { 408 }
}
