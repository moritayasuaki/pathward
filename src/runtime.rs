//! Transaction and admission decisions. OS facts are checked by the server adapter.

/// A failed/stale/draining transaction preserves the current generation.
pub fn commit_generation(
    current: u64,
    expected: u64,
    prepared: bool,
    identity_matches: bool,
    storage_isolated: bool,
    draining: bool,
) -> u64 {
    if prepared
        && identity_matches
        && storage_isolated
        && !draining
        && current == expected
        && current < u64::MAX
    {
        current + 1
    } else {
        current
    }
}

pub fn ready(draining: bool, serving: bool, tls: bool, certificate_valid: bool) -> bool {
    !draining && serving && (!tls || certificate_valid)
}
