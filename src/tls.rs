//! Pure TLS identity, secret metadata and certificate lifecycle decisions.
//! Cryptography, certificate parsing, clocks and persistence remain adapter inputs.
use crate::same_path;

pub fn identity_allowed(sni: &[u8], host: &[u8], configured: &[u8]) -> bool {
    !sni.is_empty() && same_path(sni, host) && same_path(host, configured)
}

#[derive(Clone, Copy, Debug)]
pub struct SecretFacts {
    pub regular: bool,
    pub owner: u32,
    pub mode: u32,
    pub links: u64,
    pub size: u64,
    pub device: u64,
    pub inode: u64,
}

/// Mode contains the complete Unix permission/special-bit field (07777).
pub fn secret_allowed(pin: &SecretFacts, opened: &SecretFacts, uid: u32) -> bool {
    pin.regular
        && opened.regular
        && pin.owner == uid
        && opened.owner == uid
        && pin.mode == 384
        && opened.mode == 384
        && pin.links == 1
        && opened.links == 1
        && pin.size <= 1_048_576
        && opened.size == pin.size
        && pin.device == opened.device
        && pin.inode == opened.inode
}

/// A candidate cannot replace the current identity before durable storage succeeds.
pub fn activate(
    not_before: u64,
    not_after: u64,
    now: u64,
    key_matches: bool,
    names_match: bool,
    persisted: bool,
) -> bool {
    key_matches && names_match && persisted && not_before <= now && now < not_after
}

/// Renew in the final third of certificate lifetime. Invalid/backward-clock
/// intervals trigger a retry rather than deferring renewal past expiration.
pub fn renewal_due(not_before: u64, not_after: u64, now: u64) -> bool {
    if now < not_before || now >= not_after {
        return true;
    }
    let lifetime = not_after - not_before;
    let remaining = not_after - now;
    remaining <= lifetime / 3
}
