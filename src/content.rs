//! Decisions at the static representation boundary; no header parsing or I/O.

/// A half-open range must fit the already-authorized, descriptor-checked file.
/// Subtraction follows the start check, so neither overflow nor wrap is needed.
pub fn span_allowed(size: u64, start: u64, count: u64) -> bool {
    size <= crate::serving::MAX_FILE_BYTES && start <= size && count <= size - start
}

/// RFC 9110 precedence, for the existing GET/HEAD static representation only.
/// Inputs are comparisons performed by the bounded HTTP adapter.
#[allow(clippy::manual_unwrap_or, clippy::manual_unwrap_or_default)] // explicit matches for extraction
pub fn precondition_status(
    if_match: Option<bool>,
    if_unmodified: Option<bool>,
    if_none_match: Option<bool>,
    if_not_modified: Option<bool>,
) -> u16 {
    let allowed = match if_match {
        Some(value) => value,
        None => match if_unmodified {
            Some(value) => value,
            None => true,
        },
    };
    if !allowed {
        return 412;
    }
    let unchanged = match if_none_match {
        Some(value) => value,
        None => match if_not_modified {
            Some(value) => value,
            None => false,
        },
    };
    if unchanged { 304 } else { 200 }
}

/// Only explicitly public static representations may receive shared freshness.
/// Errors and credential-bearing requests always retain no-store.
pub fn shared_cache_allowed(
    status: u16,
    authorized: bool,
    credentials: bool,
    seconds: u64,
) -> bool {
    authorized
        && !credentials
        && seconds <= 31536000
        && (status == 200 || status == 206 || status == 304)
}
