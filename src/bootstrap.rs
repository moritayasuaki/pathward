//! Pure preparation and publication decisions extracted to Lean.
pub fn preparation_allowed(rescue: bool, current: bool, source_only: bool, no_jobs: bool) -> bool {
    rescue && current && source_only && no_jobs
}
pub fn package_allowed(sealed: bool, exact: bool, private: bool, unchanged: bool) -> bool {
    sealed && exact && private && unchanged
}
pub fn asset_allowed(known: bool, additive: bool, immutable: bool, equal: bool) -> bool {
    (known || additive) && (!immutable || !known || equal)
}
pub fn restore_allowed(same_backend: bool, ours: bool, backup_verified: bool) -> bool {
    same_backend && ours && backup_verified
}
pub fn reviewed_asset_allowed(confined: bool, ordinary: bool, explicitly_public: bool) -> bool {
    confined && (ordinary || explicitly_public)
}
pub fn bridge_receipt_allowed(policy: bool, boot: bool, after_start: bool, fresh: bool) -> bool {
    policy && boot && after_start && fresh
}
