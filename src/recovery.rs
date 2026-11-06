//! Cold-boot selection from an independently durable plan and checked records.
//! Authenticity, file durability and observation of services are adapter duties.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    Hold,
    Old,
    New,
}

pub fn select(
    plan_valid: bool,
    record_valid: bool,
    committed: bool,
    same_transaction: bool,
    new_valid: bool,
    old_valid: bool,
) -> Selection {
    if !plan_valid {
        Selection::Hold
    } else if record_valid && committed && same_transaction && new_valid {
        Selection::New
    } else if old_valid {
        Selection::Old
    } else {
        Selection::Hold
    }
}

pub fn start_allowed(
    chosen: Selection,
    requested: Selection,
    same_boot: bool,
    same_plan: bool,
) -> bool {
    same_boot && same_plan && chosen != Selection::Hold && chosen == requested
}

pub fn stop_old_allowed(plan_durable: bool, boot_guard_durable: bool, old_valid: bool) -> bool {
    plan_durable && boot_guard_durable && old_valid
}

pub fn trial_allowed(same_boot: bool, same_plan: bool, timer_armed: bool, elapsed_ns: u64) -> bool {
    same_boot && same_plan && timer_armed && elapsed_ns < 900_000_000_000
}

pub fn fallback_allowed(
    selected_new: bool,
    same_boot: bool,
    same_plan: bool,
    failed: bool,
    old_valid: bool,
) -> bool {
    selected_new && same_boot && same_plan && failed && old_valid
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeAction {
    Reject,
    Install,
    Finish,
}

/// Content identities are checked separately from epochs by the adapter.
pub fn upgrade_action(
    base_epoch: u64,
    target_epoch: u64,
    current_is_base: bool,
    current_is_target: bool,
    ready: bool,
    compatible: bool,
    stable: bool,
) -> UpgradeAction {
    if !ready
        || !compatible
        || !stable
        || base_epoch == u64::MAX
        || target_epoch != base_epoch + 1
        || (current_is_base && current_is_target)
    {
        UpgradeAction::Reject
    } else if current_is_target {
        UpgradeAction::Finish
    } else if current_is_base {
        UpgradeAction::Install
    } else {
        UpgradeAction::Reject
    }
}

/// Two independently recoverable plans must agree on the running service.
pub fn migration_allowed(
    separate_records: bool,
    same_units: bool,
    source_stable: bool,
    target_ready: bool,
    same_selection: bool,
    fallback_valid: bool,
) -> bool {
    separate_records
        && same_units
        && source_stable
        && target_ready
        && same_selection
        && fallback_valid
}

/// Only unpinned, strictly older, managed objects can be retired after a reboot.
pub fn collection_allowed(
    completed: bool,
    later_boot: bool,
    quiet: bool,
    pinned: bool,
    older: bool,
    managed: bool,
) -> bool {
    completed && later_boot && quiet && !pinned && older && managed
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractChoice {
    Hold,
    Source,
    Fallback,
    Primary,
}

/// Cross-role changes require an independent durable rescue and an empty
/// service set; a same-service handoff is insufficient for this operation.
pub fn contract_install_allowed(
    rescue_durable: bool,
    all_stopped: bool,
    no_jobs: bool,
    permit_revoked: bool,
    request_current: bool,
    contract_verified: bool,
) -> bool {
    rescue_durable
        && all_stopped
        && no_jobs
        && permit_revoked
        && request_current
        && contract_verified
}

pub fn contract_commit_allowed(
    trial: bool,
    request_current: bool,
    only_target_running: bool,
    healthy: bool,
    fallback_verified: bool,
    loaded_contract: bool,
) -> bool {
    trial
        && request_current
        && only_target_running
        && healthy
        && fallback_verified
        && loaded_contract
}

pub fn contract_gate_allowed(
    choice: ContractChoice,
    member: bool,
    same_boot: bool,
    same_request: bool,
    phase_allows: bool,
    installed_contract: bool,
) -> bool {
    match choice {
        ContractChoice::Hold => false,
        _ => member && same_boot && same_request && phase_allows && installed_contract,
    }
}

/// A cold boot never resumes an uncommitted trial. Committed primary failure
/// prefers the new fallback, retaining the independently sealed source last.
pub fn contract_recovery_choice(
    committed: bool,
    fallback_requested: bool,
    primary_valid: bool,
    fallback_valid: bool,
    source_valid: bool,
) -> ContractChoice {
    if committed && !fallback_requested && primary_valid {
        ContractChoice::Primary
    } else if committed && fallback_valid {
        ContractChoice::Fallback
    } else if source_valid {
        ContractChoice::Source
    } else {
        ContractChoice::Hold
    }
}

pub fn contract_watchdog_allowed(committed: bool, incomplete: bool, request_current: bool) -> bool {
    !committed && incomplete && request_current
}
