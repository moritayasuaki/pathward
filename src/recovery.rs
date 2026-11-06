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
