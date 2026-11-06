//! Native publication and retention decisions; observations belong to the adapter.
pub fn mapping_allowed(canonical: bool, selected: bool, synthetic: bool) -> bool {
    canonical && (selected || synthetic)
}

#[allow(clippy::too_many_arguments)]
pub fn receipt_allowed(
    policy: bool,
    boot: bool,
    revision: bool,
    source: bool,
    files: bool,
    after: u64,
    observed: u64,
    now: u64,
) -> bool {
    policy && boot && revision && source && files && after < observed && observed <= now
}

pub fn collection_allowed(
    stable: bool,
    later_boot: bool,
    observed: bool,
    protected: bool,
    exact: bool,
) -> bool {
    stable && later_boot && observed && !protected && exact
}
