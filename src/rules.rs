//! Checked compilation of explicit URL-to-file declarations.
//! Targets are relative, lexical paths; this does not open or confine files.

use crate::{State, same_path, step, valid_path};

/// A declaration supplied by the configuration adapter. Both byte strings are
/// preserved exactly; compilation never adds a wildcard or implicit index.
#[derive(Clone, Copy, Debug)]
pub struct Publication<'a> {
    pub path: &'a [u8],
    pub target: &'a [u8],
}

/// A nonempty relative path with the same component grammar as public URLs.
/// The 4095-byte bound leaves room for a leading slash in its specification.
pub fn valid_target(target: &[u8]) -> bool {
    if target.is_empty() || target.len() > 4095 {
        return false;
    }
    let mut state = State::Root;
    let mut i = 0;
    while i < target.len() {
        state = step(state, target[i]);
        i += 1;
    }
    matches!(state, State::Root | State::Segment)
}

fn contains_path(path: &[u8], rules: &[Publication<'_>], index: usize) -> bool {
    if index < rules.len() {
        if same_path(path, rules[index].path) {
            true
        } else {
            contains_path(path, rules, index + 1)
        }
    } else {
        false
    }
}

fn valid_rules(rules: &[Publication<'_>], index: usize) -> bool {
    if index < rules.len() {
        let rule = rules[index];
        valid_path(rule.path)
            && valid_target(rule.target)
            && !contains_path(rule.path, rules, index + 1)
            && valid_rules(rules, index + 1)
    } else {
        true
    }
}

/// All-or-nothing compilation. Success returns exactly the input declarations.
/// Duplicate URLs (including identical duplicate mappings) are errors.
pub fn compile<'a>(rules: &'a [Publication<'a>]) -> Option<&'a [Publication<'a>]> {
    if rules.is_empty() || rules.len() > 4096 || !valid_rules(rules, 0) {
        None
    } else {
        Some(rules)
    }
}

fn lookup_from<'a>(path: &[u8], rules: &[Publication<'a>], index: usize) -> Option<&'a [u8]> {
    if index < rules.len() {
        let rule = rules[index];
        if same_path(path, rule.path) {
            if valid_target(rule.target) {
                Some(rule.target)
            } else {
                None
            }
        } else {
            lookup_from(path, rules, index + 1)
        }
    } else {
        None
    }
}

/// Resolve a raw URL path by exact match. Even callers that bypass compilation
/// cannot obtain an invalid path or target. Compile first to reject ambiguity.
pub fn lookup<'a>(path: &[u8], rules: &[Publication<'a>]) -> Option<&'a [u8]> {
    if rules.len() > 4096 || !valid_path(path) {
        None
    } else {
        lookup_from(path, rules, 0)
    }
}
