#![no_std]
#![forbid(unsafe_code)]

//! Strict, byte-preserving URL path validation and exact allowlist authorization.
//! This crate performs no decoding, normalization, allocation, or filesystem I/O.

pub mod publication;
pub mod rules;

/// The small state machine used to recognize canonical paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Start,
    Root,
    Segment,
    Dot,
    Separator,
    Reject,
}

/// ASCII characters that can begin a public path component.
// Explicit comparisons keep the extracted verification core small.
#[allow(clippy::manual_range_contains)]
pub fn name_byte(byte: u8) -> bool {
    (byte >= b'a' && byte <= b'z')
        || (byte >= b'A' && byte <= b'Z')
        || (byte >= b'0' && byte <= b'9')
        || byte == b'_'
        || byte == b'-'
        || byte == b'+'
}

/// One total transition. Reject is absorbing.
pub fn step(state: State, byte: u8) -> State {
    match state {
        State::Start => {
            if byte == b'/' {
                State::Root
            } else {
                State::Reject
            }
        }
        State::Root | State::Separator => {
            if name_byte(byte) {
                State::Segment
            } else {
                State::Reject
            }
        }
        State::Segment | State::Dot => {
            if name_byte(byte) {
                State::Segment
            } else if byte == b'.' {
                State::Dot
            } else if byte == b'/' && state == State::Segment {
                State::Separator
            } else {
                State::Reject
            }
        }
        State::Reject => State::Reject,
    }
}

/// The root, complete components, and one final directory separator are accepted.
pub fn accepting(state: State) -> bool {
    matches!(state, State::Root | State::Segment | State::Separator)
}

/// Validate a raw URL *path*, excluding query and fragment, without modifying it.
/// Paths longer than 4096 bytes are refused before scanning.
pub fn valid_path(path: &[u8]) -> bool {
    if path.len() > 4096 {
        return false;
    }
    let mut state = State::Start;
    let mut i = 0;
    while i < path.len() {
        state = step(state, path[i]);
        i += 1;
    }
    accepting(state)
}

/// Byte-for-byte comparison, including length; no prefix matching.
pub fn same_path(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut i = 0;
    while i < left.len() {
        if left[i] != right[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Deny by default. Even an explicitly listed unsafe path remains denied.
pub fn is_public(path: &[u8], published: &[&[u8]]) -> bool {
    if published.len() > 4096 || !valid_path(path) {
        return false;
    }
    listed(path, published, 0)
}

// The public entry point bounds recursion to 4097 calls. Using a recursive
// helper avoids Aeneas's nested-borrow loop-invariant limitation.
fn listed(path: &[u8], published: &[&[u8]], index: usize) -> bool {
    if index < published.len() {
        if same_path(path, published[index]) {
            true
        } else {
            listed(path, published, index + 1)
        }
    } else {
        false
    }
}

pub mod serving;

pub mod tls;

pub mod runtime;

pub mod response;

pub mod release;

pub mod proxy;

pub mod routing;

pub mod streaming;

pub mod connection;
pub mod content;
pub mod cutover;
pub mod delivery;
pub mod recovery;
pub mod upstream;
