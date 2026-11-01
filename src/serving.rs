//! Pure decisions used by the HTTP and Linux file adapters.
//! This module performs no parsing of HTTP headers, OS calls, or I/O.
use crate::{rules, same_path, valid_path};

pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

/// The exact first '?' offset, or the complete target length. No decoding.
pub fn path_length(target: &[u8]) -> usize {
    let mut i = 0;
    while i < target.len() {
        if target[i] == b'?' {
            return i;
        }
        i += 1;
    }
    i
}

// Explicit scalar comparisons keep the extracted state machine small.
#[allow(clippy::manual_range_contains)]
fn query_bytes(query: &[u8]) -> bool {
    let mut i = 0;
    while i < query.len() {
        let b = query[i];
        if b < 0x21 || b > 0x7e || b == b'#' {
            return false;
        }
        i += 1;
    }
    true
}

/// Borrow the unchanged origin-form path. An optional visible-ASCII query is
/// ignored for authorization; fragments and noncanonical paths are rejected.
pub fn request_path(target: &[u8]) -> Option<&[u8]> {
    if target.len() > 8192 {
        return None;
    }
    let (path, query) = target.split_at(path_length(target));
    if valid_path(path) && query_bytes(query) {
        Some(path)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Grant<'a> {
    pub target: &'a [u8],
    pub send_body: bool,
}

/// Host bytes are the adapter's validated, lowercase hostname without a port.
/// Every filesystem lookup in the HTTP adapter requires this grant first.
pub fn authorize<'a>(
    method: &[u8],
    host: &[u8],
    configured_host: &[u8],
    target: &[u8],
    publications: &[rules::Publication<'a>],
) -> Option<Grant<'a>> {
    let get = same_path(method, b"GET");
    if (!get && !same_path(method, b"HEAD")) || !same_path(host, configured_host) {
        return None;
    }
    if let Some(path) = request_path(target)
        && let Some(file) = rules::lookup(path, publications)
    {
        return Some(Grant {
            target: file,
            send_body: get,
        });
    }
    None
}

/// Metadata sampled from the already-opened descriptor, not the pathname.
#[derive(Clone, Copy, Debug)]
pub struct FileFacts {
    pub regular: bool,
    pub links: u64,
    pub size: u64,
    pub device: u64,
    pub inode: u64,
}

/// Both the pinned O_PATH inode and reopened readable descriptor must satisfy
/// the file policy and describe the same inode and size. The Linux kernel and
/// metadata adapter remain trusted; this cannot establish content immutability.
pub fn file_allowed(pinned: &FileFacts, opened: &FileFacts) -> bool {
    pinned.regular
        && opened.regular
        && pinned.links == 1
        && opened.links == 1
        && pinned.size <= MAX_FILE_BYTES
        && opened.size <= MAX_FILE_BYTES
        && pinned.device == opened.device
        && pinned.inode == opened.inode
        && pinned.size == opened.size
}
