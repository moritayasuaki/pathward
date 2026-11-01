//! Bounded static HTTP planning. Called only after the publication grant/open.
use crate::{
    files::OpenedFile,
    http::{Rejection, Request},
};
use pathward_config::CachePolicy;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) struct Plan {
    pub status: u16,
    pub start: u64,
    pub count: u64,
    pub fields: String,
    pub cache: String,
}

fn header<'a>(req: &Request<'a>, name: &str) -> Result<Option<&'a [u8]>, Rejection> {
    let mut found = None;
    for h in &req.headers {
        if h.name.eq_ignore_ascii_case(name) {
            if found.is_some() {
                return Err(Rejection(400));
            }
            found = Some(h.value.trim_ascii());
        }
    }
    Ok(found)
}

fn tag_matches(value: &[u8], tag: &str, strong: bool) -> Result<bool, Rejection> {
    if value == b"*" {
        return Ok(true);
    }
    let mut rest = value;
    let mut matched = false;
    let mut count = 0;
    loop {
        count += 1;
        if count > 32 {
            return Err(Rejection(400));
        }
        rest = rest.trim_ascii();
        let weak = rest.starts_with(b"W/");
        if weak {
            rest = &rest[2..];
        }
        if rest.first() != Some(&b'"') {
            return Err(Rejection(400));
        }
        let end = rest[1..]
            .iter()
            .position(|b| *b == b'"')
            .ok_or(Rejection(400))?
            + 1;
        if !rest[1..end].iter().all(|b| *b >= 0x21 && *b != 0x7f) {
            return Err(Rejection(400));
        }
        let current_weak = tag.starts_with("W/");
        let current = tag.strip_prefix("W/").unwrap_or(tag).as_bytes();
        matched |= (!strong || (!weak && !current_weak)) && &rest[..=end] == current;
        rest = rest[end + 1..].trim_ascii();
        if rest.is_empty() {
            return Ok(matched);
        }
        if rest[0] != b',' {
            return Err(Rejection(400));
        }
        rest = &rest[1..];
    }
}

fn date(value: Option<&[u8]>) -> Option<SystemTime> {
    httpdate::parse_http_date(std::str::from_utf8(value?).ok()?).ok()
}

// A missing range means full content. Invalid/unknown/multipart ranges are
// deliberately ignored, avoiding multipart amplification and extra allocation.
fn range(value: &[u8], size: u64) -> Option<Result<(u64, u64), ()>> {
    let text = std::str::from_utf8(value).ok()?;
    let (unit, value) = text.split_once('=')?;
    if !unit.eq_ignore_ascii_case("bytes") || value.contains(',') {
        return None;
    }
    let (left, right) = value.split_once('-')?;
    fn number(s: &str) -> Option<u64> {
        if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
            None
        } else {
            s.parse().ok()
        }
    }
    let span = if left.is_empty() {
        let count = number(right)?;
        if count == 0 || size == 0 {
            return Some(Err(()));
        }
        let count = count.min(size);
        (size - count, count)
    } else {
        let start = number(left)?;
        let end = if right.is_empty() {
            size.saturating_sub(1)
        } else {
            number(right)?
        };
        if !right.is_empty() && start > end {
            return None;
        }
        if start >= size {
            return Some(Err(()));
        }
        (start, end.min(size - 1) - start + 1)
    };
    Some(if pathward::content::span_allowed(size, span.0, span.1) {
        Ok(span)
    } else {
        Err(())
    })
}

pub(crate) fn plan(
    req: &Request<'_>,
    file: &OpenedFile,
    cache: CachePolicy,
) -> Result<Plan, Rejection> {
    let metadata = file.file.metadata().map_err(|_| Rejection(500))?;
    if metadata.len() != file.length {
        return Err(Rejection(404));
    }
    // Metadata is a weak validator: do not pretend a metadata fingerprint is
    // a content hash. In-place modification by a trusted publisher is unsupported.
    #[cfg(unix)]
    let identity = {
        use std::os::unix::fs::MetadataExt;
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec()
        )
    };
    #[cfg(not(unix))]
    let identity = format!("{:?}:{}", metadata.modified(), metadata.len());
    let tag = format!("W/\"{}\"", crate::deployment::revision(identity.as_bytes()));
    let now = SystemTime::now();
    let modified = metadata
        .modified()
        .ok()
        .filter(|t| *t <= now)
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| UNIX_EPOCH + Duration::from_secs(d.as_secs()));
    let im = header(req, "if-match")?;
    let ius = date(header(req, "if-unmodified-since")?);
    let inm = header(req, "if-none-match")?;
    let ims = date(header(req, "if-modified-since")?);
    let status = pathward::content::precondition_status(
        im.map(|v| tag_matches(v, &tag, true)).transpose()?,
        modified.zip(ius).map(|(m, d)| m <= d),
        inm.map(|v| tag_matches(v, &tag, false)).transpose()?,
        modified.zip(ims).map(|(m, d)| m <= d),
    );
    let mut plan = Plan {
        status,
        start: 0,
        count: if status == 200 { file.length } else { 0 },
        fields: format!("ETag: {tag}\r\nAccept-Ranges: bytes\r\n"),
        cache: "no-store".into(),
    };
    if let Some(modified) = modified {
        plan.fields += &format!("Last-Modified: {}\r\n", httpdate::fmt_http_date(modified));
    }
    // Only weak metadata validators are available: If-Range cannot establish
    // byte identity. Always send the full representation when it is present.
    let range_header = header(req, "range")?;
    let if_range = header(req, "if-range")?;
    if status == 200
        && req.method == b"GET"
        && if_range.is_none()
        && let Some(result) = range_header.and_then(|v| range(v, file.length))
    {
        match result {
            Ok((start, count)) => {
                plan.status = 206;
                plan.start = start;
                plan.count = count;
                plan.fields += &format!(
                    "Content-Range: bytes {}-{}/{}\r\n",
                    start,
                    start + count - 1,
                    file.length
                );
            }
            Err(()) => {
                plan.status = 416;
                plan.count = 0;
                plan.fields += &format!("Content-Range: bytes */{}\r\n", file.length);
            }
        }
    }
    let credentials = req.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("authorization") || h.name.eq_ignore_ascii_case("cookie")
    });
    let seconds = match cache {
        CachePolicy::Public { seconds, .. } => seconds,
        _ => 0,
    };
    if pathward::content::shared_cache_allowed(plan.status, true, credentials, seconds) {
        plan.cache = cache.value();
    }
    if !pathward::content::span_allowed(file.length, plan.start, plan.count) {
        return Err(Rejection(500));
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_ranges_are_bounded_and_do_not_wrap() {
        for (input, expected) in [
            ("bytes=0-15", Some(Ok((0, 16)))),
            ("bytes=10-", Some(Ok((10, 90)))),
            ("bytes=-10", Some(Ok((90, 10)))),
            ("bytes=-999", Some(Ok((0, 100)))),
            ("bytes=100-", Some(Err(()))),
            ("bytes=-0", Some(Err(()))),
            ("bytes=2-1", None),
            ("bytes=0-1,4-5", None),
            ("items=0-2", None),
            ("bytes=0-18446744073709551615", Some(Ok((0, 100)))),
            ("bytes=18446744073709551616-", None),
        ] {
            assert_eq!(range(input.as_bytes(), 100), expected, "{input}");
        }
        assert_eq!(range(b"bytes=0-0", 0), Some(Err(())));
        for size in 0..80 {
            for start in 0..100 {
                for end in start..100 {
                    let result = range(format!("bytes={start}-{end}").as_bytes(), size).unwrap();
                    if start >= size {
                        assert!(result.is_err());
                    } else {
                        let (first, count) = result.unwrap();
                        assert_eq!(first, start);
                        assert_eq!(count, (end + 1).min(size) - start);
                    }
                }
            }
        }
    }
    #[test]
    fn entity_tag_lists_respect_quotes_and_comparison_strength() {
        assert!(tag_matches(b"\"other,tag\", W/\"ours\"", "W/\"ours\"", false).unwrap());
        assert!(!tag_matches(b"\"ours\"", "W/\"ours\"", true).unwrap());
        assert!(tag_matches(b"*", "W/\"ours\"", true).unwrap());
        for value in [
            b"".as_slice(),
            b"\"ours\",",
            b"*,\"ours\"",
            b"\"bad\n\"",
            b"W/unquoted",
        ] {
            assert!(tag_matches(value, "W/\"ours\"", false).is_err());
        }
    }
}
