//! Descriptor-relative, no-follow traversal of publisher-owned source trees.
use crate::{Result, codec, require};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
pub const MAX_FILES: usize = 4096;
pub const MAX_FILE: u64 = 1 << 30;
const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub fn relative(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 4095
        && s.split('/').count() <= 64
        && s.split('/').all(|p| {
            let good = |b: u8| b.is_ascii_alphanumeric() || b"_-".contains(&b);
            !p.is_empty()
                && p.len() <= 255
                && good(p.as_bytes()[0])
                && good(p.as_bytes()[p.len() - 1])
                && p.bytes().all(|b| good(b) || b == b'.')
        })
}
pub fn absolute(path: &Path) -> Result<File> {
    let s = path.to_str().ok_or("nontext source")?;
    require(
        s.starts_with('/') && relative(&s[1..]),
        "noncanonical source",
    )?;
    let mut fd = File::from(rustix::fs::open("/", DIR, Mode::empty())?);
    for name in s[1..].split('/') {
        // The reviewed source base may be on a separate mounted filesystem.
        // Once pinned, every descendant lookup below it forbids mount crossings.
        fd = File::from(rustix::fs::openat(&fd, name, DIR, Mode::empty())?);
    }
    Ok(fd)
}
pub fn child(parent: &File, name: &str) -> Result<File> {
    require(
        relative(name) && !name.contains('/'),
        "invalid directory component",
    )?;
    below(parent, name, DIR)
}
fn below(parent: &File, name: &str, flags: OFlags) -> Result<File> {
    #[cfg(target_os = "linux")]
    let fd = rustix::fs::openat2(
        parent,
        name,
        flags,
        Mode::empty(),
        rustix::fs::ResolveFlags::BENEATH
            | rustix::fs::ResolveFlags::NO_SYMLINKS
            | rustix::fs::ResolveFlags::NO_MAGICLINKS
            | rustix::fs::ResolveFlags::NO_XDEV,
    )?;
    #[cfg(not(target_os = "linux"))]
    let fd = rustix::fs::openat(parent, name, flags, Mode::empty())?;
    Ok(File::from(fd))
}
pub fn descend(parent: &File, name: &str) -> Result<File> {
    require(relative(name), "invalid relative directory")?;
    let mut fd = parent.try_clone()?;
    for part in name.split('/') {
        fd = child(&fd, part)?;
    }
    Ok(fd)
}
pub fn leaf(parent: &File, name: &str) -> Result<File> {
    require(relative(name), "invalid relative file")?;
    let (dir, name) = match name.rsplit_once('/') {
        Some((d, n)) => (descend(parent, d)?, n),
        None => (parent.try_clone()?, name),
    };
    let f = below(
        &dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
    )?;
    let m = f.metadata()?;
    require(
        m.is_file() && m.nlink() == 1 && m.len() <= MAX_FILE,
        "linked, special or oversized input",
    )?;
    Ok(f)
}
pub fn reference(base: &File) -> Result<String> {
    let link = rustix::fs::readlinkat(base, "current", Vec::new())?;
    let s = link.to_str()?.to_owned();
    require(release(&s), "release link escapes base")?;
    Ok(s)
}
pub fn release(s: &str) -> bool {
    s.strip_prefix("releases/")
        .is_some_and(|v| relative(v) && !v.contains('/') && v.as_bytes()[0].is_ascii_alphanumeric())
}
pub fn names(root: &File) -> Result<Vec<String>> {
    fn walk(
        fd: &File,
        prefix: &str,
        device: u64,
        budget: &mut usize,
        out: &mut Vec<String>,
    ) -> Result<()> {
        let mut names = Vec::new();
        for item in rustix::fs::Dir::read_from(fd)? {
            let item = item?;
            let name = item.file_name().to_str()?.to_owned();
            if name == "." || name == ".." {
                continue;
            }
            require(*budget > 0, "tree entry limit")?;
            *budget -= 1;
            if name.starts_with('.') {
                continue;
            }
            require(
                relative(&name) && !name.contains('/'),
                "noncanonical source name",
            )?;
            names.push(name);
        }
        names.sort();
        for name in names {
            let path = format!("{prefix}{name}");
            require(relative(&path), "tree depth limit")?;
            let m = rustix::fs::statat(fd, &name, AtFlags::SYMLINK_NOFOLLOW)?;
            require(m.st_dev as u64 == device, "source crosses mount")?;
            if FileType::from_raw_mode(m.st_mode) == FileType::Directory {
                let next = child(fd, &name)?;
                require(
                    next.metadata()?.dev() == device,
                    "source directory changed mount",
                )?;
                walk(&next, &format!("{path}/"), device, budget, out)?;
            } else {
                let f = leaf(fd, &name)?;
                require(f.metadata()?.dev() == device, "source file changed mount")?;
                out.push(path);
                require(out.len() <= MAX_FILES, "file count limit")?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(
        root,
        "",
        root.metadata()?.dev(),
        &mut (MAX_FILES * 2),
        &mut out,
    )?;
    out.sort();
    Ok(out)
}
pub fn stream(
    mut input: File,
    mut output: Option<&mut File>,
    limit: u64,
) -> Result<serde_json::Value> {
    let before = input.metadata()?;
    require(
        before.is_file() && before.nlink() == 1 && before.len() <= limit.min(MAX_FILE),
        "input capacity or inode",
    )?;
    let identity = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
            m.nlink(),
        )
    };
    let mut h = ring::digest::Context::new(&ring::digest::SHA256);
    let mut count = 0;
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        require(count <= before.len(), "input grew")?;
        h.update(&buffer[..n]);
        if let Some(ref mut f) = output {
            f.write_all(&buffer[..n])?;
        }
    }
    require(
        count == before.len() && identity(&before) == identity(&input.metadata()?),
        "input changed while reading",
    )?;
    if let Some(f) = output {
        f.sync_all()?;
    }
    let sha: String = h
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(serde_json::json!({"sha256":sha,"bytes":count}))
}
pub fn metadata(path: &Path, owner: u32) -> Result<serde_json::Value> {
    let parent = absolute(path.parent().ok_or("metadata parent")?)?;
    let mut f = leaf(
        &parent,
        path.file_name()
            .and_then(|v| v.to_str())
            .ok_or("metadata name")?,
    )?;
    let m = f.metadata()?;
    require(
        m.uid() == owner && m.mode() & 0o022 == 0 && m.len() <= codec::LIMIT as u64,
        "untrusted publication metadata",
    )?;
    let mut bytes = Vec::new();
    (&mut f)
        .take(codec::LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    codec::parse(&bytes)
}
