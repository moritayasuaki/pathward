//! Root-owned, no-follow, bounded I/O. Every durable rename syncs its parent.
use crate::{Result, codec, require};
use rustix::fs::{Mode, OFlags};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub type Checkpoint<'a> = &'a mut dyn FnMut(&str) -> Result<()>;

pub fn absolute(path: &Path) -> bool {
    let Some(s) = path.to_str() else { return false };
    path.is_absolute()
        && s.len() <= 1024
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && !s.contains("//")
        && !s.contains("/./")
        && !s.ends_with("/.")
}
pub fn trusted(path: &Path) -> Result<()> {
    require(absolute(path), "noncanonical path")?;
    for p in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)?;
        require(
            m.is_dir()
                && !m.file_type().is_symlink()
                && (m.uid() == 0 || m.uid() == rustix::process::geteuid().as_raw())
                && (m.mode() & 0o022 == 0 || m.mode() & 0o1000 != 0),
            "untrusted ancestor",
        )?;
    }
    Ok(())
}
pub fn root_mount(path: &Path) -> Result<()> {
    trusted(path)?;
    #[cfg(target_os = "linux")]
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let point = line.split_whitespace().nth(4).ok_or("invalid mountinfo")?;
        // Reject ambiguous escaped mount names conservatively.
        require(
            !point.contains('\\') || !path.to_string_lossy().contains('\\'),
            "escaped mount path",
        )?;
        if point != "/" && path.starts_with(point) {
            return Err("durable inputs must use the root mount".into());
        }
    }
    Ok(())
}
pub fn open(path: &Path, private: bool) -> Result<File> {
    trusted(path)?;
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let file = File::from(fd);
    let m = file.metadata()?;
    require(
        m.is_file()
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o022 == 0
            && m.len() <= 256 << 20,
        "untrusted input inode",
    )?;
    if private {
        require(
            m.nlink() == 1
                && [0o400, 0o600].contains(&(m.mode() & 0o777))
                && m.len() <= codec::LIMIT as u64,
            "untrusted private record",
        )?;
    }
    Ok(file)
}
pub fn bytes(path: &Path, private: bool) -> Result<Vec<u8>> {
    let mut file = open(path, private)?;
    let mut out = Vec::new();
    (&mut file)
        .take(if private {
            codec::LIMIT as u64 + 1
        } else {
            (256 << 20) + 1
        })
        .read_to_end(&mut out)?;
    require(
        out.len() <= if private { codec::LIMIT } else { 256 << 20 },
        "input grew",
    )?;
    Ok(out)
}
pub fn record(path: &Path) -> Result<serde_json::Value> {
    codec::decode(&bytes(path, true)?)
}
pub fn sync_dir(path: &Path) -> Result<()> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    File::from(fd).sync_all()?;
    Ok(())
}
pub fn directory(path: &Path) -> Result<()> {
    trusted(path)?;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(path)?;
    require(
        m.is_dir()
            && !m.file_type().is_symlink()
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o022 == 0,
        "unsafe directory",
    )?;
    sync_dir(path)?;
    sync_dir(path.parent().ok_or("missing parent")?)
}
pub fn verified(path: &Path, expected: &str, durable: bool) -> Result<()> {
    require(codec::digest(expected), "invalid digest")?;
    if durable {
        root_mount(path)?;
    }
    let mut f = open(path, false)?;
    let mut bytes = Vec::new();
    (&mut f).take((256 << 20) + 1).read_to_end(&mut bytes)?;
    require(
        bytes.len() <= 256 << 20 && codec::hash(&bytes) == expected,
        "sealed file changed",
    )?;
    if durable {
        f.sync_all()?;
        for parent in path.ancestors().skip(1) {
            sync_dir(parent)?;
        }
    }
    Ok(())
}
fn temporary(path: &Path) -> Result<std::path::PathBuf> {
    use ring::rand::SecureRandom;
    let n = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut nonce = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "temporary-name randomness unavailable")?;
    let nonce = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(path.with_file_name(format!(
        ".{}.tmp-{}-{n}-{nonce}",
        path.file_name()
            .ok_or("missing filename")?
            .to_str()
            .ok_or("invalid filename")?,
        std::process::id()
    )))
}
pub fn replace(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    label: &str,
    cp: Checkpoint<'_>,
) -> Result<()> {
    trusted(path)?;
    let tmp = temporary(path)?;
    let result = (|| {
        let fd = rustix::fs::open(
            &tmp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(mode as _),
        )?;
        let mut f = File::from(fd);
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        cp(&format!("{label}:created"))?;
        let half = bytes.len() / 2;
        f.write_all(&bytes[..half])?;
        cp(&format!("{label}:partial"))?;
        f.write_all(&bytes[half..])?;
        f.sync_all()?;
        cp(&format!("{label}:file-synced"))?;
        fs::rename(&tmp, path)?;
        cp(&format!("{label}:renamed"))?;
        sync_dir(path.parent().ok_or("missing parent")?)?;
        cp(&format!("{label}:durable"))
    })();
    let _ = fs::remove_file(tmp);
    result
}
pub fn write_record(
    path: &Path,
    value: &serde_json::Value,
    label: &str,
    cp: Checkpoint<'_>,
) -> Result<()> {
    let raw = codec::encode(value);
    require(raw.len() <= codec::LIMIT, "record too large")?;
    replace(path, &raw, 0o600, label, cp)
}
pub fn link(path: &Path, target: &Path, label: &str, cp: Checkpoint<'_>) -> Result<()> {
    trusted(path)?;
    let tmp = temporary(path)?;
    let result = (|| {
        symlink(target, &tmp)?;
        cp(&format!("{label}:created"))?;
        fs::rename(&tmp, path)?;
        cp(&format!("{label}:renamed"))?;
        sync_dir(path.parent().ok_or("missing parent")?)?;
        cp(&format!("{label}:durable"))
    })();
    let _ = fs::remove_file(tmp);
    result
}
