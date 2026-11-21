//! Linux pooled first writes and managed sleep use independent opens of one
//! boot-scoped inode. Only the power manager can change its one-byte state.
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use std::{
    fs::File,
    io::{self, Write},
    os::unix::fs::{FileExt, MetadataExt},
    process::Command,
};

const FENCE: &str = "/run/pathward-sleep.gate";

fn open_fence(access: OFlags) -> io::Result<File> {
    let fd = open(
        FENCE,
        access | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let file = File::from(fd);
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.nlink() != 1 {
        return Err(io::Error::other("untrusted sleep fence"));
    }
    Ok(file)
}

fn require_awake(file: &File) -> io::Result<()> {
    let mut state = [0; 1];
    let count = file.metadata()?.len();
    file.read_exact_at(&mut state, 0)?;
    if !pathward::upstream::sleep_fence_awake(count, state[0]) {
        return Err(io::Error::other("sleep fence is closed or malformed"));
    }
    Ok(())
}

/// Drop releases this independent shared flock. No wait or await under the lease.
pub(crate) fn first_write_lease() -> io::Result<File> {
    let file = open_fence(OFlags::RDONLY)?;
    flock(&file, FlockOperation::NonBlockingLockShared)?;
    require_awake(&file)?;
    Ok(file)
}

/// Privileged entry for systemd sleep units and direct, coordinated kernel sleep.
/// Neither the command nor the power-control path comes from the environment.
pub fn coordinated_sleep(mode: &str) -> io::Result<()> {
    let kernel_state = match mode {
        "kernel-mem" => Some(b"mem".as_slice()),
        "kernel-disk" => Some(b"disk".as_slice()),
        "systemd-suspend"
        | "systemd-hibernate"
        | "systemd-hybrid-sleep"
        | "systemd-suspend-then-hibernate" => None,
        _ => return Err(io::Error::other("unknown coordinated sleep mode")),
    };
    let file = open_fence(OFlags::RDWR)?;
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => {
            eprintln!("Waiting for the PathWard sleep fence");
            flock(&file, FlockOperation::LockExclusive)?;
        }
        Err(e) => return Err(e.into()),
    }
    require_awake(&file)?;
    // If the supervisor dies while its child is still running, release of the
    // flock alone must not reopen the gate. A subsequent supervisor checks 'A'.
    file.write_all_at(b"S", 0)?;
    if let Some(state) = kernel_state {
        File::options()
            .write(true)
            .open("/sys/power/state")?
            .write_all(state)?;
    } else {
        let action = mode.strip_prefix("systemd-").expect("validated sleep mode");
        let status = Command::new("/usr/lib/systemd/systemd-sleep")
            .arg(action)
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "systemd-sleep exited with {status}"
            )));
        }
    }
    file.write_all_at(b"A", 0)
}
