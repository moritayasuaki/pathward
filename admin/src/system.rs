use crate::{Result, require};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::{fs::OpenOptionsExt, process::CommandExt};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub trait System {
    fn run(&mut self, args: &[String], seconds: u64) -> Result<(bool, String)>;
    fn checked(&mut self, args: &[String], seconds: u64) -> Result<String> {
        let (ok, out) = self.run(args, seconds)?;
        require(ok, "system command failed (see service journal)")?;
        Ok(out)
    }
    fn property(&mut self, unit: &str, prop: &str) -> Result<String> {
        Ok(self
            .checked(
                &words(&[
                    "/usr/bin/systemctl",
                    "show",
                    unit,
                    &format!("--property={prop}"),
                    "--value",
                ]),
                45,
            )?
            .trim()
            .to_owned())
    }
    fn control(&mut self, action: &str, units: &[String], blocking: bool) -> Result<()> {
        if units.is_empty() {
            return Ok(());
        }
        let mut args = words(&["/usr/bin/systemctl", action]);
        if !blocking {
            args.push("--no-block".into());
        }
        args.extend(units.iter().cloned());
        self.checked(&args, 600)?;
        Ok(())
    }
}
pub fn words(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_owned()).collect()
}
pub struct Real;
static NEXT: AtomicU64 = AtomicU64::new(0);
impl System for Real {
    fn run(&mut self, args: &[String], seconds: u64) -> Result<(bool, String)> {
        capture(args, seconds, 65536)
    }
}
/// The SSH transport may return a bounded file inventory larger than a systemctl reply.
pub fn capture(args: &[String], seconds: u64, limit: u64) -> Result<(bool, String)> {
    require(
        limit > 0 && limit <= crate::codec::LIMIT as u64,
        "capture bound",
    )?;
    require(
        !args.is_empty() && args[0].starts_with('/') && seconds > 0 && seconds <= 600,
        "invalid command",
    )?;
    let name = std::env::temp_dir().join(format!(
        "pathward-admin-output-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let out = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&name)?;
    // Unlink the private capture immediately. No pipe can block the child,
    // and inherited output handles cannot make the caller wait for EOF.
    fs::remove_file(&name)?;
    let mut command = Command::new(&args[0]);
    command
        .args(&args[1..])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C");
    // Transport may use the caller's already configured authentication agent.
    // Never pass it into administrator/service commands or accept it from data.
    if matches!(args[0].as_str(), "/usr/bin/ssh" | "/usr/bin/rsync")
        && let Some(socket) = std::env::var_os("SSH_AUTH_SOCK")
    {
        require(
            std::path::Path::new(&socket).is_absolute(),
            "SSH agent socket path",
        )?;
        command.env("SSH_AUTH_SOCK", socket);
    }
    if args[0] == "/usr/bin/systemctl" && args.get(1).is_some_and(|a| a == "--user") {
        require(
            !rustix::process::geteuid().is_root(),
            "root user-manager operation denied",
        )?;
        let run = format!("/run/user/{}", rustix::process::geteuid().as_raw());
        command
            .env("XDG_RUNTIME_DIR", &run)
            .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={run}/bus"));
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(out.try_clone()?))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline || out.metadata()?.len() > limit {
            if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err("command exceeded deadline or output bound".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    require(out.metadata()?.len() <= limit, "command output too large")?;
    // seek the same descriptor instead of trusting another pathname.
    let mut reader: File = out;
    use std::io::{Seek, SeekFrom};
    reader.seek(SeekFrom::Start(0))?;
    let mut text = String::new();
    reader.take(limit + 1).read_to_string(&mut text)?;
    require(text.len() as u64 <= limit, "command output grew")?;
    Ok((status.success(), text))
}
