//! Linux-only confinement. There is deliberately no path-based fallback.
use std::{fs::File, io};

pub struct OpenedFile {
    pub(crate) file: File,
    pub(crate) length: u64,
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use pathward::{
        rules::valid_target,
        serving::{FileFacts, file_allowed},
    };
    use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat2};
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};

    pub struct DocumentRoot(File);

    fn denied() -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, "file policy denied")
    }

    fn facts(file: &File) -> io::Result<FileFacts> {
        let meta = file.metadata()?;
        Ok(FileFacts {
            regular: meta.is_file(),
            links: meta.nlink(),
            size: meta.len(),
            device: meta.dev(),
            inode: meta.ino(),
        })
    }

    impl DocumentRoot {
        pub fn open(path: &str) -> io::Result<Self> {
            if !pathward::valid_path(path.as_bytes()) {
                return Err(denied());
            }
            // The configured absolute root may live on its own filesystem.
            // Symlinks in ANY root component are rejected; pin this directory.
            let slash = open(
                "/",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let relative = if path == "/" { "." } else { &path[1..] };
            let root = openat2(
                &slash,
                relative,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )?;
            Ok(Self(File::from(root)))
        }

        pub fn open_file(&self, target: &str) -> io::Result<OpenedFile> {
            if !valid_target(target.as_bytes()) {
                return Err(denied());
            }
            // Pin an inode without opening a device/FIFO for I/O. All resolution
            // restrictions are enforced together by the kernel, including races.
            let pin = openat2(
                &self.0,
                target,
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            )?;
            let pin = File::from(pin);
            let before = facts(&pin)?;
            if !file_allowed(&before, &before) {
                return Err(denied());
            }
            // /proc is a trusted, ordinary procfs mount. Keep `pin` alive while
            // reopening its inode; no attacker-controlled pathname is reused.
            let fd_path = format!("/proc/self/fd/{}", pin.as_raw_fd());
            let readable = open(
                fd_path.as_str(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )?;
            let readable = File::from(readable);
            let after = facts(&readable)?;
            if !file_allowed(&before, &after) {
                return Err(denied());
            }
            drop(pin); // Explicitly retain the pin through reopening and identity checks.
            Ok(OpenedFile {
                file: readable,
                length: after.size,
            })
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;
    pub struct DocumentRoot;
    impl DocumentRoot {
        pub fn open(_: &str) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "safe file serving requires Linux 5.6+ with openat2 and procfs",
            ))
        }
        pub fn open_file(&self, _: &str) -> io::Result<OpenedFile> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Linux is required",
            ))
        }
    }
}

pub use platform::DocumentRoot;

#[cfg(all(test, target_os = "linux"))]
#[path = "files_tests.rs"]
mod tests;
