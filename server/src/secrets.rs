//! Private, descriptor-relative, crash-safe Linux ACME storage.
#[cfg(target_os = "linux")]
mod linux {
    use pathward::tls::{SecretFacts, secret_allowed};
    use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags, ResolveFlags};
    use std::{
        fs::File,
        io::{self, Read, Write},
        os::unix::{fs::MetadataExt, io::AsRawFd},
        path::{Component, Path},
        sync::Mutex,
    };

    fn denied() -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, "unsafe ACME storage")
    }
    const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS)
        .union(ResolveFlags::NO_XDEV);
    fn facts(file: &File) -> io::Result<SecretFacts> {
        let m = file.metadata()?;
        Ok(SecretFacts {
            regular: m.is_file(),
            owner: m.uid(),
            mode: m.mode() & 0o7777,
            links: m.nlink(),
            size: m.len(),
            device: m.dev(),
            inode: m.ino(),
        })
    }
    pub struct SecretStore {
        directory: File,
        uid: u32,
        write_lock: Mutex<()>,
    }
    impl SecretStore {
        /// Create only the leaf directory. Ancestors must already be trusted.
        /// Root-owned sticky temporary directories are permitted for local tests.
        pub fn open(path: &Path, roots: &[&str]) -> io::Result<Self> {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            {
                return Err(denied());
            }
            let spelling = path.to_str().ok_or_else(denied)?;
            if spelling.contains("//")
                || spelling.ends_with('/')
                || spelling.split('/').any(|c| c == "." || c == "..")
            {
                return Err(denied());
            }
            if roots
                .iter()
                .any(|r| path.starts_with(r) || Path::new(r).starts_with(path))
            {
                return Err(denied());
            }
            let uid = rustix::process::geteuid().as_raw();
            let parts: Vec<_> = path
                .components()
                .filter_map(|c| {
                    if let Component::Normal(p) = c {
                        Some(p)
                    } else {
                        None
                    }
                })
                .collect();
            if parts.is_empty() {
                return Err(denied());
            }
            let mut directory: File = fs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?
            .into();
            for (i, part) in parts.iter().enumerate() {
                let parent = directory.metadata()?;
                if (parent.uid() != 0 && parent.uid() != uid)
                    || (parent.mode() & 0o022 != 0
                        && !(parent.uid() == 0 && parent.mode() & 0o1000 != 0))
                {
                    return Err(denied());
                }
                let leaf = i + 1 == parts.len();
                if leaf {
                    match fs::mkdirat(&directory, *part, Mode::from_raw_mode(0o700)) {
                        Ok(()) => directory.sync_all()?,
                        Err(rustix::io::Errno::EXIST) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                // Root provisioning may cross a deliberately mounted filesystem.
                directory = fs::openat2(
                    &directory,
                    *part,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    RESOLVE.difference(ResolveFlags::NO_XDEV),
                )?
                .into();
            }
            let store = Self {
                directory,
                uid,
                write_lock: Mutex::new(()),
            };
            store.check_directory()?;
            fs::flock(&store.directory, FlockOperation::NonBlockingLockExclusive)?;
            // A crash can leave the private staging inode. Validate before removal.
            if store.load_name(".pending")?.is_some() {
                fs::unlinkat(&store.directory, ".pending", AtFlags::empty())?;
                store.directory.sync_all()?;
            }
            Ok(store)
        }
        fn check_directory(&self) -> io::Result<()> {
            let m = self.directory.metadata()?;
            if !m.is_dir() || m.uid() != self.uid || m.mode() & 0o7777 != 0o700 {
                return Err(denied());
            }
            Ok(())
        }
        fn load_name(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
            self.check_directory()?;
            let pin: File = match fs::openat2(
                &self.directory,
                name,
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                RESOLVE,
            ) {
                Ok(fd) => fd.into(),
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            let before = facts(&pin)?;
            if !secret_allowed(&before, &before, self.uid) {
                return Err(denied());
            }
            let mut opened: File = fs::open(
                format!("/proc/self/fd/{}", pin.as_raw_fd()),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )?
            .into();
            if !secret_allowed(&before, &facts(&opened)?, self.uid) {
                return Err(denied());
            }
            let mut data = Vec::new();
            Read::by_ref(&mut opened)
                .take(1_048_577)
                .read_to_end(&mut data)?;
            if data.len() as u64 != before.size
                || !secret_allowed(&before, &facts(&opened)?, self.uid)
            {
                return Err(denied());
            }
            drop(pin);
            Ok(Some(data))
        }
        fn store_name(&self, name: &str, data: &[u8]) -> io::Result<()> {
            let _writer = self.write_lock.lock().map_err(|_| denied())?;
            if data.len() > 1_048_576 {
                return Err(denied());
            }
            self.check_directory()?;
            // Refuse unsafe existing destinations instead of repairing them silently.
            let _ = self.load_name(name)?;
            let mut file: File = fs::openat2(
                &self.directory,
                ".pending",
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
                RESOLVE,
            )?
            .into();
            let result = (|| {
                let initial = facts(&file)?;
                if !secret_allowed(&initial, &initial, self.uid) {
                    return Err(denied());
                }
                file.write_all(data)?;
                file.sync_all()?;
                let after = facts(&file)?;
                if !secret_allowed(&after, &after, self.uid) || after.size != data.len() as u64 {
                    return Err(denied());
                }
                fs::renameat(&self.directory, ".pending", &self.directory, name)?;
                self.directory.sync_all()?;
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::unlinkat(&self.directory, ".pending", AtFlags::empty());
            }
            result
        }
        pub fn bind(&self, identity: &[u8]) -> io::Result<()> {
            match self.load_name(".identity")? {
                Some(stored) if stored == identity => Ok(()),
                Some(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ACME storage configuration changed; use a separate directory",
                )),
                None => {
                    if self.load_account()?.is_some() || self.load_certificate()?.is_some() {
                        return Err(denied());
                    }
                    self.store_name(".identity", identity)
                }
            }
        }
        pub(crate) fn socket_path(&self) -> std::path::PathBuf {
            std::path::PathBuf::from(format!(
                "/proc/self/fd/{}/control.sock",
                self.directory.as_raw_fd()
            ))
        }
        pub fn load_config(&self) -> io::Result<Option<Vec<u8>>> {
            self.load_name(".config")
        }
        pub fn store_config(&self, bytes: &[u8]) -> io::Result<()> {
            self.store_name(".config", bytes)
        }
        pub fn load_previous(&self) -> io::Result<Option<Vec<u8>>> {
            self.load_name(".previous")
        }
        pub fn store_previous(&self, bytes: &[u8]) -> io::Result<()> {
            self.store_name(".previous", bytes)
        }
        pub fn load_account(&self) -> io::Result<Option<Vec<u8>>> {
            self.load_name(".account")
        }
        pub fn store_account(&self, bytes: &[u8]) -> io::Result<()> {
            self.store_name(".account", bytes)
        }
        pub fn load_certificate(&self) -> io::Result<Option<Vec<u8>>> {
            self.load_name(".certificate")
        }
        pub fn store_certificate(&self, bytes: &[u8]) -> io::Result<()> {
            self.store_name(".certificate", bytes)
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::SecretStore;
#[cfg(not(target_os = "linux"))]
pub struct SecretStore;
#[cfg(not(target_os = "linux"))]
impl SecretStore {
    pub fn open(_: &std::path::Path, _: &[&str]) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "private ACME storage requires Linux",
        ))
    }
    pub fn bind(&self, _: &[u8]) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    pub(crate) fn socket_path(&self) -> std::path::PathBuf {
        std::path::PathBuf::new()
    }
    pub fn load_config(&self) -> std::io::Result<Option<Vec<u8>>> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    pub fn store_config(&self, _: &[u8]) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    pub fn load_previous(&self) -> std::io::Result<Option<Vec<u8>>> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    pub fn store_previous(&self, _: &[u8]) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    pub fn load_account(&self) -> std::io::Result<Option<Vec<u8>>> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    pub fn load_certificate(&self) -> std::io::Result<Option<Vec<u8>>> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    pub fn store_account(&self, _: &[u8]) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    pub fn store_certificate(&self, _: &[u8]) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}
