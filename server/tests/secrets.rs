#![cfg(target_os = "linux")]
use pathward_server::secrets::SecretStore;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    thread,
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "pathward-secrets-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn private_atomic_store_lock_and_restart() {
    let temp = Temp::new();
    let path = temp.0.join("cache");
    let store = SecretStore::open(&path, &[]).unwrap();
    store.bind(b"fixed-config").unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert!(SecretStore::open(&path, &[]).is_err());
    store.store_account(b"account-secret").unwrap();
    store.store_certificate(b"old").unwrap();
    assert_eq!(
        fs::metadata(path.join(".account"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..500 {
                let bytes = fs::read(path.join(".certificate")).unwrap();
                assert!(bytes == b"old" || bytes == b"new-certificate");
            }
        });
        for _ in 0..50 {
            store.store_certificate(b"new-certificate").unwrap();
            store.store_certificate(b"old").unwrap();
        }
    });
    thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..10 {
                store.store_account(b"account-secret").unwrap();
            }
        });
        scope.spawn(|| {
            for _ in 0..10 {
                store.store_certificate(b"old").unwrap();
            }
        });
    });
    // A private staging file left by a killed writer is never interpreted as a certificate.
    fs::write(path.join(".pending"), b"partial-secret").unwrap();
    fs::set_permissions(path.join(".pending"), fs::Permissions::from_mode(0o600)).unwrap();
    drop(store);
    let restart = SecretStore::open(&path, &[]).unwrap();
    restart.bind(b"fixed-config").unwrap();
    assert!(restart.bind(b"other-config").is_err());
    assert_eq!(restart.load_account().unwrap().unwrap(), b"account-secret");
    assert_eq!(restart.load_certificate().unwrap().unwrap(), b"old");
    assert!(!path.join(".pending").exists());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(restart.store_certificate(b"unsafe").is_err());
    assert_eq!(fs::read(path.join(".certificate")).unwrap(), b"old");
}
#[test]
fn refuse_public_symlink_hardlink_special_and_oversized_cache() {
    let temp = Temp::new();
    let path = temp.0.join("cache");
    let store = SecretStore::open(&path, &[]).unwrap();
    store.store_account(b"secret").unwrap();
    fs::set_permissions(path.join(".account"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.load_account().is_err());
    assert!(store.store_account(b"new").is_err());
    fs::remove_file(path.join(".account")).unwrap();
    symlink("/etc/passwd", path.join(".account")).unwrap();
    assert!(store.load_account().is_err());
    assert!(store.store_account(b"new").is_err());
    fs::remove_file(path.join(".account")).unwrap();
    store.store_account(b"secret").unwrap();
    fs::hard_link(path.join(".account"), temp.0.join("link")).unwrap();
    assert!(store.load_account().is_err());
    fs::remove_file(path.join(".account")).unwrap();
    fs::create_dir(path.join(".account")).unwrap();
    assert!(store.load_account().is_err());
    fs::remove_dir(path.join(".account")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path.join(".account"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert!(store.load_account().is_err());
    fs::remove_file(path.join(".account")).unwrap();
    store.store_account(b"secret").unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(path.join(".account"))
        .unwrap()
        .set_len(1_048_577)
        .unwrap();
    assert!(store.load_account().is_err());
    assert!(store.store_certificate(&vec![0; 1_048_577]).is_err());
    assert!(SecretStore::open(&temp.0.join("inside"), &[temp.0.to_str().unwrap()]).is_err());
    symlink(&path, temp.0.join("alias")).unwrap();
    assert!(SecretStore::open(&temp.0.join("alias"), &[]).is_err());
    let public = temp.0.join("public");
    fs::create_dir(&public).unwrap();
    fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(SecretStore::open(&public, &[]).is_err());
}

#[test]
fn nondumpable_process_can_reopen_its_private_descriptors() {
    if std::env::var_os("PATHWARD_TEST_NONDUMP_CHILD").is_some() {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .unwrap();
        rustix::process::setrlimit(
            rustix::process::Resource::Core,
            rustix::process::Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .unwrap();
        let temp = Temp::new();
        let store = SecretStore::open(&temp.0.join("cache"), &[]).unwrap();
        store.store_account(b"private").unwrap();
        assert_eq!(store.load_account().unwrap().unwrap(), b"private");
        return;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "nondumpable_process_can_reopen_its_private_descriptors",
        ])
        .env("PATHWARD_TEST_NONDUMP_CHILD", "1")
        .status()
        .unwrap();
    assert!(status.success());
}
