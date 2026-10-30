use super::*;
use std::{
    fs,
    io::Read,
    os::unix::{fs::symlink, net::UnixListener},
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

struct Tree(PathBuf);
impl Tree {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pathward-files-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join("public")).unwrap();
        fs::create_dir(path.join("outside")).unwrap();
        Self(path)
    }
    fn root(&self) -> DocumentRoot {
        DocumentRoot::open(self.0.join("public").to_str().unwrap()).unwrap()
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn regular_files_are_pinned_and_opened_roots_survive_renames() {
    let tree = Tree::new();
    fs::write(tree.0.join("public/file"), b"PUBLIC").unwrap();
    let root = tree.root();
    let mut opened = root.open_file("file").unwrap();
    assert_eq!(opened.length, 6);
    fs::rename(tree.0.join("public"), tree.0.join("moved")).unwrap();
    fs::create_dir(tree.0.join("public")).unwrap();
    fs::write(tree.0.join("public/file"), b"REPLACEMENT").unwrap();
    let mut bytes = Vec::new();
    opened.file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"PUBLIC");
    let mut again = root.open_file("file").unwrap();
    bytes.clear();
    again.file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"PUBLIC");
}

#[test]
fn denies_links_traversal_special_files_and_oversized_files() {
    let tree = Tree::new();
    let public = tree.0.join("public");
    fs::write(tree.0.join("outside/secret"), b"SECRET").unwrap();
    fs::write(public.join("file"), b"PUBLIC").unwrap();
    fs::create_dir(public.join("dir")).unwrap();
    symlink(tree.0.join("outside/secret"), public.join("symlink")).unwrap();
    symlink(tree.0.join("outside"), public.join("linked-dir")).unwrap();
    symlink(public.join("file"), public.join("inside-link")).unwrap();
    fs::hard_link(tree.0.join("outside/secret"), public.join("hardlink")).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        public.join("fifo"),
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    let _socket = UnixListener::bind(public.join("socket")).unwrap();
    File::create(public.join("large"))
        .unwrap()
        .set_len(pathward::serving::MAX_FILE_BYTES + 1)
        .unwrap();
    let root = tree.root();
    let start = Instant::now();
    for path in [
        "../outside/secret",
        "/etc/passwd",
        "dir/../file",
        "symlink",
        "inside-link",
        "linked-dir/secret",
        "hardlink",
        "fifo",
        "socket",
        "dir",
        "large",
        "missing",
        ".hidden",
        "",
    ] {
        assert!(root.open_file(path).is_err(), "allowed {path}");
    }
    assert!(
        start.elapsed().as_secs() < 2,
        "special-file checks must not wait for a FIFO peer"
    );
    symlink(&public, tree.0.join("root-link")).unwrap();
    assert!(DocumentRoot::open(tree.0.join("root-link").to_str().unwrap()).is_err());
    symlink(&tree.0, tree.0.join("ancestor-link")).unwrap();
    assert!(DocumentRoot::open(tree.0.join("ancestor-link/public").to_str().unwrap()).is_err());
}

#[test]
fn symlink_and_directory_rename_races_never_read_outside_bytes() {
    let tree = Tree::new();
    let public = tree.0.join("public");
    fs::create_dir(public.join("dir")).unwrap();
    fs::write(public.join("dir/file"), b"PUBLIC").unwrap();
    fs::write(tree.0.join("outside/file"), b"SECRET").unwrap();
    let root = tree.root();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            while !stop.load(Ordering::Acquire) {
                fs::rename(public.join("dir"), tree.0.join("parked")).unwrap();
                symlink(tree.0.join("outside"), public.join("dir")).unwrap();
                fs::remove_file(public.join("dir")).unwrap();
                fs::rename(tree.0.join("parked"), public.join("dir")).unwrap();
            }
        });
        for _ in 0..2000 {
            if let Ok(mut file) = root.open_file("dir/file") {
                let mut bytes = Vec::new();
                file.file.read_to_end(&mut bytes).unwrap();
                if bytes != b"PUBLIC" {
                    stop.store(true, Ordering::Release);
                    panic!("outside bytes escaped confinement");
                }
            }
        }
        stop.store(true, Ordering::Release);
    });
    assert!(root.open_file("dir/file").is_ok());
}

#[test]
#[ignore = "requires a private mount namespace; run scripts/linux_mount_check.py on Linux CI"]
fn rejects_bind_mounts() {
    let tree = Tree::new();
    fs::write(tree.0.join("outside/secret"), b"SECRET").unwrap();
    let mountpoint = tree.0.join("public/mounted");
    fs::create_dir(&mountpoint).unwrap();
    assert!(
        std::process::Command::new("mount")
            .arg("--bind")
            .arg(tree.0.join("outside"))
            .arg(&mountpoint)
            .status()
            .unwrap()
            .success()
    );
    let result = tree.root().open_file("mounted/secret");
    let unmounted = std::process::Command::new("umount")
        .arg(&mountpoint)
        .status()
        .unwrap()
        .success();
    assert!(unmounted);
    assert!(
        result.is_err(),
        "NO_XDEV must reject even same-filesystem bind mounts"
    );
}
