#![cfg(target_os = "linux")]
use pathward_config::ParsedConfig;
use pathward_server::{
    Server,
    deployment::{ConfigStore, validate},
};
use std::{
    fs, io,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
struct Store {
    current: Mutex<Vec<u8>>,
    previous: Mutex<Vec<u8>>,
    writes: AtomicUsize,
    fail_from: usize,
    fail_once: bool,
}
impl ConfigStore for Store {
    fn current(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(Some(self.current.lock().unwrap().clone()))
    }
    fn previous(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(Some(self.previous.lock().unwrap().clone()))
    }
    fn save_previous(&self, b: &[u8]) -> io::Result<()> {
        *self.previous.lock().unwrap() = b.to_vec();
        Ok(())
    }
    fn save_current(&self, b: &[u8]) -> io::Result<()> {
        *self.current.lock().unwrap() = b.to_vec();
        let n = self.writes.fetch_add(1, Ordering::Relaxed);
        if n == self.fail_from || (!self.fail_once && n >= self.fail_from) {
            Err(io::Error::other("injected post-rename fsync failure"))
        } else {
            Ok(())
        }
    }
}
#[test]
fn failed_durable_write_restores_or_stops_and_stale_activation_cannot_overwrite() {
    let root = std::env::temp_dir().join(format!(
        "pathward-deploy-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    struct Tree(std::path::PathBuf);
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _tree = Tree(root.clone());
    fs::create_dir(root.join("public")).unwrap();
    fs::write(root.join("public/a"), b"A").unwrap();
    let text = format!(
        "site \"example.com\" {{\nroot \"{}\"\ntls \"auto\"\npublish \"/\" \"a\"\n}}",
        root.join("public").display()
    );
    let new = text.replace("publish \"/\"", "publish \"/new\"");
    let parsed = ParsedConfig::parse(&text).unwrap();
    let config = parsed.compile().unwrap();
    validate(&config, None).unwrap();
    for (fail_from, once, success, stop_expected) in [
        (0, true, false, false),
        (0, false, false, true),
        (usize::MAX, true, true, false),
    ] {
        let server = Server::new(&config).unwrap();
        let stop = AtomicBool::new(false);
        let old = server.revision();
        let store = Store {
            current: Mutex::new(text.as_bytes().to_vec()),
            previous: Mutex::new(vec![]),
            writes: AtomicUsize::new(0),
            fail_from,
            fail_once: once,
        };
        assert_eq!(
            server
                .activate(
                    &store,
                    &root.join("control"),
                    1,
                    &old,
                    new.as_bytes(),
                    &stop
                )
                .is_ok(),
            success
        );
        assert_eq!(stop.load(Ordering::Acquire), stop_expected);
        assert_eq!(server.generation(), if success { 2 } else { 1 });
        if !success && !stop_expected {
            assert_eq!(store.current().unwrap().unwrap(), text.as_bytes());
            assert_eq!(server.revision(), old);
        }
        if success {
            assert!(
                server
                    .activate(
                        &store,
                        &root.join("control"),
                        1,
                        &old,
                        text.as_bytes(),
                        &stop
                    )
                    .is_err()
            );
            assert_eq!(server.generation(), 2);
            assert_eq!(store.current().unwrap().unwrap(), new.as_bytes());
        }
    }
}
