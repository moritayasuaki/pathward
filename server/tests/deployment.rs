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

#[test]
fn managed_proxy_activation_failure_and_rollback_preserve_the_shared_service_budget() {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::time::{Duration, Instant};
    fn fetch(addr: SocketAddr) -> Vec<u8> {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: app.example\r\n\r\n")
            .unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        out
    }
    fn accept(listener: &TcpListener) -> TcpStream {
        let start = Instant::now();
        let mut socket = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(start.elapsed() < Duration::from_secs(3));
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
            assert!(head.len() < 16384);
        }
        socket
    }
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    a.set_nonblocking(true).unwrap();
    b.set_nonblocking(true).unwrap();
    let source = |addr: SocketAddr, limit: u64| {
        format!(
            "site \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{addr}\"\nproxy-limit \"connections\" \"{limit}\"\n}}\n"
        )
    };
    let old = source(a.local_addr().unwrap(), 1);
    let new = source(b.local_addr().unwrap(), 1);
    let parsed = ParsedConfig::parse(&old).unwrap();
    let server = Server::new(&parsed.compile().unwrap()).unwrap();
    let store = Store {
        current: Mutex::new(old.as_bytes().to_vec()),
        previous: Mutex::new(vec![]),
        writes: AtomicUsize::new(0),
        fail_from: usize::MAX,
        fail_once: false,
    };
    let directory = std::env::temp_dir().join("pathward-control-test-unused");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| server.serve(listener, &stop));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let pending = scope.spawn(|| fetch(addr));
            let mut socket = accept(&a);
            server
                .activate(
                    &store,
                    &directory,
                    1,
                    &server.revision(),
                    new.as_bytes(),
                    &stop,
                )
                .unwrap();
            assert!(fetch(addr).starts_with(b"HTTP/1.1 503 "));
            assert!(b.accept().is_err());
            let failed = Store {
                current: Mutex::new(new.as_bytes().to_vec()),
                previous: Mutex::new(vec![]),
                writes: AtomicUsize::new(0),
                fail_from: 0,
                fail_once: true,
            };
            let raised = source(b.local_addr().unwrap(), 2);
            assert!(
                server
                    .activate(
                        &failed,
                        &directory,
                        2,
                        &server.revision(),
                        raised.as_bytes(),
                        &stop
                    )
                    .is_err()
            );
            assert_eq!(server.generation(), 2);
            assert_eq!(failed.current().unwrap().unwrap(), new.as_bytes());
            assert!(fetch(addr).starts_with(b"HTTP/1.1 503 "));
            assert!(b.accept().is_err());
            let previous = store.previous().unwrap().unwrap();
            server
                .activate(&store, &directory, 2, &server.revision(), &previous, &stop)
                .unwrap();
            assert_eq!(server.generation(), 3);
            assert_eq!(store.current().unwrap().unwrap(), old.as_bytes());
            assert!(fetch(addr).starts_with(b"HTTP/1.1 503 "));
            assert!(a.accept().is_err());
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .unwrap();
            drop(socket);
            assert!(pending.join().unwrap().ends_with(b"OK"));
            let fresh = scope.spawn(|| fetch(addr));
            let mut socket = accept(&a);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOLD")
                .unwrap();
            drop(socket);
            assert!(fresh.join().unwrap().ends_with(b"OLD"));
        }));
        stop.store(true, Ordering::Release);
        worker.join().unwrap().unwrap();
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    });
}
