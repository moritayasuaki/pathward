#![cfg(target_os = "linux")]
use pathward_config::ParsedConfig;
use pathward_server::Server;
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::symlink,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Tree(PathBuf);
impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn with_server(test: impl FnOnce(SocketAddr)) {
    let path = std::env::temp_dir().join(format!(
        "pathward-http-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    let tree = Tree(path);
    fs::create_dir(tree.0.join("public")).unwrap();
    fs::create_dir(tree.0.join("other")).unwrap();
    fs::write(tree.0.join("public/index.html"), b"PUBLIC INDEX").unwrap();
    fs::write(tree.0.join("other/index.html"), b"SECOND SITE").unwrap();
    fs::write(tree.0.join("secret"), b"NEVER SERVE THIS SECRET").unwrap();
    symlink(tree.0.join("secret"), tree.0.join("public/link")).unwrap();
    fs::hard_link(tree.0.join("secret"), tree.0.join("public/hardlink")).unwrap();
    let text = format!(
        "site \"example.com\" {{\nroot \"{}\"\npublish \"/\" \"index.html\"\npublish \"/link\" \"link\"\npublish \"/hardlink\" \"hardlink\"\ntls \"auto\"\n}}\nsite \"other.example\" {{\nroot \"{}\"\npublish \"/\" \"index.html\"\ntls \"auto\"\n}}",
        tree.0.join("public").display(),
        tree.0.join("other").display()
    );
    let parsed = ParsedConfig::parse(&text).unwrap();
    let config = parsed.compile().unwrap();
    let server = Server::new(&config).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| server.serve(listener, &stop));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(address)));
        stop.store(true, Ordering::Release);
        worker.join().unwrap().unwrap();
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

fn exchange(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    // Admission is covered separately; keep this framing/confinement corpus below 8/s.
    std::thread::sleep(Duration::from_millis(130));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut response = Vec::new();
    if let Err(e) = stream.read_to_end(&mut response) {
        assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset);
    }
    response
}

fn get(address: SocketAddr, method: &str, host: &str, path: &str) -> Vec<u8> {
    exchange(
        address,
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
    )
}

#[test]
fn actual_http_get_head_queries_and_virtual_hosts() {
    with_server(|address| {
        let response = get(address, "GET", "EXAMPLE.COM", "/?v=1");
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Length: 12\r\n"));
        assert!(response.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert!(response.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(response.contains("Connection: close\r\n"));
        assert!(response.ends_with("\r\n\r\nPUBLIC INDEX"));
        let head = get(address, "HEAD", "example.com", "/");
        assert!(head.starts_with(b"HTTP/1.1 200"));
        assert!(head.ends_with(b"\r\n\r\n"));
        assert!(!head.windows(12).any(|w| w == b"PUBLIC INDEX"));
        assert!(get(address, "GET", "other.example", "/").ends_with(b"SECOND SITE"));
        assert!(
            get(
                address,
                "GET",
                &format!("example.com:{}", address.port()),
                "/"
            )
            .ends_with(b"PUBLIC INDEX")
        );
    });
}

#[test]
fn network_attacks_and_unlisted_or_linked_files_are_denied() {
    with_server(|address| {
        for path in [
            "/index.html",
            "/link",
            "/hardlink",
            "/../secret",
            "/%2e%2e/secret",
            "//",
            "/%69ndex.html",
            "/?q#fragment",
            "/./",
            "/index.html/",
            "/secret",
        ] {
            let response = get(address, "GET", "example.com", path);
            assert!(
                response.starts_with(b"HTTP/1.1 404"),
                "{path}: {response:?}"
            );
            assert!(!response.windows(6).any(|w| w == b"SECRET"));
        }
        assert!(get(address, "GET", "unknown.example", "/").starts_with(b"HTTP/1.1 421"));
        let method = get(address, "POST", "example.com", "/");
        assert!(method.starts_with(b"HTTP/1.1 405"));
        assert!(
            String::from_utf8(method)
                .unwrap()
                .contains("Allow: GET, HEAD\r\n")
        );
        for header in [
            "Host: other.example\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Length: 1\r\n",
            "Content-Length: 0\r\nContent-Length: 0\r\n",
        ] {
            let response = exchange(
                address,
                format!("GET / HTTP/1.1\r\nHost: example.com\r\n{header}\r\n").as_bytes(),
            );
            assert!(response.starts_with(b"HTTP/1.1 400"));
        }
        let pipeline = exchange(address, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nGET / HTTP/1.1\r\nHost: other.example\r\n\r\n");
        assert_eq!(pipeline.windows(8).filter(|w| *w == b"HTTP/1.1").count(), 1);
        assert!(!pipeline.windows(11).any(|w| w == b"SECOND SITE"));
    });
}

#[test]
fn oversized_and_stalled_clients_cannot_grow_the_worker_pool() {
    with_server(|address| {
        let mut large = b"GET / HTTP/1.1\r\nHost: example.com\r\nX: ".to_vec();
        large.resize(pathward_server::http::MAX_HEAD_BYTES, b'a');
        assert!(exchange(address, &large).starts_with(b"HTTP/1.1 431"));
        let mut streams = Vec::new();
        for _ in 0..32 {
            let stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            streams.push(stream);
        }
        let mut closed = 0;
        for stream in &mut streams {
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(0) => closed += 1,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => closed += 1,
                _ => {}
            }
        }
        assert!(
            closed > 0,
            "overload must close excess accepted connections"
        );
    });
}
