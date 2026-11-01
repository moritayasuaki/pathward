use crate::{Server, http};
use pathward_config::ParsedConfig;
use std::{
    fs,
    io::{self, Read, Write},
    sync::atomic::AtomicBool,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
struct Exchange {
    input: io::Cursor<Vec<u8>>,
    output: Vec<u8>,
    port: u16,
}
impl Read for Exchange {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.input.read(b)
    }
}
impl Write for Exchange {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.output.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl http::Transport for Exchange {
    fn deadline(&mut self, _: Instant) -> io::Result<()> {
        Ok(())
    }
    fn local_port(&self) -> io::Result<u16> {
        Ok(self.port)
    }
}
fn exchange(server: &Server, target: &str, host: &str, sni: Option<&str>) -> String {
    exchange_mode(server, target, host, sni, 80, false)
}
fn exchange_mode(
    server: &Server,
    target: &str,
    host: &str,
    sni: Option<&str>,
    port: u16,
    redirect: bool,
) -> String {
    let mut stream = Exchange {
        input: io::Cursor::new(
            format!("HEAD {target} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes(),
        ),
        output: Vec::new(),
        port,
    };
    let snapshot = server.state.read().unwrap().snapshot.clone();
    Server::respond(&snapshot, &mut stream, Instant::now(), sni, redirect).unwrap();
    String::from_utf8(stream.output).unwrap()
}
#[test]
fn configured_locations_headers_and_reload_use_one_checked_policy() {
    let root = std::env::temp_dir().join(format!(
        "pathward-response-{}-{}",
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
    fs::write(root.join("index.html"), b"CONTENT").unwrap();
    let text = format!(
        "site \"example.com\" {{\nroot \"{}\"\ntls \"auto\"\npublish \"/\" \"index.html\"\nredirect-prefix \"/old\" \"example.com\" \"/base\" \"301\"\nredirect-prefix \"/old/deep\" \"other.example\" \"/\" \"308\"\nheader \"*\" \"referrer-policy\" \"no-referrer\"\nheader \"/\" \"referrer-policy\" \"same-origin\"\nheader \"*\" \"strict-transport-security\" \"max-age=60\"\n}}\nsite \"other.example\" {{\nroot \"{}\"\ntls \"auto\"\nredirect \"/\" \"example.com\" \"/\" \"308\"\n}}\n",
        root.display(),
        root.display()
    );
    let p = ParsedConfig::parse(&text).unwrap();
    let server = Server::new(&p.compile().unwrap()).unwrap();
    for (local, sni, redirect, authority, status) in [
        (8443, Some("example.com"), false, "example.com:443", 200),
        (8443, Some("example.com"), false, "example.com:8443", 400),
        (8443, Some("example.com"), false, "example.com:80", 400),
        (8080, None, true, "example.com:80", 308),
        (8080, None, true, "example.com:8080", 400),
        (8080, None, true, "example.com:443", 400),
        (8080, None, false, "example.com:8080", 200),
        (8080, None, false, "example.com:80", 400),
    ] {
        let response = exchange_mode(&server, "/", authority, sni, local, redirect);
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{authority}: {response}"
        );
        if status == 308 {
            assert!(response.contains("Location: https://example.com/\r\n"));
        }
    }
    for (target, status, location) in [
        ("/old?q=%20", 301, "https://example.com/base?q=%20"),
        ("/old/file", 301, "https://example.com/base/file"),
        ("/old/deep/file?q=x", 308, "https://other.example/file?q=x"),
        ("/old/deep", 308, "https://other.example/"),
    ] {
        let r = exchange(&server, target, "example.com", Some("example.com"));
        assert!(r.starts_with(&format!("HTTP/1.1 {status}")), "{r}");
        assert!(r.contains(&format!("Location: {location}\r\n")), "{r}");
        assert!(r.ends_with("\r\n\r\n"));
        assert!(r.contains("Content-Length: 0\r\n"));
        assert!(r.contains("strict-transport-security: max-age=60\r\n"));
    }
    let r = exchange(&server, "/", "example.com", None);
    assert!(r.starts_with("HTTP/1.1 200"));
    assert_eq!(r.matches("referrer-policy:").count(), 1);
    assert!(r.contains("referrer-policy: same-origin\r\n"));
    assert!(!r.contains("strict-transport-security"));
    assert!(!r.contains("CONTENT"));
    for target in ["/older", "/old/%2e", "/old?q=%0d%0a"] {
        let r = exchange(&server, target, "example.com", None);
        if target == "/old?q=%0d%0a" {
            // Encoded query bytes remain literal, never decoded into response lines.
            assert!(r.contains("Location: https://example.com/base?q=%0d%0a\r\n"));
        } else {
            assert!(r.starts_with("HTTP/1.1 404"));
            assert!(!r.contains("Location:"));
        }
    }
    for (host, sni) in [
        ("evil.example", None),
        ("example.com", Some("other.example")),
    ] {
        let r = exchange(&server, "/old", host, sni);
        assert!(r.starts_with("HTTP/1.1 421"));
        assert!(!r.contains("Location:"));
    }
    let next = text
        .replace("/base", "/next")
        .replace("no-referrer", "origin");
    let p = ParsedConfig::parse(&next).unwrap();
    server
        .reload(&p.compile().unwrap(), &AtomicBool::new(false))
        .unwrap();
    let r = exchange(&server, "/old", "example.com", None);
    assert!(r.contains("Location: https://example.com/next\r\n"));
    assert!(r.contains("referrer-policy: origin\r\n"));
    assert!(!r.contains("no-referrer"));
}
