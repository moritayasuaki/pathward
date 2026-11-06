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

fn raw_exchange(server: &Server, request: &str) -> String {
    let mut stream = Exchange {
        input: io::Cursor::new(request.as_bytes().to_vec()),
        output: Vec::new(),
        port: 80,
    };
    let snapshot = server.state.read().unwrap().snapshot.clone();
    Server::respond(
        &snapshot,
        &mut stream,
        Instant::now(),
        None,
        false,
        &server.stream_quota,
        &|| false,
        None,
    )
    .unwrap();
    String::from_utf8(stream.output).unwrap()
}

#[test]
fn static_ranges_preconditions_cache_and_large_files_use_one_authorized_descriptor() {
    use std::io::{Seek, SeekFrom};
    let root = std::env::temp_dir().join(format!(
        "pathward-content-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    fs::write(root.join("index.html"), b"0123456789").unwrap();
    fs::write(root.join("secret"), b"PRIVATE").unwrap();
    let mut file = fs::File::create(root.join("big.bin")).unwrap();
    file.set_len(128 * 1024 * 1024).unwrap();
    file.seek(SeekFrom::End(-4)).unwrap();
    file.write_all(b"TAIL").unwrap();
    drop(file);
    let text = format!(
        "site \"example.com\" {{\nroot \"{}\"\ntls \"auto\"\npublish \"/\" \"index.html\"\npublish \"/big.bin\" \"big.bin\"\ncache \"*\" \"public,max-age=3600,immutable\"\n}}",
        root.display()
    );
    let parsed = ParsedConfig::parse(&text).unwrap();
    let server = Server::new(&parsed.compile().unwrap()).unwrap();
    let query = |method: &str, path: &str, headers: &str| {
        raw_exchange(
            &server,
            &format!("{method} {path} HTTP/1.1\r\nHost: example.com\r\n{headers}\r\n"),
        )
    };
    let full = query("GET", "/", "");
    assert!(full.ends_with("0123456789"));
    assert!(full.contains("Cache-Control: public,max-age=3600,immutable\r\n"));
    let etag = full.lines().find_map(|l| l.strip_prefix("ETag: ")).unwrap();
    let modified = full
        .lines()
        .find_map(|l| l.strip_prefix("Last-Modified: "))
        .unwrap();
    for (range, body, field) in [
        ("bytes=2-4", "234", "bytes 2-4/10"),
        ("bytes=-2", "89", "bytes 8-9/10"),
        ("bytes=7-", "789", "bytes 7-9/10"),
    ] {
        let r = query("GET", "/", &format!("Range: {range}\r\n"));
        assert!(r.starts_with("HTTP/1.1 206"));
        assert!(r.ends_with(body));
        assert!(r.contains(&format!("Content-Range: {field}\r\n")));
    }
    let r = query("GET", "/", "Range: bytes=10-\r\n");
    assert!(r.starts_with("HTTP/1.1 416"));
    assert!(r.contains("Content-Range: bytes */10\r\n"));
    assert!(r.contains("Cache-Control: no-store\r\n"));
    let r = query("HEAD", "/", "Range: bytes=2-4\r\n");
    assert!(r.starts_with("HTTP/1.1 200"));
    assert!(r.contains("Content-Length: 10\r\n"));
    assert!(r.ends_with("\r\n\r\n"));
    let r = query(
        "GET",
        "/",
        &format!("If-None-Match: {etag}\r\nRange: bytes=0-1\r\n"),
    );
    assert!(r.starts_with("HTTP/1.1 304"));
    assert!(!r.contains("Content-Length:"));
    assert!(r.ends_with("\r\n\r\n"));
    assert!(
        query("GET", "/", &format!("If-Modified-Since: {modified}\r\n"))
            .starts_with("HTTP/1.1 304")
    );
    assert!(
        query(
            "GET",
            "/",
            &format!("If-None-Match: \"mismatch\"\r\nIf-Modified-Since: {modified}\r\n")
        )
        .starts_with("HTTP/1.1 200")
    );
    assert!(
        query(
            "GET",
            "/",
            &format!("If-Match: \"wrong\"\r\nIf-None-Match: {etag}\r\n")
        )
        .starts_with("HTTP/1.1 412")
    );
    assert!(
        query(
            "GET",
            "/",
            &format!("If-Range: {etag}\r\nRange: bytes=0-1\r\n")
        )
        .ends_with("0123456789")
    );
    assert!(
        query("GET", "/", "Cookie: session=private\r\n").contains("Cache-Control: no-store\r\n")
    );
    assert!(
        query("GET", "/", "Range: bytes=0-1\r\nRange: bytes=3-4\r\n").starts_with("HTTP/1.1 400")
    );
    for path in ["/secret", "/../secret"] {
        let r = query("GET", path, "If-None-Match: *\r\nRange: bytes=0-1\r\n");
        assert!(r.starts_with("HTTP/1.1 404"));
        assert!(!r.contains("ETag:"));
    }
    let r = query("GET", "/big.bin", "Range: bytes=-4\r\n");
    assert!(r.starts_with("HTTP/1.1 206"));
    assert!(r.ends_with("TAIL"));
    assert!(r.contains("Content-Range: bytes 134217724-134217727/134217728\r\n"));
    // Removing a publication on reload must invalidate even a previously seen validator.
    let text = text.replace("publish \"/big.bin\" \"big.bin\"\n", "");
    let parsed = ParsedConfig::parse(&text).unwrap();
    server
        .reload(&parsed.compile().unwrap(), &AtomicBool::new(false))
        .unwrap();
    assert!(
        query("GET", "/big.bin", "If-None-Match: *\r\nRange: bytes=-4\r\n")
            .starts_with("HTTP/1.1 404")
    );
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
    Server::respond(
        &snapshot,
        &mut stream,
        Instant::now(),
        sni,
        redirect,
        &server.stream_quota,
        &|| false,
        None,
    )
    .unwrap();
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
    assert!(
        exchange(&server, "/old/deep/ja/?x=1", "example.com", None)
            .contains("Location: https://other.example/ja/?x=1\r\n")
    );
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

#[test]
fn fallback_preserves_local_denials_publications_and_explicit_redirects() {
    let root = std::env::temp_dir().join(format!(
        "pathward-fallback-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::write(root.join("index.html"), b"CONTENT").unwrap();
    struct Tree(std::path::PathBuf);
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _tree = Tree(root.clone());
    let text = format!(
        "site \"example.com\" {{\nroot \"{}\"\ntls \"auto\"\npublish \"/\" \"index.html\"\npublish \"/local\" \"index.html\"\npublish \"/guide/\" \"index.html\"\nredirect \"/guide\" \"example.com\" \"/guide/\" \"308\"\ndeny \"/private\"\nredirect-prefix \"/old\" \"other.example\" \"/new\" \"301\"\nredirect-fallback \"other.example\" \"308\"\n}}\nsite \"other.example\" {{\nroot \"{}\"\ntls \"auto\"\npublish \"/\" \"index.html\"\n}}",
        root.display(),
        root.display()
    );
    let parsed = ParsedConfig::parse(&text).unwrap();
    let server = Server::new(&parsed.compile().unwrap()).unwrap();
    for (path, status, location) in [
        ("/", 200, None),
        ("/local?x=1", 200, None),
        ("/local/", 404, None),
        ("/guide/", 200, None),
        ("/guide?x=1", 308, Some("https://example.com/guide/?x=1")),
        ("/private", 404, None),
        ("/private/file", 404, None),
        ("/.key", 404, None),
        ("/x%2fy", 404, None),
        (
            "/old/file?x=%20",
            301,
            Some("https://other.example/new/file?x=%20"),
        ),
        (
            "/missing/?x=%0d%0a",
            308,
            Some("https://other.example/missing/?x=%0d%0a"),
        ),
    ] {
        let response = exchange(&server, path, "example.com", Some("example.com"));
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{path}: {response}"
        );
        if let Some(location) = location {
            assert!(response.contains(&format!("Location: {location}\r\n")));
        } else {
            assert!(!response.contains("Location:"), "{path}: {response}");
        }
    }
    fs::remove_file(root.join("index.html")).unwrap();
    let response = exchange(&server, "/local", "example.com", Some("example.com"));
    assert!(response.starts_with("HTTP/1.1 404"));
    assert!(
        !response.contains("Location:"),
        "failed local open must remain final"
    );
    let generated = crate::deployment::generate(
        &parsed.compile().unwrap(),
        "example.com",
        root.to_str().unwrap(),
        "index.html\n",
        Some("index.html"),
    )
    .unwrap();
    assert!(generated.contains("redirect-fallback \"other.example\" \"308\""));
    assert!(ParsedConfig::parse(&generated).unwrap().compile().is_ok());
}
