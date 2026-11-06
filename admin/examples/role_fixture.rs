//! Loopback-only fixture for isolated administrator integration tests.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.first().map(String::as_str) == Some("check") {
        return Ok(());
    }
    if a.len() != 3 {
        return Err("fixture MODE LABEL PORT".into());
    }
    let port = a[2].parse::<u16>()?;
    let label = &a[1];
    if a[0] == "probe" {
        let until = Instant::now() + Duration::from_secs(15);
        while Instant::now() < until {
            if let Ok(mut s) = TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse()?,
                Duration::from_secs(1),
            ) {
                s.set_read_timeout(Some(Duration::from_secs(1)))?;
                let _ =
                    s.write_all(b"GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n");
                let mut body = String::new();
                if s.take(4096).read_to_string(&mut body).is_ok() && body.ends_with(label) {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        return Err("fixture health mismatch".into());
    }
    if a[0] != "serve" && a[0] != "files" {
        return Err("invalid fixture mode".into());
    }
    if label == "TARGET" && std::path::Path::new("/run/pathward-role-fail-primary").exists() {
        std::process::exit(9)
    }
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("PW_FIXTURE_BOUND_{label}");
    if let Ok(socket) = std::env::var("NOTIFY_SOCKET") {
        let datagram = std::os::unix::net::UnixDatagram::unbound()?;
        #[cfg(target_os = "linux")]
        if let Some(name) = socket.strip_prefix('@') {
            use std::os::linux::net::SocketAddrExt;
            datagram.send_to_addr(
                b"READY=1",
                &std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?,
            )?;
        } else {
            datagram.send_to(b"READY=1", socket)?;
        }
        #[cfg(not(target_os = "linux"))]
        datagram.send_to(b"READY=1", socket)?;
    }
    for mut stream in listener.incoming().flatten() {
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut buf = [0; 1024];
        let n = stream.read(&mut buf).unwrap_or(0);
        let body = if a[0] == "files" {
            let request = String::from_utf8_lossy(&buf[..n]);
            let name = request.split_whitespace().nth(1).unwrap_or("/");
            let name = if name == "/" {
                "index.html"
            } else {
                name.trim_start_matches('/')
            };
            if !pathward_admin::publisher::safe_asset(name) {
                continue;
            }
            std::fs::read(std::path::Path::new(label).join(name)).unwrap_or_default()
        } else {
            label.as_bytes().to_vec()
        };
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(&body);
    }
    Ok(())
}
