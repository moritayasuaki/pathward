//! Reproducible bounded mutation corpus. No network or additional dependencies.
use pathward_server::http;
fn main() {
    let rounds = std::env::args()
        .nth(1)
        .map(|s| s.parse::<usize>().expect("round count"))
        .unwrap_or(100_000);
    assert!(rounds <= 1_000_000);
    let seeds: [&[u8]; 8] = [
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"HEAD /a?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
        b"GET //evil.test HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nGET /secret HTTP/1.1\r\n\r\n",
        b"GET /%2e%2e/secret HTTP/1.1\r\nHost: EXAMPLE.COM\r\n\r\n",
        b"GET / HTTP/1.1\nHost: example.com\n\n",
    ];
    let mut state = 0x1234abcddcba4321u64;
    for i in 0..rounds {
        let mut input = seeds[i % seeds.len()].to_vec();
        for _ in 0..(i % 8 + 1) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let at = state as usize % (input.len() + 1);
            let byte = (state >> 32) as u8;
            match (state >> 24) % 4 {
                0 if at < input.len() => input[at] = byte,
                1 => {
                    input.insert(at, byte);
                }
                2 if at < input.len() => {
                    input.remove(at);
                }
                _ => input.extend_from_slice(b"\r\n"),
            }
        }
        if i % 997 == 0 {
            input.resize(http::MAX_HEAD_BYTES, 0xff);
        }
        if let Ok(req) = http::parse(&input, 80) {
            assert!(!req.host.bytes().any(|b| b == b'\r' || b == b'\n'));
            if pathward::response::redirect_allowed(
                req.host.as_bytes(),
                b"example.com",
                req.target,
                308,
            ) {
                assert!(req.target.iter().all(|b| (0x20..=0x7e).contains(b)));
            }
            let publications = [pathward::rules::Publication {
                path: b"/",
                target: b"index.html",
            }];
            if let Some(grant) = pathward::serving::authorize(
                req.method,
                req.host.as_bytes(),
                b"example.com",
                req.target,
                &publications,
            ) {
                assert_eq!(grant.target, b"index.html");
                assert!(pathward::rules::valid_target(grant.target));
            }
        }
    }
    println!("HTTP mutation corpus passed: {rounds} inputs");
}
