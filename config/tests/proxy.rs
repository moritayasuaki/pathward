use pathward_config::ParsedConfig;

fn valid(text: &str) -> bool {
    ParsedConfig::parse(text).is_ok_and(|p| p.compile().is_ok())
}
#[test]
fn proxy_requires_a_literal_loopback_and_publications_require_a_root() {
    for endpoint in ["127.0.0.1:8080", "[::1]:65535"] {
        let text =
            format!("site \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{endpoint}\"\n}}\n");
        let p = ParsedConfig::parse(&text).unwrap();
        let c = p.compile().unwrap();
        let s = &c.sites()[0];
        assert_eq!(s.root(), None);
        assert_eq!(s.upstream().unwrap().to_string(), endpoint);
        assert!(s.resolve(b"/").is_none());
        for directive in [
            "publish \"/\" \"index.html\"",
            "reverse-proxy \"127.0.0.1:8081\"",
        ] {
            assert!(!valid(&text.replace("}\n", &format!("{directive}\n}}\n"))));
        }
    }
    for address in [
        "localhost:8080",
        "example.com:80",
        "127.0.0.2:80",
        "0.0.0.0:8080",
        "192.168.1.1:80",
        "169.254.169.254:80",
        "[::]:80",
        "[::ffff:127.0.0.1]:80",
        "[::1%lo0]:80",
        "127.0.0.1:0",
        "127.0.0.1:080",
        "http://127.0.0.1:80",
        "127.0.0.1:80/path",
        "user@127.0.0.1:80",
        "127.0.0.1:65536",
    ] {
        assert!(
            !valid(&format!(
                "site \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{address}\"\n}}\n"
            )),
            "accepted {address}"
        );
    }
}

#[test]
fn mixed_routes_and_human_readable_service_limits_compile_atomically() {
    let text = "site \"app.example\" {\ntls \"auto\"\nroot \"/srv/public\"\npublish \"/robots.txt\" \"robots.txt\"\ndeny \"/admin\"\nproxy-path \"/api\"\nreverse-proxy \"127.0.0.1:3000\"\nproxy-limit \"request-body\" \"16KiB\"\nproxy-limit \"response-body\" \"64MiB\"\nproxy-limit \"connections\" \"1\"\nproxy-timeout \"connect\" \"3s\"\nproxy-timeout \"request-body\" \"10s\"\nproxy-timeout \"response-head\" \"70s\"\nproxy-timeout \"total\" \"90s\"\n}\n";
    let parsed = ParsedConfig::parse(text).unwrap();
    let config = parsed.compile().unwrap();
    let site = &config.sites()[0];
    assert_eq!(site.denies(), ["/admin"]);
    assert_eq!(site.proxy_paths(), ["/api"]);
    assert_eq!(site.resolve(b"/robots.txt"), Some("robots.txt"));
    let l = site.proxy_limits();
    assert_eq!(
        (l.request_bytes, l.response_bytes, l.connections),
        (16384, 67108864, 1)
    );
    assert_eq!(
        (l.body_ms, l.connect_ms, l.head_ms, l.total_ms),
        (10000, 3000, 70000, 90000)
    );
    for extra in [
        "deny \"/admin\"",
        "deny \"/../admin\"",
        "deny \"/admin/\"",
        "proxy-path \"/api\"",
        "proxy-limit \"request-body\" \"0B\"",
        "proxy-timeout \"total\" \"90s\"",
    ] {
        assert!(
            !valid(&text.replace("}\n", &format!("{extra}\n}}\n"))),
            "{extra}"
        );
    }
    let base = "site \"app.example\" {\ntls \"auto\"\nreverse-proxy \"127.0.0.1:3000\"\n";
    for directive in [
        "proxy-limit \"request-body\" \"17MiB\"",
        "proxy-limit \"response-body\" \"65MiB\"",
        "proxy-limit \"connections\" \"0\"",
        "proxy-limit \"connections\" \"4\"",
        "proxy-limit \"request-body\" \"1MB\"",
        "proxy-limit \"response-body\" \"01B\"",
        "proxy-limit \"request-body\" \"18446744073709551615MiB\"",
        "proxy-timeout \"total\" \"121s\"",
        "proxy-timeout \"total\" \"9s\"",
        "proxy-timeout \"connect\" \"0s\"",
        "proxy-timeout \"response-head\" \"16s\"",
        "proxy-timeout \"request-body\" \"31s\"",
        "proxy-timeout \"connect\" \"1.5s\"",
        "proxy-timeout \"connect\" \"-1s\"",
        "proxy-timeout \"read\" \"1s\"",
    ] {
        assert!(!valid(&format!("{base}{directive}\n}}\n")), "{directive}");
    }
    assert!(valid(&format!(
        "{base}proxy-limit \"request-body\" \"0B\"\nproxy-limit \"response-body\" \"0B\"\n}}\n"
    )));
    for directive in [
        "proxy-path \"/api\"",
        "proxy-limit \"connections\" \"1\"",
        "proxy-timeout \"total\" \"20s\"",
    ] {
        assert!(!valid(&format!(
            "site \"app.example\" {{\ntls \"auto\"\nroot \"/srv/public\"\npublish \"/\" \"index.html\"\n{directive}\n}}\n"
        )));
    }
}
