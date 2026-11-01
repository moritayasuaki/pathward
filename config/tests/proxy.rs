use pathward_config::ParsedConfig;

fn valid(text: &str) -> bool {
    ParsedConfig::parse(text).is_ok_and(|p| p.compile().is_ok())
}
#[test]
fn proxy_is_an_explicit_exclusive_whole_site_mode_with_literal_loopback_only() {
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
            "root \"/srv/www\"",
            "publish \"/\" \"index.html\"",
            "redirect \"/old\" \"app.example\" \"/new\" \"308\"",
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
