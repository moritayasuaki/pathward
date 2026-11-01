use pathward_config::ParsedConfig;
use pathward_server::deployment::generate;
#[test]
fn explicit_manifest_round_trips_without_expansion_and_preserves_other_policies() {
    let parsed=ParsedConfig::parse("site \"example.com\" {\nroot \"/srv/old\"\ntls \"auto\"\npublish \"/\" \"index.html\"\nheader \"*\" \"content-security-policy\" \"default-src 'none'\"\nredirect \"/legacy\" \"example.com\" \"/\" \"308\"\n}\nsite \"other.example\" {\nroot \"/srv/other\"\ntls \"auto\"\npublish \"/\" \"index.html\"\n}").unwrap();
    let base = parsed.compile().unwrap();
    let output = generate(
        &base,
        "example.com",
        "/srv/releases/v2",
        "index.html\nassets/a.js\n",
        Some("index.html"),
    )
    .unwrap();
    let p = ParsedConfig::parse(&output).unwrap();
    let c = p.compile().unwrap();
    let site = c.site("example.com").unwrap();
    assert_eq!(site.publications().len(), 3);
    assert_eq!(site.resolve(b"/"), Some("index.html"));
    assert_eq!(site.resolve(b"/assets/a.js"), Some("assets/a.js"));
    assert_eq!(site.resolve(b"/secret"), None);
    assert_eq!(site.headers()[0].value, "default-src 'none'");
    assert_eq!(site.redirects()[0].from, "/legacy");
    assert_eq!(c.site("other.example").unwrap().root(), Some("/srv/other"));
    for manifest in [
        "", ".env\n", "../key\n", "a\na\n", "a\n\n", "/a\n", "a\\b\n",
    ] {
        assert!(
            generate(&base, "example.com", "/srv/new", manifest, None).is_err(),
            "{manifest}"
        );
    }
    assert!(generate(&base, "example.com", "/srv/new", "a\n", Some("index.html")).is_err());
    assert!(generate(&base, "example.com", "/srv/new", "legacy\n", None).is_err());
}

#[test]
fn generation_preserves_other_proxy_sites_and_never_turns_a_proxy_into_publication() {
    let p=ParsedConfig::parse("site \"static.example\" {\nroot \"/srv/v1\"\ntls \"auto\"\npublish \"/\" \"index.html\"\n}\nsite \"app.example\" {\ntls \"auto\"\nreverse-proxy \"127.0.0.1:8080\"\nheader \"*\" \"x-frame-options\" \"DENY\"\n}\n").unwrap();
    let c = p.compile().unwrap();
    let text = generate(
        &c,
        "static.example",
        "/srv/v2",
        "index.html\n",
        Some("index.html"),
    )
    .unwrap();
    let p = ParsedConfig::parse(&text).unwrap();
    let c2 = p.compile().unwrap();
    let site = c2.site("app.example").unwrap();
    assert_eq!(site.upstream().unwrap().to_string(), "127.0.0.1:8080");
    assert_eq!(site.root(), None);
    assert_eq!(site.headers()[0].value, "DENY");
    assert!(
        generate(
            &c,
            "app.example",
            "/srv/v2",
            "index.html\n",
            Some("index.html")
        )
        .is_err()
    );
}

#[test]
fn generation_preserves_mixed_route_policies_and_every_service_budget() {
    let p=ParsedConfig::parse("site \"app.example\" {\ntls \"auto\"\nroot \"/srv/v1\"\npublish \"/robots.txt\" \"robots.txt\"\ndeny \"/private\"\nproxy-path \"/api\"\nreverse-proxy \"127.0.0.1:3000\"\nproxy-limit \"request-body\" \"16KiB\"\nproxy-limit \"response-body\" \"2MiB\"\nproxy-limit \"connections\" \"1\"\nproxy-timeout \"request-body\" \"7s\"\nproxy-timeout \"connect\" \"3s\"\nproxy-timeout \"response-head\" \"70s\"\nproxy-timeout \"total\" \"90s\"\n}\n").unwrap();
    let c = p.compile().unwrap();
    let text = generate(
        &c,
        "app.example",
        "/srv/v2",
        "robots.txt\nindex.html\n",
        Some("index.html"),
    )
    .unwrap();
    let p2 = ParsedConfig::parse(&text).unwrap();
    let c2 = p2.compile().unwrap();
    let s = &c2.sites()[0];
    let old = &c.sites()[0];
    assert_eq!(s.denies(), old.denies());
    assert_eq!(s.proxy_paths(), old.proxy_paths());
    assert_eq!(s.proxy_limits(), old.proxy_limits());
    assert_eq!(s.upstream(), old.upstream());
    assert_eq!(s.root(), Some("/srv/v2"));
    assert_eq!(s.resolve(b"/"), Some("index.html"));
}

#[test]
fn generation_preserves_stream_opt_ins_and_every_stream_budget() {
    let text = "site \"app.example\" {\ntls \"auto\"\nroot \"/srv/old\"\npublish \"/\" \"old.html\"\nreverse-proxy \"127.0.0.1:3000\"\nproxy-stream \"websocket\"\nproxy-stream \"sse\"\nproxy-limit \"streams\" \"12\"\nwebsocket-compression \"permessage-deflate\"\nwebsocket-origin \"https://console.example\"\nproxy-limit \"stream-upload\" \"8KiB\"\nproxy-limit \"stream-download\" \"2MiB\"\nproxy-timeout \"stream-idle\" \"5s\"\nproxy-timeout \"stream-total\" \"60s\"\n}\n";
    let parsed = ParsedConfig::parse(text).unwrap();
    let config = parsed.compile().unwrap();
    let new = generate(
        &config,
        "app.example",
        "/srv/new",
        "index.html\n",
        Some("index.html"),
    )
    .unwrap();
    let parsed_new = ParsedConfig::parse(&new).unwrap();
    let config_new = parsed_new.compile().unwrap();
    assert_eq!(
        config.sites()[0].websocket_origins(),
        config_new.sites()[0].websocket_origins()
    );
    assert_eq!(
        config.sites()[0].proxy_limits(),
        config_new.sites()[0].proxy_limits()
    );
}

#[test]
fn generated_configuration_round_trips_more_than_256_publications() {
    let p=ParsedConfig::parse("site \"example.com\" {\nroot \"/srv/www\"\ntls \"auto\"\npublish \"/\" \"index.html\"\n}\n").unwrap();
    let manifest = (0..1500)
        .map(|i| format!("page-{i}.html\n"))
        .collect::<String>();
    let result = generate(
        &p.compile().unwrap(),
        "example.com",
        "/srv/new",
        &manifest,
        None,
    )
    .unwrap();
    let parsed = ParsedConfig::parse(&result).unwrap();
    assert_eq!(
        parsed
            .compile()
            .unwrap()
            .site("example.com")
            .unwrap()
            .publications()
            .len(),
        1500
    );
}

#[test]
fn generation_retains_typed_cache_policy() {
    let p=ParsedConfig::parse("site \"example.com\" {\nroot \"/srv/www\"\ntls \"auto\"\npublish \"/\" \"index.html\"\ncache \"*\" \"no-cache\"\ncache-prefix \"/assets\" \"public,max-age=60,immutable\"\n}\n").unwrap();
    let text = generate(
        &p.compile().unwrap(),
        "example.com",
        "/srv/new",
        "index.html\n",
        Some("index.html"),
    )
    .unwrap();
    let p = ParsedConfig::parse(&text).unwrap();
    let c = p.compile().unwrap();
    let rules = c.sites()[0].cache_rules();
    assert_eq!(rules.len(), 2);
    assert!(rules[1].prefix);
    assert_eq!(rules[1].policy.value(), "public,max-age=60,immutable");
}
