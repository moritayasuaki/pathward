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
