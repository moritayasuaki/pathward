use pathward_config::{MAX_CONFIG_BYTES, ParsedConfig, TlsPolicy};

fn site(directives: &str) -> String {
    format!("site \"example.com\" {{\n{directives}\n}}")
}

fn valid() -> String {
    site("root \"/srv/www\"\npublish \"/\" \"index.html\"\ntls \"auto\"")
}

fn rejected(source: &str) {
    if let Ok(parsed) = ParsedConfig::parse(source) {
        assert!(parsed.compile().is_err(), "unexpectedly accepted: {source}");
    }
}

#[test]
fn example_compiles_into_only_explicit_rules() {
    let parsed = ParsedConfig::parse(include_str!("../../examples/Pathward.kdl")).unwrap();
    let config = parsed.compile().unwrap();
    assert_eq!(config.sites().len(), 1);
    let site = config.site("example.com").unwrap();
    assert_eq!(site.root(), Some("/srv/www"));
    assert_eq!(site.tls(), TlsPolicy::Auto);
    assert_eq!(site.publications().len(), 2);
    assert_eq!(site.resolve(b"/"), Some("index.html"));
    assert_eq!(site.resolve(b"/style.css"), Some("assets/style.css"));
    for path in [
        b"/index.html".as_slice(),
        b"/assets/style.css",
        b"/style.css/",
        b"/%73tyle.css",
        b"/style.css?q=1",
        b"//style.css",
        b"/../secret",
    ] {
        assert_eq!(site.resolve(path), None);
    }
    assert!(config.site("unknown.example").is_none());
    assert!(config.site("example.com:443").is_none());
}

#[test]
fn separate_hosts_have_separate_tables() {
    let source = format!(
        "{}\n{}",
        valid(),
        valid()
            .replace("example.com", "second.example")
            .replace("index.html", "second.html")
    );
    let parsed = ParsedConfig::parse(&source).unwrap();
    let config = parsed.compile().unwrap();
    assert_eq!(
        config.site("example.com").unwrap().resolve(b"/"),
        Some("index.html")
    );
    assert_eq!(
        config.site("second.example").unwrap().resolve(b"/"),
        Some("second.html")
    );
}

#[test]
fn duplicates_are_errors_including_decoded_and_identical_urls() {
    for extra in [
        "root \"/other\"",
        "tls \"auto\"",
        "publish \"/\" \"index.html\"",
        "publish \"/\" \"different.html\"",
        "publish \"\\u{2f}\" \"index.html\"",
    ] {
        rejected(&site(&format!(
            "root \"/srv/www\"\npublish \"/\" \"index.html\"\ntls \"auto\"\n{extra}"
        )));
    }
    rejected(&format!("{}\n{}", valid(), valid()));
}

#[test]
fn strict_schema_rejects_silent_coercion_and_unknown_settings() {
    for source in [
        "",
        "site \"example.com\"",
        "root \"/srv/www\"",
        "(tag)site \"example.com\" {}",
        "site name=\"example.com\" {}",
        "site \"example.com\" extra=#true {}",
        "site 123 {}",
    ] {
        rejected(source);
    }
    for directive in [
        "publsh \"/x\" \"x\"",
        "publish path=\"/x\" file=\"x\"",
        "publish \"/x\" (path)\"x\"",
        "publish \"/x\" 42",
        "publish \"/x\" \"x\" extra=\"no\"",
        "publish \"/x\" \"x\" {}",
        "include \"other.kdl\"",
        "proxy \"localhost:3000\"",
        "root #null",
    ] {
        rejected(&site(&format!(
            "root \"/srv/www\"\npublish \"/\" \"index.html\"\ntls \"auto\"\n{directive}"
        )));
    }
    for missing in [
        "root \"/srv/www\"",
        "tls \"auto\"",
        "publish \"/\" \"index.html\"",
    ] {
        rejected(&valid().replace(missing, ""));
    }
    rejected(&valid().replace("tls \"auto\"", "tls \"off\""));
}

#[test]
fn lexical_paths_and_hosts_are_validated_after_kdl_decoding() {
    for target in [
        "../secret",
        "/etc/passwd",
        ".secret",
        "a/../b",
        "a//b",
        "a/",
        "a.",
        "",
        "file%2fsecret",
        "C:secret",
        "${HOME}/file",
    ] {
        rejected(&valid().replace("index.html", target));
    }
    rejected(&valid().replace("index.html", "a\\\\b"));
    rejected(&valid().replace("index.html", "\\u{2e}\\u{2e}/secret"));
    for root in [
        "relative",
        "/srv/../etc",
        "/srv//www",
        "/srv/www/",
        "/srv/.secret",
    ] {
        rejected(&valid().replace("/srv/www", root));
    }
    for host in [
        "",
        "Example.com",
        "*.example.com",
        "example.com:443",
        "example.com.",
        "a..b",
        "-a.example",
        "a-.example",
        "例.example",
        "https://example.com",
    ] {
        rejected(&valid().replace("example.com", host));
    }
    rejected(&valid().replace("example.com", &format!("{}.example", "a".repeat(64))));
}

#[test]
fn kdl_line_comments_and_escapes_have_explicit_semantics() {
    let source = r##"// ordinary KDL 2 — 日本語コメント
site "example.com" {
    root "/srv/www"
    // publish "/hidden" "hidden.html"
    publish "/\u{61}" "a.html"
    tls "auto"
}"##;
    let parsed = ParsedConfig::parse(source).unwrap();
    let config = parsed.compile().unwrap();
    let site = config.site("example.com").unwrap();
    assert_eq!(site.resolve(b"/a"), Some("a.html"));
    assert_eq!(site.resolve(b"/hidden"), None);
    assert_eq!(site.publications().len(), 1);
    rejected(&valid().replace("tls \"auto\"", "/- tls \"auto\""));
}

#[test]
fn no_partial_configuration_after_late_failure() {
    let source = format!(
        "{}\n{}",
        valid(),
        valid()
            .replace("example.com", "second.example")
            .replace("index.html", "../private")
    );
    let parsed = ParsedConfig::parse(&source).unwrap();
    assert!(parsed.compile().is_err());
}

#[test]
fn size_utf8_and_structure_are_bounded_before_parsing() {
    let mut source = valid();
    source.push_str(&" ".repeat(MAX_CONFIG_BYTES - source.len()));
    assert!(ParsedConfig::parse(&source).unwrap().compile().is_ok());
    source.push(' ');
    assert!(ParsedConfig::parse(&source).is_err());
    assert!(ParsedConfig::read(std::io::repeat(b' ')).is_err());
    assert!(ParsedConfig::read(&b"\xff\xfe"[..]).is_err());
    for source in [
        "}".repeat(MAX_CONFIG_BYTES),
        "=".repeat(MAX_CONFIG_BYTES),
        format!("/*{}*/", "*".repeat(MAX_CONFIG_BYTES - 4)),
        format!("{}{}", "site \"x\" { ".repeat(100), " }".repeat(100)),
        format!("{}{}", "/*".repeat(100), "*/".repeat(100)),
        format!("site {}x", "/- ".repeat(100)),
        valid().replace("index.html", "\\u{d800}"),
        valid().replace("index.html", "\\u{110000}"),
        valid().replace("index.html", "\\u{}"),
        valid().replace("index.html", "\\u{0000000}"),
        valid().replace("index.html", "\\q"),
        valid().replace("root \"/srv/www\"", "root #\"/srv/www\"#"),
        valid().replace("root \"/srv/www\"", "root \"\"\"\n/srv/www\n\"\"\""),
        valid().replace("tls \"auto\"", "/- tls \"auto\""),
        valid().replace("root \"/srv/www\"", "root\\\n \"/srv/www\""),
        valid().replace(
            "publish \"/\" \"index.html\"",
            "publish \"/\"\"index.html\"",
        ),
    ] {
        assert!(
            ParsedConfig::parse(&source).is_err(),
            "accepted unsupported syntax"
        );
    }
}

#[test]
fn site_and_publication_count_limits_are_enforced() {
    for count in [256, 257] {
        let pubs = (0..count)
            .map(|n| format!("publish \"/f{n}\" \"f{n}\"\n"))
            .collect::<String>();
        let text = site(&format!("root \"/srv/www\"\ntls \"auto\"\n{pubs}"));
        assert_eq!(
            ParsedConfig::parse(&text).is_ok_and(|p| p.compile().is_ok()),
            count == 256
        );
    }
    for count in [16, 17] {
        let source = (0..count)
            .map(|n| valid().replace("example.com", &format!("site{n}.example")))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            ParsedConfig::parse(&source).is_ok_and(|p| p.compile().is_ok()),
            count == 16
        );
    }
}

#[test]
fn schema_errors_include_location() {
    let error = match ParsedConfig::parse("site \"example.com\" {\n    unknown \"x\"\n}") {
        Err(e) => e,
        Ok(_) => panic!("unknown directive accepted"),
    };
    assert_eq!((error.line, error.column), (2, 5));
}

#[test]
fn deterministic_malformed_corpus_never_produces_unchecked_rules() {
    let alphabet = b"sitepublishrootlauto \"{}/*-;=\\012\n#";
    let mut state = 0x1234_5678_u32;
    for length in 0..128 {
        for _ in 0..8 {
            let text: String = (0..length)
                .map(|_| {
                    state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                    alphabet[state as usize % alphabet.len()] as char
                })
                .collect();
            if let Ok(parsed) = ParsedConfig::parse(&text)
                && let Ok(compiled) = parsed.compile()
            {
                for site in compiled.sites() {
                    assert!(pathward::rules::compile(site.publications()).is_some());
                }
            }
        }
    }
}

#[test]
fn supported_layout_agrees_with_upstream_kdl() {
    for newline in [
        "\n", "\r\n", "\r", "\u{85}", "\u{b}", "\u{c}", "\u{2028}", "\u{2029}",
    ] {
        let text = valid().replace('\n', &format!(" // 日本語 comments /* /- {{ }}{newline}"));
        assert!(ParsedConfig::parse(&text).unwrap().compile().is_ok());
        let text = format!("site \"example.com\" {{{newline}    unknown \"x\"{newline}}}");
        let err = ParsedConfig::parse(&text).err().unwrap();
        assert_eq!((err.line, err.column), (2, 5));
    }
    let text =
        "site \"example.com\" {root \"/srv/www\"; publish \"/\" \"index.html\"; tls \"auto\";};";
    assert!(ParsedConfig::parse(text).unwrap().compile().is_ok());
    for escape in ["\\u{69}", "\\u{000069}"] {
        assert!(
            ParsedConfig::parse(&valid().replace("index", &format!("{escape}ndex")))
                .unwrap()
                .compile()
                .is_ok()
        );
    }
}
