use pathward_config::ParsedConfig;

const SITE: &str = "site \"app.example\" {\n tls \"auto\"\n reverse-proxy \"127.0.0.1:3000\"\n}\n";

#[test]
fn capacity_is_explicit_bounded_and_does_not_consume_a_site_slot() {
    for (prefix, expected) in [
        ("", false),
        ("capacity \"standard\"\n", false),
        ("capacity \"shared-nat\"\n", true),
    ] {
        let source = format!("{prefix}{SITE}");
        let parsed = ParsedConfig::parse(&source).unwrap();
        assert_eq!(parsed.compile().unwrap().shared_nat(), expected);
    }
    let mut source = "capacity \"shared-nat\"\n".to_owned();
    for i in 0..16 {
        source.push_str(&SITE.replace("app.example", &format!("a{i}.example")));
    }
    assert_eq!(
        ParsedConfig::parse(&source)
            .unwrap()
            .compile()
            .unwrap()
            .sites()
            .len(),
        16
    );
    source.push_str(SITE);
    assert!(ParsedConfig::parse(&source).is_err());
}

#[test]
fn unknown_duplicate_late_typed_or_nested_capacity_is_rejected() {
    for source in [
        format!("capacity \"unlimited\"\n{SITE}"),
        format!("capacity \"shared-nat\"\ncapacity \"standard\"\n{SITE}"),
        format!("{SITE}capacity \"shared-nat\"\n"),
        format!("capacity kind=\"shared-nat\"\n{SITE}"),
        format!("capacity \"shared-nat\" {{}}\n{SITE}"),
        format!("capacity \"shared-nat\" \"extra\"\n{SITE}"),
        format!("capacity true\n{SITE}"),
        format!("(type)capacity \"shared-nat\"\n{SITE}"),
        "capacity \"shared-nat\"\n".to_owned(),
    ] {
        assert!(
            ParsedConfig::parse(&source)
                .and_then(|p| p.compile().map(|_| ()))
                .is_err(),
            "{source}"
        );
    }
}
