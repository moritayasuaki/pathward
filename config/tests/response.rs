use pathward_config::ParsedConfig;
fn config(extra: &str) -> String {
    format!(
        "site \"example.com\" {{\nroot \"/srv/www\"\npublish \"/\" \"index.html\"\ntls \"auto\"\n{extra}\n}}"
    )
}
#[test]
fn compile_redirects_headers_and_reject_unsafe_forms() {
    let parsed=ParsedConfig::parse(&config("redirect-prefix \"/old\" \"example.com\" \"/new\" \"308\"\nheader \"*\" \"content-security-policy\" \"default-src 'none'\"")).unwrap();
    let compiled = parsed.compile().unwrap();
    assert_eq!(compiled.sites()[0].redirects().len(), 1);
    assert_eq!(compiled.sites()[0].headers().len(), 1);
    for extra in [
        "redirect \"/old\" \"evil.test\" \"/new\" \"308\"",
        "redirect \"/\" \"example.com\" \"/new\" \"308\"",
        "redirect \"/old\" \"example.com\" \"/new\" \"302\"",
        "header \"*\" \"content-length\" \"0\"",
        "header \"*\" \"link\" \"x\\r\\nY: z\"",
        "header \"*\" \"link\" \"x\"\nheader \"*\" \"link\" \"y\"",
    ] {
        assert!(
            ParsedConfig::parse(&config(extra))
                .and_then(|p| p.compile().map(|_| ()))
                .is_err(),
            "{extra}"
        );
    }
}
