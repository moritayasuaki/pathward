use pathward_config::ParsedConfig;
fn config(extra: &str) -> String {
    format!(
        "site \"example.com\" {{\nroot \"/srv/www\"\npublish \"/\" \"index.html\"\ntls \"auto\"\n{extra}\n}}"
    )
}

#[test]
fn fallback_requires_one_fixed_configured_other_host_and_no_proxy() {
    let destination = "\nsite \"other.example\" {\nroot \"/srv/other\"\ntls \"auto\"\npublish \"/\" \"index.html\"\n}";
    let good = config("redirect-fallback \"other.example\" \"308\"") + destination;
    let parsed = ParsedConfig::parse(&good).unwrap();
    assert!(parsed.compile().unwrap().sites()[0].redirects()[0].fallback);
    for rule in [
        "redirect-fallback \"example.com\" \"308\"",
        "redirect-fallback \"unknown.example\" \"308\"",
        "redirect-fallback \"https://other.example\" \"308\"",
        "redirect-fallback \"other.example\" \"302\"",
        "redirect-fallback \"other.example\" \"308\"\nredirect-fallback \"other.example\" \"301\"",
        "redirect-fallback \"other.example\" \"308\"\nreverse-proxy \"127.0.0.1:9000\"",
    ] {
        let text = config(rule) + destination;
        assert!(
            ParsedConfig::parse(&text)
                .and_then(|p| p.compile().map(|_| ()))
                .is_err(),
            "{rule}"
        );
    }
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

#[test]
fn directory_site_redirect_capacity_is_bounded() {
    let mut rules = String::new();
    for i in 0..512 {
        rules.push_str(&format!(
            "redirect \"/guide-{i}\" \"example.com\" \"/guide-{i}/\" \"308\"\n"
        ));
    }
    let text = config(&rules);
    let parsed = ParsedConfig::parse(&text).unwrap();
    assert_eq!(parsed.compile().unwrap().sites()[0].redirects().len(), 512);
    rules.push_str("redirect \"/extra\" \"example.com\" \"/extra/\" \"308\"\n");
    assert!(
        ParsedConfig::parse(&config(&rules))
            .and_then(|p| p.compile().map(|_| ()))
            .is_err()
    );
}
