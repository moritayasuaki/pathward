use pathward_config::ParsedConfig;
fn accepts(extra: &str) -> bool {
    ParsedConfig::parse(&format!(
        "site \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"127.0.0.1:3000\"\n{extra}\n}}"
    ))
    .is_ok_and(|p| p.compile().is_ok())
}
#[test]
fn explicit_routes_and_header_scopes_are_bounded_and_unambiguous() {
    assert!(accepts(
        "proxy-resource \"/v1/rooms\" \"12\" \"127.0.0.1:3000,127.0.0.1:3001\"\nproxy-route \"/v1/feedback\" \"[::1]:3002\"\nheader-prefix \"/v1\" \"x-robots-tag\" \"noindex, nofollow\"\nheader-query \"room\" \"x-robots-tag\" \"noindex\""
    ));
    for value in [
        "proxy-resource \"/v1/rooms/\" \"12\" \"127.0.0.1:3000\"",
        "proxy-resource \"/\" \"12\" \"127.0.0.1:3000\"",
        "proxy-resource \"/v1/rooms\" \"0\" \"127.0.0.1:3000\"",
        "proxy-resource \"/v1/rooms\" \"65\" \"127.0.0.1:3000\"",
        "proxy-resource \"/v1/rooms\" \"012\" \"127.0.0.1:3000\"",
        "proxy-resource \"/v1/rooms\" \"12\" \"127.0.0.1:3000,127.0.0.1:3000\"",
        "proxy-route \"/a\" \"192.0.2.1:3000\"",
        "proxy-route \"/a\" \"localhost:3000\"",
        "proxy-route \"/a\" \"127.0.0.1:3000,127.0.0.1:3001\"",
        "proxy-route \"/a\" \"127.0.0.1:3000\"\nproxy-resource \"/a\" \"12\" \"127.0.0.1:3001\"",
        "header-prefix \"*\" \"x-robots-tag\" \"noindex\"",
        "header-query \"room=1\" \"x-robots-tag\" \"noindex\"",
        "header-query \"room\" \"set-cookie\" \"a=b\"",
    ] {
        assert!(!accepts(value), "{value}");
    }
    let addresses = (3000..3032)
        .map(|p| format!("127.0.0.1:{p}"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(accepts(&format!(
        "proxy-resource \"/rooms\" \"12\" \"{addresses}\""
    )));
    assert!(!accepts(&format!(
        "proxy-resource \"/rooms\" \"12\" \"{addresses},127.0.0.1:3032\""
    )));
}
