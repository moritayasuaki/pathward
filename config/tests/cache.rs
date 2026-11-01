use pathward_config::{CachePolicy, ParsedConfig};
#[test]
fn cache_policies_have_typed_bounded_output() {
    for good in [
        "no-store",
        "no-cache",
        "public,max-age=0",
        "public,max-age=31536000,immutable",
    ] {
        assert!(CachePolicy::parse(good).is_some());
    }
    for bad in [
        "public",
        "public,max-age=-1",
        "public,max-age=31536001",
        "public,max-age=1\r\nSet-Cookie:x",
        "public,max-age=0,immutable",
        "public,max-age=1,private",
    ] {
        assert!(CachePolicy::parse(bad).is_none(), "{bad}");
    }
    let good = "site \"example.com\" {\nroot \"/srv/www\"\ntls \"auto\"\npublish \"/\" \"index.html\"\ncache \"*\" \"no-cache\"\ncache-prefix \"/assets\" \"public,max-age=31536000,immutable\"\n}";
    let p = ParsedConfig::parse(good).unwrap();
    assert_eq!(p.compile().unwrap().sites()[0].cache_rules().len(), 2);
    for bad in [
        good.replace("/assets", "/assets/"),
        good.replace("cache-prefix", "cache-unknown"),
        good.replace("cache-prefix \"/assets\"", "cache \"*\""),
    ] {
        assert!(ParsedConfig::parse(&bad).map_or(true, |p| p.compile().is_err()));
    }
}
