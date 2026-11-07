use super::*;
use crate::system::System;
use std::io::{Read, Write};
struct Fixture {
    base: PathBuf,
    config: Value,
    sys: Mock,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}
#[derive(Clone)]
struct Mock {
    properties: Value,
}
impl System for Mock {
    fn run(&mut self, args: &[String], _: u64) -> Result<(bool, String)> {
        require(args[1] == "show", "unexpected service operation")?;
        if args[2] == "pathward.service" {
            return Ok((true, "active".into()));
        }
        let key = args[3].strip_prefix("--property=").ok_or("property")?;
        Ok((
            true,
            self.properties[key]
                .as_str()
                .ok_or("unknown property")?
                .into(),
        ))
    }
}
fn put(path: &Path, data: &[u8]) -> Result<()> {
    f::replace(path, data, 0o600, "fixture", &mut |_| Ok(()))
}
impl Fixture {
    fn new() -> Result<Self> {
        let base = std::env::temp_dir()
            .canonicalize()?
            .join(format!("pathward-wrapper-{}", nonce()?));
        private(&base)?;
        for name in ["release", "release/public", "source"] {
            private(&base.join(name))?;
        }
        put(&base.join("release/public/index.html"), b"OLD")?;
        put(&base.join("release/public/app.js"), b"old asset")?;
        put(&base.join("source/index.html"), b"NEW")?;
        put(&base.join("source/app.js"), b"new asset")?;
        put(&base.join("backend.service"), b"reviewed unit")?;
        let exe = std::env::current_exe()?.canonicalize()?;
        let exe_hash = io::stream(
            io::leaf(
                &io::absolute(exe.parent().unwrap())?,
                exe.file_name().unwrap().to_str().unwrap(),
            )?,
            None,
            256 << 20,
        )?["sha256"]
            .clone();
        let props = json!({"WorkingDirectory":base.join("release"),"Environment":"PORT=18089","FragmentPath":base.join("backend.service"),"NoNewPrivileges":"yes"});
        let policy = json!({"schema":1,"capacity":"shared-nat","sites":[{"id":"site","host":"example.test","source_base":null,"index":"index.html","public_paths":null,"synthetic_files":{},"directives":[["reverse-proxy","127.0.0.1:18089"]]}]});
        put(&base.join("hosting.json"), &codec::canonical(&policy))?;
        let config = json!({"schema":1,"hosting_policy":base.join("hosting.json"),"profiles":{"site":{"kind":"backend","work":base.join("work"),"root":base.join("release/public"),"unit":"backend.service","upstream":"127.0.0.1:18089","executable":exe,"properties":props,"sealed_files":{exe.to_str().unwrap():exe_hash,base.join("backend.service").to_str().unwrap():codec::hash(b"reviewed unit")},"host":"example.test","origin":"https://example.test","checks":{},"immutable_prefixes":["avatars/"],"additive_prefixes":["avatars/v6/"]}}});
        let mut properties = props;
        properties["ActiveState"] = "active".into();
        properties["MainPID"] = std::process::id().to_string().into();
        properties["ExecMainStartTimestampMonotonic"] = "123".into();
        Ok(Self {
            base,
            config,
            sys: Mock { properties },
        })
    }
    fn stage(&mut self) -> Result<Value> {
        let expected = describe(&self.config, "site", &mut self.sys)?;
        prepare(
            &self.base.join("source"),
            &expected,
            None,
            &self.base.join("upload"),
            &mut |_| Ok(()),
        )
    }
}
struct Pass;

#[test]
fn dependency_license_documents_do_not_allow_server_code() {
    for name in [
        "licenses/mux-js-LICENSE",
        "licenses/server/wasi-0.11.1+wasi-snapshot-preview1/LICENSE-MIT",
        "licenses/server/windows-sys-0.52.0/license-apache-2.0",
    ] {
        assert!(safe_asset(name), "{name}");
    }
    for name in [
        "server/LICENSE",
        "licenses/server/main.rs",
        "licenses/server/config.json",
        "licenses/private/LICENSE",
        "licenses/server/../LICENSE",
        "licenses/+escape/LICENSE",
    ] {
        assert!(!safe_asset(name), "{name}");
    }
}

#[test]
fn static_release_keeps_reviewed_immutable_assets() -> Result<()> {
    let mut x = Fixture::new()?;
    let base = x.base.join("static");
    private(&base)?;
    private(&base.join("releases"))?;
    fs::rename(x.base.join("release"), base.join("releases/one"))?;
    std::os::unix::fs::symlink("releases/one", base.join("current"))?;
    x.config["profiles"]["site"]["kind"] = "release".into();
    x.config["profiles"]["site"]["immutable_prefixes"] = json!(["app.js"]);
    let mut policy = read_policy(&x.config)?;
    policy["sites"][0]["source_base"] = json!(base);
    put(&x.base.join("hosting.json"), &codec::canonical(&policy))?;
    x.stage()?;
    assert!(
        apply(
            &x.config,
            "site",
            &x.base.join("upload"),
            &mut x.sys,
            &mut Pass,
            &mut |_| Ok(())
        )
        .is_err()
    );
    assert_eq!(
        fs::read_link(base.join("current"))?,
        Path::new("releases/one")
    );
    assert_eq!(
        fs::read(base.join("releases/one/public/app.js"))?,
        b"old asset"
    );
    assert!(!x.base.join("work/active.json").exists());
    Ok(())
}

#[test]
fn backend_environment_can_be_bound_without_disclosing_it() -> Result<()> {
    let mut x = Fixture::new()?;
    x.config["profiles"]["site"]["properties"]
        .as_object_mut()
        .unwrap()
        .remove("Environment");
    x.config["profiles"]["site"]["environment_sha256"] = codec::hash(b"PORT=18089").into();
    let observed = describe(&x.config, "site", &mut x.sys)?;
    assert!(observed["backend"].get("Environment").is_none());
    x.sys.properties["Environment"] = "PORT=18090".into();
    assert!(describe(&x.config, "site", &mut x.sys).is_err());
    Ok(())
}

#[test]
fn exceptional_types_require_exact_reviewed_paths_and_policy_binding() -> Result<()> {
    let x = Fixture::new()?;
    for n in [
        "certificate.pem",
        "verify.ps1",
        "proof.sig",
        "eng.traineddata",
    ] {
        put(&x.base.join("source").join(n), b"public fixture")?;
    }
    let rules = json!({"reviewed_assets":["certificate.pem", "verify.ps1", "proof.sig", "eng.traineddata"]});
    assert!(scan(&x.base.join("source")).is_err());
    let files = scan_reviewed(&x.base.join("source"), &rules)?;
    assert_eq!(files.as_object().unwrap().len(), 6);
    put(&x.base.join("source/unreviewed.pem"), b"no")?;
    assert!(scan_reviewed(&x.base.join("source"), &rules).is_err());
    assert!(!permitted_asset(
        &json!({"reviewed_assets":["private/key.pem"]}),
        "private/key.pem"
    ));
    assert!(asset_contract(&json!({"reviewed_assets":["secret.key"]})).is_err());
    Ok(())
}

#[test]
fn root_index_must_match_hosting_policy() -> Result<()> {
    let mut x = Fixture::new()?;
    x.config["profiles"]["site"]["index"] = "Standalone.html".into();
    assert!(describe(&x.config, "site", &mut x.sys).is_err());
    let mut policy = read_policy(&x.config)?;
    policy["sites"][0]["index"] = "Standalone.html".into();
    put(&x.base.join("hosting.json"), &codec::canonical(&policy))?;
    put(&x.base.join("release/public/Standalone.html"), b"entry")?;
    let d = describe(&x.config, "site", &mut x.sys)?;
    assert_eq!(d["index"], "Standalone.html");
    x.config["profiles"]["site"]["reviewed_assets"] = json!(["certificate.pem"]);
    assert!(describe(&x.config, "site", &mut x.sys).is_err());
    Ok(())
}

#[test]
fn backend_current_alias_is_bound_to_the_sealed_release() -> Result<()> {
    let mut x = Fixture::new()?;
    let base = x.base.join("backend");
    private(&base)?;
    private(&base.join("releases"))?;
    fs::rename(x.base.join("release"), base.join("releases/one"))?;
    std::os::unix::fs::symlink("releases/one", base.join("current"))?;
    x.config["profiles"]["site"]["release_base"] = json!(base);
    x.config["profiles"]["site"]["root"] = json!(base.join("releases/one/public"));
    x.config["profiles"]["site"]["properties"]["WorkingDirectory"] = json!(base.join("current"));
    x.sys.properties["WorkingDirectory"] = json!(base.join("current"));
    describe(&x.config, "site", &mut x.sys)?;
    private(&base.join("releases/one/bin"))?;
    let exe = base.join("releases/one/bin/backend");
    put(&exe, b"sealed executable fixture")?;
    x.config["profiles"]["site"]["executable"] = json!(exe);
    x.config["profiles"]["site"]["exec_start"] = json!(base.join("current/bin/backend"));
    x.config["profiles"]["site"]["executable_observation"] = "systemd".into();
    x.config["profiles"]["site"]["sealed_files"][exe.to_str().unwrap()] =
        codec::hash(b"sealed executable fixture").into();
    x.sys.properties["ExecStart"] = format!(
        "{{ path={} ; }}",
        base.join("current/bin/backend").display()
    )
    .into();
    describe(&x.config, "site", &mut x.sys)?;
    x.config["profiles"]["site"]["exec_start"] = json!(base.join("current/bin/unreviewed"));
    assert!(describe(&x.config, "site", &mut x.sys).is_err());
    x.config["profiles"]["site"]["exec_start"] = json!(base.join("current/bin/backend"));
    for target in ["releases/two", "../outside", "/etc"] {
        fs::remove_file(base.join("current"))?;
        std::os::unix::fs::symlink(target, base.join("current"))?;
        assert!(describe(&x.config, "site", &mut x.sys).is_err());
    }
    Ok(())
}

#[test]
fn loaded_executable_observation_requires_explicit_single_match() -> Result<()> {
    let mut x = Fixture::new()?;
    x.config["profiles"]["site"]["executable_observation"] = "systemd".into();
    let executable = x.config["profiles"]["site"]["executable"].as_str().unwrap();
    x.sys.properties["ExecStart"] =
        format!("{{ path={executable} ; argv[]={executable} ; }}").into();
    describe(&x.config, "site", &mut x.sys)?;
    for text in [
        "{ path=/bin/other ; }",
        &format!("{{ path={executable} ; }} {{ path=/bin/other ; }}"),
    ] {
        x.sys.properties["ExecStart"] = text.into();
        assert!(describe(&x.config, "site", &mut x.sys).is_err());
    }
    x.config["profiles"]["site"]["executable_observation"] = "skip".into();
    assert!(describe(&x.config, "site", &mut x.sys).is_err());
    Ok(())
}
impl Verify for Pass {
    fn check(&mut self, _: &Value, _: &Value, _: &Path) -> Result<()> {
        Ok(())
    }
}
struct Fail;
impl Verify for Fail {
    fn check(&mut self, _: &Value, _: &Value, _: &Path) -> Result<()> {
        Err("HTTP failed".into())
    }
}
#[test]
fn package_and_backend_rollback() -> Result<()> {
    let mut x = Fixture::new()?;
    x.stage()?;
    assert!(
        apply(
            &x.config,
            "site",
            &x.base.join("upload"),
            &mut x.sys,
            &mut Fail,
            &mut |_| Ok(())
        )
        .is_err()
    );
    assert_eq!(fs::read(x.base.join("release/public/index.html"))?, b"OLD");
    assert_eq!(
        fs::read(x.base.join("release/public/app.js"))?,
        b"old asset"
    );
    Ok(())
}
#[test]
fn stale_backend_and_tampered_payload_are_denied() -> Result<()> {
    let mut x = Fixture::new()?;
    x.stage()?;
    x.sys.properties["MainPID"] = "2".into();
    assert!(
        apply(
            &x.config,
            "site",
            &x.base.join("upload"),
            &mut x.sys,
            &mut Pass,
            &mut |_| Ok(())
        )
        .is_err()
    );
    x.sys.properties["MainPID"] = std::process::id().to_string().into();
    put(&x.base.join("upload/public/index.html"), b"tampered")?;
    assert!(
        apply(
            &x.config,
            "site",
            &x.base.join("upload"),
            &mut x.sys,
            &mut Pass,
            &mut |_| Ok(())
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn asset_rules_and_paths() -> Result<()> {
    for name in [
        "../index.html",
        "private/data.json",
        "bin/run.js",
        "secret.key",
        "server/api.js",
    ] {
        assert!(!safe_asset(name));
    }
    assert!(!origin("http://public.test"));
    assert!(!origin("https://example.test@evil.test"));
    assert!(!origin("https://example.test/path"));
    let v = json!({"immutable_prefixes":["avatars/"],"additive_prefixes":["avatars/v6/"]});
    assert!(immutable(&v, "app.0123456789ab.js"));
    assert!(immutable(&v, "avatars/v6/a.webp"));
    assert!(additive(&v, "avatars/v6/a.webp"));
    assert!(!pathward::bootstrap::asset_allowed(
        true, false, true, false
    ));
    let mut x = Fixture::new()?;
    put(&x.base.join("source/new.html"), b"unsupported")?;
    x.stage()?;
    assert!(
        apply(
            &x.config,
            "site",
            &x.base.join("upload"),
            &mut x.sys,
            &mut Pass,
            &mut |_| Ok(())
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn writes_assets_before_html_and_preserves_omitted_assets() -> Result<()> {
    let mut x = Fixture::new()?;
    put(&x.base.join("release/public/retained.js"), b"retained")?;
    x.stage()?;
    let live = x.base.join("release/public");
    let mut checked = false;
    apply(
        &x.config,
        "site",
        &x.base.join("upload"),
        &mut x.sys,
        &mut Pass,
        &mut |label| {
            if label == "asset-renamed"
                && fs::read(live.join("app.js"))? == b"new asset"
                && !checked
            {
                assert_eq!(fs::read(live.join("index.html"))?, b"OLD");
                checked = true;
            }
            Ok(())
        },
    )?;
    assert!(checked);
    assert_eq!(fs::read(live.join("retained.js"))?, b"retained");
    Ok(())
}
#[test]
fn recovery_preserves_newer_edits_and_stops_new_publications() -> Result<()> {
    let mut x = Fixture::new()?;
    let m = x.stage()?;
    let live = x.base.join("release/public");
    let result = apply(
        &x.config,
        "site",
        &x.base.join("upload"),
        &mut x.sys,
        &mut Pass,
        &mut |label| {
            if label == "asset-renamed" && fs::read(live.join("app.js"))? == b"new asset" {
                put(&live.join("app.js"), b"newer writer")?;
                return Err("interrupted".into());
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(fs::read(live.join("app.js"))?, b"newer writer");
    assert!(
        recover(
            &x.config,
            "site",
            string(&m, "operation")?,
            &mut x.sys,
            &mut |_| Ok(())
        )
        .is_err()
    );
    assert!(
        apply(
            &x.config,
            "site",
            &x.base.join("upload"),
            &mut x.sys,
            &mut Pass,
            &mut |_| Ok(())
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn actual_http_checker_hashes_body_and_refuses_redirects() -> Result<()> {
    use std::net::TcpListener;
    let x = Fixture::new()?;
    for (response, ok) in [
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nNEW",
            true,
        ),
        (
            "HTTP/1.1 302 Found\r\nLocation: https://example.test/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            false,
        ),
    ] {
        let l = TcpListener::bind("127.0.0.1:0")?;
        let origin = format!("http://{}", l.local_addr()?);
        let t = std::thread::spawn(move || {
            for _ in 0..if ok { 2 } else { 1 } {
                let (mut stream, _) = l.accept().unwrap();
                let mut b = [0u8; 4096];
                let _ = stream.read(&mut b);
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        let v = json!({"host":"example.test","origin":origin,"checks":{}});
        let result = Curl.check(&v, &json!({"index.html":codec::hash(b"NEW")}), &x.base);
        t.join().unwrap();
        assert_eq!(result.is_ok(), ok);
    }
    Ok(())
}
#[test]
fn preflight_cannot_run_the_application_or_use_public_network() -> Result<()> {
    let source = "[Unit]\nDescription=Original\n[Service]\nType=exec\nUser=service\nExecStart=/bin/server serve\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nPrivateNetwork=no\nRuntimeDirectory=live-secrets\n[Install]\nWantedBy=multi-user.target\n";
    let text =
        crate::provision::preflight(source, &words(&["/bin/server", "check", "/opt/config"]))?;
    assert!(!text.contains("serve\n"));
    assert!(!text.contains("RuntimeDirectory="));
    assert!(!text.contains("PrivateNetwork=no"));
    assert!(text.contains("PrivateNetwork=yes"));
    assert!(text.contains("ProtectSystem=strict"));
    Ok(())
}

#[test]
fn public_extra_checks_verify_redirect_headers_and_private_paths() -> Result<()> {
    use std::net::TcpListener;
    let x = Fixture::new()?;
    for (response, status, headers, ok) in [
        (
            "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://other.test/?x=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            308,
            json!({"location":"https://other.test/?x=1"}),
            true,
        ),
        (
            "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://wrong.test/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            308,
            json!({"location":"https://other.test/"}),
            false,
        ),
        (
            "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://other.test/\r\nLocation: https://wrong.test/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            308,
            json!({"location":"https://other.test/"}),
            false,
        ),
        (
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            404,
            json!({}),
            true,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            200,
            json!({}),
            false,
        ),
    ] {
        let l = TcpListener::bind("127.0.0.1:0")?;
        let origin = format!("http://{}", l.local_addr()?);
        let t = std::thread::spawn(move || {
            let (mut stream, _) = l.accept().unwrap();
            let mut b = [0u8; 4096];
            let _ = stream.read(&mut b);
            stream.write_all(response.as_bytes()).unwrap();
        });
        let v = json!({"checks":{},"extra_checks":[{"host":"other.test","origin":origin,"path":"/.git/config?x=1","status":status,"headers":headers}]});
        let result = Curl.check(&v, &json!({}), &x.base);
        t.join().unwrap();
        assert_eq!(result.is_ok(), ok);
    }
    assert!(http_check_contract(&json!({"host":"example.test","origin":"https://unrelated.test","path":"/","status":200})).is_err());
    assert!(http_check_contract(&json!({"host":"example.test","origin":"https://example.test","path":"/\r\nx-header:value","status":200})).is_err());
    Ok(())
}

#[test]
fn offline_report_binds_exact_files_and_excludes_release_metadata() -> Result<()> {
    let x = Fixture::new()?;
    let src = x.base.join("offline");
    private(&src)?;
    put(&src.join("index.html"), b"tested")?;
    put(&src.join("offline.zip"), b"zip")?;
    let files = json!({"index.html":{"sha256":codec::hash(b"tested"),"bytes":6},"offline.zip":{"sha256":codec::hash(b"zip"),"bytes":3}});
    let package = json!({"release":"v1","files":files});
    put(&src.join("release.json"), &codec::canonical(&package))?;
    let report =
        json!({"passed":true,"errors":[],"externalRequests":[],"release":"v1","files":files});
    let zip = json!({"passed":true,"release":"v1","zipSha256":codec::hash(b"zip")});
    put(&x.base.join("report.json"), &codec::canonical(&report))?;
    put(&x.base.join("zip.json"), &codec::canonical(&zip))?;
    offline_package(
        &src,
        &x.base.join("report.json"),
        &x.base.join("zip.json"),
        &x.base.join("reviewed"),
    )?;
    assert!(!x.base.join("reviewed/release.json").exists());
    put(&src.join("index.html"), b"changed")?;
    assert!(
        offline_package(
            &src,
            &x.base.join("report.json"),
            &x.base.join("zip.json"),
            &x.base.join("denied")
        )
        .is_err()
    );
    Ok(())
}
