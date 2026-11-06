//! Cooperative legacy/native bridge switch, reverse migration and interrupted retry.
use super::*;
use pathward_admin::{bridge_rollout, publication, publication_gate};
const OLD: &str = "pathward-hosting.service";
const NEW: &str = "pathward-native-hosting.service";
const POLICY: &str = "/etc/pathward/hosting.json";
const RECEIPT: &str = "/run/pathward-hosting/receipt.json";
fn json_file(p: &Path, v: &Value) -> Result<()> {
    put(p, &codec::canonical(v), 0o644)
}
fn user(args: &[&str]) -> Result<String> {
    let mut a = words(&["/usr/sbin/runuser", "-u", "pathward", "--"]);
    a.extend(words(args));
    Real.checked(&a, 180)
}
fn service(name: &str, text: &str) -> Result<()> {
    put(&Path::new(UNITS).join(name), text.as_bytes(), 0o644)
}
fn mode() -> Result<Value> {
    codec::parse(native("mode", "site0", &[])?.as_bytes())
}
fn unchanged(before: &Value) -> Result<()> {
    for unit in ["pathward.service", "backend.service"] {
        require(
            before[unit] == Real.property(unit, "MainPID")?,
            "bridge migration restarted an application",
        )?;
    }
    Ok(())
}
fn application_ids() -> Result<Value> {
    Ok(
        json!({"pathward.service":Real.property("pathward.service","MainPID")?,"backend.service":Real.property("backend.service","MainPID")?}),
    )
}
fn ready(config: &Value, m: &str) -> Result<()> {
    bridge_rollout::health(config, m, &mut Real, Path::new(ROOT))
}
fn switch(input: &Value, m: &str) -> Result<()> {
    let mut e = engine();
    let _l = e.lock()?;
    bridge_rollout::switch(&mut e, input, m, &path("pathward-admin"), &mut |_| Ok(()))?;
    Ok(())
}
fn legacy_begin() -> Result<String> {
    run(&[
        "/usr/sbin/runuser",
        "-u",
        "nobody",
        "--",
        "/usr/bin/python3",
        "-I",
        path("legacy-reader.py").to_str().unwrap(),
        "begin",
        "site0",
    ])
}

pub fn initialize() -> Result<()> {
    run(&[
        "/usr/sbin/useradd",
        "--system",
        "--user-group",
        "--home-dir",
        ROOT,
        "--shell",
        "/usr/sbin/nologin",
        "pathward",
    ])?;
    let uid = run(&["/usr/bin/id", "-u", "pathward"])?
        .trim()
        .parse::<u32>()?;
    let gid = run(&["/usr/bin/id", "-g", "pathward"])?
        .trim()
        .parse::<u32>()?;
    dir(Path::new("/etc/pathward"), true)?;
    for d in ["legacy-state", "service", "publisher"] {
        dir(&path(d), true)?;
    }
    run(&[
        "/usr/bin/chown",
        "-R",
        "pathward:pathward",
        path("legacy-state").to_str().unwrap(),
        path("service").to_str().unwrap(),
    ])?;
    let mut policy = json!({"schema":1,"capacity":"shared-nat","sites":[]});
    let mut profiles = json!({});
    let mut locks = Vec::new();
    let mut checks = Vec::new();
    for n in 0..9 {
        let id = format!("site{n}");
        let host = format!("site{n}.example.test");
        let base = path(&id);
        for d in [
            base.clone(),
            base.join("releases"),
            base.join("releases/one"),
            base.join("releases/one/public"),
            base.join("static-work"),
        ] {
            dir(&d, true)?;
        }
        let public = base.join("releases/one/public");
        let index = if n == 1 {
            "Standalone.html"
        } else {
            "index.html"
        };
        put(&public.join(index), format!("OLD {n}").as_bytes(), 0o644)?;
        if n == 1 {
            put(&public.join("index.html"), b"ALTERNATE", 0o644)?;
        }
        let special = if n == 2 {
            Some("certificate.pem")
        } else if n == 3 {
            Some("eng.traineddata")
        } else {
            None
        };
        if let Some(name) = special {
            put(&public.join(name), b"public fixture", 0o644)?;
        }
        symlink("releases/one", base.join("current"))?;
        let lock = base.join("static-work/deploy.lock");
        put(&lock, b"", 0o600)?;
        run(&[
            "/usr/bin/chown",
            "-R",
            "65534:65534",
            base.to_str().unwrap(),
        ])?;
        let legacy = json!({"path":lock,"owner":65534});
        locks.push(legacy.clone());
        let directives = if n == 8 {
            json!([["reverse-proxy", "127.0.0.1:18089"]])
        } else {
            json!([["header", "/", "X-Content-Type-Options", "nosniff"]])
        };
        let explicit = special.map(|name| json!(["/", format!("/{index}"), format!("/{name}")]));
        policy["sites"].as_array_mut().unwrap().push(json!({"id":id,"host":host,"source_base":if n==8{Value::Null}else{json!(base)},"index":index,"public_paths":explicit.unwrap_or(Value::Null),"synthetic_files":{},"directives":directives}));
        profiles[&id] = json!({"kind":if n==8{"backend"}else{"release"},"index":index,"host":host,"origin":"http://127.0.0.1:18081","work":base.join("static-work/native"),"legacy_lock":legacy,"checks":{}});
        if let Some(name) = special {
            profiles[&id]["reviewed_assets"] = json!([name]);
        }
        checks.push(json!({"host":host,"origin":"http://127.0.0.1:18081","checks":{},"extra_checks":[{"host":host,"origin":"http://127.0.0.1:18081","path":"/","status":200}]}));
    }
    json_file(Path::new(POLICY), &policy)?;
    let mut native_policy = policy.clone();
    native_policy["schema"] = 2.into();
    for s in native_policy["sites"].as_array_mut().unwrap() {
        s["directory_indexes"] = if s["index"] == "index.html" {
            json!(["index.html", "index.txt"])
        } else {
            json!([s["index"]])
        };
    }
    json_file(&path("native-policy.json"), &native_policy)?;
    let server = path("reference-server");
    let built = codec::parse(
        user(&[
            "/usr/bin/python3",
            "-I",
            path("legacy-bridge.py").to_str().unwrap(),
            "build",
            "--policy",
            POLICY,
            "--state",
            path("legacy-state").to_str().unwrap(),
            "--binary",
            server.to_str().unwrap(),
        ])?
        .as_bytes(),
    )?;
    user(&[
        server.to_str().unwrap(),
        "init",
        path("service/control").to_str().unwrap(),
        string(&built, "candidate")?,
    ])?;
    let restrictions = format!(
        "NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateDevices=yes\nRestrictSUIDSGID=no\nReadWritePaths={ROOT}\nUMask=0077\nTimeoutStopSec=15\n"
    );
    service(
        "pathward.service",
        &format!(
            "[Unit]\nDescription=Retained HTTP server\n[Service]\nType=simple\nUser=pathward\nExecStart={} serve-http {ROOT}/service/control/.config 127.0.0.1:18081 --control-dir {ROOT}/service/control\n{restrictions}[Install]\nWantedBy=multi-user.target\n",
            server.display()
        ),
    )?;
    service(
        "backend.service",
        &format!(
            "[Unit]\nDescription=Retained backend\n[Service]\nType=exec\nUser=nobody\nWorkingDirectory={ROOT}/site8/releases/one\nExecStart={ROOT}/role_fixture files {ROOT}/site8/releases/one/public 18089\n{restrictions}[Install]\nWantedBy=multi-user.target\n"
        ),
    )?;
    let bridge_restrictions = format!(
        "{restrictions}RuntimeDirectory=pathward-hosting\nRuntimeDirectoryMode=0755\nReadWritePaths=/run/pathward-hosting\n"
    );
    let old_text = format!(
        "[Unit]\nDescription=Legacy publication bridge\nRequires=pathward.service\nAfter=pathward.service\n[Service]\nType=simple\nUser=pathward\nExecStart=/usr/bin/python3 -I {ROOT}/legacy-bridge.py reconcile --policy {POLICY} --state {ROOT}/legacy-state --binary {} --control {ROOT}/service/control --receipt {RECEIPT} --watch\n{bridge_restrictions}[Install]\nWantedBy=multi-user.target\n",
        server.display()
    );
    let new_text = format!(
        "[Unit]\nDescription=Native publication bridge\nRequires=pathward.service\nAfter=pathward.service\n[Service]\nType=simple\nUser=pathward\nExecStart={ROOT}/pathward-hosting reconcile --policy {ROOT}/native-policy.json --state {ROOT}/native-state --binary {} --control {ROOT}/service/control --receipt {RECEIPT} --watch\n{bridge_restrictions}[Install]\nWantedBy=multi-user.target\n",
        server.display()
    );
    service(OLD, &old_text)?;
    run(&["/usr/bin/systemctl", "daemon-reload"])?;
    run(&[
        "/usr/bin/systemctl",
        "enable",
        "--now",
        "pathward.service",
        "backend.service",
        OLD,
    ])?;
    let mut properties = json!({});
    for key in ["WorkingDirectory", "FragmentPath", "NoNewPrivileges"] {
        properties[key] = Real.property("backend.service", key)?.into();
    }
    let backend = &mut profiles["site8"];
    backend["properties"] = properties;
    backend["environment_sha256"] =
        codec::hash(Real.property("backend.service", "Environment")?.as_bytes()).into();
    backend["unit"] = "backend.service".into();
    backend["upstream"] = "127.0.0.1:18089".into();
    backend["root"] = json!(path("site8/releases/one/public"));
    backend["executable"] = json!(path("role_fixture"));
    backend["sealed_files"] = filemap(&[
        &path("role_fixture"),
        &Path::new(UNITS).join("backend.service"),
    ])?;
    let fence = json!({"schema":1,"lock":"/etc/pathward/publication.lock","writers":locks});
    let config = json!({"schema":1,"hosting_policy":path("native-policy.json"),"receipt":RECEIPT,"receipt_owner":uid,"profiles":profiles,"health":checks,"rollout":{"lock":fence["lock"],"legacy_unit":OLD,"native_unit":NEW,"legacy_policy_sha256":codec::hash(&publication::encoded(&policy)),"native_policy_sha256":codec::hash(&publication::encoded(&native_policy))}});
    json_file(&path("publisher.json"), &config)?;
    ready(&config, "legacy")?;
    let python = Path::new("/usr/bin/python3").canonicalize()?;
    let mut files = filemap(&[
        &server,
        &python,
        &path("legacy-bridge.py"),
        &path("pathward-hosting"),
        &path("pathward-publish"),
        &path("pathward-admin"),
        &path("role_fixture"),
        &path("publisher.json"),
        Path::new(POLICY),
        &path("native-policy.json"),
        Path::new("/usr/bin/curl"),
    ])?;
    files[engine()
        .root
        .join("publication-fence.json")
        .to_str()
        .unwrap()] = codec::hash(&codec::encode(&fence)).into();
    let old = json!({"units":{OLD:template("legacy-template.service",&old_text)?},"files":files,"executable_aliases":{"/usr/bin/python3":python},"check":[path("role_fixture"),"check"],"health":[path("pathward-admin"),"--root",engine().root,"bridge-health",path("publisher.json"),"legacy"]});
    let new = json!({"units":{NEW:template("native-template.service",&new_text)?},"files":files,"check":[path("role_fixture"),"check"],"health":[path("pathward-admin"),"--root",engine().root,"bridge-health",path("publisher.json"),"native"]});
    let input = json!({"schema":1,"publisher":path("publisher.json"),"legacy_policy":POLICY,"account":"pathward","uid":uid,"gid":gid,"deployment_uid":65534,"deployment_gid":65534,"state":path("native-state"),"hosting_binary":path("pathward-hosting"),"server_binary":server,"fence":fence,"contract":{"selected":"new","old":old,"new":new}});
    record("bridge-input.json", &input)?;
    record(
        "bridge-report.json",
        &json!({"scenario":"bridge","boots":[],"legacy_bridge_sha256":hash(&path("legacy-bridge.py"))?,"legacy_reader_sha256":hash(&path("legacy-reader.py"))?,"retained_server_sha256":hash(&server)?}),
    )?;
    put(&path("bridge-case"), b"0", 0o600)?;
    service(
        "test-bridge-case.service",
        &format!(
            "[Unit]\nDescription=Bridge rollout rehearsal\nAfter=multi-user.target pathward-role-recovery.service\n[Service]\nType=oneshot\nExecStart={ROOT}/bootstrap_vm_guest --bridge-cases\nTimeoutStartSec=1200\n[Install]\nWantedBy=multi-user.target\n"
        ),
    )?;
    run(&["/usr/bin/systemctl", "daemon-reload"])?;
    run(&[
        "/usr/bin/systemctl",
        "enable",
        "--now",
        "--no-block",
        "test-bridge-case.service",
    ])?;
    Ok(())
}

fn stage(id: &str, label: &str) -> Result<PathBuf> {
    let expected = codec::parse(native("describe", id, &[])?.as_bytes())?;
    let src = path(&format!("payload-{}", publisher::nonce()?));
    dir(&src, true)?;
    put(
        &src.join(string(&expected, "index")?),
        label.as_bytes(),
        0o644,
    )?;
    if let Some(a) = expected["reviewed_assets"].as_array() {
        for name in a {
            put(&src.join(name.as_str().unwrap()), b"public fixture", 0o644)?;
        }
    }
    let temp = path(&format!("upload-{}", publisher::nonce()?));
    publisher::prepare(&src, &expected, None, &temp, &mut |_| Ok(()))?;
    let dest = PathBuf::from(native("receive", id, &[])?.trim());
    fs::rename(temp, &dest)?;
    run(&[
        "/usr/bin/chown",
        "-R",
        "65534:65534",
        dest.to_str().unwrap(),
    ])?;
    Ok(dest)
}
pub fn cases() -> Result<()> {
    let n = fs::read_to_string(path("bridge-case"))?.parse::<u32>()?;
    let input = f::record(&path("bridge-input.json"))?;
    let config = confined::metadata(&path("publisher.json"), 0)?;
    let mut report = f::record(&path("bridge-report.json"))?;
    report["boots"]
        .as_array_mut()
        .unwrap()
        .push(publication::clock()?["boot"].clone());
    if n == 0 {
        let before = application_ids()?;
        let mut e = engine();
        {
            let _l = e.lock()?;
            bridge_rollout::prepare(&mut e, &input, &path("pathward-admin"), &mut |_| Ok(()))?;
        }
        unchanged(&before)?;
        require(mode()?["mode"] == "legacy", "preparation switched bridge")?;
        legacy_begin()?;
        require(
            native("describe", "site0", &[]).is_err(),
            "native publication accepted legacy bridge",
        )?;
        {
            let _lease = publication_gate::publisher(&config, None)?;
            require(
                e.lock().is_err(),
                "administrator ignored active publication",
            )?;
        }
        {
            let file = fs::File::open(path("site0/static-work/deploy.lock"))?;
            file.try_lock()?;
            require(e.lock().is_err(), "administrator ignored legacy writer")?;
        }
        let mut bad = input.clone();
        bad["contract"]["new"]["health"] = json!([path("role_fixture"), "probe", "FAIL", "18081"]);
        require(switch(&bad, "native").is_err(), "failed health accepted")?;
        ready(&config, "legacy")?;
        unchanged(&before)?;
        switch(&input, "native")?;
        ready(&config, "native")?;
        unchanged(&before)?;
        require(
            legacy_begin().is_err(),
            "legacy reader accepted native policy",
        )?;
        for i in 0..9 {
            let id = format!("site{i}");
            let stage = stage(&id, &format!("NATIVE {i}"))?;
            native("apply", &id, &["--stage", stage.to_str().unwrap()])?;
        }
        let stale = stage("site0", "STALE")?;
        record("stale-stage.json", &json!({"stage":stale}))?;
        unchanged(&before)?;
        switch(&input, "legacy")?;
        ready(&config, "legacy")?;
        legacy_begin()?;
        unchanged(&before)?;
        report["nine_hosts_native_publication_and_legacy_rollback"] = true.into();
        report["old_reader_rejects_native_policy"] = true.into();
        report["coordinated_native_and_legacy_locks"] = true.into();
        report["failed_candidate_health_restores_legacy"] = true.into();
        report["application_pids_unchanged"] = true.into();
        record("bridge-report.json", &report)?;
        put(&path("bridge-case"), b"1", 0o600)?;
        let mut e = engine();
        let _l = e.lock()?;
        bridge_rollout::switch(
            &mut e,
            &input,
            "native",
            &path("pathward-admin"),
            &mut |label| {
                if label == "unit-pathward-native-hosting.service:durable" {
                    emit("PW_CUT_POWER bridge-partial-unit")?;
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                Ok(())
            },
        )?;
        return Err("power cut was not reached".into());
    }
    ready(&config, "legacy")?;
    require(
        mode()?["mode"] == "legacy",
        "reboot lost safe legacy selection",
    )?;
    legacy_begin()?;
    let before = application_ids()?;
    switch(&input, "native")?;
    ready(&config, "native")?;
    let stale = f::record(&path("stale-stage.json"))?;
    require(
        native("apply", "site0", &["--stage", string(&stale, "stage")?]).is_err(),
        "old upload revived after bridge switch",
    )?;
    unchanged(&before)?;
    if n == 1 {
        report["partial_switch_power_cut_recovered_and_retried"] = true.into();
        switch(&input, "legacy")?;
        ready(&config, "legacy")?;
        unchanged(&before)?;
        record("bridge-report.json", &report)?;
        put(&path("bridge-case"), b"2", 0o600)?;
        emit("PW_COLD_REBOOT durable-legacy-rollback")?;
        run(&["/usr/bin/systemctl", "reboot"])?;
        return Ok(());
    }
    report["rollback_survives_reboot"] = true.into();
    report["stale_upload_never_revived"] = true.into();
    report["final_native_health"] = true.into();
    emit(&format!("PW_VM_RECOVERY_PASS {report}"))?;
    run(&["/usr/bin/systemctl", "poweroff"])?;
    Ok(())
}
