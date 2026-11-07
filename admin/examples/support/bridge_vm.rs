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
    let (ok, out) = Real.run(&a, 180)?;
    require(ok, &format!("fixture service command {args:?}: {out}"))?;
    Ok(out)
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

/// Replay reviewed route and filename metadata with synthetic public bytes.
/// This checks policy compatibility without copying private application state.
fn replay(uid: u32) -> Result<Value> {
    if !path("replay-policy.json").exists() {
        return Ok(Value::Null);
    }
    let mut policy = confined::metadata(&path("replay-policy.json"), 0)?;
    let inventory = confined::metadata(&path("replay-inventory.json"), 0)?;
    publication::validate(&policy)?;
    dir(&path("replay"), true)?;
    let mut count = 0usize;
    for site in policy["sites"].as_array_mut().ok_or("replay sites")? {
        if site["source_base"].is_null() {
            continue;
        }
        let id = string(site, "id")?.to_owned();
        require(
            confined::relative(&id) && !id.contains('/'),
            "replay site id",
        )?;
        let base = path("replay").join(&id);
        for d in [
            &base,
            &base.join("releases"),
            &base.join("releases/one"),
            &base.join("releases/one/public"),
        ] {
            dir(d, true)?;
        }
        for name in inventory["sources"][&id]["files"]
            .as_array()
            .ok_or("replay inventory")?
        {
            let name = name.as_str().ok_or("replay filename")?;
            require(
                confined::relative(name) || name == ".nojekyll",
                "replay path",
            )?;
            let file = base.join("releases/one/public").join(name);
            let mut parent = base.join("releases/one/public");
            for part in Path::new(name).parent().unwrap().components() {
                parent.push(part);
                dir(&parent, true)?;
            }
            put(
                &file,
                format!("reviewed public path {name}\n").as_bytes(),
                0o644,
            )?;
            count += 1;
        }
        symlink("releases/one", base.join("current"))?;
        site["source_base"] = json!(base);
    }
    json_file(&path("replay/old.json"), &policy)?;
    let mut native = policy.clone();
    native["schema"] = 2.into();
    for site in native["sites"].as_array_mut().unwrap() {
        site["directory_indexes"] = if site["index"] == "index.html" {
            json!(["index.html", "index.txt"])
        } else {
            json!([site["index"]])
        };
    }
    json_file(&path("replay/new.json"), &native)?;
    let mut configurations = Vec::new();
    let mut snapshots = Vec::new();
    for (label, program) in [
        (
            "old",
            words(&[
                "/usr/bin/python3",
                "-I",
                path("legacy-bridge.py").to_str().unwrap(),
            ]),
        ),
        ("new", words(&[path("pathward-hosting").to_str().unwrap()])),
    ] {
        let state = path("replay").join(format!("{label}-state"));
        dir(&state, false)?;
        run(&[
            "/usr/bin/chown",
            "pathward:pathward",
            state.to_str().unwrap(),
        ])?;
        let mut a = program;
        a.extend(words(&[
            "build",
            "--policy",
            path(&format!("replay/{label}.json")).to_str().unwrap(),
            "--state",
            state.to_str().unwrap(),
            "--binary",
            path("reference-server").to_str().unwrap(),
        ]));
        let built =
            codec::parse(user(&a.iter().map(String::as_str).collect::<Vec<_>>())?.as_bytes())?;
        let text = fs::read_to_string(string(&built, "candidate")?)?;
        configurations.push(
            text.lines()
                .filter(|l| !l.trim_start().starts_with("root "))
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        );
        let mut manifests = json!({});
        for entry in fs::read_dir(state.join("snapshots"))? {
            let mut m = confined::metadata(&entry?.path().join("manifest.json"), uid)?;
            let host = string(&m, "host")?.to_owned();
            m.as_object_mut().unwrap().remove("key");
            manifests[host] = m;
        }
        snapshots.push(manifests);
    }
    require(
        configurations[0] == configurations[1],
        "replayed routes differ",
    )?;
    require(
        snapshots[0] == snapshots[1],
        "replayed publication maps differ",
    )?;
    emit("PW_BRIDGE_STAGE reviewed route and filename replay passed")?;
    Ok(
        json!({"hosts":policy["sites"].as_array().unwrap().len(),"source_files":count,"same_routes":true,"same_publication_maps":true,"synthetic_content":true}),
    )
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
    let replay = replay(uid)?;
    dir(Path::new("/etc/pathward"), true)?;
    for d in ["legacy-state", "service", "publisher"] {
        dir(&path(d), d == "publisher")?;
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
        if n == 8 && path("candidate-publisher").exists() {
            for name in ["licenses", "licenses/server", "licenses/server/dependency"] {
                dir(&public.join(name), true)?;
            }
            put(
                &public.join("licenses/server/dependency/LICENSE.txt"),
                b"Reviewed license notice",
                0o644,
            )?;
        }
        symlink("releases/one", base.join("current"))?;
        let lock = base.join("static-work/deploy.lock");
        put(&lock, b"", 0o600)?;
        if n != 7 {
            run(&[
                "/usr/bin/chown",
                "-R",
                "65534:65534",
                base.to_str().unwrap(),
            ])?;
        }
        let legacy = json!({"path":lock,"owner":if n==7{0}else{65534}});
        locks.push(legacy.clone());
        let directives = if n == 8 {
            json!([["reverse-proxy", "127.0.0.1:18089"]])
        } else {
            json!([["header", "/", "x-frame-options", "DENY"]])
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
    emit("PW_BRIDGE_STAGE legacy snapshot build")?;
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
    if path("candidate-publisher").exists() {
        // A reviewed user service normally lives below a private component.
        // Keep real backend observations and add the same resource location
        // to its pinned metadata so the retained CLI reproduces the refusal.
        for name in [".config", ".config/systemd", ".config/systemd/user"] {
            dir(&path(name), true)?;
        }
        let resource = path(".config/systemd/user/backend.service");
        put(
            &resource,
            &fs::read(Path::new(UNITS).join("backend.service"))?,
            0o644,
        )?;
        backend["sealed_files"][resource.to_str().unwrap()] = hash(&resource)?.into();
    }
    let fence = json!({"schema":1,"lock":"/etc/pathward/publication.lock","writers":locks});
    let mut manual = profiles.as_object_mut().unwrap().remove("site7").unwrap();
    manual["work"] = json!(engine().root);
    let config = json!({"schema":1,"hosting_policy":path("native-policy.json"),"receipt":RECEIPT,"receipt_owner":uid,"profiles":profiles,"manual_profiles":{"site7":manual},"health":checks,"rollout":{"lock":fence["lock"],"legacy_unit":OLD,"native_unit":NEW,"legacy_policy_sha256":codec::hash(&publication::encoded(&policy)),"native_policy_sha256":codec::hash(&publication::encoded(&native_policy))}});
    json_file(&path("publisher.json"), &config)?;
    ready(&config, "legacy")?;
    emit("PW_BRIDGE_STAGE legacy ready on nine hosts")?;
    let python = Path::new("/usr/bin/python3").canonicalize()?;
    // Live service definitions are checked by a sealed validator input, never
    // used as immutable role resources that the migration engine may replace.
    let retained = Path::new(UNITS).join("pathward.service");
    let retained_manifest = path("retained-units.sha256");
    put(
        &retained_manifest,
        format!("{}  {}\n", hash(&retained)?, retained.display()).as_bytes(),
        0o600,
    )?;
    let check = json!([
        "/usr/bin/sha256sum",
        "--strict",
        "--check",
        retained_manifest
    ]);
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
        Path::new("/usr/bin/sha256sum"),
        &retained_manifest,
    ])?;
    files[engine()
        .root
        .join("publication-fence.json")
        .to_str()
        .unwrap()] = codec::hash(&codec::encode(&fence)).into();
    let old = json!({"units":{OLD:template("legacy-template.service",&old_text)?},"files":files,"executable_aliases":{"/usr/bin/python3":python},"check":check,"health":[path("pathward-admin"),"--root",engine().root,"bridge-health",path("publisher.json"),"legacy"]});
    let new = json!({"units":{NEW:template("native-template.service",&new_text)?},"files":files,"check":check,"health":[path("pathward-admin"),"--root",engine().root,"bridge-health",path("publisher.json"),"native"]});
    let input = json!({"schema":1,"minimum_free_bytes":134217728,"publisher":path("publisher.json"),"legacy_policy":POLICY,"account":"pathward","uid":uid,"gid":gid,"deployment_uid":65534,"deployment_gid":65534,"state":path("native-state"),"hosting_binary":path("pathward-hosting"),"server_binary":server,"fence":fence,"contract":{"selected":"new","old":old,"new":new}});
    record("bridge-input.json", &input)?;
    record(
        "bridge-report.json",
        &json!({"scenario":"bridge","boots":[],"policy_replay":replay,"legacy_bridge_sha256":hash(&path("legacy-bridge.py"))?,"legacy_reader_sha256":hash(&path("legacy-reader.py"))?,"retained_server_sha256":hash(&server)?}),
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
    let mut input = f::record(&path("bridge-input.json"))?;
    let config = confined::metadata(&path("publisher.json"), 0)?;
    let mut report = f::record(&path("bridge-report.json"))?;
    report["boots"]
        .as_array_mut()
        .unwrap()
        .push(publication::clock()?["boot"].clone());
    if n == 0 {
        use std::os::unix::fs::MetadataExt;
        let before = application_ids()?;
        let bridge_before = Real.property(OLD, "MainPID")?;
        let mut e = engine();
        let retained = Path::new(UNITS).join("pathward.service");
        let mut invalid = input.clone();
        for side in ["old", "new"] {
            invalid["contract"][side]["files"][retained.to_str().unwrap()] =
                hash(&retained)?.into();
        }
        {
            let _l = e.lock()?;
            let err =
                bridge_rollout::prepare(&mut e, &invalid, &path("pathward-admin"), &mut |_| Ok(()))
                    .expect_err("live unit resource accepted");
            require(
                err.to_string() == "live unit files cannot be sealed resources",
                &format!("unexpected preparation failure: {err}"),
            )?;
        }
        require(
            e.current()?.is_none(),
            "failed preparation selected a request",
        )?;
        require(
            path("native-state").is_dir(),
            "partial preparation not exercised",
        )?;
        let fence = Path::new("/etc/pathward/publication.lock");
        let fence_inode = fs::metadata(fence)?.ino();
        require(
            Real.property(OLD, "MainPID")? == bridge_before,
            "failed preparation restarted legacy bridge",
        )?;
        unchanged(&before)?;
        ready(&config, "legacy")?;
        emit("PW_BRIDGE_STAGE live unit resource rejected after partial preparation")?;
        {
            let _l = e.lock()?;
            bridge_rollout::prepare(&mut e, &input, &path("pathward-admin"), &mut |_| Ok(()))?;
        }
        unchanged(&before)?;
        require(
            fs::metadata(fence)?.ino() == fence_inode,
            "retry replaced publication lock",
        )?;
        require(
            Real.property(OLD, "MainPID")? == bridge_before,
            "retry restarted legacy bridge",
        )?;
        report["rejected_live_resource_retry_same_store_and_fence"] = true.into();
        emit("PW_BRIDGE_STAGE preparation retained application processes")?;
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
        let retained_bytes = fs::read(&retained)?;
        let current = e.current()?;
        let mut drift = retained_bytes.clone();
        drift.extend_from_slice(b"\n# Unexpected retained service drift\n");
        put(&retained, &drift, 0o644)?;
        let refused = switch(&input, "native");
        put(&retained, &retained_bytes, 0o644)?;
        require(
            refused.is_err_and(|e| e.to_string() == "configuration validation failed"),
            "retained service drift did not fail closed",
        )?;
        require(
            e.current()? == current,
            "retained drift selected another request",
        )?;
        require(
            Real.property(OLD, "MainPID")? == bridge_before,
            "retained drift restarted bridge",
        )?;
        unchanged(&before)?;
        ready(&config, "legacy")?;
        report["retained_service_drift_rejected_before_switch"] = true.into();
        emit("PW_BRIDGE_STAGE retained service drift rejected before switch")?;
        let mut bad = input.clone();
        bad["contract"]["new"]["health"] = json!([path("role_fixture"), "probe", "FAIL", "18081"]);
        require(switch(&bad, "native").is_err(), "failed health accepted")?;
        ready(&config, "legacy")?;
        unchanged(&before)?;
        switch(&input, "native")?;
        ready(&config, "native")?;
        emit("PW_BRIDGE_STAGE native bridge ready")?;
        unchanged(&before)?;
        require(
            legacy_begin().is_err(),
            "legacy reader accepted native policy",
        )?;
        if path("candidate-publisher").exists() {
            // The production command helper deliberately hides stderr. Capture
            // this fixture's known diagnostic without changing that behavior.
            let (accepted, error) = Real.run(
                &words(&[
                    "/bin/sh",
                    "-c",
                    "exec \"$@\" 2>&1",
                    "publisher-refusal",
                    "/usr/sbin/runuser",
                    "-u",
                    "nobody",
                    "--",
                    path("pathward-publish").to_str().unwrap(),
                    "describe",
                    "--config",
                    path("publisher.json").to_str().unwrap(),
                    "--profile",
                    "site8",
                ]),
                180,
            )?;
            require(
                !accepted && error.contains("noncanonical source"),
                &format!("unexpected authority refusal: {error}"),
            )?;
            let old_hash = hash(&path("pathward-publish"))?;
            let staged = stage("site0", "BEFORE PUBLISHER UPGRADE")?;
            for side in ["old", "new"] {
                input["contract"][side]["files"][path("candidate-publisher").to_str().unwrap()] =
                    hash(&path("candidate-publisher"))?.into();
            }
            let upgrade = path("publisher-upgrade-input.json");
            put(&upgrade, &codec::canonical(&input), 0o600)?;
            // Exercise the retained, already-installed administrator itself.
            run(&[
                path("pathward-admin").to_str().unwrap(),
                "--root",
                engine().root.to_str().unwrap(),
                "bridge-native",
                upgrade.to_str().unwrap(),
                &hash(&upgrade)?,
            ])?;
            put(&path("use-candidate-publisher"), b"1", 0o600)?;
            record("bridge-input.json", &input)?;
            require(
                hash(&path("pathward-publish"))? == old_hash,
                "publisher upgrade overwrote sealed legacy binary",
            )?;
            let description = codec::parse(native("describe", "site8", &[])?.as_bytes())?;
            require(
                description["files"]["licenses/server/dependency/LICENSE.txt"].is_string(),
                "text license was not accepted",
            )?;
            require(
                native("apply", "site0", &["--stage", staged.to_str().unwrap()]).is_err(),
                "publisher migration revived a stale upload",
            )?;
            unchanged(&before)?;
            report["private_authority_verified_without_publication_permission"] = true.into();
            report["versioned_publisher_bound_by_retained_administrator"] = true.into();
            report["server_license_text_accepted"] = true.into();
            emit("PW_BRIDGE_STAGE private authority publisher upgrade passed")?;
        }
        for i in 0..9 {
            let id = format!("site{i}");
            if i == 7 {
                require(
                    native("describe", &id, &[]).is_err(),
                    "administrator site delegated to unprivileged publisher",
                )?;
                let dest = path("site7/releases/two");
                dir(&dest, true)?;
                dir(&dest.join("public"), true)?;
                put(&dest.join("public/index.html"), b"NATIVE 7", 0o644)?;
                let manifest = path("manual-manifest.txt");
                put(
                    &manifest,
                    format!("{}  public/index.html\n", codec::hash(b"NATIVE 7")).as_bytes(),
                    0o600,
                )?;
                run(&[
                    path("pathward-admin").to_str().unwrap(),
                    "--root",
                    engine().root.to_str().unwrap(),
                    "manual-publish",
                    path("publisher.json").to_str().unwrap(),
                    &id,
                    "releases/one",
                    "releases/two",
                    manifest.to_str().unwrap(),
                    &hash(&manifest)?,
                ])?;
                continue;
            }
            let stage = stage(&id, &format!("NATIVE {i}"))?;
            native("apply", &id, &["--stage", stage.to_str().unwrap()])?;
            emit(&format!("PW_BRIDGE_STAGE publication {id}"))?;
        }
        let stale = stage("site0", "STALE")?;
        record("stale-stage.json", &json!({"stage":stale}))?;
        unchanged(&before)?;
        switch(&input, "legacy")?;
        ready(&config, "legacy")?;
        legacy_begin()?;
        unchanged(&before)?;
        report["nine_hosts_native_publication_and_legacy_rollback"] = true.into();
        report["administrator_owned_site_not_delegated"] = true.into();
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
