//! NIC-free first installation and publication test, without a Python fixture.
use pathward_admin::{
    Result,
    codec::{self, string},
    confined,
    engine::{Engine, Environment},
    provision, publisher, require, storage as f,
    system::{Real, System, words},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const ROOT: &str = "/opt/pathward-reboot-test";
const INSTALL: &str = "/opt/pathward-initial-install";
const UNITS: &str = "/etc/systemd/system";
#[path = "support/bridge_vm.rs"]
mod bridge;
fn path(n: &str) -> PathBuf {
    Path::new(ROOT).join(n)
}
fn emit(s: &str) -> Result<()> {
    let mut f = fs::OpenOptions::new().write(true).open("/dev/ttyS0")?;
    writeln!(f, "{s}")?;
    f.flush()?;
    Ok(())
}
fn run(a: &[&str]) -> Result<String> {
    Real.checked(&words(a), 180)
}
fn put(p: &Path, b: &[u8], mode: u32) -> Result<()> {
    f::replace(p, b, mode, "fixture", &mut |_| Ok(()))
}
fn hash(p: &Path) -> Result<String> {
    Ok(codec::hash(&f::bytes(p, false)?))
}
fn record(n: &str, v: &Value) -> Result<()> {
    f::write_record(&path(n), v, "fixture", &mut |_| Ok(()))
}
fn dir(p: &Path, public: bool) -> Result<()> {
    f::directory(p)?;
    if public {
        fs::set_permissions(p, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}
fn engine() -> Engine<Real> {
    Engine {
        root: path("native"),
        env: Environment::production(),
        sys: Real,
    }
}
fn filemap(paths: &[&Path]) -> Result<Value> {
    let mut v = json!({});
    for p in paths {
        v[p.to_str().unwrap()] = hash(p)?.into();
    }
    Ok(v)
}
fn template(name: &str, text: &str) -> Result<Value> {
    let p = path(name);
    put(&p, text.as_bytes(), 0o600)?;
    Ok(json!({"path":p,"sha256":hash(&p)?}))
}
fn native(mode: &str, id: &str, extra: &[&str]) -> Result<String> {
    let mut a = words(&[
        "/usr/sbin/runuser",
        "-u",
        "nobody",
        "--",
        path("pathward-publish").to_str().unwrap(),
        mode,
        "--config",
        path("publisher.json").to_str().unwrap(),
        "--profile",
        id,
    ]);
    a.extend(extra.iter().map(|s| s.to_string()));
    Real.checked(&a, 180)
}
fn upload(id: &str, label: &str) -> Result<(PathBuf, Value)> {
    let expected = codec::parse(native("describe", id, &[])?.as_bytes())?;
    let source = path(&format!("payload-{}", publisher::nonce()?));
    dir(&source, true)?;
    put(&source.join("index.html"), label.as_bytes(), 0o644)?;
    put(
        &source.join("app.js"),
        format!("{label} asset").as_bytes(),
        0o644,
    )?;
    let tmp = path(&format!("upload-{}", publisher::nonce()?));
    let m = publisher::prepare(&source, &expected, None, &tmp, &mut |_| Ok(()))?;
    let dest = PathBuf::from(native("receive", id, &[])?.trim());
    fs::rename(&tmp, &dest)?;
    run(&[
        "/usr/bin/chown",
        "-R",
        "65534:65534",
        dest.to_str().unwrap(),
    ])?;
    Ok((dest, m))
}
fn initialize() -> Result<()> {
    for d in [
        "source",
        "source/releases",
        "source/releases/one",
        "source/releases/one/public",
        "publisher",
        "backend-base",
        "backend-base/releases",
        "backend-base/releases/one",
        "backend-base/releases/one/public",
    ] {
        dir(&path(d), true)?;
    }
    for (d, label) in [
        ("source/releases/one/public", "ONE"),
        ("backend-base/releases/one/public", "BACKEND"),
    ] {
        put(&path(d).join("index.html"), label.as_bytes(), 0o644)?;
        put(
            &path(d).join("app.js"),
            format!("{label} asset").as_bytes(),
            0o644,
        )?;
    }
    symlink("releases/one", path("source/current"))?;
    symlink("releases/one", path("backend-base/current"))?;
    for d in ["source", "publisher", "backend-base/releases/one/public"] {
        run(&[
            "/usr/bin/chown",
            "-R",
            "65534:65534",
            path(d).to_str().unwrap(),
        ])?;
    }
    let fixture = path("role_fixture");
    let oldtext = format!(
        "[Unit]\nDescription=Initial source\n[Service]\nType=exec\nUser=nobody\nExecStart={} serve SOURCE 18080\nNoNewPrivileges=yes\nPrivateTmp=yes\nTimeoutStopSec=3\n[Install]\nWantedBy=multi-user.target\n",
        fixture.display()
    );
    put(
        &Path::new(UNITS).join("test-old.service"),
        oldtext.as_bytes(),
        0o644,
    )?;
    run(&["/usr/bin/systemctl", "daemon-reload"])?;
    run(&["/usr/bin/systemctl", "enable", "--now", "test-old.service"])?;
    let policy = json!({"schema":1,"capacity":"shared-nat","sites":[
        {"id":"portal","host":"example.test","source_base":path("source"),"index":"index.html","public_paths":null,"synthetic_files":{},"directives":[]},
        {"id":"backend","host":"backend.test","source_base":null,"index":"index.html","public_paths":null,"synthetic_files":{},"directives":[["reverse-proxy","127.0.0.1:18089"]]}
    ]});
    put(&path("hosting.json"), &codec::canonical(&policy), 0o644)?;
    let mut members = json!({});
    for name in [
        "pathward-server",
        "pathward-hosting",
        "pathward-publish",
        "hosting.json",
    ] {
        members[name] = json!({"source":path(name),"sha256":hash(&path(name))?});
    }
    let server = format!("{INSTALL}/pathward-server");
    let hosting = format!("{INSTALL}/pathward-hosting");
    let policy_path = format!("{INSTALL}/hosting.json");
    let restrictions = format!(
        "NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths={INSTALL}/state {INSTALL}/receipts\nTimeoutStopSec=15\n"
    );
    let servertext = format!(
        "[Unit]\nDescription=Native prepared server\n[Service]\nType=exec\nUser=pwservice\nGroup=pwservice\nExecStart={server} serve-http {INSTALL}/state/control/.config 127.0.0.1:18081 --control-dir {INSTALL}/state/control\n{restrictions}[Install]\nWantedBy=multi-user.target\n"
    );
    let hostingtext = format!(
        "[Unit]\nDescription=Native prepared publisher\nAfter=pathward.service\nRequires=pathward.service\n[Service]\nType=exec\nUser=pwservice\nGroup=pwservice\nExecStart={hosting} reconcile --policy {policy_path} --state {INSTALL}/state/snapshots --binary {server} --control {INSTALL}/state/control --receipt {INSTALL}/receipts/receipt.json --watch\n{restrictions}[Install]\nWantedBy=multi-user.target\n"
    );
    let old = json!({"units":{"test-old.service":template("old.service",&oldtext)?},"files":filemap(&[&fixture])?,"check":[fixture,"check"],"health":[fixture,"probe","SOURCE","18080"]});
    let mut files = json!({});
    for name in [
        "pathward-server",
        "pathward-hosting",
        "pathward-publish",
        "hosting.json",
    ] {
        files[format!("{INSTALL}/{name}")] = members[name]["sha256"].clone();
    }
    for p in [Path::new("/usr/bin/curl"), fixture.as_path()] {
        files[p.to_str().unwrap()] = hash(p)?.into();
    }
    let new = json!({"units":{"pathward.service":template("server.service",&servertext)?,"pathward-hosting.service":template("hosting.service",&hostingtext)?},"files":files,"check":[fixture,"check"],"health":["/usr/bin/curl","--disable","--fail","--silent","--noproxy","*","--max-time","5","--header","Host: example.test","http://127.0.0.1:18081/"]});
    record(
        "input.json",
        &json!({"schema":1,"network":"isolated","minimum_free_bytes":134217728,"installation":INSTALL,"account":"pwservice","members":members,"contract":{"selected":"new","old":old,"new":new}}),
    )?;
    record("report.json", &json!({"boots":[],"no_python":true}))?;
    put(&path("case"), b"0", 0o600)?;
    let unit = format!(
        "[Unit]\nDescription=Initial native and publisher test\nAfter=test-old.service pathward-role-recovery.service\n[Service]\nType=oneshot\nExecStart={ROOT}/bootstrap_vm_guest\nTimeoutStartSec=600\n[Install]\nWantedBy=multi-user.target\n"
    );
    put(
        &Path::new(UNITS).join("test-bootstrap-case.service"),
        unit.as_bytes(),
        0o644,
    )?;
    run(&["/usr/bin/systemctl", "daemon-reload"])?;
    run(&[
        "/usr/bin/systemctl",
        "enable",
        "--now",
        "test-bootstrap-case.service",
    ])?;
    Ok(())
}
fn configure_publisher() -> Result<Value> {
    let text = format!(
        "[Unit]\nDescription=Unchanged backend fixture\n[Service]\nType=exec\nUser=nobody\nWorkingDirectory={ROOT}/backend-base/current\nEnvironment=PORT=18089\nExecStart={ROOT}/role_fixture files {ROOT}/backend-base/releases/one/public 18089\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n[Install]\nWantedBy=multi-user.target\n"
    );
    put(
        &Path::new(UNITS).join("backend.service"),
        text.as_bytes(),
        0o644,
    )?;
    run(&["/usr/bin/systemctl", "daemon-reload"])?;
    run(&["/usr/bin/systemctl", "enable", "--now", "backend.service"])?;
    let mut props = json!({});
    for key in [
        "WorkingDirectory",
        "Environment",
        "FragmentPath",
        "NoNewPrivileges",
        "ProtectSystem",
    ] {
        props[key] = Real.property("backend.service", key)?.into();
    }
    let uid = run(&["/usr/bin/id", "-u", "pwservice"])?
        .trim()
        .parse::<u32>()?;
    let mut config = json!({"schema":1,"hosting_policy":format!("{INSTALL}/hosting.json"),"receipt":format!("{INSTALL}/receipts/receipt.json"),"receipt_owner":uid,"profiles":{
        "portal":{"kind":"release","host":"example.test","origin":"http://127.0.0.1:18081","work":path("publisher/portal"),"checks":{},"extra_checks":[{"host":"backend.test","origin":"http://127.0.0.1:18081","path":"/","status":200}]},
        "backend":{"kind":"backend","host":"backend.test","origin":"http://127.0.0.1:18081","work":path("publisher/backend"),"checks":{},"root":path("backend-base/releases/one/public"),"release_base":path("backend-base"),"unit":"backend.service","upstream":"127.0.0.1:18089","executable":path("role_fixture"),"properties":props,"sealed_files":filemap(&[&path("role_fixture"),&Path::new(UNITS).join("backend.service")])?,"immutable_prefixes":["avatars/"],"additive_prefixes":["avatars/v6/"]}
    }});
    put(&path("publisher.json"), &codec::canonical(&config), 0o644)?;
    native("describe", "backend", &[])?;
    config["profiles"]["backend"]["executable_observation"] = "systemd".into();
    put(&path("publisher.json"), &codec::canonical(&config), 0o644)?;
    native("describe", "backend", &[])?;
    Ok(config)
}
fn cut_child() -> Result<()> {
    let config = confined::metadata(&path("publisher.json"), 0)?;
    let request = confined::metadata(&path("cut.json"), 0)?;
    publisher::apply(
        &config,
        "backend",
        Path::new(string(&request, "stage")?),
        &mut Real,
        &mut publisher::Curl,
        &mut |label| {
            if label == "asset-renamed"
                && fs::read(path("backend-base/releases/one/public/app.js"))? == b"THIRD asset"
            {
                fs::write(path("publisher/cut-ready"), b"ready")?;
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            Ok(())
        },
    )?;
    Err("cut boundary not reached".into())
}
fn cases() -> Result<()> {
    let n = fs::read_to_string(path("case"))?.parse::<u64>()?;
    let mut report = f::record(&path("report.json"))?;
    report["boots"].as_array_mut().unwrap().push(
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
    );
    record("report.json", &report)?;
    let mut e = engine();
    let until = Instant::now() + Duration::from_secs(45);
    let lock = loop {
        match e.lock() {
            Ok(l) => break l,
            Err(err) => {
                require(
                    Instant::now() < until,
                    &format!("administrator lock: {err}"),
                )?;
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };
    let input = f::record(&path("input.json"))?;
    if n == 0 {
        put(&path("case"), b"1", 0o600)?;
        provision::prepare(&mut e, &input, &path("pathward-admin"), &mut |label| {
            if label == "initial-gate:durable" {
                emit("PW_CUT_POWER initial-gate:durable")?;
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            Ok(())
        })?;
        return Err("initial cut not reached".into());
    }
    if n == 1 {
        run(&[
            path("role_fixture").to_str().unwrap(),
            "probe",
            "SOURCE",
            "18080",
        ])?;
        let before = Real.property("test-old.service", "MainPID")?;
        let id = provision::prepare(&mut e, &input, &path("pathward-admin"), &mut |_| Ok(()))?;
        require(
            before == Real.property("test-old.service", "MainPID")?,
            "prepare restarted source",
        )?;
        require(!e.gate("pathward.service")?, "prepare authorized candidate")?;
        require(
            id == provision::prepare(&mut e, &input, &path("pathward-admin"), &mut |_| Ok(()))?,
            "prepare retry changed identity",
        )?;
        e.apply(&id, &mut |_| Ok(()))?;
        drop(lock);
        let config = configure_publisher()?;
        let (stage, _) = upload("portal", "TWO")?;
        native("apply", "portal", &["--stage", stage.to_str().unwrap()])?;
        let current = fs::read_link(path("source/current"))?;
        let mut bad = config.clone();
        bad["profiles"]["portal"]["extra_checks"][0]["headers"] =
            json!({"content-type":"text/invalid"});
        put(&path("publisher.json"), &codec::canonical(&bad), 0o644)?;
        let (stage, m) = upload("portal", "BAD")?;
        require(
            native("apply", "portal", &["--stage", stage.to_str().unwrap()]).is_err(),
            "bad public response accepted",
        )?;
        require(
            fs::read_link(path("source/current"))? == current,
            "public failure did not roll back",
        )?;
        native(
            "recover",
            "portal",
            &["--operation", string(&m, "operation")?],
        )?;
        put(&path("publisher.json"), &codec::canonical(&config), 0o644)?;
        let pid = Real.property("backend.service", "MainPID")?;
        let (stage, _) = upload("backend", "NEXT")?;
        native("apply", "backend", &["--stage", stage.to_str().unwrap()])?;
        require(
            pid == Real.property("backend.service", "MainPID")?,
            "publisher restarted backend",
        )?;
        let (stage, m) = upload("backend", "THIRD")?;
        put(
            &path("cut.json"),
            &codec::canonical(&json!({"stage":stage})),
            0o644,
        )?;
        let mut child = std::process::Command::new("/usr/sbin/runuser")
            .args([
                "-u",
                "nobody",
                "--",
                path("bootstrap_vm_guest").to_str().unwrap(),
                "--cut-child",
            ])
            .spawn()?;
        let until = Instant::now() + Duration::from_secs(45);
        while !path("publisher/cut-ready").exists() {
            require(
                child.try_wait()?.is_none() && Instant::now() < until,
                "wrapper cut not reached",
            )?;
            std::thread::sleep(Duration::from_millis(100));
        }
        run(&["/usr/bin/pkill", "-KILL", "-P", &child.id().to_string()])?;
        let _ = child.kill();
        let _ = child.wait();
        native(
            "recover",
            "backend",
            &["--operation", string(&m, "operation")?],
        )?;
        require(
            fs::read(path("backend-base/releases/one/public/index.html"))? == b"NEXT"
                && fs::read(path("backend-base/releases/one/public/app.js"))? == b"NEXT asset",
            "partial backend recovery failed",
        )?;
        require(
            pid == Real.property("backend.service", "MainPID")?,
            "recovery restarted backend",
        )?;
        report["initial_power_cut_resume_no_source_restart"] = true.into();
        report["static_http_failure_rollback"] = true.into();
        report["cross_host_header_failure_rollback"] = true.into();
        report["backend_process_kill_recovery"] = true.into();
        report["native_runtime_no_python"] = true.into();
        report["proc_and_systemd_executable_observation"] = true.into();
        report["backend_current_alias_is_bound"] = true.into();
        record("report.json", &report)?;
        put(&path("case"), b"2", 0o600)?;
        emit("PW_COLD_REBOOT initial-and-publication")?;
        run(&["/usr/bin/systemctl", "reboot"])?;
        return Ok(());
    }
    drop(lock);
    require(
        e.status()?["state"]["phase"] == "committed",
        "committed native role lost on reboot",
    )?;
    require(
        fs::read(path("backend-base/releases/one/public/index.html"))? == b"NEXT",
        "published backend files lost",
    )?;
    require(
        fs::read(
            path("source")
                .join(fs::read_link(path("source/current"))?)
                .join("public/index.html"),
        )? == b"TWO",
        "static release lost",
    )?;
    report["committed_restart_preserves_publication"] = true.into();
    emit(&format!("PW_VM_RECOVERY_PASS {}", report))?;
    run(&["/usr/bin/systemctl", "poweroff"])?;
    Ok(())
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let r = if args.iter().any(|a| a == "--bridge-initialize") {
        bridge::initialize()
    } else if args.iter().any(|a| a == "--bridge-cases") {
        bridge::cases()
    } else if args.iter().any(|a| a == "--initialize") {
        initialize()
    } else if args.iter().any(|a| a == "--cut-child") {
        cut_child()
    } else {
        cases()
    };
    if let Err(e) = r {
        let _ = emit(&format!("PW_VM_FAILURE {e}"));
        for unit in [
            "test-bootstrap-case.service",
            "test-bridge-case.service",
            "pathward.service",
            "pathward-hosting.service",
            "pathward-native-hosting.service",
            "pathward-role-recovery.service",
        ] {
            if let Ok(log) = run(&[
                "/usr/bin/journalctl",
                "-b",
                "-u",
                unit,
                "--no-pager",
                "-n",
                "30",
                "-o",
                "cat",
            ]) {
                let _ = emit(&log);
            }
        }
        std::process::exit(1);
    }
}
