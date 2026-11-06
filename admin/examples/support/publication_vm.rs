//! Publication and collection assertions under real, disposable PID 1.
use super::*;
use pathward_admin::publication;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::{PermissionsExt, symlink};

const BASE: &str = "/var/lib/pathward-publication-test";
const HOSTING: &str = "/usr/local/bin/pathward-hosting-fixture";
const SERVER: &str = "/usr/local/bin/pathward-server-fixture";
const POLICY: &str = "/etc/pathward-publication-test.json";
const RECEIPT: &str = "/run/pathward-publication-test/receipt.json";
fn b(s: &str) -> PathBuf {
    Path::new(BASE).join(s)
}
fn http(path: &str) -> Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", 18081))?;
    s.set_read_timeout(Some(Duration::from_secs(4)))?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
    )?;
    let mut out = String::new();
    s.take(1 << 20).read_to_string(&mut out)?;
    Ok(out)
}
fn ready(body: &str) -> Result<()> {
    let until = std::time::Instant::now() + Duration::from_secs(45);
    loop {
        if http("/").is_ok_and(|s| s.ends_with(body)) {
            return Ok(());
        }
        require(
            std::time::Instant::now() < until,
            "publication HTTP readiness",
        )?;
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn release(name: &str, body: &str) -> Result<()> {
    for path in [
        b(&format!("source/releases/{name}")),
        b(&format!("source/releases/{name}/public")),
        b(&format!("source/releases/{name}/public/docs")),
    ] {
        f::directory(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    }
    let dir = b(&format!("source/releases/{name}/public"));
    for (n, t) in [
        ("index.html", body),
        ("docs/index.html", "documentation"),
        ("secret.txt", "NEVER PUBLIC"),
    ] {
        file(&dir.join(n), t, 0o644)?;
    }
    file(
        &b(&format!("{name}.manifest")),
        &format!(
            "{}  public/index.html\n{}  public/docs/index.html\n{}  public/secret.txt\n",
            codec::hash(body.as_bytes()),
            codec::hash(b"documentation"),
            codec::hash(b"NEVER PUBLIC")
        ),
        0o600,
    )
}
fn native(mode: &str, extra: &[&str]) -> Result<String> {
    let mut a = words(&[
        HOSTING,
        mode,
        "--policy",
        POLICY,
        "--receipt",
        RECEIPT,
        "--receipt-owner",
        "65534",
        "--profile",
        "portal",
    ]);
    a.extend(extra.iter().map(|s| s.to_string()));
    Real.checked(&a, 180)
}
fn setup_publication() -> Result<()> {
    for (name, source) in [(HOSTING, "pathward-hosting"), (SERVER, "pathward-server")] {
        f::replace(
            Path::new(name),
            &f::bytes(&p(source), false)?,
            0o755,
            "fixture",
            &mut |_| Ok(()),
        )?;
    }
    for path in [PathBuf::from(BASE), b("source"), b("source/releases")] {
        f::directory(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    }
    for path in [
        b("state"),
        b("control"),
        PathBuf::from("/run/pathward-publication-test"),
    ] {
        f::directory(&path)?;
        command(&["/usr/bin/chown", "65534:65534", path.to_str().unwrap()])?;
    }
    fs::set_permissions(
        "/run/pathward-publication-test",
        fs::Permissions::from_mode(0o755),
    )?;
    release("one", "ONE")?;
    release("two", "TWO")?;
    symlink("releases/one", b("source/current"))?;
    let value = json!({"schema":1,"capacity":"shared-nat","sites":[{"id":"portal","host":"example.test","source_base":b("source"),"index":"index.html","directory_indexes":["index.html"],"public_paths":["/","/docs/index.html"],"synthetic_files":{"robots.txt":"User-agent: *\n"},"directives":[]}]});
    file(
        Path::new(POLICY),
        std::str::from_utf8(&publication::encoded(&value))?,
        0o644,
    )?;
    let built = command(&[
        "/usr/sbin/runuser",
        "-u",
        "nobody",
        "--",
        HOSTING,
        "build",
        "--policy",
        POLICY,
        "--state",
        b("state").to_str().unwrap(),
        "--binary",
        SERVER,
    ])?;
    let built = codec::parse(built.as_bytes())?;
    command(&[
        "/usr/sbin/runuser",
        "-u",
        "nobody",
        "--",
        SERVER,
        "init",
        b("control").to_str().unwrap(),
        codec::string(&built, "candidate")?,
    ])?;
    file(
        &Path::new(UNITS).join("pathward.service"),
        &format!(
            "[Unit]\nDescription=Isolated publication HTTP server\n[Service]\nType=simple\nUser=nobody\nGroup=nogroup\nExecStart={SERVER} serve-http {BASE}/control/.config 127.0.0.1:18081 --control-dir {BASE}/control\nNoNewPrivileges=yes\nProtectSystem=strict\nReadWritePaths={BASE}\n[Install]\nWantedBy=multi-user.target\n"
        ),
        0o644,
    )?;
    file(
        &Path::new(UNITS).join("pathward-hosting.service"),
        &format!(
            "[Unit]\nDescription=Isolated native publication bridge\nAfter=pathward.service\nRequires=pathward.service\n[Service]\nType=simple\nUser=nobody\nGroup=nogroup\nExecStart={HOSTING} reconcile --policy {POLICY} --state {BASE}/state --binary {SERVER} --control {BASE}/control --receipt {RECEIPT} --watch\nRuntimeDirectory=pathward-publication-test\nRuntimeDirectoryMode=0755\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nReadWritePaths={BASE} /run/pathward-publication-test\n[Install]\nWantedBy=multi-user.target\n"
        ),
        0o644,
    )?;
    command(&["/usr/bin/systemctl", "daemon-reload"])?;
    command(&[
        "/usr/bin/systemctl",
        "enable",
        "--now",
        "pathward.service",
        "pathward-hosting.service",
    ])?;
    ready("ONE")?;
    let until = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if native("begin", &[]).is_ok() {
            break;
        }
        require(
            std::time::Instant::now() < until,
            "initial publication receipt",
        )?;
        std::thread::sleep(Duration::from_millis(100));
    }
    let stamp = native("begin", &[])?;
    file(&p("old-publication-stamp"), stamp.trim(), 0o600)?;
    let result = native(
        "publish",
        &[
            "--expect",
            "releases/one",
            "--reference",
            "releases/two",
            "--manifest",
            b("two.manifest").to_str().unwrap(),
        ],
    )?;
    require(
        result.contains("PUBLICATION_ACKNOWLEDGED"),
        "native publish acknowledgement",
    )?;
    ready("TWO")?;
    require(
        http("/secret.txt")?.starts_with("HTTP/1.1 404"),
        "private file leaked",
    )?;
    require(
        http("/docs/index.html")?.ends_with("documentation"),
        "explicit nested URL failed",
    )?;
    let r = pathward_admin::confined::metadata(Path::new(RECEIPT), 65534)?;
    let files = publication::selected_files(
        &value,
        "portal",
        &publication::public_manifest(&b("two.manifest"))?,
    )?;
    let mut wrong = codec::parse(stamp.trim().as_bytes())?;
    wrong["boot"] = json!("old-boot");
    require(
        !publication::acknowledged(
            &r,
            "portal",
            "releases/two",
            &files,
            &wrong,
            &publication::clock()?,
        )?,
        "old boot receipt accepted",
    )?;
    require(
        native(
            "publish",
            &[
                "--expect",
                "releases/one",
                "--reference",
                "releases/two",
                "--manifest",
                b("two.manifest").to_str().unwrap(),
            ],
        )
        .is_err(),
        "stale publisher accepted",
    )?;
    release("three", "THREE")?;
    fs::remove_file(b("source/releases/three/public/index.html"))?;
    symlink("/etc/passwd", b("source/releases/three/public/index.html"))?;
    require(
        native(
            "publish",
            &[
                "--expect",
                "releases/two",
                "--reference",
                "releases/three",
                "--manifest",
                b("three.manifest").to_str().unwrap(),
            ],
        )
        .is_err(),
        "linked ready release accepted",
    )?;
    ready("TWO")?;
    // A bind mount on the same filesystem is not caught by st_dev comparison.
    let mounted = b("source/releases/three/public/mounted");
    f::directory(&mounted)?;
    command(&[
        "/usr/bin/mount",
        "--bind",
        b("source/releases/one/public").to_str().unwrap(),
        mounted.to_str().unwrap(),
    ])?;
    let root = pathward_admin::confined::absolute(&b("source/releases/three/public"))?;
    let denied = pathward_admin::confined::child(&root, "mounted").is_err();
    command(&["/usr/bin/umount", mounted.to_str().unwrap()])?;
    require(denied, "same-device bind mount accepted")?;
    Ok(())
}
fn add_legacy_retired() -> Result<String> {
    let active = fs::read_link(p("legacy/current"))?;
    let mut old = f::record(&p("legacy").join(active).join("manifest.json"))?;
    old["epoch"] = json!(0);
    old["parent"] = json!("");
    let id = codec::hash(&codec::canonical(&old));
    let dir = p("legacy/generations").join(&id);
    f::directory(&dir)?;
    f::write_record(
        &dir.join("manifest.json"),
        &old,
        "legacy fixture",
        &mut |_| Ok(()),
    )?;
    for (n, t) in old["units"].as_object().ok_or("units")? {
        let path = dir.join(n);
        if path.parent() != Some(&dir) {
            f::directory(path.parent().unwrap())?;
        }
        file(&path, t.as_str().unwrap(), 0o644)?;
    }
    Ok(id)
}
pub fn run() -> Result<()> {
    let case = fs::read_to_string(p("case"))?.parse::<u64>()?;
    let mut report = f::record(&p("report.json"))?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    require(
        !report["boots"].as_array().unwrap().contains(&json!(boot)),
        "boot did not change",
    )?;
    report["boots"].as_array_mut().unwrap().push(boot.into());
    emit(&format!("PW_BOOT_CHECKED {case} PUBLICATION_RETENTION"))?;
    if case == 0 {
        probe("SOURCE")?;
        setup_publication()?;
        report["native_publication_http_private_files_stale_requests_links"] = true.into();
        let legacy = add_legacy_retired()?;
        file(&p("retired-legacy"), &legacy, 0o600)?;
        let mut e = engine();
        let _lock = settled_lock(&e)?;
        let mut input = f::record(&p("input.json"))?;
        let mut ids = Vec::new();
        for _ in 0..3 {
            let id = e.prepare(&input, &p("pathward-admin"), &mut |_| Ok(()))?;
            e.apply(&id, &mut |_| Ok(()))?;
            input["source_current"] = id.clone().into();
            ids.push(id);
        }
        let prepared = e.prepare(&input, &p("pathward-admin"), &mut |_| Ok(()))?;
        save(
            "retention-ids.json",
            &json!({"applied":ids,"prepared":prepared}),
        )?;
        e.observe_collection(&mut |_| Ok(()))?;
        require(
            e.plan_collection(&[], &mut |_| Ok(())).is_err(),
            "same boot collection accepted",
        )?;
        record_next(&report, 1)?;
        drop(_lock);
        emit("PW_COLD_REBOOT 0")?;
        command(&["/usr/bin/systemctl", "reboot"])?;
        return Ok(());
    }
    probe("TARGET")?;
    ready("TWO")?;
    let mut e = engine();
    let _lock = settled_lock(&e)?;
    let request = if case == 1 {
        let id = e.plan_collection(&[], &mut |_| Ok(()))?;
        file(&p("collection-request"), &id, 0o600)?;
        id
    } else {
        fs::read_to_string(p("collection-request"))?
    };
    if case <= 3 {
        let points = [
            "collection:moved",
            "collection:unlinked",
            "collection-complete:partial",
        ];
        record_next(&report, case + 1)?;
        e.apply_collection(&request, &mut cut(points[(case - 1) as usize]))?;
        return Err("collection cut point absent".into());
    }
    require(
        e.apply_collection(&request, &mut |_| Ok(()))? == 2,
        "retired native and legacy collection count",
    )?;
    let ids = f::record(&p("retention-ids.json"))?;
    let applied = ids["applied"].as_array().ok_or("ids")?;
    require(
        !e.root
            .join("transactions")
            .join(applied[0].as_str().unwrap())
            .exists(),
        "old native transaction survived",
    )?;
    require(
        !p("legacy/generations")
            .join(fs::read_to_string(p("retired-legacy"))?)
            .exists(),
        "old legacy generation survived",
    )?;
    for id in [
        applied[1].as_str().unwrap(),
        applied[2].as_str().unwrap(),
        ids["prepared"].as_str().unwrap(),
    ] {
        e.plan(id)?;
    }
    require(
        p("legacy-plan.json").exists() && p("pathward_recovery.py").exists(),
        "external recovery material deleted",
    )?;
    require(
        e.apply_collection(&request, &mut |_| Ok(()))? == 2,
        "collection retry",
    )?;
    report["native_and_legacy_collection_after_reboot"] = true.into();
    report["three_hard_cuts_retry_preserves_current_parent_prepared"] = true.into();
    report["native_runtime_no_python"] = true.into();
    report["admin_sha256"] = digest(&p("pathward-admin"))?.into();
    report["hosting_sha256"] = digest(&p("pathward-hosting"))?.into();
    report["versions"] = json!({"systemd":command(&["/usr/bin/systemd","--version"])?.lines().next(),"kernel":command(&["/usr/bin/uname","-r"])?.trim()});
    save("report.json", &report)?;
    drop(_lock);
    emit(&format!(
        "PW_VM_RECOVERY_PASS {}",
        serde_json::to_string(&report)?
    ))?;
    command(&["/usr/bin/systemctl", "poweroff"])?;
    Ok(())
}
