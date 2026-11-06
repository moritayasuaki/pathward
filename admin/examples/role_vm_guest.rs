//! Real PID 1 and persistent filesystem assertions. No Python in this driver.
use pathward_admin::{
    Result, codec,
    engine::{Engine, Environment},
    require, storage as f,
    system::{Real, System, words},
};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

const ROOT: &str = "/opt/pathward-reboot-test";
const UNITS: &str = "/etc/systemd/system";
const FIXTURE: &str = "/usr/local/bin/pathward-role-fixture";
#[path = "support/publication_vm.rs"]
mod publication_vm;
fn p(name: &str) -> PathBuf {
    Path::new(ROOT).join(name)
}
fn emit(s: &str) -> Result<()> {
    let mut serial = fs::OpenOptions::new().write(true).open("/dev/ttyS0")?;
    writeln!(serial, "{s}")?;
    serial.flush()?;
    Ok(())
}
fn command(a: &[&str]) -> Result<String> {
    Real.checked(&words(a), 180)
}
fn file(path: &Path, text: &str, mode: u32) -> Result<()> {
    f::replace(path, text.as_bytes(), mode, "fixture", &mut |_| Ok(()))
}
fn save(name: &str, v: &Value) -> Result<()> {
    f::write_record(&p(name), v, "fixture", &mut |_| Ok(()))
}
fn digest(path: &Path) -> Result<String> {
    Ok(codec::hash(&f::bytes(path, false)?))
}
fn engine() -> Engine<Real> {
    Engine {
        root: p("native"),
        env: Environment::production(),
        sys: Real,
    }
}
fn settled_lock(e: &Engine<Real>) -> Result<fs::File> {
    // A listening fallback can be visible just before its recovery worker
    // finishes the final health check and releases the shared lock.
    let until = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match e.lock() {
            Ok(lock) => return Ok(lock),
            Err(error)
                if matches!(
                    error.downcast_ref::<std::fs::TryLockError>(),
                    Some(std::fs::TryLockError::WouldBlock)
                ) =>
            {
                require(
                    std::time::Instant::now() < until,
                    "recovery worker did not release lock",
                )?;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
}
fn unit(label: &str, kind: &str) -> String {
    format!(
        "[Unit]\nDescription=Native isolated fixture {label}\n[Service]\nType={kind}\nUser=nobody\nGroup=nogroup\nExecStart={FIXTURE} serve {label} 18080\nTimeoutStartSec=10\nTimeoutStopSec=3\n[Install]\nWantedBy=multi-user.target\n"
    )
}
fn fixture_role(name: &str, label: &str, kind: &str) -> Result<Value> {
    let template = p(&format!("template-{label}.service"));
    file(&template, &unit(label, kind), 0o600)?;
    Ok(
        json!({"units":{name:{"path":template,"sha256":digest(&template)?}},"files":{FIXTURE:digest(Path::new(FIXTURE))?},"check":[FIXTURE,"check"],"health":[FIXTURE,"probe",label,"18080"]}),
    )
}
fn legacy_units(helper: &Path, plan: &Path, sha: &str) -> Value {
    let cmd = format!(
        "/usr/bin/python3 -I {} --plan {} --sha256 {sha}",
        helper.display(),
        plan.display()
    );
    let boot = format!(
        "[Unit]\nDescription=PathWard durable boot recovery\nAfter=local-fs.target\nBefore=test-old.service test-new.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart={cmd} boot\nTimeoutStartSec=180\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\n\n[Install]\nWantedBy=multi-user.target\n"
    );
    let fallback = format!(
        "[Unit]\nDescription=PathWard verified fallback after candidate failure\nAfter=pathward-recovery.service\n\n[Service]\nType=oneshot\nExecStart={cmd} boot-failure\nTimeoutStartSec=480\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\n"
    );
    let mut units =
        json!({"pathward-recovery.service":boot,"pathward-recovery-fallback.service":fallback});
    for (name, side, other, extra) in [
        ("test-old.service", "old", "test-new.service", ""),
        (
            "test-new.service",
            "new",
            "test-old.service",
            "Before=test-old.service\nOnFailure=pathward-recovery-fallback.service\n",
        ),
    ] {
        units[format!("{name}.d/90-pathward-recovery.conf")]=format!("[Unit]\nRequires=pathward-recovery.service\nAfter=pathward-recovery.service\nConflicts={other}\n{extra}\n[Service]\nExecStartPre=+{cmd} allow-{side}\n").into();
    }
    units
}
fn initialize() -> Result<()> {
    command(&[
        "/usr/bin/systemctl",
        "mask",
        "systemd-networkd-wait-online.service",
    ])?;
    f::replace(
        Path::new(FIXTURE),
        &f::bytes(&p("role_fixture"), false)?,
        0o755,
        "fixture",
        &mut |_| Ok(()),
    )?;
    let helper = p("pathward_recovery.py");
    let plan = p("legacy-plan.json");
    let journal = p("legacy-journal.json");
    let initial = json!({"phase":"committed","transaction":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","prepared_at":1793950000.125});
    f::write_record(&journal, &initial, "fixture", &mut |_| Ok(()))?;
    let mut value = json!({"schema":1,"transaction":initial["transaction"],"journal":journal,"permit":"/run/pathward-recovery/permit.json",
        "kernel":p("pathward-recovery"),"kernel_sha256":digest(&p("pathward-recovery"))?,"state_seed":initial});
    for (side, label) in [("old", "OLD"), ("new", "SOURCE")] {
        let name = format!("test-{side}.service");
        file(&Path::new(UNITS).join(&name), &unit(label, "simple"), 0o644)?;
        value[side] = json!({"units":[name],"files":{FIXTURE:digest(Path::new(FIXTURE))?},"check":[FIXTURE,"check"]});
    }
    f::write_record(&plan, &value, "fixture", &mut |_| Ok(()))?;
    let sha = digest(&plan)?;
    let units = legacy_units(&helper, &plan, &sha);
    let g = json!({"schema":1,"epoch":1,"parent":"0".repeat(64),"helper":helper,"helper_sha256":digest(&p("pathward_recovery.py"))?,
        "plan":plan,"plan_sha256":sha,"old_unit":"test-old.service","new_unit":"test-new.service","units":units});
    let gid = codec::hash(&codec::canonical(&g));
    for dir in [
        p("legacy"),
        p("legacy/generations"),
        p(&format!("legacy/generations/{gid}")),
    ] {
        f::directory(&dir)?;
    }
    let gen_dir = p(&format!("legacy/generations/{gid}"));
    f::write_record(&gen_dir.join("manifest.json"), &g, "fixture", &mut |_| {
        Ok(())
    })?;
    f::link(
        &p("legacy/current"),
        Path::new(&format!("generations/{gid}")),
        "fixture",
        &mut |_| Ok(()),
    )?;
    for (name, text) in units.as_object().unwrap() {
        let path = gen_dir.join(name);
        if path.parent() != Some(&gen_dir) {
            f::directory(path.parent().unwrap())?;
        }
        file(&path, text.as_str().unwrap(), 0o644)?;
        let dest = Path::new(UNITS).join(name);
        if dest.parent() != Some(Path::new(UNITS)) {
            f::directory(dest.parent().unwrap())?;
        }
        f::link(
            &dest,
            &p("legacy/current").join(name),
            "fixture",
            &mut |_| Ok(()),
        )?;
    }
    save(
        "legacy/last-applied.json",
        &json!({"base":"0".repeat(64),"target":gid,"epoch":1,"plan_sha256":sha,"boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()}),
    )?;
    let input = json!({"source_legacy":{"store":p("legacy"),"plan":plan,"sha256":sha,"health":{"old":[FIXTURE,"probe","OLD","18080"],"new":[FIXTURE,"probe","SOURCE","18080"]}},
        "target":{"selected":"new","old":fixture_role("test-new.service","FALLBACK","notify")?,"new":fixture_role("test-old.service","TARGET","exec")?}});
    save("input.json", &input)?;
    save(
        "report.json",
        &json!({"boots":[],"results":[],"legacy_journal_sha256":digest(&journal)?}),
    )?;
    file(&p("case"), "0", 0o600)?;
    file(
        &Path::new(UNITS).join("test-role-case.service"),
        &format!(
            "[Unit]\nDescription=Isolated native role migration assertions\nAfter=pathward-recovery.service pathward-role-recovery.service\nWants=pathward-recovery.service\n[Service]\nType=oneshot\nExecStart={ROOT}/role_vm_guest\nTimeoutStartSec=infinity\n[Install]\nWantedBy=multi-user.target\n"
        ),
        0o644,
    )?;
    command(&["/usr/bin/systemctl", "daemon-reload"])?;
    command(&[
        "/usr/bin/systemctl",
        "enable",
        "pathward-recovery.service",
        "test-old.service",
        "test-new.service",
        "test-role-case.service",
    ])?;
    // The seed has finished provisioning. Later cold boots exercise only the
    // real service manager and recovery, without repeating cloud metadata work.
    file(
        Path::new("/etc/cloud/cloud-init.disabled"),
        "isolated fixture initialized\n",
        0o600,
    )?;
    command(&[
        "/usr/bin/systemctl",
        "start",
        "--no-block",
        "test-role-case.service",
    ])?;
    Ok(())
}

fn probe(label: &str) -> Result<()> {
    command(&[FIXTURE, "probe", label, "18080"])?;
    Ok(())
}
fn cut(wanted: &str) -> impl FnMut(&str) -> Result<()> + '_ {
    move |point| {
        if point == wanted {
            emit(&format!("PW_CUT_POWER {point}"))?;
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        Ok(())
    }
}
fn record_next(report: &Value, next: u64) -> Result<()> {
    save("report.json", report)?;
    file(&p("case"), &next.to_string(), 0o600)
}
fn run() -> Result<()> {
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
    require(
        report["legacy_journal_sha256"] == digest(&p("legacy-journal.json"))?,
        "legacy application record changed",
    )?;
    let expected = match case {
        0..=7 => "SOURCE",
        8 => "TARGET",
        9 => "FALLBACK",
        _ => "THIRD",
    };
    probe(expected)?;
    report["results"]
        .as_array_mut()
        .unwrap()
        .push(json!({"case":case,"selected":expected}));
    emit(&format!("PW_BOOT_CHECKED {case} {expected}"))?;
    let mut e = engine();
    let _lock = settled_lock(&e)?;
    let id = if case == 0 {
        let id = e.prepare(
            &f::record(&p("input.json"))?,
            &p("pathward-admin"),
            &mut |_| Ok(()),
        )?;
        file(&p("request"), &id, 0o600)?;
        id
    } else {
        fs::read_to_string(p("request"))?
    };
    if case <= 7 {
        record_next(&report, case + 1)?;
        let points = [
            "active-request:renamed",
            "rescue-enabled:durable",
            "all-stopped",
            "unit-test-old.service:renamed",
            "permit:renamed",
            "target-started",
            "state-committed:partial",
            "state-committed:durable",
        ];
        e.apply(&id, &mut cut(points[case as usize]))?;
        return Err("power cut was not reached".into());
    }
    if case == 8 {
        let before = command(&[
            "/usr/bin/systemctl",
            "show",
            "test-old.service",
            "--property=MainPID",
            "--value",
        ])?;
        e.apply(&id, &mut |_| Ok(()))?;
        e.watchdog(&mut |_| Ok(()))?;
        require(
            before
                == command(&[
                    "/usr/bin/systemctl",
                    "show",
                    "test-old.service",
                    "--property=MainPID",
                    "--value",
                ])?,
            "completed retry/watchdog restarted listener",
        )?;
        report["completed_retry_preserves_pid"] = true.into();
        report["committed_watchdog_noop"] = true.into();
        file(
            Path::new("/run/pathward-role-fail-primary"),
            "fail on next start",
            0o644,
        )?;
        // /run is volatile: make the deliberate failure persistent via a
        // fixture-only generator service before the primary on the next boot.
        file(
            &Path::new(UNITS).join("fixture-fail-primary.service"),
            "[Unit]\nDescription=Isolated deliberate startup failure\nBefore=test-old.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/touch /run/pathward-role-fail-primary\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n",
            0o644,
        )?;
        command(&["/usr/bin/systemctl", "daemon-reload"])?;
        command(&[
            "/usr/bin/systemctl",
            "enable",
            "fixture-fail-primary.service",
        ])?;
        record_next(&report, 9)?;
    } else if case == 9 {
        require(
            e.status()?["state"]["phase"] == "fallback",
            "fallback did not persist",
        )?;
        report["notify_fallback_after_primary_failure"] = true.into();
        let input = json!({"source_current":id,"target":{"selected":"new",
            "old":fixture_role("test-new.service","FALLBACK","notify")?,
            "new":fixture_role("test-third.service","THIRD","notify")?}});
        let next = e.prepare(&input, &p("pathward-admin"), &mut |_| Ok(()))?;
        e.apply(&next, &mut |_| Ok(()))?;
        probe("THIRD")?;
        file(&p("second-request"), &next, 0o600)?;
        record_next(&report, 10)?;
    } else {
        let active = e.current()?.ok_or("active request")?;
        require(
            active == fs::read_to_string(p("second-request"))?,
            "wrong native successor",
        )?;
        require(
            e.apply(&id, &mut |_| Ok(())).is_err(),
            "stale request was accepted",
        )?;
        let pid = command(&[
            "/usr/bin/systemctl",
            "show",
            "test-third.service",
            "--property=MainPID",
            "--value",
        ])?;
        require(
            e.gate("test-third.service")?
                && !e.gate("test-old.service")?
                && !e.gate("test-new.service")?,
            "role exclusivity failed",
        )?;
        let _ = Real.run(
            &words(&["/usr/bin/systemctl", "start", "test-old.service"]),
            45,
        );
        probe("THIRD")?;
        require(
            pid == command(&[
                "/usr/bin/systemctl",
                "show",
                "test-third.service",
                "--property=MainPID",
                "--value",
            ])?,
            "rejected old start disturbed primary",
        )?;
        for name in [
            "pathward-recovery.service",
            "pathward-recovery-fallback.service",
        ] {
            require(
                fs::read_link(Path::new(UNITS).join(name))? == Path::new("/dev/null"),
                "legacy Python guard still enabled",
            )?;
        }
        report["stale_request_rejected"] = true.into();
        report["retired_start_rejected"] = true.into();
        // A failure callback must not disappear just because an administrator
        // owns the shared lock. Only lock contention requests a systemd retry.
        let _ = Real.run(
            &words(&[
                "/usr/bin/systemctl",
                "start",
                "pathward-role-fallback.service",
            ]),
            45,
        );
        let until = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if Real
                .property("pathward-role-fallback.service", "NRestarts")?
                .parse::<u64>()?
                > 0
            {
                break;
            }
            require(
                std::time::Instant::now() < until,
                "fallback contention not retried",
            )?;
            std::thread::sleep(Duration::from_millis(100));
        }
        drop(_lock);
        let until = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if Real.property("pathward-role-fallback.service", "ActiveState")? == "inactive"
                && Real.property("pathward-role-fallback.service", "ExecMainStatus")? == "0"
            {
                break;
            }
            require(
                std::time::Instant::now() < until,
                "fallback did not finish after lock release",
            )?;
            std::thread::sleep(Duration::from_millis(100));
        }
        probe("THIRD")?;
        report["fallback_lock_contention_retried"] = true.into();
        report["role_rename_and_notify_primary"] = true.into();
        report["native_runtime_has_no_python"] = true.into();
        report["final_request"] = active.into();
        report["admin_sha256"] = digest(&p("pathward-admin"))?.into();
        report["versions"] = json!({"systemd":command(&["/usr/bin/systemd","--version"])?.lines().next(),"kernel":command(&["/usr/bin/uname","-r"])?.trim()});
        save("report.json", &report)?;
        emit(&format!(
            "PW_VM_RECOVERY_PASS {}",
            serde_json::to_string(&report)?
        ))?;
        command(&["/usr/bin/systemctl", "poweroff"])?;
        return Ok(());
    }
    drop(_lock);
    emit(&format!("PW_COLD_REBOOT {case}"))?;
    command(&["/usr/bin/systemctl", "reboot"])?;
    Ok(())
}
fn main() {
    let result = if std::env::args().any(|a| a == "--publication-initialize") {
        file(
            &p("publication-mode"),
            "native publication and retention",
            0o600,
        )
        .and_then(|()| initialize())
    } else if std::env::args().any(|a| a == "--initialize") {
        initialize()
    } else if p("publication-mode").exists() {
        publication_vm::run()
    } else {
        run()
    };
    if let Err(error) = result {
        for name in [
            "test-role-case.service",
            "pathward.service",
            "pathward-hosting.service",
            "pathward-role-recovery.service",
            "pathward-role-fallback.service",
            "test-old.service",
            "test-new.service",
            "test-third.service",
        ] {
            if let Ok(out) = command(&[
                "/usr/bin/journalctl",
                "-b",
                "-u",
                name,
                "--no-pager",
                "-n",
                "20",
            ]) {
                let _ = emit(&out);
            }
        }
        let _ = emit(&format!("PW_VM_FAILURE {error}"));
        std::process::exit(1);
    }
}
