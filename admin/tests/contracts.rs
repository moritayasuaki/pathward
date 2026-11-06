use pathward_admin::{
    Result, codec, contract,
    engine::{Engine, Environment},
    storage as f,
    system::{System, words},
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn save(path: &Path, value: &Value) -> Result<()> {
    f::write_record(path, value, "test", &mut |_| Ok(()))
}
fn file(path: &Path, text: &str) -> Result<()> {
    f::replace(path, text.as_bytes(), 0o600, "test", &mut |_| Ok(()))
}
fn unit(exe: &Path, label: &str, kind: &str) -> String {
    format!(
        "[Unit]\nDescription=Contract fixture {label}\n[Service]\nType={kind}\nExecStart={} serve {label}\nTimeoutStopSec=3\n",
        exe.display()
    )
}

#[derive(Clone)]
struct Mock {
    base: PathBuf,
}
impl Mock {
    fn state(&self) -> Result<Value> {
        f::record(&self.base.join("machine.json"))
    }
    fn update(&self, s: &Value) -> Result<()> {
        save(&self.base.join("machine.json"), s)
    }
    fn engine(&self) -> Engine<Self> {
        engine(&self.base)
    }
    fn reload(&self, s: &mut Value) -> Result<()> {
        let units = self.base.join("units");
        let mut loaded = json!({});
        for entry in fs::read_dir(&units)? {
            let path = entry?.path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".service")
                || fs::read_link(&path).is_ok_and(|p| p == Path::new("/dev/null"))
            {
                continue;
            }
            let text = match fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let d = units.join(format!("{name}.d/90-pathward-recovery.conf"));
            let drop = fs::read_to_string(&d).unwrap_or_default();
            loaded[&name] = json!({"text":text,"drop":drop,"fragment":path,"drops":if drop.is_empty(){String::new()}else{d.to_string_lossy().into_owned()}});
        }
        s["loaded"] = loaded;
        Ok(())
    }
}
impl System for Mock {
    fn run(&mut self, args: &[String], _: u64) -> Result<(bool, String)> {
        let mut s = self.state()?;
        if args[0] != "/usr/bin/systemctl" {
            let ok = !(args.iter().any(|v| v == "health-target") && s["bad_health"] == true);
            return Ok((ok, String::new()));
        }
        let mut ok = true;
        let mut out = String::new();
        match args[1].as_str() {
            "daemon-reload" => {
                if s["fail_reload"] == true {
                    s["fail_reload"] = false.into();
                    ok = false;
                } else {
                    self.reload(&mut s)?;
                }
            }
            "show" => {
                let name = &args[2];
                let prop = args[3].strip_prefix("--property=").unwrap();
                out = match prop {
                    "ActiveState" => s["active"][name].as_str().unwrap_or("inactive").into(),
                    "LoadState" => if s["loaded"][name].is_object() {
                        "loaded"
                    } else {
                        "not-found"
                    }
                    .into(),
                    "Names" => name.clone(),
                    "UnitFileState" => if s["active"][name] == "active" {
                        "enabled"
                    } else {
                        "disabled"
                    }
                    .into(),
                    "FragmentPath" => s["loaded"][name]["fragment"].as_str().unwrap_or("").into(),
                    "DropInPaths" => s["loaded"][name]["drops"].as_str().unwrap_or("").into(),
                    "ExecStartPre" => s["loaded"][name]["drop"]
                        .as_str()
                        .unwrap_or("")
                        .lines()
                        .filter_map(|x| x.strip_prefix("ExecStartPre="))
                        .collect::<Vec<_>>()
                        .join(" "),
                    _ => return Err(format!("unmocked property {prop}").into()),
                };
            }
            "list-jobs" => {
                if s["busy"] == true {
                    out = "1 fixture.service start running".into();
                }
            }
            "reset-failed" => (),
            "stop" => {
                if s["cannot_stop"] != true {
                    for name in args.iter().skip(2).filter(|s| !s.starts_with('-')) {
                        s["active"][name] = "inactive".into();
                    }
                }
            }
            "start" | "restart" => {
                for name in args.iter().skip(2).filter(|s| !s.starts_with('-')) {
                    if name == "pathward-role-recovery.service" {
                        self.update(&s)?;
                        ok = self.engine().boot_fast_path()?;
                    } else if s["loaded"][name]["drop"]
                        .as_str()
                        .unwrap_or("")
                        .contains(" gate ")
                    {
                        self.update(&s)?;
                        ok = self.engine().gate(name).unwrap_or(false);
                    }
                    if ok {
                        s["active"][name] = "active".into();
                        let n = s["starts"][name].as_u64().unwrap_or(0);
                        s["starts"][name] = (n + 1).into();
                    } else {
                        s["active"][name] = "failed".into();
                        break;
                    }
                }
            }
            v => return Err(format!("unmocked system operation {v}").into()),
        }
        self.update(&s)?;
        Ok((ok, out))
    }
}
fn engine(base: &Path) -> Engine<Mock> {
    Engine {
        root: base.join("native"),
        env: Environment {
            units: base.join("units"),
            boot_id: base.join("boot"),
            run: base.join("run"),
            lock: base.join("lock"),
        },
        sys: Mock { base: base.into() },
    }
}
struct Fixture {
    base: PathBuf,
    input: Value,
    exe: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}
impl Fixture {
    fn new() -> Result<Self> {
        let base = PathBuf::from("/private/tmp")
            .canonicalize()
            .unwrap_or(std::env::temp_dir())
            .join(format!(
                "pathward-native-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        f::directory(&base)?;
        for name in ["units", "run", "legacy", "legacy/generations"] {
            f::directory(&base.join(name))?;
        }
        file(&base.join("boot"), "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")?;
        let exe = base.join("fixture");
        file(&exe, "reviewed test executable")?;
        file(&base.join("helper.py"), "reviewed legacy helper")?;
        for (name, label) in [("old.service", "source-old"), ("new.service", "source-new")] {
            file(&base.join("units").join(name), &unit(&exe, label, "simple"))?;
        }
        let resource = json!({exe.to_str().unwrap():codec::hash(&f::bytes(&exe,false)?)});
        let plan = json!({"schema":1,"transaction":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","journal":base.join("journal.json"),"permit":base.join("run/legacy.json"),
            "old":{"units":["old.service"],"files":resource,"check":[exe,"check"]},
            "new":{"units":["new.service"],"files":resource,"check":[exe,"check"]},
            "state_seed":{"prepared_at":1793950000.123}});
        let plan_path = base.join("plan.json");
        save(&plan_path, &plan)?;
        let sha = codec::hash(&f::bytes(&plan_path, true)?);
        save(
            &base.join("journal.json"),
            &json!({"transaction":plan["transaction"],"phase":"committed","metadata":1.25}),
        )?;
        save(
            &base.join("run/legacy.json"),
            &json!({"boot_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","plan_sha256":sha,"selection":"NEW"}),
        )?;
        let old_units = json!({"pathward-recovery.service":"legacy boot","pathward-recovery-fallback.service":"legacy fallback",
            "old.service.d/90-pathward-recovery.conf":"legacy gate old","new.service.d/90-pathward-recovery.conf":"legacy gate new"});
        let g = json!({"schema":1,"epoch":7,"plan":plan_path,"plan_sha256":sha,"helper":base.join("helper.py"),"helper_sha256":codec::hash(b"reviewed legacy helper"),"units":old_units});
        let gid = codec::hash(&codec::canonical(&g));
        let gen_dir = base.join("legacy/generations").join(&gid);
        f::directory(&gen_dir)?;
        save(&gen_dir.join("manifest.json"), &g)?;
        for (name, text) in old_units.as_object().unwrap() {
            let path = gen_dir.join(name);
            if path.parent() != Some(&gen_dir) {
                f::directory(path.parent().unwrap())?;
            }
            file(&path, text.as_str().unwrap())?;
            let dest = base.join("units").join(name);
            if dest.parent() != Some(base.join("units").as_path()) {
                f::directory(dest.parent().unwrap())?;
            }
            f::link(
                &dest,
                &base.join("legacy/current").join(name),
                "test",
                &mut |_| Ok(()),
            )?;
        }
        f::link(
            &base.join("legacy/current"),
            Path::new(&format!("generations/{gid}")),
            "test",
            &mut |_| Ok(()),
        )?;
        save(
            &base.join("legacy/last-applied.json"),
            &json!({"target":gid,"plan_sha256":sha,"epoch":7}),
        )?;
        let input = json!({"source_legacy":{"store":base.join("legacy"),"plan":plan_path,"sha256":sha,"health":{"old":[exe,"health-source"],"new":[exe,"health-source"]}},"target":{
            "selected":"new",
            "old":{"units":{"new.service":template_input(&base,&exe,"fallback","notify")?},"files":resource,"check":[exe,"check"],"health":[exe,"health-fallback"]},
            "new":{"units":{"old.service":template_input(&base,&exe,"target","exec")?},"files":resource,"check":[exe,"check"],"health":[exe,"health-target"]}
        }});
        save(
            &base.join("machine.json"),
            &json!({"active":{"old.service":"inactive","new.service":"active","pathward-recovery.service":"active"},"starts":{},"loaded":{}}),
        )?;
        let mut mock = Mock { base: base.clone() };
        mock.run(&words(&["/usr/bin/systemctl", "daemon-reload"]), 45)?;
        Ok(Self { base, input, exe })
    }
    fn prepare(&self) -> Result<String> {
        engine(&self.base).prepare(&self.input, &self.exe, &mut |_| Ok(()))
    }
    fn reboot(&self) -> Result<()> {
        file(
            &self.base.join("boot"),
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        )?;
        let mut s = engine(&self.base).sys.state()?;
        s["active"] = json!({"pathward-role-recovery.service":"active"});
        engine(&self.base).sys.update(&s)?;
        engine(&self.base).recover(true, false, &mut |_| Ok(()))
    }
}
fn template_input(base: &Path, exe: &Path, label: &str, kind: &str) -> Result<Value> {
    let path = base.join(format!("{label}.service"));
    file(&path, &unit(exe, label, kind))?;
    Ok(json!({"path":path,"sha256":codec::hash(&f::bytes(&path,false)?)}))
}

fn fresh_fixture() -> Result<Fixture> {
    let mut f = Fixture::new()?;
    for name in [
        "pathward-recovery.service",
        "pathward-recovery-fallback.service",
        "old.service",
    ] {
        fs::remove_file(f.base.join("units").join(name))?;
    }
    for name in ["old.service.d", "new.service.d"] {
        fs::remove_dir_all(f.base.join("units").join(name))?;
    }
    let text = f::bytes(
        Path::new(
            f.input["target"]["old"]["units"]["new.service"]["path"]
                .as_str()
                .unwrap(),
        ),
        false,
    )?;
    f::replace(
        &f.base.join("units/new.service"),
        &text,
        0o644,
        "fixture",
        &mut |_| Ok(()),
    )?;
    let mut source = f.input["target"].clone();
    source["selected"] = "old".into();
    f.input = json!({"source_fresh":source,"target":f.input["target"]});
    let mut sys = engine(&f.base).sys;
    let mut s = sys.state()?;
    s["active"] = json!({"new.service":"active"});
    sys.update(&s)?;
    sys.run(&words(&["/usr/bin/systemctl", "daemon-reload"]), 45)?;
    Ok(f)
}
#[test]
fn initial_preparation_keeps_source_and_never_starts_candidate() -> Result<()> {
    let f = fresh_fixture()?;
    let mut e = engine(&f.base);
    let id = e.initialize(&f.input, &f.exe, &mut |_| Ok(()))?;
    assert!(e.gate("new.service")?);
    assert!(!e.gate("old.service")?);
    assert_eq!(e.sys.state()?["active"]["new.service"], "active");
    assert!(e.sys.state()?["starts"]["new.service"].is_null());
    assert_eq!(id, e.initialize(&f.input, &f.exe, &mut |_| Ok(()))?);
    let mut changed = f.input.clone();
    changed["unexpected"] = true.into();
    assert!(e.initialize(&changed, &f.exe, &mut |_| Ok(())).is_err());
    f.reboot()?;
    assert!(e.gate("new.service")?);
    assert!(!e.gate("old.service")?);
    e.apply(&id, &mut |_| Ok(()))?;
    assert_eq!(e.status()?["state"]["phase"], "committed");
    Ok(())
}
#[test]
fn initial_preparation_retries_each_durable_write() -> Result<()> {
    let f = fresh_fixture()?;
    let mut labels = Vec::new();
    engine(&f.base).initialize(&f.input, &f.exe, &mut |s| {
        labels.push(s.to_owned());
        Ok(())
    })?;
    for (point, label) in labels.iter().enumerate() {
        let f = fresh_fixture()?;
        let mut e = engine(&f.base);
        let mut n = 0;
        let r = e.initialize(&f.input, &f.exe, &mut |_| {
            let hit = n == point;
            n += 1;
            if hit {
                Err("interrupted".into())
            } else {
                Ok(())
            }
        });
        assert!(r.is_err(), "{}", label);
        assert_eq!(e.sys.state()?["active"]["new.service"], "active");
        let id = e.initialize(&f.input, &f.exe, &mut |_| Ok(()))?;
        assert_eq!(e.current()?, Some(id));
        assert!(!e.gate("old.service")?);
    }
    println!("INITIAL_WRITE_BOUNDARIES {}", labels.len());
    Ok(())
}

fn collection_fixture() -> Result<(Fixture, Vec<String>, String)> {
    let f = Fixture::new()?;
    let mut e = engine(&f.base);
    let first = f.prepare()?;
    e.apply(&first, &mut |_| Ok(()))?;
    let mut ids = vec![first];
    for _ in 0..2 {
        let mut input = f.input.clone();
        input["source_current"] = ids.last().unwrap().clone().into();
        let id = e.prepare(&input, &f.exe, &mut |_| Ok(()))?;
        e.apply(&id, &mut |_| Ok(()))?;
        ids.push(id);
    }
    let mut input = f.input.clone();
    input["source_current"] = ids.last().unwrap().clone().into();
    let prepared = e.prepare(&input, &f.exe, &mut |_| Ok(()))?;
    e.observe_collection(&mut |_| Ok(()))?;
    assert!(e.plan_collection(&[], &mut |_| Ok(())).is_err());
    f.reboot()?;
    Ok((f, ids, prepared))
}
#[test]
fn native_collection_preserves_current_parent_prepared_and_explicit_keep() -> Result<()> {
    let (f, ids, prepared) = collection_fixture()?;
    let mut e = engine(&f.base);
    let _lock = e.lock()?;
    assert!(
        e.plan_collection(&[format!("native-{}", ids[0])], &mut |_| Ok(()))
            .is_err()
    );
    let request = e.plan_collection(&[], &mut |_| Ok(()))?;
    assert_eq!(e.apply_collection(&request, &mut |_| Ok(()))?, 1);
    assert!(!e.root.join("transactions").join(&ids[0]).exists());
    for id in [&ids[1], &ids[2], &prepared] {
        assert!(e.plan(id).is_ok());
    }
    assert_eq!(e.apply_collection(&request, &mut |_| Ok(()))?, 1);
    assert!(f.base.join("plan.json").exists());
    assert!(f.base.join("helper.py").exists());
    Ok(())
}
#[test]
fn native_collection_retries_every_partial_delete_and_rejects_stale_requests() -> Result<()> {
    let (f, _, _) = collection_fixture()?;
    let mut e = engine(&f.base);
    let request = e.plan_collection(&[], &mut |_| Ok(()))?;
    let mut labels = Vec::new();
    e.apply_collection(&request, &mut |s| {
        labels.push(s.to_owned());
        Ok(())
    })?;
    for point in 0..labels.len() {
        let (f, ids, _) = collection_fixture()?;
        let mut e = engine(&f.base);
        let request = e.plan_collection(&[], &mut |_| Ok(()))?;
        let mut n = 0;
        assert!(
            e.apply_collection(&request, &mut |_| {
                let fail = n == point;
                n += 1;
                if fail {
                    Err("interrupted collection".into())
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        e.apply_collection(&request, &mut |_| Ok(()))?;
        for id in &ids[1..] {
            assert!(e.plan(id).is_ok());
        }
    }
    let (f, _, prepared) = collection_fixture()?;
    let mut e = engine(&f.base);
    let request = e.plan_collection(&[], &mut |_| Ok(()))?;
    e.apply(&prepared, &mut |_| Ok(()))?;
    assert!(e.apply_collection(&request, &mut |_| Ok(())).is_err());
    println!("collection interruption boundaries: {}", labels.len());
    Ok(())
}
#[test]
fn changed_or_foreign_collection_members_and_pending_jobs_are_refused() -> Result<()> {
    let (f, ids, _) = collection_fixture()?;
    let mut e = engine(&f.base);
    let request = e.plan_collection(&[], &mut |_| Ok(()))?;
    let mut machine = e.sys.state()?;
    machine["busy"] = true.into();
    e.sys.update(&machine)?;
    assert!(e.apply_collection(&request, &mut |_| Ok(())).is_err());
    machine["busy"] = false.into();
    e.sys.update(&machine)?;
    file(
        &e.root.join("transactions").join(&ids[0]).join("unexpected"),
        "foreign",
    )?;
    assert!(e.apply_collection(&request, &mut |_| Ok(())).is_err());
    assert!(e.plan(&ids[0]).is_ok());
    Ok(())
}

#[test]
fn collection_keeps_a_retained_contracts_explicit_generation_resource() -> Result<()> {
    let (f, ids, _) = collection_fixture()?;
    let mut e = engine(&f.base);
    let old = e.root.join("transactions").join(&ids[0]).join("plan.json");
    let mut input = f.input.clone();
    input["source_current"] = ids[2].clone().into();
    input["target"]["new"]["files"][old.to_str().unwrap()] =
        codec::hash(&f::bytes(&old, true)?).into();
    let next = e.prepare(&input, &f.exe, &mut |_| Ok(()))?;
    e.apply(&next, &mut |_| Ok(()))?;
    e.observe_collection(&mut |_| Ok(()))?;
    file(&f.base.join("boot"), "cccccccc-cccc-cccc-cccc-cccccccccccc")?;
    let mut state = e.sys.state()?;
    state["active"] = json!({"pathward-role-recovery.service":"active"});
    e.sys.update(&state)?;
    e.recover(true, false, &mut |_| Ok(()))?;
    let request = e.plan_collection(&[], &mut |_| Ok(()))?;
    e.apply_collection(&request, &mut |_| Ok(()))?;
    assert!(e.plan(&ids[0]).is_ok());
    assert!(!e.root.join("transactions").join(&ids[1]).exists());
    assert!(e.plan(&ids[2]).is_ok());
    assert!(e.plan(&next).is_ok());
    Ok(())
}

#[test]
fn swaps_roles_and_startup_contract_without_python() -> Result<()> {
    let f = Fixture::new()?;
    let journal = fs::read(f.base.join("journal.json"))?;
    let id = f.prepare()?;
    let mut e = engine(&f.base);
    e.apply(&id, &mut |_| Ok(()))?;
    assert_eq!(e.status()?["state"]["phase"], "committed");
    assert!(e.gate("old.service")?);
    assert!(!e.gate("new.service")?);
    assert!(fs::read_to_string(f.base.join("units/old.service"))?.contains("Type=exec"));
    assert!(
        !fs::read_to_string(f.base.join("units/old.service.d/90-pathward-recovery.conf"))?
            .contains("python")
    );
    assert_eq!(fs::read(f.base.join("journal.json"))?, journal);
    assert_eq!(
        fs::read_link(f.base.join("units/pathward-recovery.service"))?,
        Path::new("/dev/null")
    );
    e.apply(&id, &mut |_| Ok(()))?;
    f.reboot()?;
    assert!(engine(&f.base).gate("old.service")?);
    Ok(())
}

#[test]
fn failed_health_restores_source_and_same_request_retries() -> Result<()> {
    let f = Fixture::new()?;
    let id = f.prepare()?;
    let mut e = engine(&f.base);
    let mut state = e.sys.state()?;
    state["bad_health"] = true.into();
    e.sys.update(&state)?;
    assert!(e.apply(&id, &mut |_| Ok(())).is_err());
    assert_eq!(e.status()?["state"]["phase"], "source");
    assert!(e.gate("new.service")?);
    assert!(!e.gate("old.service")?);
    let mut state = e.sys.state()?;
    state["bad_health"] = false.into();
    e.sys.update(&state)?;
    e.apply(&id, &mut |_| Ok(()))?;
    assert!(e.gate("old.service")?);
    Ok(())
}

#[test]
fn stale_permits_and_unstopped_services_are_denied() -> Result<()> {
    let f = Fixture::new()?;
    let id = f.prepare()?;
    let mut e = engine(&f.base);
    let mut s = e.sys.state()?;
    s["cannot_stop"] = true.into();
    e.sys.update(&s)?;
    assert!(e.apply(&id, &mut |_| Ok(())).is_err());
    assert!(fs::read_to_string(f.base.join("units/old.service"))?.contains("source-old"));
    let mut s = e.sys.state()?;
    s["cannot_stop"] = false.into();
    e.sys.update(&s)?;
    e.apply(&id, &mut |_| Ok(()))?;
    file(&f.base.join("boot"), "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")?;
    assert!(!e.gate("old.service")?);
    Ok(())
}

#[test]
fn sealed_records_and_startup_hooks_are_strict() -> Result<()> {
    assert!(codec::parse(br#"{"x":1,"x":2}"#).is_err());
    assert!(codec::parse(br#"{"x":NaN}"#).is_err());
    let value = json!({"text":"日本語🙂","time":1793950000.125});
    assert_eq!(codec::decode(&codec::encode(&value))?, value);
    for hook in [
        "ExecStartPre=/usr/bin/false",
        "ExecCondition=/usr/bin/true",
        "KillMode=process",
        "Type=forking",
        "TimeoutStopSec=infinity",
    ] {
        assert!(
            contract::template(&format!("[Service]\nExecStart=/usr/bin/true\n{hook}\n")).is_err()
        );
    }
    let f = Fixture::new()?;
    let mut contract = contract::materialize(&f.input["target"])?;
    let name = contract["new"]["units"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    contract["new"]["units"][&name] = "[Service]\nExecStart = /unsealed/program\n".into();
    assert!(contract::validate(&contract).is_err());
    let id = f.prepare()?;
    let path = f
        .base
        .join("native/transactions")
        .join(&id)
        .join("plan.json");
    file(&path, "broken")?;
    assert!(engine(&f.base).apply(&id, &mut |_| Ok(())).is_err());
    Ok(())
}

#[test]
fn competing_changes_and_foreign_targets_are_refused() -> Result<()> {
    let f = Fixture::new()?;
    let id = f.prepare()?;
    let mut e = engine(&f.base);
    let mut s = e.sys.state()?;
    s["busy"] = true.into();
    e.sys.update(&s)?;
    assert!(e.apply(&id, &mut |_| Ok(())).is_err());
    assert!(e.current()?.is_none());
    s["busy"] = false.into();
    e.sys.update(&s)?;
    save(
        &f.base.join("journal.json"),
        &json!({"transaction":"changed","phase":"prepared"}),
    )?;
    assert!(e.apply(&id, &mut |_| Ok(())).is_err());
    assert!(e.current()?.is_none());
    let f = Fixture::new()?;
    let mut input = f.input.clone();
    input["target"]["new"]["units"] =
        json!({"foreign.service":input["target"]["new"]["units"]["old.service"]});
    file(
        &f.base.join("units/foreign.service"),
        &unit(&f.exe, "foreign", "exec"),
    )?;
    let mut e = engine(&f.base);
    e.sys
        .run(&words(&["/usr/bin/systemctl", "daemon-reload"]), 45)?;
    assert!(e.prepare(&input, &f.exe, &mut |_| Ok(())).is_err());
    Ok(())
}

#[test]
fn native_successor_rejects_old_requests_and_retired_starts() -> Result<()> {
    let f = Fixture::new()?;
    let id = f.prepare()?;
    let mut e = engine(&f.base);
    e.apply(&id, &mut |_| Ok(()))?;
    let mut input = f.input.clone();
    input["source_current"] = id.clone().into();
    input["target"]["new"]["units"] =
        json!({"renamed.service":input["target"]["new"]["units"]["old.service"]});
    let next = e.prepare(&input, &f.exe, &mut |_| Ok(()))?;
    e.apply(&next, &mut |_| Ok(()))?;
    assert!(e.apply(&id, &mut |_| Ok(())).is_err());
    assert!(e.gate("renamed.service")?);
    assert!(!e.gate("old.service")?);
    assert!(!e.gate("new.service")?);
    let state = e.sys.state()?;
    e.watchdog(&mut |_| Ok(()))?;
    assert_eq!(e.sys.state()?["starts"], state["starts"]);
    Ok(())
}

#[test]
fn process_exit_watchdog_restores_source_without_reboot() -> Result<()> {
    let sample = Fixture::new()?;
    let id = sample.prepare()?;
    let mut labels = Vec::new();
    engine(&sample.base).apply(&id, &mut |label| {
        labels.push(label.to_owned());
        Ok(())
    })?;
    let point = labels.iter().position(|s| s == "target-started").unwrap();
    let f = Fixture::new()?;
    let id = f.prepare()?;
    let status = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "crash_child"])
        .env("PATHWARD_ROLE_CHILD", &f.base)
        .env("PATHWARD_ROLE_REQUEST", &id)
        .env("PATHWARD_ROLE_POINT", point.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    assert!(!status.success());
    let mut e = engine(&f.base);
    assert_eq!(e.status()?["state"]["phase"], "trial");
    e.watchdog(&mut |_| Ok(()))?;
    assert_eq!(e.status()?["state"]["phase"], "source");
    assert!(e.gate("new.service")?);
    assert!(!e.gate("old.service")?);
    e.apply(&id, &mut |_| Ok(()))?;
    e.watchdog(&mut |_| Ok(()))?;
    assert_eq!(e.status()?["state"]["phase"], "committed");
    Ok(())
}

#[test]
fn legacy_resource_pins_cannot_be_replaced_by_target_review() -> Result<()> {
    let f = Fixture::new()?;
    file(&f.exe, "changed executable")?;
    let mut input = f.input.clone();
    let sha = codec::hash(&f::bytes(&f.exe, false)?);
    for role in ["old", "new"] {
        input["target"][role]["files"][f.exe.to_str().unwrap()] = sha.clone().into();
    }
    assert!(
        engine(&f.base)
            .prepare(&input, &f.exe, &mut |_| Ok(()))
            .is_err()
    );
    Ok(())
}

#[test]
fn shared_lock_contention_is_distinct_from_invalid_state() -> Result<()> {
    let f = Fixture::new()?;
    let e = engine(&f.base);
    let _guard = e.lock()?;
    let error = e.lock().unwrap_err();
    assert!(matches!(
        error.downcast_ref::<std::fs::TryLockError>(),
        Some(std::fs::TryLockError::WouldBlock)
    ));
    Ok(())
}

#[test]
fn crash_child() -> Result<()> {
    let Ok(base) = std::env::var("PATHWARD_ROLE_CHILD") else {
        return Ok(());
    };
    let request = std::env::var("PATHWARD_ROLE_REQUEST")?;
    let stop = std::env::var("PATHWARD_ROLE_POINT")?.parse::<usize>()?;
    let mut count = 0;
    engine(Path::new(&base)).apply(&request, &mut |_| {
        if count == stop {
            rustix::process::kill_process(
                rustix::process::getpid(),
                rustix::process::Signal::KILL,
            )?;
        }
        count += 1;
        Ok(())
    })
}

#[test]
fn every_process_kill_boundary_recovers_and_retries() -> Result<()> {
    let sample = Fixture::new()?;
    let id = sample.prepare()?;
    let mut boundaries = Vec::new();
    engine(&sample.base).apply(&id, &mut |name| {
        boundaries.push(name.to_owned());
        Ok(())
    })?;
    for (point, label) in boundaries.iter().enumerate() {
        let f = Fixture::new()?;
        let id = f.prepare()?;
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "crash_child", "--nocapture"])
            .env("PATHWARD_ROLE_CHILD", &f.base)
            .env("PATHWARD_ROLE_REQUEST", &id)
            .env("PATHWARD_ROLE_POINT", point.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        assert!(!status.success(), "missing SIGKILL at {point}: {label}");
        if engine(&f.base).current()?.is_some() {
            // If power fails before rescue installation, the still-unchanged
            // legacy boot selects the source; retry installs the rescue first.
            if fs::read_link(
                f.base
                    .join("units/multi-user.target.wants/pathward-role-recovery.service"),
            )
            .is_ok()
            {
                f.reboot()
                    .unwrap_or_else(|error| panic!("recovery at {point} {label}: {error}"));
            }
        }
        engine(&f.base)
            .apply(&id, &mut |_| Ok(()))
            .unwrap_or_else(|error| panic!("retry at {point} {label}: {error}"));
        assert!(
            engine(&f.base).gate("old.service")?,
            "final gate at {point} {label}"
        );
    }
    println!("NATIVE_ROLE_SIGKILL_BOUNDARIES {}", boundaries.len());
    Ok(())
}
