//! Prepare and reverse a publication-only role migration using the durable engine.
use crate::{
    Result,
    codec::{self, string},
    confined, contract,
    engine::Engine,
    provision, publication, publication_gate,
    publisher::{self, Verify},
    require, storage as f,
    storage::Checkpoint,
    system::{System, words},
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, Instant},
};

pub fn health<S: System>(config: &Value, mode: &str, sys: &mut S, work: &Path) -> Result<()> {
    require(["legacy", "native"].contains(&mode), "bridge mode")?;
    let end = Instant::now() + Duration::from_secs(15);
    let epoch = loop {
        if let Ok(v) = publication_gate::observe(config, sys)
            && v["mode"] == mode
        {
            break v["epoch"].clone();
        }
        require(Instant::now() < end, "bridge readiness deadline")?;
        std::thread::sleep(Duration::from_millis(200));
    };
    let checks = config["health"].as_array().ok_or("bridge health checks")?;
    require(
        !checks.is_empty() && checks.len() <= 16,
        "bridge health scope",
    )?;
    for v in checks {
        publisher::Curl.check(v, &json!({}), work)?;
    }
    require(
        publication_gate::observe(config, sys)?["epoch"] == epoch,
        "bridge changed during health check",
    )
}

pub fn prepare<S: System>(
    e: &mut Engine<S>,
    input: &Value,
    exe: &Path,
    cp: Checkpoint<'_>,
) -> Result<String> {
    require(input["schema"] == 1, "bridge preparation schema")?;
    let config_path = Path::new(string(input, "publisher")?);
    let config = confined::metadata(config_path, 0)?;
    let native_policy = Path::new(string(&config, "hosting_policy")?);
    let policy = confined::metadata(native_policy, 0)?;
    publication::validate(&policy)?;
    require(
        policy["schema"] == 2
            && config["rollout"]["native_policy_sha256"]
                == codec::hash(&publication::encoded(&policy)),
        "native policy generation",
    )?;
    let old = confined::metadata(Path::new(string(input, "legacy_policy")?), 0)?;
    require(
        old["schema"] == 1
            && config["rollout"]["legacy_policy_sha256"]
                == codec::hash(&publication::encoded(&old)),
        "legacy policy generation",
    )?;
    let mut equivalent = policy.clone();
    equivalent["schema"] = 1.into();
    // Explicit index order is the only permitted representation change.
    for site in equivalent["sites"].as_array_mut().ok_or("sites")? {
        site.as_object_mut().unwrap().remove("directory_indexes");
    }
    require(
        equivalent == old,
        "rollout changes routing; separately review policy migration",
    )?;
    for site in policy["sites"].as_array().unwrap() {
        let expected = if site["index"] == "index.html" {
            json!(["index.html", "index.txt"])
        } else {
            json!([site["index"]])
        };
        require(
            site["directory_indexes"] == expected,
            "explicit legacy directory index order",
        )?;
    }
    let user = string(input, "account")?;
    require(
        !user.is_empty()
            && user.len() <= 32
            && user.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "service account",
    )?;
    let account = e
        .sys
        .checked(&words(&["/usr/bin/getent", "passwd", user]), 45)?;
    let parts: Vec<_> = account.trim().split(':').collect();
    let uid: u32 = input["uid"].as_u64().ok_or("service uid")?.try_into()?;
    let gid: u32 = input["gid"].as_u64().ok_or("service gid")?.try_into()?;
    require(
        parts.len() == 7
            && parts[0] == user
            && parts[2] == uid.to_string()
            && parts[3] == gid.to_string()
            && uid != 0
            && gid != 0
            && ["/usr/sbin/nologin", "/bin/false"].contains(&parts[6]),
        "service identity changed",
    )?;
    let target = contract::materialize(&input["contract"])?;
    require(
        target["old"]["units"]
            .as_object()
            .is_some_and(|u| u.len() == 1)
            && target["new"]["units"]
                .as_object()
                .is_some_and(|u| u.len() == 1)
            && target["old"]["units"]
                .get(string(&config["rollout"], "legacy_unit")?)
                .is_some()
            && target["new"]["units"]
                .get(string(&config["rollout"], "native_unit")?)
                .is_some(),
        "publication-only role scope",
    )?;
    f::directory(&e.root)?;
    let fence = &input["fence"];
    require(
        fence["schema"] == 1 && fence["lock"] == config["rollout"]["lock"],
        "fence configuration",
    )?;
    let fence_path = e.root.join("publication-fence.json");
    let fresh_fence = fence_path.symlink_metadata().is_err();
    if !fresh_fence {
        require(
            f::record(&fence_path)? == *fence,
            "changed publication fence",
        )?;
    }
    let lock_path = Path::new(string(fence, "lock")?);
    if lock_path.symlink_metadata().is_err() {
        f::replace(lock_path, b"", 0o644, "publication-lock", cp)?;
    }
    // Never replace an existing lock inode, including on interrupted retries.
    require(
        fs::symlink_metadata(lock_path)?.uid() == 0,
        "publication lock owner",
    )?;
    if fresh_fence {
        f::write_record(&fence_path, fence, "publication-fence", cp)?;
    }
    // The outer administrator lease predates the first fence installation.
    let _initial_lease = if fresh_fence {
        Some(publication_gate::administrator(&e.root)?)
    } else {
        None
    };
    for side in ["old", "new"] {
        require(
            target[side]["files"][fence_path.to_str().ok_or("fence path")?]
                == codec::hash(&codec::encode(fence)),
            "contract must seal publication fencing",
        )?;
        require(
            target[side]["files"][config_path.to_str().ok_or("publisher path")?]
                == codec::hash(&f::bytes(config_path, false)?),
            "contract must seal publication profiles",
        )?;
        contract::verified(&mut e.sys, &target[side], true)?;
    }
    let state = Path::new(string(input, "state")?);
    let minimum = input["minimum_free_bytes"]
        .as_u64()
        .ok_or("storage reserve required")?;
    require(minimum >= 128 << 20, "storage reserve is too small")?;
    let disk = rustix::fs::statvfs(state.parent().ok_or("state parent")?)?;
    require(
        u128::from(disk.f_bavail) * u128::from(disk.f_frsize) >= u128::from(minimum),
        "insufficient publication storage reserve",
    )?;
    provision::owned_dir(state, uid, gid, 0o700)?;
    let deploy_uid: u32 = input["deployment_uid"]
        .as_u64()
        .ok_or("deployment uid")?
        .try_into()?;
    let deploy_gid: u32 = input["deployment_gid"]
        .as_u64()
        .ok_or("deployment gid")?
        .try_into()?;
    require(
        deploy_uid != 0 && deploy_gid != 0,
        "unprivileged deployment identity",
    )?;
    for (id, v) in config["profiles"].as_object().ok_or("profiles")? {
        publisher::profile(&config, id)?;
        provision::owned_dir(Path::new(string(v, "work")?), deploy_uid, deploy_gid, 0o700)?;
        let legacy = v
            .get("legacy_lock")
            .ok_or("legacy serialization required")?;
        require(
            fence["writers"]
                .as_array()
                .is_some_and(|a| a.iter().any(|w| w == legacy)),
            "unfenced legacy writer",
        )?;
    }
    let args = words(&[
        string(input, "hosting_binary")?,
        "build",
        "--policy",
        native_policy.to_str().unwrap(),
        "--state",
        state.to_str().unwrap(),
        "--binary",
        string(input, "server_binary")?,
    ]);
    let mut command = words(&["/usr/sbin/runuser", "-u", user, "--"]);
    command.extend(args.iter().cloned());
    let built = codec::parse(e.sys.checked(&command, 180)?.as_bytes())?;
    require(
        Path::new(string(&built, "candidate")?).starts_with(state),
        "candidate escaped state",
    )?;
    // Exercise the real bridge builder under the reviewed restrictions without networking.
    let identity = codec::hash(&codec::canonical(input));
    let unit = format!("pathward-bridge-preflight-{}.service", &identity[..16]);
    let transient = e.env.run.join("systemd/system").join(&unit);
    let text = target["new"]["units"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .as_str()
        .unwrap();
    let text = provision::preflight(text, &args)?;
    if transient.symlink_metadata().is_ok() {
        require(
            f::bytes(&transient, false)? == text.as_bytes(),
            "preflight conflict",
        )?;
    }
    f::replace(&transient, text.as_bytes(), 0o644, "bridge-preflight", cp)?;
    let result = (|| {
        e.sys
            .checked(&words(&["/usr/bin/systemctl", "daemon-reload"]), 45)?;
        e.sys.control("start", std::slice::from_ref(&unit), true)
    })();
    let _ = e.sys.control("stop", std::slice::from_ref(&unit), true);
    fs::remove_file(&transient)?;
    f::sync_dir(transient.parent().unwrap())?;
    e.sys
        .checked(&words(&["/usr/bin/systemctl", "daemon-reload"]), 45)?;
    result?;
    let mut source = input["contract"].clone();
    source["selected"] = "old".into();
    e.initialize(
        &json!({"source_fresh":source,"target":input["contract"]}),
        exe,
        cp,
    )
}

/// A durable reverse migration; the requested role becomes primary even after reboot.
pub fn switch<S: System>(
    e: &mut Engine<S>,
    input: &Value,
    mode: &str,
    exe: &Path,
    cp: Checkpoint<'_>,
) -> Result<String> {
    require(["native", "legacy"].contains(&mode), "bridge switch mode")?;
    let mut target = input["contract"].clone();
    if mode == "legacy" {
        let old = target["old"].clone();
        target["old"] = target["new"].clone();
        target["new"] = old;
    }
    let id = e.prepare(
        &json!({"source_current":e.current()?.ok_or("unprepared bridge")?,"target":target}),
        exe,
        cp,
    )?;
    e.apply(&id, cp)?;
    Ok(id)
}
