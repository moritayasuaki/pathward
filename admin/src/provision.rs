//! Sealed initial installation. No existing service is stopped or enabled.
use crate::{
    Result,
    codec::{self, string},
    contract,
    engine::Engine,
    publication, require, storage as f,
    storage::Checkpoint,
    system::{System, words},
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

fn public_dir(path: &Path) -> Result<()> {
    f::directory(path)?;
    let fd = crate::confined::absolute(path)?;
    require(
        fd.metadata()?.uid() == rustix::process::geteuid().as_raw(),
        "installation directory owner",
    )?;
    fd.set_permissions(fs::Permissions::from_mode(0o755))?;
    fd.sync_all()?;
    f::sync_dir(path.parent().ok_or("directory parent")?)
}
fn owned_dir(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<()> {
    use rustix::process::{Gid, Uid};
    let parent = crate::confined::absolute(path.parent().ok_or("state parent")?)?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("state name")?;
    match rustix::fs::mkdirat(&parent, name, rustix::fs::Mode::from_raw_mode(0o700)) {
        Ok(()) => (),
        Err(e) if e == rustix::io::Errno::EXIST => (),
        Err(e) => return Err(e.into()),
    }
    let fd = crate::confined::child(&parent, name)?;
    let m = fd.metadata()?;
    require(
        m.uid() == uid || (m.uid() == 0 && fs::read_dir(path)?.next().is_none()),
        "preexisting service state belongs elsewhere",
    )?;
    rustix::fs::fchown(&fd, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
    fd.set_permissions(fs::Permissions::from_mode(mode))?;
    fd.sync_all()?;
    parent.sync_all()?;
    Ok(())
}
fn as_user<S: System>(s: &mut S, user: &str, args: &[String]) -> Result<String> {
    let mut a = words(&["/usr/sbin/runuser", "-u", user, "--"]);
    a.extend_from_slice(args);
    s.checked(&a, 180)
}
/// Produce a check-only unit using the complete reviewed Service restrictions.
/// Neither inherited application ExecStart nor RuntimeDirectory is retained.
pub fn preflight(text: &str, command: &[String]) -> Result<String> {
    contract::template(text)?;
    require(
        command.iter().all(|v| {
            !v.is_empty()
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b))
        }),
        "preflight argument",
    )?;
    let mut section = "";
    let mut lines = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
    {
        if line.starts_with('[') {
            section = line;
            continue;
        }
        if section != "[Service]" {
            continue;
        }
        let (k, _) = line.split_once('=').ok_or("unit directive")?;
        if [
            "Type",
            "ExecStart",
            "Restart",
            "RestartSec",
            "RuntimeDirectory",
            "RuntimeDirectoryMode",
            "PrivateNetwork",
            "TimeoutStartSec",
            "TimeoutStopSec",
            "StandardOutput",
            "StandardError",
            "RemainAfterExit",
            "KillMode",
        ]
        .contains(&k.trim())
        {
            continue;
        }
        lines.push(line);
    }
    require(
        lines.contains(&"NoNewPrivileges=yes") && lines.contains(&"PrivateTmp=yes"),
        "preflight isolation contract",
    )?;
    Ok(format!(
        "[Unit]\nDescription=PathWard initial isolated validation\n[Service]\n{}\nType=oneshot\nExecStart={}\nPrivateNetwork=yes\nTimeoutStartSec=180\nTimeoutStopSec=15\nKillMode=control-group\nStandardOutput=journal\nStandardError=journal\n",
        lines.join("\n"),
        command.join(" ")
    ))
}
fn validate_network<S: System>(sys: &mut S, input: &Value, policy: &Value) -> Result<()> {
    let network = string(input, "network")?;
    require(
        ["public", "isolated"].contains(&network),
        "explicit provisioning network scope required",
    )?;
    if network == "isolated" {
        require(
            fs::read_dir("/sys/class/net")?.all(|e| e.is_ok_and(|e| e.file_name() == "lo")),
            "isolated preparation requires a host with no network interfaces",
        )?;
    }
    if network == "public" {
        let addresses = input["expected_addresses"]
            .as_object()
            .ok_or("reviewed DNS addresses required")?;
        let sites = policy["sites"].as_array().ok_or("sites")?;
        require(
            addresses.len() == sites.len(),
            "DNS scope differs from hosting policy",
        )?;
        for site in sites {
            let host = string(site, "host")?;
            let expected = addresses[host]
                .as_array()
                .ok_or("missing reviewed host addresses")?
                .iter()
                .map(|v| {
                    v.as_str()
                        .ok_or("address")
                        .and_then(|s| s.parse::<std::net::IpAddr>().map_err(|_| "address"))
                })
                .collect::<std::result::Result<std::collections::BTreeSet<_>, _>>()?;
            require(!expected.is_empty(), "empty DNS address scope")?;
            let answer = sys.checked(&words(&["/usr/bin/getent", "ahosts", host]), 45)?;
            let observed = answer
                .lines()
                .map(|line| {
                    line.split_whitespace()
                        .next()
                        .ok_or("DNS response")
                        .and_then(|s| s.parse::<std::net::IpAddr>().map_err(|_| "DNS response"))
                })
                .collect::<std::result::Result<std::collections::BTreeSet<_>, _>>()?;
            require(expected == observed, "DNS differs from reviewed addresses")?;
        }
    }
    Ok(())
}
pub fn prepare<S: System>(
    e: &mut Engine<S>,
    input: &Value,
    exe: &Path,
    cp: Checkpoint<'_>,
) -> Result<String> {
    require(input["schema"] == 1, "provision schema")?;
    let base = PathBuf::from(string(input, "installation")?);
    f::root_mount(&base)?;
    require(
        base != e.root && !base.starts_with(&e.root) && !e.root.starts_with(&base),
        "private recovery store and public installation must be disjoint",
    )?;
    let user = string(input, "account")?;
    require(
        (1..=32).contains(&user.len())
            && user
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && user != "root",
        "dedicated account name",
    )?;
    let members = input["members"].as_object().ok_or("package members")?;
    require(
        members.len() == 4
            && [
                "pathward-server",
                "pathward-hosting",
                "pathward-publish",
                "hosting.json",
            ]
            .iter()
            .all(|n| members.contains_key(*n)),
        "exact native package inventory",
    )?;
    let mut contents = std::collections::BTreeMap::new();
    for (name, item) in members {
        let p = Path::new(string(item, "source")?);
        let m = fs::symlink_metadata(p)?;
        require(m.nlink() == 1, "linked bundle member")?;
        f::verified(p, string(item, "sha256")?, false)?;
        let data = f::bytes(p, false)?;
        require(
            codec::hash(&data) == string(item, "sha256")?,
            "bundle changed while copying",
        )?;
        contents.insert(name.clone(), data);
    }
    let policy = codec::parse(&contents["hosting.json"])?;
    publication::validate(&policy)?;
    validate_network(&mut e.sys, input, &policy)?;
    let minimum = input["minimum_free_bytes"]
        .as_u64()
        .ok_or("storage reserve required")?;
    require(minimum >= 128 << 20, "storage reserve is too small")?;
    let disk = rustix::fs::statvfs(base.parent().ok_or("installation parent")?)?;
    require(
        u128::from(disk.f_bavail) * u128::from(disk.f_frsize) >= u128::from(minimum),
        "insufficient installation reserve",
    )?;
    let identity = codec::hash(&codec::canonical(input));
    for name in input["contract"]["old"]["units"]
        .as_object()
        .ok_or("source units")?
        .keys()
    {
        require(
            contract::unit_name(name) && e.sys.property(name, "ActiveState")? == "active",
            "preparation requires active source",
        )?;
    }
    for name in input["contract"]["new"]["units"]
        .as_object()
        .ok_or("candidate units")?
        .keys()
    {
        require(
            contract::unit_name(name) && contract::inactive(&e.sys.property(name, "ActiveState")?),
            "preparation refuses an active candidate",
        )?;
    }
    // Existing installations must be the same immutable package, including a
    // partially completed copy. No repair of different root-owned files.
    public_dir(&base)?;
    let marker = base.join("provision.json");
    if marker.symlink_metadata().is_ok() {
        require(
            f::record(&marker)?["input"] == identity,
            "different installation manifest",
        )?;
    } else {
        require(
            fs::read_dir(&base)?.next().is_none(),
            "nonempty unclaimed installation",
        )?;
        f::write_record(&marker, &json!({"input":identity}), "provision-intent", cp)?;
    }
    for (name, data) in &contents {
        let path = base.join(name);
        if path.symlink_metadata().is_ok() {
            require(f::bytes(&path, false)? == *data, "installed member changed")?;
        }
        f::replace(
            &path,
            data,
            if name == "hosting.json" { 0o644 } else { 0o755 },
            "provision-member",
            cp,
        )?;
        f::verified(&path, string(&members[name], "sha256")?, true)?;
    }
    let state = base.join("state");
    let query = words(&["/usr/bin/getent", "passwd", user]);
    let (found, mut passwd) = e.sys.run(&query, 45)?;
    if !found {
        e.sys.checked(
            &words(&[
                "/usr/sbin/useradd",
                "--system",
                "--user-group",
                "--home-dir",
                state.to_str().ok_or("state")?,
                "--shell",
                "/usr/sbin/nologin",
                user,
            ]),
            45,
        )?;
        passwd = e.sys.checked(&query, 45)?;
    }
    let parts: Vec<_> = passwd.trim().split(':').collect();
    require(
        parts.len() == 7
            && parts[0] == user
            && parts[5] == state.to_str().ok_or("state")?
            && ["/usr/sbin/nologin", "/bin/false"].contains(&parts[6]),
        "unexpected dedicated account",
    )?;
    let uid = parts[2].parse::<u32>()?;
    let gid = parts[3].parse::<u32>()?;
    require(uid != 0 && gid != 0, "privileged service identity")?;
    owned_dir(&state, uid, gid, 0o700)?;
    for name in ["snapshots", "cache"] {
        owned_dir(&state.join(name), uid, gid, 0o700)?;
    }
    owned_dir(&base.join("receipts"), uid, gid, 0o755)?;
    let server = base.join("pathward-server");
    let hosting = base.join("pathward-hosting");
    let policy = base.join("hosting.json");
    let args = vec![
        hosting.display().to_string(),
        "build".into(),
        "--policy".into(),
        policy.display().to_string(),
        "--state".into(),
        state.join("snapshots").display().to_string(),
        "--binary".into(),
        server.display().to_string(),
    ];
    let built = codec::parse(as_user(&mut e.sys, user, &args)?.as_bytes())?;
    let control = state.join("control");
    let candidate = Path::new(string(&built, "candidate")?);
    require(
        candidate.starts_with(state.join("snapshots")),
        "candidate escaped service state",
    )?;
    if !control.exists() {
        as_user(
            &mut e.sys,
            user,
            &words(&[
                server.to_str().unwrap(),
                "init",
                control.to_str().unwrap(),
                candidate.to_str().unwrap(),
            ]),
        )?;
    }
    // Compare via the service-owned no-follow reader, not root's record reader.
    let a = crate::confined::absolute(&control)?;
    let b = crate::confined::absolute(candidate.parent().unwrap())?;
    let fd = rustix::fs::openat(
        &a,
        ".config",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let active = std::fs::File::from(fd);
    require(active.metadata()?.uid() == uid, "control owner changed")?;
    let active = crate::confined::stream(active, None, 1 << 20)?;
    let candidate_hash = crate::confined::stream(
        crate::confined::leaf(&b, candidate.file_name().unwrap().to_str().unwrap())?,
        None,
        1 << 20,
    )?;
    require(
        active["sha256"] == candidate_hash["sha256"],
        "prepared control differs from rebuilt candidate",
    )?;
    as_user(
        &mut e.sys,
        user,
        &words(&[
            server.to_str().unwrap(),
            "check",
            control.join(".config").to_str().unwrap(),
            "--cache",
            state.join("cache").to_str().unwrap(),
        ]),
    )?;
    let target = contract::materialize(&input["contract"])?;
    for name in [
        "pathward-server",
        "pathward-hosting",
        "pathward-publish",
        "hosting.json",
    ] {
        require(
            target["new"]["files"][base.join(name).to_str().unwrap()] == members[name]["sha256"],
            "candidate contract must seal installed members",
        )?;
    }
    let transient = e.env.run.join("systemd/system");
    f::trusted(&transient.join("probe"))?;
    for (name, text) in target["new"]["units"]
        .as_object()
        .ok_or("candidate units")?
    {
        let text = text.as_str().ok_or("unit text")?;
        require(
            text.lines().any(|l| l == format!("User={user}")),
            "candidate must use dedicated account",
        )?;
        let command = words(&[
            server.to_str().unwrap(),
            "check",
            control.join(".config").to_str().unwrap(),
            "--cache",
            state.join("cache").to_str().unwrap(),
        ]);
        let unit = format!("pathward-preflight-{}-{name}", &identity[..16]);
        let path = transient.join(&unit);
        let text = preflight(text, &command)?;
        if path.symlink_metadata().is_ok() {
            require(
                f::bytes(&path, false)? == text.as_bytes(),
                "preflight conflict",
            )?;
        }
        f::replace(&path, text.as_bytes(), 0o644, "preflight-unit", cp)?;
        let result = (|| {
            e.sys.checked(
                &words(&["/usr/bin/systemd-analyze", "verify", path.to_str().unwrap()]),
                45,
            )?;
            e.sys
                .checked(&words(&["/usr/bin/systemctl", "daemon-reload"]), 45)?;
            e.sys.control("start", std::slice::from_ref(&unit), true)
        })();
        let _ = e.sys.control("stop", std::slice::from_ref(&unit), true);
        fs::remove_file(&path)?;
        f::sync_dir(&transient)?;
        e.sys
            .checked(&words(&["/usr/bin/systemctl", "daemon-reload"]), 45)?;
        result?;
    }
    let mut source = input["contract"].clone();
    source["selected"] = "old".into();
    let initial = json!({"source_fresh":source,"target":input["contract"]});
    let id = e.initialize(&initial, exe, cp)?;
    f::write_record(
        &base.join("prepared.json"),
        &json!({"input":identity,"request":id,"uid":uid,"gid":gid}),
        "provision-complete",
        cp,
    )?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Resolver(&'static str);
    impl System for Resolver {
        fn run(&mut self, args: &[String], _: u64) -> Result<(bool, String)> {
            require(
                args == words(&["/usr/bin/getent", "ahosts", "example.test"]),
                "unexpected DNS command",
            )?;
            Ok((true, self.0.into()))
        }
    }
    #[test]
    fn public_preparation_rejects_missing_changed_and_extra_dns_scope() -> Result<()> {
        let policy = json!({"sites":[{"host":"example.test"}]});
        let mut input =
            json!({"network":"public","expected_addresses":{"example.test":["192.0.2.1"]}});
        validate_network(
            &mut Resolver("192.0.2.1 STREAM example.test\n192.0.2.1 DGRAM"),
            &input,
            &policy,
        )?;
        for answer in [
            "",
            "192.0.2.2 STREAM example.test",
            "bad address",
            "192.0.2.1 STREAM\n192.0.2.2 STREAM",
        ] {
            assert!(validate_network(&mut Resolver(answer), &input, &policy).is_err());
        }
        input["expected_addresses"]["example.test"] = json!([]);
        assert!(validate_network(&mut Resolver("192.0.2.1 STREAM"), &input, &policy).is_err());
        input["expected_addresses"]["unrelated.test"] = json!(["192.0.2.1"]);
        assert!(validate_network(&mut Resolver("192.0.2.1 STREAM"), &input, &policy).is_err());
        input["network"] = "skip".into();
        assert!(validate_network(&mut Resolver("192.0.2.1 STREAM"), &input, &policy).is_err());
        Ok(())
    }
}
