//! Explicit unit contracts and bounded sealed resources; no shell evaluation.
use crate::{
    Result,
    codec::{self, string},
    require, storage,
    system::System,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

pub fn unit_name(s: &str) -> bool {
    s.len() <= 100
        && s.ends_with(".service")
        && s.len() > 8
        && s[..s.len() - 8]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        && !s.starts_with("pathward-role-")
        && ![
            "pathward-recovery.service",
            "pathward-recovery-fallback.service",
        ]
        .contains(&s)
}
pub fn command(v: &Value) -> Result<Vec<String>> {
    let a = v.as_array().ok_or("command must be array")?;
    require(!a.is_empty() && a.len() <= 24, "command bound")?;
    let out = a
        .iter()
        .map(|x| {
            x.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "command string required".into())
        })
        .collect::<Result<Vec<_>>>()?;
    require(
        storage::absolute(Path::new(&out[0]))
            && out
                .iter()
                .all(|s| s.len() <= 2048 && s.is_ascii() && !s.bytes().any(|b| b < 32 || b == 127)),
        "invalid command argument",
    )?;
    Ok(out)
}
pub fn template(text: &str) -> Result<()> {
    require(
        text.len() <= 16384 && text.is_ascii() && !text.contains('\r') && !text.contains('\0'),
        "invalid unit text",
    )?;
    let mut section = "";
    let mut starts = 0;
    let mut seen = BTreeSet::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#') && !s.starts_with(';'))
    {
        require(!line.ends_with('\\'), "continued directives unsupported")?;
        if line.starts_with('[') {
            require(
                ["[Unit]", "[Service]", "[Install]"].contains(&line),
                "unsupported unit section",
            )?;
            section = line;
            continue;
        }
        let (k, v) = line.split_once('=').ok_or("invalid unit directive")?;
        require(
            !section.is_empty() && !k.trim().is_empty(),
            "directive outside section",
        )?;
        let k = k.trim();
        let v = v.trim();
        if section == "[Service]" {
            // The gate must precede every application command. Do not silently
            // discard preparation/cleanup hooks or escape a service cgroup.
            require(
                ![
                    "ExecStartPre",
                    "ExecCondition",
                    "ExecStartPost",
                    "ExecStop",
                    "ExecStopPost",
                    "RootDirectory",
                    "RootImage",
                    "PAMName",
                    "Delegate",
                ]
                .contains(&k),
                "unsupported startup hook or isolation contract",
            )?;
            if [
                "Type",
                "ExecStart",
                "TimeoutStartSec",
                "TimeoutStopSec",
                "KillMode",
            ]
            .contains(&k)
            {
                require(seen.insert(k.to_owned()), "duplicate startup contract")?;
            }
            match k {
                "Type" => require(
                    ["simple", "exec", "notify"].contains(&v),
                    "unsupported startup type",
                )?,
                "ExecStart" => {
                    starts += 1;
                    require(
                        v.starts_with('/') && !v.contains('%'),
                        "absolute non-templated ExecStart required",
                    )?;
                }
                "KillMode" => require(
                    ["control-group", "mixed"].contains(&v),
                    "service must drain its cgroup",
                )?,
                "TimeoutStartSec" | "TimeoutStopSec" => {
                    let n = v.trim_end_matches('s').parse::<u64>()?;
                    require(
                        (1..=180).contains(&n),
                        "startup/stop deadline must be 1..180 seconds",
                    )?;
                }
                _ => (),
            }
        }
    }
    require(starts == 1, "exactly one application command required")
}
pub fn names(c: &Value) -> Result<Vec<String>> {
    let mut names = BTreeSet::new();
    for side in ["old", "new"] {
        let units = c[side]["units"].as_object().ok_or("unit map required")?;
        require(
            !units.is_empty() && units.len() <= 3,
            "role must contain 1..3 units",
        )?;
        for name in units.keys() {
            require(
                unit_name(name) && names.insert(name.to_owned()),
                "invalid or overlapping service role",
            )?;
        }
    }
    Ok(names.into_iter().collect())
}
pub fn validate(c: &Value) -> Result<()> {
    names(c)?;
    require(
        ["old", "new"].contains(&string(c, "selected")?),
        "selected role required",
    )?;
    for side in ["old", "new"] {
        let r = &c[side];
        let files = r["files"].as_object().ok_or("sealed resources required")?;
        require(!files.is_empty() && files.len() <= 64, "resource bound")?;
        for (p, h) in files {
            require(
                storage::absolute(Path::new(p)) && h.as_str().is_some_and(codec::digest),
                "invalid resource",
            )?;
        }
        for operation in ["check", "health"] {
            let args = command(&r[operation])?;
            require(files.contains_key(&args[0]), "validator must be sealed")?;
        }
        for text in r["units"].as_object().ok_or("units required")?.values() {
            let text = text.as_str().ok_or("unit text required")?;
            template(text)?;
            for line in text
                .lines()
                .map(str::trim)
                .filter(|l| l.starts_with("ExecStart="))
            {
                let exe = line[10..]
                    .split_whitespace()
                    .next()
                    .ok_or("missing program")?;
                require(
                    files.contains_key(exe),
                    "application executable must be sealed",
                )?;
            }
        }
    }
    Ok(())
}
pub fn verified<S: System>(s: &mut S, role: &Value, durable: bool) -> Result<()> {
    for (path, digest) in role["files"].as_object().ok_or("resources required")? {
        storage::verified(
            Path::new(path),
            digest.as_str().ok_or("digest required")?,
            durable,
        )?;
    }
    let (ok, _) = s.run(&command(&role["check"])?, 45)?;
    require(ok, "configuration validation failed")
}
pub fn health<S: System>(s: &mut S, role: &Value) -> Result<()> {
    let (ok, _) = s.run(&command(&role["health"])?, 45)?;
    require(ok, "service health check failed")
}
pub fn materialize(input: &Value) -> Result<Value> {
    let mut out = input.clone();
    for side in ["old", "new"] {
        let mut units = serde_json::Map::new();
        for (name, source) in input[side]["units"]
            .as_object()
            .ok_or("template map required")?
        {
            let path = Path::new(string(source, "path")?);
            storage::verified(path, string(source, "sha256")?, true)?;
            units.insert(
                name.clone(),
                String::from_utf8(storage::bytes(path, false)?)?.into(),
            );
        }
        out[side]["units"] = Value::Object(units);
    }
    validate(&out)?;
    Ok(out)
}
pub fn role_units(role: &Value) -> Result<Vec<String>> {
    Ok(role["units"]
        .as_object()
        .ok_or("role unit map")?
        .keys()
        .cloned()
        .collect())
}
pub fn inactive(state: &str) -> bool {
    ["inactive", "failed"].contains(&state)
}
pub fn stable<S: System>(sys: &mut S, universe: &[String], role: &Value) -> Result<bool> {
    let selected = role_units(role)?;
    for name in universe {
        let state = sys.property(name, "ActiveState")?;
        if if selected.contains(name) {
            state != "active"
        } else {
            !inactive(&state)
        } {
            return Ok(false);
        }
    }
    Ok(true)
}
pub fn legacy_role<S: System>(
    sys: &mut S,
    item: &Value,
    health: &Value,
    unit_dir: &Path,
    expected_dropins: &[String],
) -> Result<Value> {
    let mut units = serde_json::Map::new();
    for name in item["units"].as_array().ok_or("legacy units required")? {
        let name = name.as_str().ok_or("legacy unit name")?;
        require(unit_name(name), "invalid legacy unit")?;
        let aliases = sys.property(name, "Names")?;
        require(
            aliases.split_whitespace().all(|v| v == name),
            "aliased units unsupported",
        )?;
        let drops = sys.property(name, "DropInPaths")?;
        require(
            drops
                .split_whitespace()
                .all(|p| expected_dropins.iter().any(|v| v == p)),
            "unmanaged drop-in",
        )?;
        let fragment = sys.property(name, "FragmentPath")?;
        let fragment = std::fs::canonicalize(fragment)?;
        storage::root_mount(&fragment)?;
        let text = String::from_utf8(storage::bytes(&fragment, false)?)?;
        template(&text)?;
        let installed = unit_dir.join(name);
        if installed.symlink_metadata().is_ok() {
            require(
                std::fs::canonicalize(&installed)? == fragment,
                "fragment mismatch",
            )?;
        }
        units.insert(name.to_owned(), text.into());
    }
    let mut files = item["files"].clone();
    // Unit definitions are captured in the sealed request. Their live paths
    // will change during handoff and cannot also be fallback configuration.
    if let Some(map) = files.as_object_mut() {
        map.retain(|p, _| !Path::new(p).starts_with(unit_dir));
    }
    let health_args = command(health)?;
    // The explicit health executable is sealed during preparation like the
    // legacy configuration checker; callers review the sealed request hash.
    for args in [health_args, command(&item["check"])?] {
        files[&args[0]] = codec::hash(&storage::bytes(Path::new(&args[0]), false)?).into();
    }
    for text in units.values().filter_map(Value::as_str) {
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("ExecStart="))
        {
            let exe = line[10..]
                .split_whitespace()
                .next()
                .ok_or("missing executable")?;
            files[exe] = codec::hash(&storage::bytes(Path::new(exe), false)?).into();
        }
    }
    Ok(json!({"units":units,"files":files,"check":item["check"],"health":health}))
}
