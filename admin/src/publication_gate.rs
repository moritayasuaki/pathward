//! Shared publication leases and exclusive administrator fencing.
//! The legacy writer's existing lock is also held; no uploaded code is trusted.
use crate::{
    Result,
    codec::{self, string},
    confined, contract, publication, require, storage,
    system::System,
};
use serde_json::{Value, json};
use std::{fs::File, os::unix::fs::MetadataExt, path::Path};

#[derive(Debug)]
pub struct Lease {
    _files: Vec<File>,
}
fn lock(path: &Path, owner: u32, shared: bool) -> Result<File> {
    // Descriptor-relative NOFOLLOW traversal rejects substituted ancestors too.
    let parent = confined::absolute(path.parent().ok_or("lock parent")?)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("lock name")?;
    let file = confined::leaf(&parent, name)?;
    let m = file.metadata()?;
    require(
        m.is_file() && m.uid() == owner && m.nlink() == 1 && m.mode() & 0o002 == 0 && m.len() == 0,
        "untrusted publication lock",
    )?;
    if shared {
        file.try_lock_shared()?;
    } else {
        file.try_lock()?;
    }
    Ok(file)
}
pub fn publisher(config: &Value, id: Option<&str>) -> Result<Lease> {
    let mut files = Vec::new();
    if let Some(g) = config.get("rollout") {
        files.push(lock(Path::new(string(g, "lock")?), 0, true)?);
    }
    if let Some(id) = id
        && let Some(v) = config["profiles"][id].get("legacy_lock")
    {
        files.push(lock(
            Path::new(string(v, "path")?),
            v["owner"].as_u64().ok_or("legacy lock owner")?.try_into()?,
            false,
        )?);
    }
    Ok(Lease { _files: files })
}
pub fn administrator(root: &Path) -> Result<Lease> {
    let mut files = Vec::new();
    let path = root.join("publication-fence.json");
    match path.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
        Ok(_) => {
            let v = storage::record(&path)?;
            require(v["schema"] == 1, "publication fence schema")?;
            files.push(lock(Path::new(string(&v, "lock")?), 0, false)?);
            let writers = v["writers"].as_array().ok_or("legacy writer locks")?;
            require(writers.len() <= 16, "legacy writer count")?;
            let mut seen = std::collections::BTreeSet::new();
            for writer in writers {
                let p = string(writer, "path")?;
                require(seen.insert(p), "duplicate legacy writer lock")?;
                files.push(lock(
                    Path::new(p),
                    writer["owner"].as_u64().ok_or("legacy owner")?.try_into()?,
                    false,
                )?);
            }
        }
    }
    Ok(Lease { _files: files })
}
pub fn observe<S: System>(config: &Value, sys: &mut S) -> Result<Value> {
    let g = config
        .get("rollout")
        .ok_or("publication rollout gate required")?;
    let old = string(g, "legacy_unit")?;
    let new = string(g, "native_unit")?;
    require(
        old != new && contract::unit_name(old) && contract::unit_name(new),
        "bridge units",
    )?;
    let old_state = sys.property(old, "ActiveState")?;
    let new_state = sys.property(new, "ActiveState")?;
    let native = new_state == "active" && contract::inactive(&old_state);
    let legacy = old_state == "active" && contract::inactive(&new_state);
    require(
        native != legacy,
        "publication bridge transitioning or ambiguous",
    )?;
    let unit = if native { new } else { old };
    require(
        native || Path::new(string(config, "receipt")?).starts_with("/run"),
        "legacy receipts require volatile runtime storage",
    )?;
    let pid = sys.property(unit, "MainPID")?.parse::<u64>()?;
    let started = sys
        .property(unit, "ExecMainStartTimestampMonotonic")?
        .parse::<u64>()?
        .checked_mul(1000)
        .ok_or("bridge start overflow")?;
    require(pid > 1 && started > 0, "bridge process identity")?;
    let now = publication::clock()?;
    let receipt = confined::metadata(
        Path::new(string(config, "receipt")?),
        config["receipt_owner"]
            .as_u64()
            .ok_or("receipt owner")?
            .try_into()?,
    )?;
    accept_receipt(native, g, &receipt, &now, started)?;
    Ok(json!({"mode":if native {"native"} else {"legacy"},
        "epoch":{"boot":now["boot"],"unit":unit,"pid":pid,"started_ns":started,
            "policy_sha256":receipt["policy_sha256"]}}))
}
fn accept_receipt(
    native: bool,
    g: &Value,
    receipt: &Value,
    now: &Value,
    started: u64,
) -> Result<()> {
    let observed = receipt["observed_monotonic_ns"]
        .as_u64()
        .ok_or("receipt time")?;
    let ns = now["ns"].as_u64().ok_or("clock")?;
    let old_hash = string(g, "legacy_policy_sha256")?;
    let new_hash = string(g, "native_policy_sha256")?;
    require(
        codec::digest(old_hash) && codec::digest(new_hash) && old_hash != new_hash,
        "bridge policy generations must differ",
    )?;
    require(
        pathward::bootstrap::bridge_receipt_allowed(
            receipt["policy_sha256"] == if native { new_hash } else { old_hash },
            if native {
                receipt["schema"] == 2 && receipt["boot"] == now["boot"]
            } else {
                receipt["schema"] == 1
            },
            observed >= started,
            observed <= ns && ns - observed <= 10_000_000_000,
        ),
        "bridge receipt is stale or belongs to another mode",
    )
}

pub fn native_epoch<S: System>(config: &Value, sys: &mut S) -> Result<Option<Value>> {
    if !config["rollout"].is_null() {
        let observation = observe(config, sys)?;
        require(
            observation["mode"] == "native",
            "native publication is not active",
        )?;
        Ok(Some(observation["epoch"].clone()))
    } else {
        Ok(None)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bridge_receipt_rejects_old_boot_process_policy_and_schema() -> Result<()> {
        let g =
            json!({"legacy_policy_sha256":"a".repeat(64),"native_policy_sha256":"b".repeat(64)});
        let now = json!({"boot":"current","ns":20_000_000_000u64});
        let r = json!({"boot":"current","schema":2,"policy_sha256":"b".repeat(64),"observed_monotonic_ns":19_000_000_000u64});
        accept_receipt(true, &g, &r, &now, 18_000_000_000)?;
        for (field, value) in [
            ("boot", json!("previous")),
            ("schema", json!(1)),
            ("policy_sha256", json!("a".repeat(64))),
            ("observed_monotonic_ns", json!(17_000_000_000u64)),
            ("observed_monotonic_ns", json!(21_000_000_000u64)),
        ] {
            let mut bad = r.clone();
            bad[field] = value;
            assert!(accept_receipt(true, &g, &bad, &now, 18_000_000_000).is_err());
        }
        assert!(accept_receipt(false, &g, &r, &now, 18_000_000_000).is_err());
        let mut old = r.clone();
        old["schema"] = 1.into();
        old["policy_sha256"] = g["legacy_policy_sha256"].clone();
        accept_receipt(false, &g, &old, &now, 18_000_000_000)?;
        let mut same = g;
        same["legacy_policy_sha256"] = same["native_policy_sha256"].clone();
        assert!(accept_receipt(true, &same, &r, &now, 18_000_000_000).is_err());
        Ok(())
    }
    #[test]
    fn shared_publications_exclude_switch_and_lock_substitution_is_rejected() -> Result<()> {
        let dir = std::env::temp_dir()
            .canonicalize()?
            .join(format!("pathward-fence-{}", crate::publisher::nonce()?));
        storage::directory(&dir)?;
        let path = dir.join("lease");
        storage::replace(&path, b"", 0o600, "lock", &mut |_| Ok(()))?;
        let owner = rustix::process::geteuid().as_raw();
        let a = lock(&path, owner, true)?;
        let b = lock(&path, owner, true)?;
        assert!(lock(&path, owner, false).is_err());
        drop(a);
        assert!(lock(&path, owner, false).is_err());
        drop(b);
        let exclusive = lock(&path, owner, false)?;
        assert!(lock(&path, owner, true).is_err());
        drop(exclusive);
        std::os::unix::fs::symlink(&path, dir.join("alias"))?;
        assert!(lock(&dir.join("alias"), owner, false).is_err());
        std::fs::hard_link(&path, dir.join("hard"))?;
        assert!(lock(&path, owner, false).is_err());
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
