use pathward_admin::{
    Result, codec, confined,
    publication::{self as p, Bridge},
    require,
    system::Real,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
fn main() {
    if run().is_err() {
        eprintln!("PathWard publication failed; no success receipt was issued");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    require(cfg!(target_os = "linux"), "Linux required")?;
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mode = a.first().ok_or("operation required")?;
    let mut args = BTreeMap::new();
    let mut watch = false;
    let mut i = 1;
    while i < a.len() {
        if a[i] == "--watch" {
            require(!watch, "duplicate watch")?;
            watch = true;
            i += 1;
            continue;
        }
        require(
            a[i].starts_with("--") && i + 1 < a.len(),
            "named arguments required",
        )?;
        require(
            args.insert(a[i].as_str(), a[i + 1].as_str()).is_none(),
            "duplicate argument",
        )?;
        i += 2;
    }
    let get = |n: &str| -> Result<&str> {
        args.get(n)
            .copied()
            .ok_or_else(|| format!("missing {n}").into())
    };
    let allowed = match mode.as_str() {
        "build" => vec!["--policy", "--state", "--binary"],
        "reconcile" => vec!["--policy", "--state", "--binary", "--control", "--receipt"],
        "begin" => vec!["--policy", "--receipt", "--receipt-owner", "--profile"],
        "ack" => vec![
            "--policy",
            "--receipt",
            "--receipt-owner",
            "--profile",
            "--reference",
            "--manifest",
            "--stamp",
        ],
        "publish" => vec![
            "--policy",
            "--receipt",
            "--receipt-owner",
            "--profile",
            "--expect",
            "--reference",
            "--manifest",
        ],
        _ => return Err("unknown operation".into()),
    };
    require(
        args.keys().all(|k| allowed.contains(k)) && (!watch || mode == "reconcile"),
        "unknown option",
    )?;
    let policy = Path::new(get("--policy")?);
    if mode == "build" || mode == "reconcile" {
        let state = PathBuf::from(get("--state")?);
        let _lock = p::lock(&state)?;
        let mut bridge = Bridge {
            state,
            binary: get("--binary")?.into(),
            control: args.get("--control").unwrap_or(&"").into(),
            receipt: args.get("--receipt").unwrap_or(&"").into(),
            sys: Real,
        };
        loop {
            let result = (|| {
                let policy = confined::metadata(policy, 0)?;
                if mode == "build" {
                    let (path, r) = bridge.build(&policy, &mut |_| Ok(()))?;
                    println!(
                        "{}",
                        serde_json::json!({"candidate":path,"config_sha256":r["config_sha256"]})
                    );
                } else {
                    let r = bridge.reconcile(&policy, &p::clock()?, &mut |_| Ok(()))?;
                    println!(
                        "{}",
                        serde_json::json!({"event":"reconciled","active":r["active"]})
                    );
                }
                Ok(())
            })();
            if !watch {
                return result;
            }
            if result.is_err() {
                eprintln!("{{\"event\":\"reconcile_failed\"}}");
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    let policy = confined::metadata(policy, 0)?;
    let receipt = Path::new(get("--receipt")?);
    let owner = get("--receipt-owner")?.parse()?;
    let profile = get("--profile")?;
    if mode == "publish" {
        let r = p::publish(
            &policy,
            receipt,
            owner,
            profile,
            get("--expect")?,
            get("--reference")?,
            &p::public_manifest(Path::new(get("--manifest")?))?,
            &mut Real,
            &mut |_| Ok(()),
        )?;
        println!("PUBLICATION_ACKNOWLEDGED {r}");
        return Ok(());
    }
    let now = p::clock()?;
    let current = p::begin(&policy, receipt, owner, profile, &mut Real, &now)?;
    if mode == "begin" {
        println!("{}", current);
        return Ok(());
    }
    let stamp = codec::parse(get("--stamp")?.as_bytes())?;
    require(
        stamp["routing"] == "pathward",
        "native acknowledgement requires PathWard",
    )?;
    require(
        stamp["profile"] == profile
            && stamp["routing"] == current["routing"]
            && stamp["policy_sha256"] == current["policy_sha256"]
            && stamp["boot"] == current["boot"],
        "publication stamp authority",
    )?;
    let reference = get("--reference")?;
    require(confined::release(reference), "release reference")?;
    let files = p::selected_files(
        &policy,
        profile,
        &p::public_manifest(Path::new(get("--manifest")?))?,
    )?;
    if stamp["routing"] == "pathward" {
        p::wait(
            receipt,
            owner,
            profile,
            reference,
            &files,
            &stamp,
            Duration::from_secs(30),
        )?;
    }
    println!("PUBLICATION_ACKNOWLEDGED");
    Ok(())
}
