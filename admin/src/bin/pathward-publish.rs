//! Native local transfer and remote publication entry point; no remote code upload.
use pathward_admin::{
    Result, codec, confined, publisher as p, require, storage as f,
    system::{self, Real, words},
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
fn main() {
    if let Err(e) = run() {
        eprintln!("PathWard publisher: {e}");
        std::process::exit(1);
    }
}
fn safe(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.len() <= 2048
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/@._:-".contains(&b))
}
fn command(args: &[String]) -> Result<String> {
    let (ok, out) = system::capture(args, 600, codec::LIMIT as u64)?;
    require(ok, "transfer command failed")?;
    Ok(out)
}
fn remote(
    host: &str,
    exe: &str,
    config: &str,
    id: &str,
    mode: &str,
    extra: &[&str],
) -> Result<String> {
    let mut cmd = vec![exe, mode, "--config", config, "--profile", id];
    cmd.extend_from_slice(extra);
    require(
        safe(host)
            && cmd.iter().all(|s| {
                safe(s)
                    || s.starts_with("--") && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
            }),
        "unsafe SSH argument",
    )?;
    command(&words(&[
        "/usr/bin/ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "--",
        host,
        &cmd.join(" "),
    ]))
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().skip(1).collect();
    let mode = a.first().ok_or("operation required")?;
    require(a.len() % 2 == 1, "named arguments required")?;
    let mut opts = BTreeMap::new();
    for pair in a[1..].as_chunks::<2>().0 {
        require(
            pair[0].starts_with("--") && opts.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
            "duplicate/invalid option",
        )?;
    }
    let get = |n: &str| -> Result<&str> {
        opts.get(n)
            .copied()
            .ok_or_else(|| format!("missing {n}").into())
    };
    let allowed = match mode.as_str() {
        "upload" => vec![
            "--remote",
            "--binary",
            "--config",
            "--profile",
            "--source",
            "--files",
            "--stage-only",
            "--offline-report",
            "--zip-report",
        ],
        "check-package" => vec!["--source", "--offline-report", "--zip-report"],
        "route" => vec!["--remote", "--binary", "--config", "--profile"],
        "mode" | "describe" | "receive" => vec!["--config", "--profile"],
        "apply" => vec!["--config", "--profile", "--stage"],
        "recover" => vec!["--config", "--profile", "--operation"],
        _ => return Err("unknown publication operation".into()),
    };
    require(opts.keys().all(|k| allowed.contains(k)), "unknown option")?;
    if mode == "check-package" {
        let source = std::env::current_dir()?.join(get("--source")?);
        let report = std::env::current_dir()?.join(get("--offline-report")?);
        let zip = std::env::current_dir()?.join(get("--zip-report")?);
        let out = std::env::temp_dir()
            .canonicalize()?
            .join(format!("pathward-reviewed-{}", p::nonce()?));
        p::offline_package(&source, &report, &zip, &out)?;
        fs::remove_dir_all(out)?;
        println!("VERIFIED_OFFLINE_PACKAGE");
        return Ok(());
    }
    let id = get("--profile")?;
    let config = get("--config")?;
    if mode == "route" {
        require(
            f::absolute(Path::new(get("--binary")?)) && f::absolute(Path::new(config)),
            "installed remote paths required",
        )?;
        let value = codec::parse(
            remote(get("--remote")?, get("--binary")?, config, id, "mode", &[])?.as_bytes(),
        )?;
        let selected = codec::string(&value, "mode")?;
        require(
            ["legacy", "native"].contains(&selected),
            "unknown publication mode",
        )?;
        println!("{selected}");
        return Ok(());
    }
    if mode == "upload" {
        require(
            !opts.contains_key("--stage-only") || opts.get("--stage-only") == Some(&"yes"),
            "--stage-only must be yes",
        )?;
        let host = get("--remote")?;
        let exe = get("--binary")?;
        require(
            f::absolute(Path::new(exe)) && f::absolute(Path::new(config)),
            "installed absolute remote paths required",
        )?;
        let expected = codec::parse(remote(host, exe, config, id, "describe", &[])?.as_bytes())?;
        let temp = std::env::temp_dir()
            .canonicalize()?
            .join(format!("pathward-upload-{}", p::nonce()?));
        let source = PathBuf::from(get("--source")?);
        let mut source = if source.is_absolute() {
            source
        } else {
            std::env::current_dir()?.join(source)
        };
        require(
            opts.contains_key("--offline-report") == opts.contains_key("--zip-report"),
            "both offline and ZIP reports required",
        )?;
        let reviewed = if let Some(report) = opts.get("--offline-report") {
            let out = std::env::temp_dir()
                .canonicalize()?
                .join(format!("pathward-reviewed-{}", p::nonce()?));
            p::offline_package(
                &source,
                &std::env::current_dir()?.join(report),
                &std::env::current_dir()?.join(get("--zip-report")?),
                &out,
            )?;
            source = out.clone();
            Some(out)
        } else {
            None
        };
        p::prepare(
            &source,
            &expected,
            opts.get("--files").map(Path::new),
            &temp,
            &mut |_| Ok(()),
        )?;
        let incoming = remote(host, exe, config, id, "receive", &[])?;
        let incoming = incoming.trim();
        require(
            safe(incoming)
                && f::absolute(Path::new(incoming))
                && Path::new(incoming).parent()
                    == Some(
                        Path::new(codec::string(&expected, "work")?)
                            .join("uploads")
                            .as_path(),
                    ),
            "remote upload destination",
        )?;
        command(&words(&[
            "/usr/bin/rsync",
            "-rlt",
            "--chmod=Du=rwx,Dgo=,Fu=rw,Fgo=",
            "-e",
            "ssh -o BatchMode=yes -o ConnectTimeout=10",
            "--",
            &format!("{}/", temp.display()),
            &format!("{host}:{incoming}/"),
        ]))?;
        if opts.get("--stage-only") == Some(&"yes") {
            println!("STAGED {incoming}");
        } else {
            println!(
                "{}",
                remote(host, exe, config, id, "apply", &["--stage", incoming])?
            );
        }
        fs::remove_dir_all(temp)?;
        if let Some(out) = reviewed {
            fs::remove_dir_all(out)?;
        }
        return Ok(());
    }
    require(
        cfg!(target_os = "linux") && !rustix::process::geteuid().is_root(),
        "remote publication requires the unprivileged deployment account",
    )?;
    let config = confined::metadata(Path::new(config), 0)?;
    if mode == "mode" {
        require(
            config["profiles"].get(id).is_some() || config["manual_profiles"].get(id).is_some(),
            "unknown publication profile",
        )?;
        let _lease = pathward_admin::publication_gate::publisher(&config, None)?;
        println!(
            "{}",
            pathward_admin::publication_gate::observe(&config, &mut Real)?
        );
        return Ok(());
    }
    let profile = p::profile(&config, id)?;
    let result: Value = match mode.as_str() {
        "describe" => p::describe(&config, id, &mut Real)?,
        "receive" => {
            let _lease = pathward_admin::publication_gate::publisher(&config, None)?;
            pathward_admin::publication_gate::native_epoch(&config, &mut Real)?;
            let work = PathBuf::from(codec::string(profile, "work")?);
            f::directory(&work)?;
            let _lock = pathward_admin::publication::lock(&work)?;
            let uploads = work.join("uploads");
            f::directory(&uploads)?;
            require(
                fs::read_dir(&uploads)?.count() < 64,
                "upload retention limit",
            )?;
            let dest = uploads.join(p::nonce()?);
            f::directory(&dest)?;
            println!("{}", dest.display());
            return Ok(());
        }
        "apply" => {
            let stage = Path::new(get("--stage")?);
            require(
                stage.parent()
                    == Some(
                        Path::new(codec::string(profile, "work")?)
                            .join("uploads")
                            .as_path(),
                    )
                    && stage
                        .file_name()
                        .and_then(|s| s.to_str())
                        .is_some_and(p::operation),
                "upload outside profile workspace",
            )?;
            p::apply(&config, id, stage, &mut Real, &mut p::Curl, &mut |_| Ok(()))?
        }
        "recover" => {
            p::recover(&config, id, get("--operation")?, &mut Real, &mut |_| Ok(()))?;
            serde_json::json!({"restored":true})
        }
        _ => return Err("operation".into()),
    };
    println!("{}", result);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn remote_words_reject_shell_and_transport_syntax() {
        for word in [
            "/tmp/a b",
            "/tmp/a;id",
            "/tmp/$(id)",
            "-oProxyCommand=id",
            "a\nb",
            "",
        ] {
            assert!(!super::safe(word));
        }
        assert!(super::safe("deploy@example.test"));
        assert!(super::safe("/opt/publisher/uploads/0123456789abcdef"));
    }
}
