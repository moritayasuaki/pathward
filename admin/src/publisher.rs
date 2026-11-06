//! Profile-driven publication wrappers. Staging never contains application code.
use crate::{
    Result,
    codec::{self, string},
    confined as io, contract, publication as p, require, storage as f,
    storage::Checkpoint,
    system::{System, words},
};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
const TOTAL: u64 = 2 << 30;
#[cfg(test)]
#[path = "publisher_tests.rs"]
mod tests;
fn read_policy(config: &Value) -> Result<Value> {
    #[cfg(test)]
    let owner = rustix::process::geteuid().as_raw();
    #[cfg(not(test))]
    let owner = 0;
    io::metadata(Path::new(string(config, "hosting_policy")?), owner)
}

pub fn operation(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
pub fn nonce() -> Result<String> {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "randomness unavailable")?;
    Ok(b.iter().map(|n| format!("{n:02x}")).collect())
}
pub fn safe_asset(name: &str) -> bool {
    let p = Path::new(name);
    public_path(name)
        && (p.extension().and_then(|n| n.to_str()).is_some_and(|s| {
            [
                "html", "css", "js", "mjs", "json", "svg", "png", "jpg", "jpeg", "webp", "ico",
                "txt", "md", "xml", "pdf", "zip", "gz", "wasm", "onnx", "udpipe", "lean", "map",
                "woff", "woff2",
            ]
            .contains(&s.to_ascii_lowercase().as_str())
        }) || p
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|s| ["LICENSE", "NOTICE", "COPYING", "ATTRIBUTION"].contains(&s))
            || license_document(name))
}
fn license_document(name: &str) -> bool {
    name.starts_with("licenses/")
        && name.rsplit('/').next().is_some_and(|n| {
            let n = n.to_ascii_lowercase();
            ["license", "notice", "copying", "attribution"].contains(&n.as_str())
                || n.starts_with("license-")
                || n.ends_with("-license")
        })
}
fn public_path(name: &str) -> bool {
    io::relative(name)
        && !name.split('/').any(|n| {
            [
                "bin",
                "private",
                "deploy",
                "scripts",
                "tests",
                "reports",
                "node_modules",
            ]
            .contains(&n)
        })
        && (!name.split('/').any(|n| n == "server") || license_document(name))
}
fn asset_contract(v: &Value) -> Result<()> {
    let index = v["index"].as_str().unwrap_or("index.html");
    require(
        safe_asset(index) && !index.contains('/'),
        "public root index",
    )?;
    if let Some(names) = v.get("reviewed_assets") {
        let names = names.as_array().ok_or("reviewed asset names")?;
        let mut seen = std::collections::BTreeSet::new();
        require(names.len() <= 256, "reviewed asset count")?;
        for name in names {
            let name = name.as_str().ok_or("reviewed asset name")?;
            require(
                public_path(name)
                    && seen.insert(name)
                    && Path::new(name)
                        .extension()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| ["pem", "sig", "ps1", "traineddata"].contains(&s)),
                "unsupported reviewed asset",
            )?;
        }
    }
    Ok(())
}
fn permitted_asset(v: &Value, name: &str) -> bool {
    pathward::bootstrap::reviewed_asset_allowed(
        public_path(name),
        safe_asset(name),
        v["reviewed_assets"]
            .as_array()
            .is_some_and(|a| a.iter().any(|n| n == name)),
    )
}
pub fn scan(path: &Path) -> Result<Value> {
    scan_reviewed(path, &json!({}))
}
fn scan_reviewed(path: &Path, authority: &Value) -> Result<Value> {
    asset_contract(authority)?;
    let root = io::absolute(path)?;
    let mut out = json!({});
    let mut total = 0;
    for name in io::names(&root)? {
        if name == "_headers" {
            continue;
        }
        require(
            permitted_asset(authority, &name),
            "nonpublic asset path or type",
        )?;
        let item = io::stream(io::leaf(&root, &name)?, None, io::MAX_FILE)?;
        total += item["bytes"].as_u64().ok_or("asset size")?;
        require(total <= TOTAL, "publication capacity")?;
        out[&name] = item["sha256"].clone();
    }
    require(
        out[authority["index"].as_str().unwrap_or("index.html")].is_string(),
        "declared root index required",
    )?;
    require(
        codec::canonical(&out).len() < codec::LIMIT / 2,
        "inventory metadata bound",
    )?;
    Ok(out)
}
fn private(path: &Path) -> Result<()> {
    f::directory(path)?;
    let m = fs::symlink_metadata(path)?;
    require(
        m.uid() == rustix::process::geteuid().as_raw() && m.mode() & 0o777 == 0o700,
        "private publisher workspace required",
    )
}
fn directories(root: &Path, name: &str, mode: u32) -> Result<()> {
    let mut path = root.to_path_buf();
    if let Some(parent) = Path::new(name).parent() {
        for part in parent.components() {
            path.push(part);
            f::directory(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}
fn copy(root: &File, name: &str, dest: &Path, mode: u32, cp: Checkpoint<'_>) -> Result<String> {
    let parent = dest.parent().ok_or("copy parent")?;
    f::trusted(dest)?;
    let temp = parent.join(format!("copy-{}", nonce()?));
    let fd = rustix::fs::open(
        &temp,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(mode as _),
    )?;
    let mut output = File::from(fd);
    output.set_permissions(fs::Permissions::from_mode(mode))?;
    let result = (|| {
        let item = io::stream(io::leaf(root, name)?, Some(&mut output), io::MAX_FILE)?;
        cp("asset-copy-synced")?;
        fs::rename(&temp, dest)?;
        f::sync_dir(parent)?;
        cp("asset-renamed")?;
        Ok(string(&item, "sha256")?.to_owned())
    })();
    let _ = fs::remove_file(temp);
    result
}
pub fn origin(s: &str) -> bool {
    if let Some(host) = s.strip_prefix("https://") {
        return !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|p| {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
    }
    s.strip_prefix("http://127.0.0.1:")
        .and_then(|p| p.parse::<u16>().ok())
        .is_some_and(|p| p >= 1024)
}
pub fn profile<'a>(config: &'a Value, id: &str) -> Result<&'a Value> {
    require(
        config["schema"] == 1 && io::relative(id) && !id.contains('/'),
        "publisher config/profile",
    )?;
    let v = config["profiles"]
        .get(id)
        .ok_or("unknown publisher profile")?;
    asset_contract(v)?;
    require(
        ["release", "backend"].contains(&string(v, "kind")?)
            && f::absolute(Path::new(string(v, "work")?))
            && origin(string(v, "origin")?),
        "publisher profile contract",
    )?;
    require(
        v["checks"].as_object().is_some_and(|x| x.len() <= 4096),
        "public checks map required",
    )?;
    for (path, h) in v["checks"].as_object().unwrap() {
        require(
            (path == "/" || io::relative(path.strip_prefix('/').unwrap_or("")))
                && h.as_str().is_some_and(codec::digest),
            "public check path/digest",
        )?;
    }
    if let Some(extra) = v.get("extra_checks") {
        let extra = extra.as_array().ok_or("extra public checks")?;
        require(extra.len() <= 128, "extra public check count")?;
        for check in extra {
            http_check_contract(check)?;
        }
    }
    Ok(v)
}
fn backend<S: System>(sys: &mut S, v: &Value) -> Result<Value> {
    let unit = string(v, "unit")?;
    require(contract::unit_name(unit), "backend unit")?;
    let manager = v["manager"].as_str().unwrap_or("system");
    require(
        ["system", "user"].contains(&manager),
        "service manager scope",
    )?;
    let mut property = |key: &str| -> Result<String> {
        if manager == "system" {
            sys.property(unit, key)
        } else {
            Ok(sys
                .checked(
                    &words(&[
                        "/usr/bin/systemctl",
                        "--user",
                        "show",
                        unit,
                        &format!("--property={key}"),
                        "--value",
                    ]),
                    45,
                )?
                .trim()
                .to_owned())
        }
    };
    let expected = v["properties"].as_object().ok_or("backend properties")?;
    require(
        expected.get("NoNewPrivileges") == Some(&json!("yes"))
            && expected.contains_key("WorkingDirectory")
            && (expected.contains_key("Environment")
                || v["environment_sha256"].as_str().is_some_and(codec::digest))
            && expected.contains_key("FragmentPath"),
        "backend isolation/routing contract required",
    )?;
    require(property("ActiveState")? == "active", "backend is inactive")?;
    let mut out = json!({});
    if let Some(hash) = v.get("environment_sha256") {
        require(
            !expected.contains_key("Environment") && hash.as_str().is_some_and(codec::digest),
            "choose exact environment or digest binding",
        )?;
        let actual = codec::hash(property("Environment")?.as_bytes());
        require(hash == &actual, "backend environment changed")?;
        out["environment_sha256"] = actual.into();
    }
    for (key, value) in expected {
        require(
            [
                "WorkingDirectory",
                "Environment",
                "FragmentPath",
                "NoNewPrivileges",
                "DynamicUser",
                "ProtectSystem",
                "ProtectHome",
            ]
            .contains(&key.as_str()),
            "unsupported backend property",
        )?;
        let actual = property(key)?;
        require(
            value.as_str() == Some(&actual),
            "backend routing/isolation changed",
        )?;
        out[key] = actual.into();
    }
    for key in ["MainPID", "ExecMainStartTimestampMonotonic"] {
        let raw = property(key)?;
        require(
            raw.parse::<u64>()? > 0,
            "backend process identity unavailable",
        )?;
        out[key] = raw.into();
    }
    let executable = string(v, "executable")?;
    let start_executable = v["exec_start"].as_str().unwrap_or(executable);
    let mut working = PathBuf::from(string(&v["properties"], "WorkingDirectory")?);
    if let Some(base) = v.get("release_base") {
        let base = Path::new(base.as_str().ok_or("backend release base")?);
        require(
            working == base.join("current"),
            "backend current alias differs",
        )?;
        let reference = io::reference(&io::absolute(base)?)?;
        working = base.join(&reference);
        out["release_reference"] = reference.into();
        if start_executable != executable {
            let suffix = Path::new(start_executable).strip_prefix(base.join("current"))?;
            require(
                suffix.to_str().is_some_and(io::relative)
                    && working.join(suffix) == Path::new(executable),
                "backend executable alias differs from sealed release",
            )?;
        }
    } else {
        require(
            start_executable == executable,
            "unbound backend executable alias",
        )?;
    }
    let files = v["sealed_files"]
        .as_object()
        .ok_or("backend sealed files")?;
    require(
        !files.is_empty()
            && files.len() <= 16
            && files.contains_key(string(&v["properties"], "FragmentPath")?)
            && files.contains_key(string(v, "executable")?),
        "backend binary and unit must be pinned",
    )?;
    for (path, hash) in files {
        let path = Path::new(path);
        let root = io::absolute(path.parent().ok_or("resource parent")?)?;
        let h = io::stream(
            io::leaf(
                &root,
                path.file_name().unwrap().to_str().ok_or("resource name")?,
            )?,
            None,
            256 << 20,
        )?;
        require(
            hash.as_str().is_some_and(codec::digest) && h["sha256"] == *hash,
            "backend sealed file changed",
        )?;
    }
    let observation = v["executable_observation"].as_str().unwrap_or("proc");
    require(
        ["proc", "systemd"].contains(&observation),
        "executable observation mode",
    )?;
    if observation == "systemd" {
        let start = property("ExecStart")?;
        let expected = format!("{{ path={start_executable} ;");
        require(
            start.starts_with(&expected) && start.matches("{ path=").count() == 1,
            "loaded backend executable differs",
        )?;
    } else {
        #[cfg(target_os = "linux")]
        require(
            fs::read_link(format!("/proc/{}/exe", string(&out, "MainPID")?))?
                == Path::new(string(v, "executable")?),
            "running backend executable differs",
        )?;
    }
    let root = Path::new(string(v, "root")?);
    let subdir = v["public_subdir"].as_str().unwrap_or("public");
    require(
        ["public", "dist"].contains(&subdir),
        "backend static subtree",
    )?;
    require(
        root == working.join(subdir),
        "backend public directory differs",
    )?;
    out["root"] = v["root"].clone();
    Ok(out)
}
pub fn describe<S: System>(config: &Value, id: &str, sys: &mut S) -> Result<Value> {
    let _lease = crate::publication_gate::publisher(config, None)?;
    let epoch = crate::publication_gate::native_epoch(config, sys)?;
    let v = profile(config, id)?;
    let policy = read_policy(config)?;
    p::validate(&policy)?;
    let site = policy["sites"]
        .as_array()
        .ok_or("sites")?
        .iter()
        .find(|s| s["id"] == id)
        .ok_or("hosting profile missing")?;
    require(
        v["host"] == site["host"]
            && (string(v, "origin")? == format!("https://{}", string(site, "host")?)
                || string(v, "origin")?.starts_with("http://127.0.0.1:")),
        "verification host differs from routing",
    )?;
    let mut out = json!({"schema":1,"profile":id,"config_sha256":codec::hash(&codec::canonical(config)),"policy_sha256":codec::hash(&p::encoded(&policy)),"work":v["work"]});
    let index = v["index"].as_str().unwrap_or("index.html");
    require(
        site["index"] == index,
        "publisher root index differs from hosting policy",
    )?;
    if let Some(names) = v["reviewed_assets"].as_array() {
        for name in names {
            let url = format!("/{}", name.as_str().ok_or("asset name")?);
            require(
                site["public_paths"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|p| p == &url)),
                "reviewed asset must be explicitly public in hosting policy",
            )?;
        }
        out["reviewed_assets"] = v["reviewed_assets"].clone();
    }
    out["index"] = index.into();
    if let Some(epoch) = epoch {
        require(
            epoch["policy_sha256"] == out["policy_sha256"],
            "native bridge policy differs",
        )?;
        out["epoch"] = epoch;
    }
    let root = if v["kind"] == "release" {
        require(site["source_base"].is_string(), "static source required")?;
        let base = Path::new(string(site, "source_base")?);
        let fd = io::absolute(base)?;
        let r = io::reference(&fd)?;
        out["current"] = r.clone().into();
        out["source_base"] = site["source_base"].clone();
        base.join(r).join("public")
    } else {
        let authority = backend(sys, v)?;
        let upstream = string(v, "upstream")?;
        require(
            upstream
                .strip_prefix("127.0.0.1:")
                .and_then(|s| s.parse::<u16>().ok())
                .is_some()
                && site["directives"]
                    .as_array()
                    .ok_or("directives")?
                    .iter()
                    .filter(|n| n[0] == "reverse-proxy")
                    .count()
                    == 1
                && site["directives"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|n| n[0] == "reverse-proxy" && n[1] == upstream),
            "backend is not the configured default upstream",
        )?;
        out["backend"] = authority;
        PathBuf::from(string(v, "root")?)
    };
    require(
        sys.property("pathward.service", "ActiveState")? == "active",
        "publisher requires active PathWard",
    )?;
    out["files"] = scan_reviewed(&root, &out)?;
    out["root"] = json!(root);
    Ok(out)
}
/// Check the exact offline/browser-tested package before copying public members.
/// release.json is build metadata and is deliberately excluded from publication.
pub fn offline_package(source: &Path, report: &Path, zip_report: &Path, out: &Path) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    let package = io::metadata(&source.join("release.json"), uid)?;
    let report = io::metadata(report, uid)?;
    let zip = io::metadata(zip_report, uid)?;
    require(
        report["passed"] == true
            && report["errors"].as_array().is_some_and(Vec::is_empty)
            && report["externalRequests"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && report["release"] == package["release"]
            && report["files"] == package["files"],
        "offline report does not match package",
    )?;
    let files = package["files"].as_object().ok_or("offline file map")?;
    require(
        !files.is_empty()
            && files.len() <= io::MAX_FILES
            && zip["passed"] == true
            && zip["release"] == package["release"]
            && zip["zipSha256"].as_str().is_some_and(codec::digest)
            && files
                .iter()
                .any(|(n, v)| n.ends_with(".zip") && v["sha256"] == zip["zipSha256"]),
        "offline ZIP report mismatch",
    )?;
    let root = io::absolute(source)?;
    let mut expected: std::collections::BTreeSet<_> = files.keys().cloned().collect();
    expected.insert("release.json".into());
    require(
        io::names(&root)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            == expected,
        "offline package membership",
    )?;
    require(
        out.symlink_metadata().is_err(),
        "offline staging already exists",
    )?;
    private(out)?;
    let mut total = 0;
    for (name, item) in files {
        require(safe_asset(name), "offline package public name")?;
        let meta = io::stream(io::leaf(&root, name)?, None, io::MAX_FILE)?;
        require(
            meta["sha256"] == item["sha256"] && meta["bytes"] == item["bytes"],
            "offline package digest or size mismatch",
        )?;
        total += meta["bytes"].as_u64().ok_or("offline size")?;
        require(total <= TOTAL, "offline capacity")?;
        directories(out, name, 0o700)?;
        require(
            copy(&root, name, &out.join(name), 0o600, &mut |_| Ok(()))? == string(item, "sha256")?,
            "offline file changed",
        )?;
    }
    Ok(())
}
pub fn prepare(
    source: &Path,
    expected: &Value,
    allowlist: Option<&Path>,
    stage: &Path,
    cp: Checkpoint<'_>,
) -> Result<Value> {
    require(
        stage.symlink_metadata().is_err(),
        "staging directory already exists",
    )?;
    let files = scan_reviewed(source, expected)?;
    if let Some(list) = allowlist {
        let text = fs::read_to_string(list)?;
        require(text.len() <= codec::LIMIT, "allowlist limit")?;
        let mut names = std::collections::BTreeSet::new();
        for line in text.lines() {
            if [".nojekyll", "_headers"].contains(&line) {
                continue;
            }
            require(names.insert(line.to_owned()), "duplicate allowlist member")?;
        }
        require(
            names == files.as_object().unwrap().keys().cloned().collect(),
            "reviewed public allowlist differs",
        )?;
    }
    private(stage)?;
    let public = stage.join("public");
    private(&public)?;
    let src = io::absolute(source)?;
    for (name, hash) in files.as_object().unwrap() {
        directories(&public, name, 0o700)?;
        require(
            copy(&src, name, &public.join(name), 0o600, cp)? == hash.as_str().unwrap(),
            "source changed while preparing",
        )?;
    }
    require(
        scan_reviewed(&public, expected)? == files && scan_reviewed(source, expected)? == files,
        "publication source changed",
    )?;
    let manifest = json!({"schema":1,"operation":nonce()?,"expected":expected,"files":files});
    f::write_record(
        &stage.join("manifest.json"),
        &manifest,
        "upload-manifest",
        cp,
    )?;
    Ok(manifest)
}
pub trait Verify {
    fn check(&mut self, v: &Value, files: &Value, work: &Path) -> Result<()>;
}
pub struct Curl;
fn http_check_contract(v: &Value) -> Result<()> {
    let host = string(v, "host")?;
    let base = string(v, "origin")?;
    let path = string(v, "path")?;
    require(
        !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            && origin(base)
            && (!base.starts_with("https:") || base == format!("https://{host}"))
            && path.starts_with('/')
            && path.len() <= 2048
            && path
                .bytes()
                .all(|b| (33..=126).contains(&b) && !b"#\\".contains(&b))
            && [json!(200), json!(308), json!(404)].contains(&v["status"]),
        "public check URL/status contract",
    )?;
    if let Some(hash) = v.get("sha256") {
        require(
            hash.as_str().is_some_and(codec::digest),
            "public check digest",
        )?;
    }
    if let Some(headers) = v.get("headers") {
        let headers = headers.as_object().ok_or("public check headers")?;
        require(headers.len() <= 32, "public check header count")?;
        for (key, value) in headers {
            require(
                !key.is_empty()
                    && key.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
                    && value
                        .as_str()
                        .is_some_and(|s| s.len() <= 8192 && !s.bytes().any(|b| b < 32 || b == 127)),
                "public check header contract",
            )?;
        }
    }
    Ok(())
}
fn curl_check(v: &Value, work: &Path) -> Result<()> {
    http_check_contract(v)?;
    let base = string(v, "origin")?;
    let path = string(v, "path")?;
    let host = string(v, "host")?;
    let target = work.join(format!("download-{}", nonce()?));
    // The enclosing workspace is private; the result is never an uploaded path.
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)?;
    let limit = if v.get("sha256").is_some() {
        io::MAX_FILE
    } else {
        1 << 20
    };
    let args = words(&[
        "/usr/bin/curl",
        "--disable",
        "--silent",
        "--show-error",
        "--noproxy",
        "*",
        "--proto",
        if base.starts_with("https:") {
            "=https"
        } else {
            "=http"
        },
        "--globoff",
        "--path-as-is",
        "--max-redirs",
        "0",
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "--max-filesize",
        &limit.to_string(),
        "--header",
        "Accept-Encoding: identity",
        "--header",
        "Cache-Control: no-cache",
        "--header",
        &format!("Host: {host}"),
        "--output",
        target.to_str().unwrap(),
        "--write-out",
        "%{http_code}\n%{header_json}",
        &format!("{base}{path}"),
    ]);
    let result = (|| {
        let (ok, text) = crate::system::capture(&args, 40, 65536)?;
        let (status, headers) = text.split_once('\n').ok_or("HTTP observation")?;
        require(
            ok && status.len() == 3 && status.parse::<u64>().ok() == v["status"].as_u64(),
            "public HTTP validation failed",
        )?;
        let headers = codec::parse(headers.as_bytes())?;
        if let Some(expected) = v["headers"].as_object() {
            for (key, value) in expected {
                require(
                    headers[key] == json!([value]),
                    "public response header differs",
                )?;
            }
        }
        let fd = io::absolute(work)?;
        let item = io::stream(
            io::leaf(&fd, target.file_name().unwrap().to_str().unwrap())?,
            None,
            limit,
        )?;
        if let Some(hash) = v.get("sha256") {
            require(item["sha256"] == *hash, "public response digest differs")?;
        } else if v["status"] == 200 {
            require(
                item["bytes"].as_u64().is_some_and(|n| n > 0),
                "empty public response",
            )?;
        }
        Ok(())
    })();
    fs::remove_file(target)?;
    result
}
impl Verify for Curl {
    fn check(&mut self, v: &Value, files: &Value, work: &Path) -> Result<()> {
        let mut checks = v["checks"].as_object().ok_or("checks")?.clone();
        for (name, h) in files.as_object().ok_or("files")? {
            require(permitted_asset(v, name), "verification path")?;
            checks.insert(format!("/{name}"), h.clone());
            if name == v["index"].as_str().unwrap_or("index.html") {
                checks.insert("/".into(), h.clone());
            }
        }
        for (path, hash) in checks {
            curl_check(
                &json!({"origin":v["origin"],"host":v["host"],"path":path,"status":200,"sha256":hash}),
                work,
            )?;
        }
        if let Some(extra) = v.get("extra_checks") {
            let extra = extra.as_array().ok_or("extra public checks")?;
            require(extra.len() <= 128, "extra public check count")?;
            for check in extra {
                curl_check(check, work)?;
            }
        }
        Ok(())
    }
}

fn hashes(root: &Path, names: &Value) -> Result<Value> {
    let mut out = json!({});
    let fd = io::absolute(root)?;
    for name in names.as_object().ok_or("file map")?.keys() {
        out[name] = io::stream(io::leaf(&fd, name)?, None, io::MAX_FILE)?["sha256"].clone();
    }
    Ok(out)
}
fn immutable(v: &Value, name: &str) -> bool {
    v["immutable_prefixes"].as_array().is_some_and(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .any(|p| name.starts_with(p))
    }) || name.split('/').next_back().is_some_and(|n| {
        n.as_bytes()
            .windows(12)
            .any(|w| w.iter().all(u8::is_ascii_hexdigit))
    })
}
fn additive(v: &Value, name: &str) -> bool {
    v["additive_prefixes"].as_array().is_some_and(|a| {
        a.iter().filter_map(Value::as_str).any(|p| {
            !p.is_empty()
                && p.ends_with('/')
                && io::relative(p.trim_end_matches('/'))
                && name.starts_with(p)
        })
    })
}
fn ordered(files: &Value, rollback: bool) -> Vec<String> {
    let mut names: Vec<_> = files.as_object().unwrap().keys().cloned().collect();
    names.sort_by_key(|n| {
        if rollback {
            (!n.ends_with(".html"), false, n.clone())
        } else {
            (n.ends_with(".html"), n == "index.html", n.clone())
        }
    });
    names
}

pub fn recover<S: System>(
    config: &Value,
    id: &str,
    operation_id: &str,
    sys: &mut S,
    cp: Checkpoint<'_>,
) -> Result<()> {
    let _lease = crate::publication_gate::publisher(config, Some(id))?;
    crate::publication_gate::native_epoch(config, sys)?;
    require(operation(operation_id), "operation identity")?;
    let v = profile(config, id)?;
    let work = Path::new(string(v, "work")?);
    let _lock = p::lock(work)?;
    restore(config, id, &work.join(operation_id), sys, cp)
}
fn restore<S: System>(
    config: &Value,
    id: &str,
    job: &Path,
    sys: &mut S,
    cp: Checkpoint<'_>,
) -> Result<()> {
    let record = f::record(&job.join("transaction.json"))?;
    require(
        record["profile"] == id
            && record["config_sha256"] == codec::hash(&codec::canonical(config)),
        "rollback authority",
    )?;
    if record["phase"] == "complete" || record["phase"] == "restored" {
        return Ok(());
    }
    require(record["phase"] == "prepared", "unknown publication phase")?;
    let v = profile(config, id)?;
    if v["kind"] == "release" {
        let expected = &record["expected"];
        let base = io::absolute(Path::new(string(expected, "source_base")?))?;
        let current = io::reference(&base)?;
        if current != string(expected, "current")? {
            require(
                current == string(&record, "reference")?,
                "newer publication retained; rollback refused",
            )?;
            let policy = read_policy(config)?;
            require(
                codec::hash(&p::encoded(&policy)) == expected["policy_sha256"],
                "rollback policy changed",
            )?;
            p::publish(
                &policy,
                Path::new(string(config, "receipt")?),
                config["receipt_owner"]
                    .as_u64()
                    .ok_or("receipt owner")?
                    .try_into()?,
                id,
                &current,
                string(expected, "current")?,
                &expected["files"],
                sys,
                cp,
            )?;
        }
        let mut done = record;
        done["phase"] = "restored".into();
        return f::write_record(
            &job.join("transaction.json"),
            &done,
            "publication-restored",
            cp,
        );
    }
    let expected = &record["expected"];
    let actual = describe(config, id, sys)?;
    require(
        actual["backend"] == expected["backend"]
            && actual["policy_sha256"] == expected["policy_sha256"],
        "backend changed; explicit recovery review required",
    )?;
    let root = Path::new(string(expected, "root")?);
    let current = io::absolute(root)?;
    let backups = io::absolute(&job.join("backup"))?;
    for name in ordered(&record["files"], true) {
        let now = io::leaf(&current, &name)
            .and_then(|f| io::stream(f, None, io::MAX_FILE))
            .ok()
            .map(|v| v["sha256"].clone());
        let old = &expected["files"][&name];
        let verified = old.is_null()
            || io::stream(io::leaf(&backups, &name)?, None, io::MAX_FILE)?["sha256"] == *old;
        if pathward::bootstrap::restore_allowed(
            backend(sys, v)? == expected["backend"],
            now.as_ref() == Some(&record["files"][&name]),
            verified,
        ) {
            if old.is_null() {
                fs::remove_file(root.join(&name))?;
                f::sync_dir(root.join(&name).parent().unwrap())?;
            } else {
                require(
                    copy(&backups, &name, &root.join(&name), 0o644, cp)?
                        == old.as_str().ok_or("backup hash")?,
                    "backup changed during restoration",
                )?;
            }
        } else {
            require(
                now.as_ref() == Some(old) || (now.is_none() && old.is_null()),
                "newer edit retained; rollback incomplete",
            )?;
        }
    }
    let mut done = record;
    done["phase"] = "restored".into();
    f::write_record(
        &job.join("transaction.json"),
        &done,
        "publication-restored",
        cp,
    )
}
pub fn apply<S: System, V: Verify>(
    config: &Value,
    id: &str,
    stage: &Path,
    sys: &mut S,
    verify: &mut V,
    cp: Checkpoint<'_>,
) -> Result<Value> {
    let _lease = crate::publication_gate::publisher(config, Some(id))?;
    crate::publication_gate::native_epoch(config, sys)?;
    let v = profile(config, id)?;
    let work = Path::new(string(v, "work")?);
    private(work)?;
    let _lock = p::lock(work)?;
    let active = work.join("active.json");
    if active.symlink_metadata().is_ok() {
        let a = f::record(&active)?;
        let op = string(&a, "operation")?;
        require(operation(op), "active operation")?;
        let prior = f::record(&work.join(op).join("transaction.json"))?;
        require(
            ["complete", "restored"].contains(&string(&prior, "phase")?),
            "unfinished publication requires recovery",
        )?;
    }
    require(
        fs::read_dir(work)?.count() < 128,
        "publisher workspace retention limit",
    )?;
    let manifest = f::record(&stage.join("manifest.json"))?;
    let op = string(&manifest, "operation")?;
    require(
        manifest["schema"] == 1 && operation(op) && manifest["expected"]["profile"] == id,
        "upload manifest scope",
    )?;
    let expected = &manifest["expected"];
    let files = &manifest["files"];
    let sealed = scan_reviewed(&stage.join("public"), v)? == *files;
    let unchanged = describe(config, id, sys)? == *expected;
    let meta = fs::symlink_metadata(stage)?;
    require(
        pathward::bootstrap::package_allowed(
            sealed,
            manifest["expected"]["config_sha256"] == codec::hash(&codec::canonical(config)),
            meta.uid() == rustix::process::geteuid().as_raw() && meta.mode() & 0o777 == 0o700,
            unchanged,
        ),
        "upload changed or stale",
    )?;
    let job = work.join(op);
    require(
        job.symlink_metadata().is_err(),
        "operation already exists; recover or prepare a new upload",
    )?;
    private(&job)?;
    let incoming = job.join("incoming");
    private(&incoming)?;
    let src = io::absolute(&stage.join("public"))?;
    for (name, hash) in files.as_object().ok_or("files")? {
        require(permitted_asset(v, name), "public file name")?;
        let old = &expected["files"][name];
        require(
            pathward::bootstrap::asset_allowed(
                !old.is_null(),
                v["kind"] == "release" || additive(v, name),
                immutable(v, name),
                old == hash,
            ),
            "unreviewed route or immutable asset collision",
        )?;
        directories(&incoming, name, 0o755)?;
        require(
            copy(&src, name, &incoming.join(name), 0o644, cp)?
                == hash.as_str().ok_or("file digest")?,
            "upload changed during copy",
        )?;
    }
    require(
        describe(config, id, sys)? == *expected,
        "live publication changed while staging",
    )?;
    let mut transaction = json!({"phase":"prepared","profile":id,"config_sha256":expected["config_sha256"],"expected":expected,"files":files});
    if v["kind"] == "release" {
        let base = Path::new(string(expected, "source_base")?);
        let release = format!("releases/{op}");
        let dir = base.join(&release);
        require(dir.symlink_metadata().is_err(), "release already exists")?;
        f::directory(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;
        fs::rename(&incoming, dir.join("public"))?;
        fs::set_permissions(dir.join("public"), fs::Permissions::from_mode(0o755))?;
        f::sync_dir(&dir)?;
        f::sync_dir(work)?;
        transaction["reference"] = release.clone().into();
        f::write_record(
            &job.join("transaction.json"),
            &transaction,
            "publication-intent",
            cp,
        )?;
        f::write_record(&active, &json!({"operation":op}), "publication-active", cp)?;
        let policy = read_policy(config)?;
        require(
            codec::hash(&p::encoded(&policy)) == expected["policy_sha256"],
            "publication policy changed before switch",
        )?;
        p::publish_checked(
            &policy,
            Path::new(string(config, "receipt")?),
            config["receipt_owner"]
                .as_u64()
                .ok_or("receipt owner")?
                .try_into()?,
            id,
            string(expected, "current")?,
            &release,
            files,
            sys,
            cp,
            &mut |sys| {
                verify.check(v, files, &job)?;
                require(
                    crate::publication_gate::native_epoch(config, sys)?
                        == expected.get("epoch").cloned(),
                    "bridge restarted during publication",
                )
            },
        )?;
        transaction["reference"] = release.into();
    } else {
        let root = Path::new(string(expected, "root")?);
        let backups = job.join("backup");
        private(&backups)?;
        let live = io::absolute(root)?;
        for name in files.as_object().unwrap().keys() {
            if !expected["files"][name].is_null() {
                directories(&backups, name, 0o700)?;
                require(
                    copy(&live, name, &backups.join(name), 0o600, cp)?
                        == expected["files"][name].as_str().unwrap(),
                    "backup source changed",
                )?;
            }
        }
        f::write_record(
            &job.join("transaction.json"),
            &transaction,
            "publication-intent",
            cp,
        )?;
        f::write_record(&active, &json!({"operation":op}), "publication-active", cp)?;
        let result: Result<()> = (|| {
            let ready = io::absolute(&incoming)?;
            for name in ordered(files, false) {
                if files[&name] == expected["files"][&name] {
                    continue;
                }
                require(
                    backend(sys, v)? == expected["backend"],
                    "backend changed before asset replacement",
                )?;
                let observed = scan_reviewed(root, v)?;
                require(
                    observed[&name] == expected["files"][&name],
                    "concurrent public edit",
                )?;
                directories(root, &name, 0o755)?;
                copy(&ready, &name, &root.join(&name), 0o644, cp)?;
            }
            verify.check(v, files, &job)?;
            let after = describe(config, id, sys)?;
            require(
                after["backend"] == expected["backend"]
                    && after["policy_sha256"] == expected["policy_sha256"]
                    && after["epoch"] == expected["epoch"]
                    && hashes(root, files)? == *files,
                "backend or public files changed during verification",
            )?;
            Ok(())
        })();
        if result.is_err() {
            restore(config, id, &job, sys, &mut |_| Ok(()))?;
        }
        result?;
    }
    transaction["phase"] = "complete".into();
    f::write_record(
        &job.join("transaction.json"),
        &transaction,
        "publication-complete",
        cp,
    )?;
    Ok(
        json!({"profile":id,"operation":op,"files":files.as_object().unwrap().len(),"service_restart":false,"verified":true}),
    )
}
