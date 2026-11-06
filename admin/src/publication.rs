//! Unprivileged publication bridge, immutable captures, CAS and boot-bound receipts.
use crate::{
    Result,
    codec::{self, string},
    confined as io, require, storage as f,
    storage::Checkpoint,
    system::{System, words},
};
use pathward::publication as policy;
use serde_json::{Value, json};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const SNAPSHOT_BYTES: u64 = 2 << 30;
const STATE_BYTES: u64 = 8 << 30;
const DIRECTIVES: &[&str] = &[
    "encode",
    "header",
    "header-prefix",
    "header-query",
    "cache",
    "cache-prefix",
    "redirect",
    "redirect-prefix",
    "redirect-fallback",
    "deny",
    "proxy-route",
    "proxy-resource",
    "reverse-proxy",
    "proxy-limit",
    "proxy-timeout",
    "proxy-stream",
    "websocket-origin",
    "websocket-compression",
];
pub fn encoded(v: &Value) -> Vec<u8> {
    let mut b = codec::canonical(v);
    b.push(b'\n');
    b
}
fn object<'a>(v: &'a Value, key: &str) -> Result<&'a serde_json::Map<String, Value>> {
    v[key]
        .as_object()
        .ok_or_else(|| format!("missing object {key}").into())
}
pub fn clock() -> Result<Value> {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    require(
        boot.len() == 36 && boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "boot identity",
    )?;
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let ns = u64::try_from(t.tv_sec)?
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(t.tv_nsec as u64))
        .ok_or("clock overflow")?;
    Ok(json!({"boot":boot,"ns":ns}))
}
pub fn validate(p: &Value) -> Result<()> {
    require(
        p["schema"] == 1 && p["capacity"] == "shared-nat",
        "hosting schema",
    )?;
    let sites = p["sites"].as_array().ok_or("sites")?;
    require(!sites.is_empty() && sites.len() <= 16, "site count")?;
    let mut ids = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    for s in sites {
        let id = string(s, "id")?;
        let host = string(s, "host")?;
        require(
            !id.is_empty()
                && id.len() <= 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && ids.insert(id),
            "site identity",
        )?;
        require(
            !host.is_empty()
                && host.len() <= 253
                && host
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
                && hosts.insert(host),
            "host identity",
        )?;
        require(
            s.get("source_base").is_some()
                && (s["source_base"].is_null()
                    || s["source_base"]
                        .as_str()
                        .is_some_and(|v| f::absolute(Path::new(v)))),
            "source base",
        )?;
        require(
            io::relative(string(s, "index")?) && !string(s, "index")?.contains('/'),
            "index name",
        )?;
        require(
            s.get("public_paths").is_some(),
            "missing explicit publication policy",
        )?;
        if let Some(a) = s["public_paths"].as_array() {
            require(a.len() <= io::MAX_FILES, "public URL count")?;
            let mut unique = BTreeSet::new();
            for u in a {
                let u = u.as_str().ok_or("public URL")?;
                require(
                    pathward::valid_path(u.as_bytes()) && unique.insert(u),
                    "public URL",
                )?;
            }
        } else {
            require(s["public_paths"].is_null(), "public URL list")?;
        }
        if let Some(a) = s.get("directory_indexes") {
            let a = a.as_array().ok_or("directory indexes")?;
            require(a.len() <= 8, "index count")?;
            for i in a {
                let i = i.as_str().ok_or("directory index")?;
                require(io::relative(i) && !i.contains('/'), "directory index")?;
            }
        }
        let synthetic = object(s, "synthetic_files")?;
        require(synthetic.len() <= 8, "synthetic count")?;
        for (name, text) in synthetic {
            require(
                io::relative(name) && text.as_str().is_some_and(|t| t.len() <= 65536),
                "synthetic file",
            )?;
        }
        let nodes = s["directives"].as_array().ok_or("directives")?;
        require(nodes.len() <= 4096, "directive count")?;
        for n in nodes {
            let a = n.as_array().ok_or("directive")?;
            require(
                (2..=5).contains(&a.len())
                    && a[0].as_str().is_some_and(|s| DIRECTIVES.contains(&s)),
                "unreviewed directive",
            )?;
            for v in a {
                require(
                    v.as_str().is_some_and(|s| {
                        s.len() <= 4096 && s.bytes().all(|b| (32..=126).contains(&b))
                    }),
                    "non-ASCII directive",
                )?;
            }
        }
    }
    Ok(())
}
fn reference(s: &Value) -> Result<Value> {
    if s["source_base"].is_null() {
        return Ok(Value::Null);
    }
    Ok(io::reference(&io::absolute(Path::new(string(s, "source_base")?))?)?.into())
}
fn references(p: &Value) -> Result<Value> {
    let mut out = json!({});
    for s in p["sites"].as_array().ok_or("sites")? {
        out[string(s, "id")?] = reference(s)?;
    }
    Ok(out)
}
pub fn mappings(s: &Value, names: &[String]) -> Result<BTreeMap<String, String>> {
    let synthetic = object(s, "synthetic_files")?;
    let all: BTreeSet<_> = names
        .iter()
        .cloned()
        .chain(synthetic.keys().cloned())
        .collect();
    let mut out: BTreeMap<String, String> =
        all.iter().map(|n| (format!("/{n}"), n.clone())).collect();
    if let Some(allowed) = s["public_paths"].as_array() {
        let allowed: BTreeSet<_> = allowed
            .iter()
            .map(|v| v.as_str().ok_or("public path"))
            .collect::<std::result::Result<_, _>>()?;
        out.retain(|k, _| allowed.contains(k.as_str()));
        if allowed.contains("/") {
            let index = string(s, "index")?;
            require(all.contains(index), "missing root index")?;
            out.insert("/".into(), index.into());
        }
        require(
            allowed.iter().all(|k| out.contains_key(*k)),
            "missing declared public file",
        )?;
    } else if !s["source_base"].is_null() {
        let index = string(s, "index")?;
        if all.contains(index) {
            out.insert("/".into(), index.into());
        }
        let defaults = json!(["index.html", "index.txt"]);
        for index in s
            .get("directory_indexes")
            .unwrap_or(&defaults)
            .as_array()
            .ok_or("indexes")?
        {
            let index = index.as_str().ok_or("index")?;
            for name in &all {
                if name.ends_with(&format!("/{index}")) {
                    out.entry(format!("/{}", &name[..name.len() - index.len()]))
                        .or_insert_with(|| name.clone());
                }
            }
        }
    }
    // Reviewed synthetic files are explicit additions, including with an allowlist.
    for name in synthetic.keys() {
        out.insert(format!("/{name}"), name.clone());
    }
    require(out.len() <= io::MAX_FILES, "mapping count")?;
    for (url, name) in &out {
        require(
            policy::mapping_allowed(
                pathward::valid_path(url.as_bytes()) && io::relative(name),
                names.contains(name),
                synthetic.contains_key(name),
            ),
            "unselected mapping",
        )?;
    }
    Ok(out)
}
fn directories(path: &Path, root: &Path) -> Result<()> {
    if path == root {
        return Ok(());
    }
    require(path.starts_with(root), "output escapes private root")?;
    directories(path.parent().ok_or("output parent")?, root)?;
    f::directory(path)
}
fn private(path: &Path) -> Result<()> {
    f::directory(path)?;
    let m = fs::symlink_metadata(path)?;
    require(m.mode() & 0o777 == 0o700, "state must be private")
}
pub fn lock(state: &Path) -> Result<File> {
    private(state)?;
    let fd = rustix::fs::open(
        state.join("lock"),
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o600),
    )?;
    let f = File::from(fd);
    let m = f.metadata()?;
    require(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o077 == 0,
        "publication lock",
    )?;
    f.try_lock()?;
    Ok(f)
}
fn state_size(path: &Path, count: &mut usize) -> Result<u64> {
    let mut total = 0u64;
    for entry in fs::read_dir(path)? {
        let p = entry?.path();
        *count += 1;
        require(*count <= 100_000, "state entry bound")?;
        let m = fs::symlink_metadata(&p)?;
        require(
            !m.file_type().is_symlink() && m.uid() == rustix::process::geteuid().as_raw(),
            "foreign state entry",
        )?;
        total = total
            .checked_add(if m.is_dir() {
                state_size(&p, count)?
            } else {
                require(m.is_file() && m.nlink() == 1, "special state entry")?;
                m.len()
            })
            .ok_or("state size overflow")?;
        require(total <= STATE_BYTES, "state size bound")?;
    }
    Ok(total)
}
fn capture(
    s: &Value,
    reference: &Value,
    state: &Path,
    ph: &str,
    left: &mut u64,
    cp: Checkpoint<'_>,
) -> Result<Value> {
    let key = codec::hash(&encoded(&json!({"site":s,"source":reference,"policy":ph})));
    let target = state.join("snapshots").join(&key);
    let synthetic = object(s, "synthetic_files")?;
    if target.exists() {
        private(&target)?;
        let manifest = codec::parse(&f::bytes(&target.join("manifest.json"), true)?)?;
        require(
            manifest["key"] == key
                && manifest["host"] == s["host"]
                && manifest["source"] == *reference,
            "cached snapshot identity",
        )?;
        let root = io::absolute(&target.join("public"))?;
        let names = io::names(&root)?;
        let files = object(&manifest, "files")?;
        require(
            names.iter().collect::<BTreeSet<_>>() == files.keys().collect(),
            "cached snapshot membership",
        )?;
        for name in &names {
            require(
                io::stream(io::leaf(&root, name)?, None, MAX_FILE_BYTES)? == files[name],
                "cached snapshot changed",
            )?;
        }
        let urls: BTreeMap<String, String> = mappings(s, &names)?;
        require(
            serde_json::to_value(urls)? == manifest["urls"],
            "cached mappings changed",
        )?;
        return Ok(manifest);
    }
    // A deterministic private staging name makes interrupted capture retry bounded.
    let folder = state.join(format!("capture-{key}"));
    if folder.exists() {
        require(fs::symlink_metadata(&folder)?.is_dir(), "capture type")?;
        remove_capture(&folder)?;
    }
    private(&folder)?;
    private(&folder.join("public"))?;
    let mut files = json!({});
    let mut used = 0u64;
    let (source, names) = if let Some(r) = reference.as_str() {
        let base = io::absolute(Path::new(string(s, "source_base")?))?;
        require(io::reference(&base)? == r, "concurrent publication")?;
        let root = io::descend(&base, &format!("{r}/public"))?;
        let names = io::names(&root)?;
        (Some(root), names)
    } else {
        (None, Vec::new())
    };
    let urls = mappings(s, &names)?;
    for name in urls.values().collect::<BTreeSet<_>>() {
        let dest = folder.join("public").join(name);
        directories(dest.parent().ok_or("destination parent")?, &folder)?;
        if let Some(text) = synthetic.get(name) {
            let bytes = text.as_str().ok_or("synthetic")?.as_bytes();
            require(
                bytes.len() as u64 <= (*left).min(SNAPSHOT_BYTES - used),
                "snapshot capacity",
            )?;
            f::replace(&dest, bytes, 0o600, "synthetic", cp)?;
            files[name] = json!({"sha256":codec::hash(bytes),"bytes":bytes.len()});
        } else {
            let fd = rustix::fs::open(
                &dest,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
            )?;
            let mut output = File::from(fd);
            output.set_permissions(fs::Permissions::from_mode(0o600))?;
            files[name] = io::stream(
                io::leaf(source.as_ref().ok_or("missing source")?, name)?,
                Some(&mut output),
                (*left).min(SNAPSHOT_BYTES - used),
            )?;
            cp("capture:file-synced")?;
        }
        let size = files[name]["bytes"].as_u64().ok_or("captured size")?;
        used += size;
        *left -= size;
        f::sync_dir(dest.parent().ok_or("destination parent")?)?;
    }
    require(
        self::reference(s)? == *reference,
        "source changed during capture",
    )?;
    let manifest = json!({"key":key,"host":s["host"],"source":reference,"files":files,"urls":urls});
    let raw = encoded(&manifest);
    require(raw.len() <= codec::LIMIT, "snapshot manifest capacity")?;
    f::replace(&folder.join("manifest.json"), &raw, 0o600, "manifest", cp)?;
    sync_tree(&folder)?;
    fs::rename(&folder, &target)?;
    cp("snapshot:renamed")?;
    f::sync_dir(&state.join("snapshots"))?;
    f::sync_dir(state)?;
    cp("snapshot:durable")?;
    Ok(manifest)
}
const MAX_FILE_BYTES: u64 = 1 << 30;
fn sync_tree(p: &Path) -> Result<()> {
    for e in fs::read_dir(p)? {
        let p = e?.path();
        if fs::symlink_metadata(&p)?.is_dir() {
            sync_tree(&p)?;
        }
    }
    f::sync_dir(p)
}
fn remove_capture(p: &Path) -> Result<()> {
    private(p)?;
    for e in fs::read_dir(p)? {
        let p = e?.path();
        let m = fs::symlink_metadata(&p)?;
        require(
            m.uid() == rustix::process::geteuid().as_raw() && !m.file_type().is_symlink(),
            "foreign capture",
        )?;
        if m.is_dir() {
            remove_capture(&p)?;
        } else {
            require(m.is_file() && m.nlink() == 1, "foreign capture inode")?;
            fs::remove_file(&p)?;
        }
    }
    fs::remove_dir(p)?;
    f::sync_dir(p.parent().ok_or("capture parent")?)
}
pub struct Bridge<S: System> {
    pub state: PathBuf,
    pub binary: PathBuf,
    pub control: PathBuf,
    pub receipt: PathBuf,
    pub sys: S,
}
impl<S: System> Bridge<S> {
    /// Caller holds `lock(state)` through build/activation/receipt publication.
    pub fn build(&mut self, p: &Value, cp: Checkpoint<'_>) -> Result<(PathBuf, Value)> {
        validate(p)?;
        private(&self.state)?;
        private(&self.state.join("snapshots"))?;
        require(
            fs::read_dir(&self.state)?.count() < 256
                && fs::read_dir(self.state.join("snapshots"))?.count() < 128,
            "state retention limit",
        )?;
        let size = state_size(&self.state, &mut 0)?;
        require(size < STATE_BYTES - SNAPSHOT_BYTES, "state capacity")?;
        let mut left = STATE_BYTES - size - (16 << 20);
        let refs = references(p)?;
        let ph = codec::hash(&encoded(p));
        let mut manifests = json!({});
        let mut text = String::from("capacity \"shared-nat\"\n");
        let q = |s: &str| serde_json::to_string(s).expect("quoted string");
        for s in p["sites"].as_array().ok_or("sites")? {
            let id = string(s, "id")?;
            let m = capture(s, &refs[id], &self.state, &ph, &mut left, cp)?;
            let urls = object(&m, "urls")?;
            text += &format!("site {} {{\n  tls \"auto\"\n", q(string(s, "host")?));
            if !urls.is_empty() {
                text += &format!(
                    "  root {}\n",
                    q(self
                        .state
                        .join("snapshots")
                        .join(string(&m, "key")?)
                        .join("public")
                        .to_str()
                        .ok_or("snapshot path")?)
                );
            }
            let mut nodes = s["directives"].as_array().ok_or("nodes")?.clone();
            let declared: BTreeSet<_> = nodes
                .iter()
                .filter(|n| n[0] == "redirect" || n[0] == "redirect-prefix")
                .map(|n| n[1].clone().to_string())
                .collect();
            for url in urls.keys() {
                if url != "/" && url.ends_with('/') {
                    let bare = &url[..url.len() - 1];
                    require(
                        !urls.contains_key(bare) && !declared.contains(&json!(bare).to_string()),
                        "ambiguous entrance redirect",
                    )?;
                    nodes.push(json!(["redirect", bare, s["host"], url, "308"]));
                }
            }
            require(
                nodes
                    .iter()
                    .filter(|n| n[0].as_str().is_some_and(|s| s.starts_with("redirect")))
                    .count()
                    <= 512,
                "redirect limit",
            )?;
            for n in nodes {
                let a = n.as_array().ok_or("node")?;
                text += &format!("  {}", a[0].as_str().ok_or("node name")?);
                for v in &a[1..] {
                    text += &format!(" {}", q(v.as_str().ok_or("node arg")?));
                }
                text += '\n'.to_string().as_str();
            }
            for (url, name) in urls {
                text += &format!(
                    "  publish {} {}\n",
                    q(url),
                    q(name.as_str().ok_or("mapping")?)
                );
            }
            text += "}\n";
            manifests[id] = m;
        }
        require(text.len() <= codec::LIMIT, "configuration size")?;
        let hash = codec::hash(text.as_bytes());
        let receipt = json!({"schema":2,"policy_sha256":ph,"config_sha256":hash,"sites":manifests});
        // Reserve all fixed receipt fields before any server activation. A
        // valid KDL can be smaller than its exact file-digest receipt.
        require(
            encoded(&receipt).len() <= codec::LIMIT - 1024,
            "publication receipt capacity",
        )?;
        let path = self.state.join(format!("candidate-{hash}.kdl"));
        f::replace(&path, text.as_bytes(), 0o600, "candidate", cp)?;
        self.sys.checked(
            &words(&[
                self.binary.to_str().ok_or("binary")?,
                "check",
                path.to_str().ok_or("candidate")?,
            ]),
            60,
        )?;
        require(refs == references(p)?, "release changed before activation")?;
        Ok((path, receipt))
    }
    fn control(&mut self, mode: &str, tail: &[&str]) -> Result<String> {
        let mut a = words(&[
            self.binary.to_str().ok_or("binary")?,
            mode,
            "--control-dir",
            self.control.to_str().ok_or("control")?,
        ]);
        a.extend(tail.iter().map(|s| s.to_string()));
        let s = self.sys.checked(&a, 30)?.trim().to_owned();
        revision(&s)?;
        Ok(s)
    }
    pub fn reconcile(&mut self, p: &Value, now: &Value, cp: Checkpoint<'_>) -> Result<Value> {
        let (path, mut receipt) = self.build(p, cp)?;
        let mut expected = self.control("status", &[])?;
        if revision(&expected)?.1 != string(&receipt, "config_sha256")? {
            expected = self.control(
                "activate",
                &["--expect", &expected, path.to_str().ok_or("candidate")?],
            )?;
        }
        require(
            revision(&expected)?.1 == string(&receipt, "config_sha256")?
                && self.control("status", &[])? == expected,
            "concurrent activation",
        )?;
        for s in p["sites"].as_array().ok_or("sites")? {
            require(
                reference(s)? == receipt["sites"][string(s, "id")?]["source"],
                "publication changed after activation",
            )?;
        }
        receipt["active"] = expected.into();
        receipt["boot"] = now["boot"].clone();
        receipt["observed_monotonic_ns"] = now["ns"].clone();
        // `now` is sampled before build: conservatively cannot acknowledge a switch during build.
        require(
            now["ns"].as_u64().is_some() && now["boot"].as_str().is_some(),
            "receipt clock",
        )?;
        let bytes = encoded(&receipt);
        require(bytes.len() <= codec::LIMIT, "receipt size")?;
        f::replace(&self.receipt, &bytes, 0o644, "receipt", cp)?;
        Ok(receipt)
    }
}
pub fn revision(s: &str) -> Result<(u64, &str)> {
    let (g, h) = s.split_once(':').ok_or("invalid revision")?;
    let g = g.parse::<u64>()?;
    require(codec::digest(h), "invalid revision digest")?;
    Ok((g, h))
}
pub fn acknowledged(
    receipt: &Value,
    profile: &str,
    source: &str,
    files: &Value,
    stamp: &Value,
    now: &Value,
) -> Result<bool> {
    let current = &receipt["sites"][profile];
    let observed = receipt["observed_monotonic_ns"]
        .as_u64()
        .ok_or("receipt time")?;
    let current_files = object(current, "files")?;
    let expected = files.as_object().ok_or("expected files")?;
    let matches = expected.len() == current_files.len()
        && expected
            .iter()
            .all(|(n, h)| current_files.get(n).is_some_and(|f| f["sha256"] == *h));
    let active = string(receipt, "active")?;
    Ok(policy::receipt_allowed(
        receipt["schema"] == 2 && receipt["policy_sha256"] == stamp["policy_sha256"],
        receipt["boot"] == now["boot"] && stamp["boot"] == now["boot"],
        revision(active)?.1 == string(receipt, "config_sha256")?,
        current["source"] == source,
        matches,
        stamp["after"].as_u64().ok_or("switch time")?,
        observed,
        now["ns"].as_u64().ok_or("now")?,
    ))
}
pub fn public_manifest(path: &Path) -> Result<Value> {
    let root = io::absolute(path.parent().ok_or("manifest parent")?)?;
    let mut f = io::leaf(
        &root,
        path.file_name()
            .and_then(|s| s.to_str())
            .ok_or("manifest name")?,
    )?;
    require(f.metadata()?.len() <= codec::LIMIT as u64, "manifest limit")?;
    let mut text = String::new();
    (&mut f)
        .take(codec::LIMIT as u64 + 1)
        .read_to_string(&mut text)?;
    require(text.len() <= codec::LIMIT, "manifest grew")?;
    let mut out = json!({});
    let mut seen = BTreeSet::new();
    for line in text.lines() {
        let (h, n) = line.split_once("  public/").ok_or("manifest line")?;
        require(
            codec::digest(h)
                && (io::relative(n) || n == ".nojekyll")
                && seen.insert(n)
                && seen.len() <= io::MAX_FILES,
            "duplicate or escaping manifest",
        )?;
        if n != ".nojekyll" {
            out[n] = h.into();
        }
    }
    require(
        !out.as_object().ok_or("manifest")?.is_empty()
            && out.as_object().ok_or("manifest")?.len() <= io::MAX_FILES,
        "manifest count",
    )?;
    Ok(out)
}
pub fn wait(
    receipt: &Path,
    owner: u32,
    profile: &str,
    source: &str,
    files: &Value,
    stamp: &Value,
    timeout: Duration,
) -> Result<String> {
    let until = Instant::now() + timeout;
    loop {
        let r = io::metadata(receipt, owner)?;
        let now = clock()?;
        require(
            r["policy_sha256"] == stamp["policy_sha256"]
                && r["boot"] == stamp["boot"]
                && now["boot"] == stamp["boot"],
            "publication authority changed",
        )?;
        if acknowledged(&r, profile, source, files, stamp, &now)? {
            return Ok(string(&r, "active")?.into());
        }
        require(
            Instant::now() < until,
            "publication acknowledgement timeout",
        )?;
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A publisher may acknowledge only the files selected by the reviewed policy.
pub fn selected_files(p: &Value, profile: &str, manifest: &Value) -> Result<Value> {
    validate(p)?;
    let s = p["sites"]
        .as_array()
        .ok_or("sites")?
        .iter()
        .find(|s| s["id"] == profile)
        .ok_or("unknown publication profile")?;
    let names: Vec<String> = manifest
        .as_object()
        .ok_or("manifest")?
        .keys()
        .cloned()
        .collect();
    let urls = mappings(s, &names)?;
    let mut out = json!({});
    for n in urls.values() {
        out[n] = if let Some(t) = object(s, "synthetic_files")?.get(n) {
            codec::hash(t.as_str().ok_or("synthetic")?.as_bytes()).into()
        } else {
            manifest[n].clone()
        };
    }
    Ok(out)
}
pub fn begin<S: System>(
    p: &Value,
    receipt: &Path,
    owner: u32,
    profile: &str,
    sys: &mut S,
    now: &Value,
) -> Result<Value> {
    validate(p)?;
    require(
        p["sites"]
            .as_array()
            .ok_or("sites")?
            .iter()
            .any(|s| s["id"] == profile),
        "unknown profile",
    )?;
    let active = sys.property("pathward.service", "ActiveState")?;
    let routing = if active == "active" {
        "pathward"
    } else {
        require(
            ["inactive", "failed"].contains(&active.as_str())
                && sys.property("caddy.service", "ActiveState")? == "active",
            "routing is transitioning",
        )?;
        "caddy"
    };
    let ph = codec::hash(&encoded(p));
    if routing == "pathward" {
        let r = io::metadata(receipt, owner)?;
        let n = now["ns"].as_u64().ok_or("clock")?;
        let t = r["observed_monotonic_ns"].as_u64().ok_or("receipt time")?;
        require(
            r["schema"] == 2
                && r["boot"] == now["boot"]
                && r["policy_sha256"] == ph
                && r["sites"].get(profile).is_some()
                && t <= n
                && n - t <= 10_000_000_000,
            "stale publication authority",
        )?;
        require(
            revision(string(&r, "active")?)?.1 == string(&r, "config_sha256")?,
            "receipt revision mismatch",
        )?;
    }
    Ok(
        json!({"schema":2,"profile":profile,"routing":routing,"policy_sha256":ph,"boot":now["boot"],"after":now["ns"]}),
    )
}
/// The ready release already exists; this command owns the current-link CAS and
/// rollback barrier. All publishers must hold this same per-source lock.
#[allow(clippy::too_many_arguments)]
pub fn publish<S: System>(
    p: &Value,
    receipt: &Path,
    owner: u32,
    profile: &str,
    expected: &str,
    next: &str,
    manifest: &Value,
    sys: &mut S,
    cp: Checkpoint<'_>,
) -> Result<String> {
    publish_checked(
        p,
        receipt,
        owner,
        profile,
        expected,
        next,
        manifest,
        sys,
        cp,
        &mut || Ok(()),
    )
}

/// Public HTTP verification remains inside the source lock and rollback scope.
#[allow(clippy::too_many_arguments)]
pub fn publish_checked<S: System>(
    p: &Value,
    receipt: &Path,
    owner: u32,
    profile: &str,
    expected: &str,
    next: &str,
    manifest: &Value,
    sys: &mut S,
    cp: Checkpoint<'_>,
    verify: &mut dyn FnMut() -> Result<()>,
) -> Result<String> {
    require(
        io::release(expected) && io::release(next) && expected != next,
        "invalid release transition",
    )?;
    validate(p)?;
    let site = p["sites"]
        .as_array()
        .ok_or("sites")?
        .iter()
        .find(|s| s["id"] == profile)
        .ok_or("profile")?;
    let base = Path::new(string(site, "source_base")?);
    f::trusted(&base.join("current"))?;
    // Source directories are public; the lock itself remains owner-private.
    let path = base.join(".pathward-publication.lock");
    let fd = rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o600),
    )?;
    let lock = File::from(fd);
    let m = lock.metadata()?;
    require(
        m.uid() == rustix::process::geteuid().as_raw()
            && m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o077 == 0,
        "publisher lock",
    )?;
    lock.try_lock()?;
    let base_fd = io::absolute(base)?;
    require(
        io::reference(&base_fd)? == expected,
        "stale publication request",
    )?;
    let source = io::descend(&base_fd, &format!("{next}/public"))?;
    let names = io::names(&source)?;
    let expected_names: BTreeSet<_> = manifest
        .as_object()
        .ok_or("manifest")?
        .keys()
        .cloned()
        .collect();
    require(
        names.iter().cloned().collect::<BTreeSet<_>>() == expected_names,
        "ready release manifest membership",
    )?;
    for name in &names {
        let input = io::leaf(&source, name)?;
        input.sync_all()?;
        require(
            io::stream(input, None, MAX_FILE_BYTES)?["sha256"] == manifest[name],
            "ready release hash",
        )?;
    }
    sync_tree(&base.join(next).join("public"))?;
    f::sync_dir(&base.join(next))?;
    f::sync_dir(&base.join("releases"))?;
    let files = selected_files(p, profile, manifest)?;
    let stamp = begin(p, receipt, owner, profile, sys, &clock()?)?;
    require(
        stamp["routing"] == "pathward",
        "native publish requires active PathWard acknowledgement",
    )?;
    require(
        io::reference(&base_fd)? == expected,
        "source changed before switch",
    )?;
    let result = (|| {
        f::link(
            &base.join("current"),
            Path::new(next),
            "publication-link",
            cp,
        )?;
        let active = if stamp["routing"] == "pathward" {
            wait(
                receipt,
                owner,
                profile,
                next,
                &files,
                &stamp,
                Duration::from_secs(30),
            )?
        } else {
            "caddy".into()
        };
        require(
            io::reference(&base_fd)? == next,
            "publication changed during verification",
        )?;
        let after = begin(p, receipt, owner, profile, sys, &clock()?)?;
        require(
            after["routing"] == stamp["routing"]
                && after["policy_sha256"] == stamp["policy_sha256"]
                && after["boot"] == stamp["boot"],
            "routing changed during publication",
        )?;
        verify()?;
        require(
            io::reference(&base_fd)? == next,
            "publication changed during public verification",
        )?;
        Ok(active)
    })();
    if result.is_err() && io::reference(&base_fd)? == next {
        // A stale failed publisher must never overwrite a newer current link.
        let rollback = clock()?;
        f::link(
            &base.join("current"),
            Path::new(expected),
            "publication-rollback",
            cp,
        )?;
        if stamp["routing"] == "pathward" {
            let old = io::descend(&base_fd, &format!("{expected}/public"))?;
            let mut hashes = json!({});
            for name in io::names(&old)? {
                hashes[&name] =
                    io::stream(io::leaf(&old, &name)?, None, MAX_FILE_BYTES)?["sha256"].clone();
            }
            let mut s = stamp.clone();
            s["after"] = rollback["ns"].clone();
            wait(
                receipt,
                owner,
                profile,
                expected,
                &selected_files(p, profile, &hashes)?,
                &s,
                Duration::from_secs(30),
            )?;
        }
    }
    result
}
