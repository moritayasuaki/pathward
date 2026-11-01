//! Explicit manifests and checked, durable local release transactions.
use crate::{Server, control};
use pathward_config::{CompiledConfig, ParsedConfig};
use std::{io, path::Path};

pub fn revision(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn error() -> io::Error {
    io::Error::other("release validation failed")
}
pub fn validate(config: &CompiledConfig<'_>, cache: Option<&Path>) -> io::Result<usize> {
    Snapshot::prepare(config, cache)?.check_files()
}
fn quoted(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}
/// Only listed files are granted; the optional root alias must name a listed file.
pub fn generate(
    base: &CompiledConfig<'_>,
    host: &str,
    root: &str,
    manifest: &str,
    index: Option<&str>,
) -> io::Result<String> {
    if base.site(host).is_none_or(|site| site.root().is_none())
        || !pathward::valid_path(root.as_bytes())
        || manifest.len() > 65_536
    {
        return Err(error());
    }
    let files: Vec<_> = manifest.lines().collect();
    if files.is_empty()
        || files.len() + usize::from(index.is_some()) > 256
        || files
            .iter()
            .any(|f| !pathward::rules::valid_target(f.as_bytes()))
    {
        return Err(error());
    }
    let mut seen = std::collections::BTreeSet::new();
    for file in &files {
        if !seen.insert(*file) {
            return Err(error());
        }
    }
    if index.is_some_and(|i| !seen.contains(i)) {
        return Err(error());
    }
    let mut out = String::new();
    for site in base.sites() {
        out.push_str(&format!(
            "site {} {{\n    tls \"auto\"\n",
            quoted(site.host())
        ));
        if let Some(old_root) = site.root() {
            out.push_str(&format!(
                "    root {}\n",
                quoted(if site.host() == host { root } else { old_root })
            ));
        }
        if let Some(upstream) = site.upstream() {
            out.push_str(&format!(
                "    reverse-proxy {}\n",
                quoted(&upstream.to_string())
            ));
        }
        for path in site.denies() {
            out.push_str(&format!("    deny {}\n", quoted(path)));
        }
        for path in site.proxy_paths() {
            out.push_str(&format!("    proxy-path {}\n", quoted(path)));
        }
        if site.upstream().is_some() {
            let l = site.proxy_limits();
            for origin in site.websocket_origins() {
                out.push_str(&format!("    websocket-origin {}\n", quoted(origin)));
            }
            if l.deflate {
                out.push_str("    websocket-compression \"permessage-deflate\"\n");
            }

            for (enabled, name) in [(l.websocket, "websocket"), (l.sse, "sse")] {
                if enabled {
                    out.push_str(&format!("    proxy-stream {}\n", quoted(name)));
                }
            }
            for (name, value, unit) in [
                ("request-body", l.request_bytes, "B"),
                ("response-body", l.response_bytes, "B"),
                ("connections", l.connections, ""),
            ] {
                out.push_str(&format!(
                    "    proxy-limit {} {}\n",
                    quoted(name),
                    quoted(&format!("{value}{unit}"))
                ));
            }
            if l.websocket || l.sse {
                out.push_str(&format!("    proxy-limit \"streams\" \"{}\"\n", l.streams));
                for (name, value) in [
                    ("stream-upload", l.stream_upload_bytes),
                    ("stream-download", l.stream_download_bytes),
                ] {
                    out.push_str(&format!(
                        "    proxy-limit {} {}\n",
                        quoted(name),
                        quoted(&format!("{value}B"))
                    ));
                }
                for (name, value) in [
                    ("stream-idle", l.stream_idle_ms),
                    ("stream-total", l.stream_total_ms),
                ] {
                    out.push_str(&format!(
                        "    proxy-timeout {} {}\n",
                        quoted(name),
                        quoted(&format!("{value}ms"))
                    ));
                }
            }
            for (name, value) in [
                ("request-body", l.body_ms),
                ("connect", l.connect_ms),
                ("response-head", l.head_ms),
                ("total", l.total_ms),
            ] {
                out.push_str(&format!(
                    "    proxy-timeout {} {}\n",
                    quoted(name),
                    quoted(&format!("{value}ms"))
                ));
            }
        }
        let mappings: Vec<(String, String)> = if site.host() == host {
            let mut mappings = Vec::new();
            for file in &files {
                let url = format!("/{file}");
                if !pathward::release::generated_rule(
                    url.as_bytes(),
                    file.as_bytes(),
                    file.as_bytes(),
                    false,
                ) {
                    return Err(error());
                }
                mappings.push((url, (*file).to_owned()));
            }
            if let Some(index) = index {
                if !pathward::release::generated_rule(
                    b"/",
                    index.as_bytes(),
                    index.as_bytes(),
                    true,
                ) {
                    return Err(error());
                }
                mappings.push(("/".into(), index.into()));
            }
            mappings
        } else {
            site.publications()
                .iter()
                .map(|p| {
                    (
                        String::from_utf8_lossy(p.path).into_owned(),
                        String::from_utf8_lossy(p.target).into_owned(),
                    )
                })
                .collect()
        };
        for (url, file) in mappings {
            out.push_str(&format!("    publish {} {}\n", quoted(&url), quoted(&file)));
        }
        for r in site.redirects() {
            out.push_str(&format!(
                "    {} {} {} {} \"{}\"\n",
                if r.prefix {
                    "redirect-prefix"
                } else {
                    "redirect"
                },
                quoted(r.from),
                quoted(r.host),
                quoted(r.to),
                r.status
            ));
        }
        for h in site.headers() {
            out.push_str(&format!(
                "    header {} {} {}\n",
                quoted(h.scope),
                quoted(h.name),
                quoted(h.value)
            ));
        }
        out.push_str("}\n");
    }
    // Round trip the exact output through the same bounded schema and core compiler.
    let parsed = ParsedConfig::parse(&out).map_err(|_| error())?;
    parsed.compile().map_err(|_| error())?;
    Ok(out)
}
pub fn check(path: &Path, cache: Option<&Path>) -> io::Result<(String, usize)> {
    let parsed = control::read_config(path)?;
    let config = parsed.compile().map_err(|_| error())?;
    Ok((
        revision(config.source().as_bytes()),
        validate(&config, cache)?,
    ))
}

use crate::{runtime::Snapshot, secrets::SecretStore};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub trait ConfigStore {
    fn current(&self) -> io::Result<Option<Vec<u8>>>;
    fn previous(&self) -> io::Result<Option<Vec<u8>>>;
    fn save_current(&self, bytes: &[u8]) -> io::Result<()>;
    fn save_previous(&self, bytes: &[u8]) -> io::Result<()>;
}
impl ConfigStore for SecretStore {
    fn current(&self) -> io::Result<Option<Vec<u8>>> {
        self.load_config()
    }
    fn previous(&self) -> io::Result<Option<Vec<u8>>> {
        self.load_previous()
    }
    fn save_current(&self, b: &[u8]) -> io::Result<()> {
        self.store_config(b)
    }
    fn save_previous(&self, b: &[u8]) -> io::Result<()> {
        self.store_previous(b)
    }
}
impl Server {
    /// Same serial lock as SIGHUP; all policy/root/file checks precede durable writes.
    pub fn activate(
        &self,
        store: &impl ConfigStore,
        directory: &Path,
        expected_generation: u64,
        expected: &str,
        bytes: &[u8],
        shutdown: &AtomicBool,
    ) -> io::Result<u64> {
        let _serial = self.reload_lock.lock().map_err(|_| error())?;
        let result = (|| {
            let (generation, old) = {
                let state = self.state.read().map_err(|_| error())?;
                (state.generation, state.snapshot.clone())
            };
            if generation != expected_generation
                || generation == u64::MAX
                || !pathward::release::commit_allowed(
                    revision(old.source.as_bytes()).as_bytes(),
                    expected.as_bytes(),
                    true,
                    true,
                    self.is_draining() || shutdown.load(Ordering::Acquire),
                )
            {
                return Err(error());
            }
            // Detect an out-of-band disk edit instead of overwriting it.
            if store.current()?.as_deref() != Some(old.source.as_bytes()) {
                return Err(error());
            }
            let text = std::str::from_utf8(bytes).map_err(|_| error())?;
            let parsed = ParsedConfig::parse(text).map_err(|_| error())?;
            let config = parsed.compile().map_err(|_| error())?;
            if !old.same_hosts(&config)
                || !self.isolated(&config)
                || !Snapshot::isolated(&config, Some(directory))
            {
                return Err(error());
            }
            let mut candidate = Snapshot::prepare(&config, self.cache.as_deref())?;
            candidate.inherit_budgets(&old);
            let candidate = Arc::new(candidate);
            candidate.check_files()?;
            store.save_previous(old.source.as_bytes())?;
            // Errors may happen AFTER rename. Restore before returning, otherwise stop.
            let saved = store.save_current(bytes);
            let commit = (|| {
                saved?;
                let mut state = self.state.write().map_err(|_| error())?;
                let draining = state.draining || shutdown.load(Ordering::Acquire);
                if !pathward::release::commit_allowed(
                    revision(state.snapshot.source.as_bytes()).as_bytes(),
                    expected.as_bytes(),
                    true,
                    true,
                    draining,
                ) {
                    return Err(error());
                }
                let next = pathward::runtime::commit_generation(
                    state.generation,
                    expected_generation,
                    true,
                    true,
                    true,
                    draining,
                );
                if next == state.generation {
                    return Err(error());
                }
                candidate.install_limits();
                state.snapshot = candidate;
                state.generation = next;
                Ok(next)
            })();
            if commit.is_err() && store.save_current(old.source.as_bytes()).is_err() {
                shutdown.store(true, Ordering::Release);
                self.begin_shutdown();
                self.observe
                    .event("deployment_recovery_failed", generation, 0);
            }
            commit
        })();
        self.observe.reload(result.is_ok(), self.generation());
        result
    }
}

pub struct Managed {
    store: SecretStore,
    directory: PathBuf,
    socket: PathBuf,
    listener: UnixListener,
    socket_identity: (u64, u64),
}
impl Managed {
    pub fn open(
        directory: &Path,
        config: &CompiledConfig<'_>,
        cache: Option<&Path>,
    ) -> io::Result<Self> {
        if cache.is_some_and(|c| directory.starts_with(c) || c.starts_with(directory)) {
            return Err(error());
        }
        let roots: Vec<_> = config.sites().iter().filter_map(|s| s.root()).collect();
        let store = SecretStore::open(directory, &roots)?;
        if store.load_config()?.as_deref() != Some(config.source().as_bytes()) {
            return Err(error());
        }
        validate(config, cache)?;
        let socket = store.socket_path();
        match fs::symlink_metadata(&socket) {
            Ok(meta) if meta.file_type().is_socket() => {
                #[cfg(target_os = "linux")]
                if meta.uid() != rustix::process::geteuid().as_raw()
                    || meta.mode() & 0o7777 != 0o600
                {
                    return Err(error());
                }
                fs::remove_file(&socket)?;
            }
            Ok(_) => return Err(error()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let meta = fs::symlink_metadata(&socket)?;
        let socket_identity = (meta.dev(), meta.ino());
        Ok(Self {
            store,
            directory: directory.to_owned(),
            socket,
            listener,
            socket_identity,
        })
    }
    pub fn run(&self, server: &Server, shutdown: &AtomicBool) -> io::Result<()> {
        while !shutdown.load(Ordering::Acquire) {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    let result = (|| -> io::Result<String> {
                        let line = read_line(&mut stream, deadline)?;
                        let fields: Vec<_> = line.split(' ').collect();
                        if fields == ["STATUS"] {
                            let (generation, revision) = server.status();
                            return Ok(format!("OK {generation} {revision}\n"));
                        }
                        if fields.len() != 4 || !matches!(fields[0], "APPLY" | "ROLLBACK") {
                            return Err(error());
                        }
                        let generation = fields[1].parse().map_err(|_| error())?;
                        let expected = fields[2];
                        if expected.len() != 64
                            || !expected
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        {
                            return Err(error());
                        }
                        let length: usize = fields[3].parse().map_err(|_| error())?;
                        if length > 65_536 {
                            return Err(error());
                        }
                        let bytes = if fields[0] == "ROLLBACK" {
                            if length != 0 {
                                return Err(error());
                            }
                            self.store.load_previous()?.ok_or_else(error)?
                        } else {
                            let mut bytes = vec![0; length];
                            let mut offset = 0;
                            while offset < length {
                                prepare(&stream, deadline)?;
                                let n = stream.read(&mut bytes[offset..])?;
                                if n == 0 {
                                    return Err(error());
                                }
                                offset += n;
                            }
                            bytes
                        };
                        let next = server.activate(
                            &self.store,
                            &self.directory,
                            generation,
                            expected,
                            &bytes,
                            shutdown,
                        )?;
                        Ok(format!("OK {next} {}\n", revision(&bytes)))
                    })();
                    // Exactly one command; no shell, paths or error details from a peer.
                    let response = result.unwrap_or_else(|_| "ERR\n".into());
                    let _ = write_deadline(
                        &mut stream,
                        response.as_bytes(),
                        Instant::now() + Duration::from_secs(1),
                    );
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
impl Drop for Managed {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.socket)
            .is_ok_and(|m| m.file_type().is_socket() && (m.dev(), m.ino()) == self.socket_identity)
        {
            let _ = fs::remove_file(&self.socket);
        }
    }
}
fn write_deadline(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    let mut left = bytes;
    while !left.is_empty() {
        prepare(stream, deadline)?;
        let n = stream.write(left)?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        left = &left[n..];
    }
    Ok(())
}
fn prepare(stream: &UnixStream, deadline: Instant) -> io::Result<()> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
    stream.set_read_timeout(Some(left))?;
    stream.set_write_timeout(Some(left))
}
fn read_line(stream: &mut UnixStream, deadline: Instant) -> io::Result<String> {
    let mut out = Vec::new();
    loop {
        prepare(stream, deadline)?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            break;
        }
        if !(0x20..=0x7e).contains(&byte[0]) || out.len() >= 160 {
            return Err(error());
        }
        out.push(byte[0]);
    }
    String::from_utf8(out).map_err(|_| error())
}
pub fn initialize(directory: &Path, config: &CompiledConfig<'_>) -> io::Result<()> {
    validate(config, None)?;
    let roots: Vec<_> = config.sites().iter().filter_map(|s| s.root()).collect();
    let store = SecretStore::open(directory, &roots)?;
    if store.load_config()?.is_some() {
        return Err(error());
    }
    store.store_config(config.source().as_bytes())
}
pub fn command(
    directory: &Path,
    action: &str,
    expected: Option<&str>,
    bytes: &[u8],
) -> io::Result<String> {
    let mut stream = UnixStream::connect(directory.join("control.sock"))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let header = if action == "STATUS" {
        "STATUS\n".into()
    } else {
        let (generation, revision) = expected
            .ok_or_else(error)?
            .split_once(':')
            .ok_or_else(error)?;
        format!("{action} {generation} {revision} {}\n", bytes.len())
    };
    write_deadline(&mut stream, header.as_bytes(), deadline)?;
    write_deadline(&mut stream, bytes, deadline)?;
    let reply = read_line(&mut stream, deadline)?;
    if !reply.starts_with("OK ") {
        return Err(error());
    }
    Ok(reply)
}
