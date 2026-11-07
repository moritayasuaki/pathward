//! Durable rescue before a quiescent, cross-role startup-contract transition.
use crate::{
    Result,
    codec::{self, string},
    contract as c, require, storage as f,
    storage::Checkpoint,
    system::{System, words},
};
use pathward::recovery::{self as policy, ContractChoice as Choice};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

const BOOT: &str = "pathward-role-recovery.service";
const FALLBACK: &str = "pathward-role-fallback.service";
const WATCHDOG: &str = "pathward-role-watchdog.service";
const TIMER: &str = "pathward-role-watchdog.timer";
const DROP: &str = "90-pathward-recovery.conf";
const LEGACY: [&str; 2] = [
    "pathward-recovery.service",
    "pathward-recovery-fallback.service",
];

#[path = "collection.rs"]
mod collection;

#[path = "bootstrap.rs"]
mod initial;

#[derive(Clone)]
pub struct Environment {
    pub units: PathBuf,
    pub boot_id: PathBuf,
    pub run: PathBuf,
    pub lock: PathBuf,
}
impl Environment {
    pub fn production() -> Self {
        Self {
            units: "/etc/systemd/system".into(),
            boot_id: "/proc/sys/kernel/random/boot_id".into(),
            run: "/run".into(),
            lock: "/run/pathward-migration.lock".into(),
        }
    }
}
pub struct Engine<S: System> {
    pub root: PathBuf,
    pub env: Environment,
    pub sys: S,
}
#[derive(Debug)]
pub struct AdministrationLease {
    _coordinator: File,
    _publication: crate::publication_gate::Lease,
}
impl<S: System> Engine<S> {
    pub fn lock(&self) -> Result<AdministrationLease> {
        f::trusted(&self.env.lock)?;
        let fd = rustix::fs::open(
            &self.env.lock,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )?;
        let lock = File::from(fd);
        use std::os::unix::fs::MetadataExt;
        let m = lock.metadata()?;
        require(
            m.is_file()
                && m.uid() == rustix::process::geteuid().as_raw()
                && m.nlink() == 1
                && m.mode() & 0o077 == 0,
            "untrusted lock",
        )?;
        lock.try_lock()?;
        Ok(AdministrationLease {
            _coordinator: lock,
            _publication: crate::publication_gate::administrator(&self.root)?,
        })
    }
    fn dir(&self, id: &str) -> Result<PathBuf> {
        require(codec::digest(id), "invalid request identity")?;
        Ok(self.root.join("transactions").join(id))
    }
    fn permit_path(&self) -> PathBuf {
        self.env.run.join(format!(
            "pathward-role-{}.json",
            codec::hash(self.root.to_string_lossy().as_bytes())
        ))
    }
    fn boot_id(&self) -> Result<String> {
        let s = fs::read_to_string(&self.env.boot_id)?.trim().to_owned();
        require(
            s.len() == 36 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "invalid boot identity",
        )?;
        Ok(s)
    }
    pub fn current(&self) -> Result<Option<String>> {
        let p = self.root.join("active");
        match fs::read_link(&p) {
            Ok(v) => {
                let s = v.to_str().ok_or("nontext pointer")?;
                let id = s
                    .strip_prefix("transactions/")
                    .ok_or("foreign active pointer")?;
                require(codec::digest(id), "invalid active pointer")?;
                self.plan(id)?;
                Ok(Some(id.into()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                require(p.symlink_metadata().is_err(), "dangling active pointer")?;
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }
    pub fn plan(&self, id: &str) -> Result<Value> {
        // Gates may run in a service's read-only mount namespace. Durability
        // is checked by the mutating coordinator in its host namespace.
        f::trusted(&self.root)?;
        let raw = f::bytes(&self.dir(id)?.join("plan.json"), true)?;
        require(codec::hash(&raw) == id, "sealed request changed")?;
        let p = codec::decode(&raw)?;
        require(
            p["schema"] == 2 && p["root"] == self.root.to_str().ok_or("root path")?,
            "wrong request root/schema",
        )?;
        c::validate(&p["source"])?;
        c::validate(&p["target"])?;
        f::verified(
            Path::new(string(&p, "engine")?),
            string(&p, "engine_sha256")?,
            false,
        )?;
        let names = Self::universe(&p)?;
        for contract in [&p["source"], &p["target"]] {
            require(
                c::names(contract)?.iter().all(|n| names.contains(n)),
                "unit outside sealed universe",
            )?;
        }
        Ok(p)
    }
    fn universe(p: &Value) -> Result<Vec<String>> {
        let a = p["universe"].as_array().ok_or("missing unit universe")?;
        let mut names = BTreeSet::new();
        require(!a.is_empty() && a.len() <= 24, "unit universe bound")?;
        for x in a {
            let n = x.as_str().ok_or("unit name")?;
            require(
                c::unit_name(n) && names.insert(n.to_owned()),
                "invalid unit universe",
            )?;
        }
        Ok(names.into_iter().collect())
    }
    fn state(&self, id: &str) -> Result<Value> {
        let state = f::record(&self.dir(id)?.join("state.json"))?;
        require(
            state["request"] == id
                && [
                    "prepared",
                    "armed",
                    "trial",
                    "committed",
                    "source",
                    "fallback",
                    "held",
                ]
                .contains(&string(&state, "phase")?),
            "invalid transition state",
        )?;
        Ok(state)
    }
    fn write_state(&self, id: &str, phase: &str, cp: Checkpoint<'_>) -> Result<()> {
        f::write_record(
            &self.dir(id)?.join("state.json"),
            &json!({"request":id,"phase":phase}),
            &format!("state-{phase}"),
            cp,
        )
    }
    fn role(p: &Value, choice: Choice) -> Result<&Value> {
        match choice {
            Choice::Source => Ok(&p["source"][string(&p["source"], "selected")?]),
            Choice::Fallback => Ok(&p["target"]["old"]),
            Choice::Primary => Ok(&p["target"]["new"]),
            Choice::Hold => Err("held transition has no role".into()),
        }
    }
    fn selected_contract(p: &Value, choice: Choice) -> Result<&Value> {
        match choice {
            Choice::Source => Ok(&p["source"]),
            Choice::Fallback | Choice::Primary => Ok(&p["target"]),
            Choice::Hold => Err("held contract".into()),
        }
    }
    fn choice_text(choice: Choice) -> &'static str {
        match choice {
            Choice::Hold => "hold",
            Choice::Source => "source",
            Choice::Fallback => "fallback",
            Choice::Primary => "primary",
        }
    }
    fn choice_parse(s: &str) -> Choice {
        match s {
            "source" => Choice::Source,
            "fallback" => Choice::Fallback,
            "primary" => Choice::Primary,
            _ => Choice::Hold,
        }
    }
    fn phase_allows(phase: &str, choice: Choice) -> bool {
        match phase {
            "prepared" | "source" => choice == Choice::Source,
            "trial" | "committed" => choice == Choice::Primary,
            "fallback" => choice == Choice::Fallback,
            _ => false,
        }
    }
    fn quiet(&mut self, p: &Value) -> Result<bool> {
        for unit in Self::universe(p)? {
            if !c::inactive(&self.sys.property(&unit, "ActiveState")?) {
                return Ok(false);
            }
        }
        self.no_jobs(p)
    }
    fn no_jobs(&mut self, p: &Value) -> Result<bool> {
        let mut args = words(&[
            "/usr/bin/systemctl",
            "list-jobs",
            "--no-legend",
            "--no-pager",
        ]);
        args.extend(Self::universe(p)?);
        Ok(self.sys.checked(&args, 45)?.trim().is_empty())
    }
    fn stop_all(&mut self, p: &Value, cp: Checkpoint<'_>) -> Result<()> {
        self.revoke(cp)?;
        let mut loaded = Vec::new();
        for unit in Self::universe(p)? {
            if self.sys.property(&unit, "LoadState")? != "not-found" {
                loaded.push(unit);
            }
        }
        // A stop may report a failed pre-existing service; inspect every actual
        // state and remaining job rather than treating failure as quiescence.
        let _ = self.sys.control("stop", &loaded, true);
        require(
            self.quiet(p)?,
            "services or jobs remain; contract change refused",
        )?;
        cp("all-stopped")
    }
    fn revoke(&self, cp: Checkpoint<'_>) -> Result<()> {
        match fs::remove_file(self.permit_path()) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        f::sync_dir(&self.env.run)?;
        cp("permit-revoked")
    }
    fn publish(&self, id: &str, choice: Choice, cp: Checkpoint<'_>) -> Result<()> {
        f::write_record(
            &self.permit_path(),
            &json!({"request":id,"boot":self.boot_id()?,"choice":Self::choice_text(choice)}),
            "permit",
            cp,
        )
    }
    fn gate_text(&self, p: &Value, unit: &str) -> Result<String> {
        Ok(format!(
            "[Unit]\nRequires={BOOT}\nAfter={BOOT}\nOnFailure=\nOnFailure={FALLBACK}\n\n[Service]\nExecStartPre=\nExecStartPre=+{} --root {} gate {}\nKillMode=control-group\nTimeoutStopSec=180\n",
            string(p, "engine")?,
            self.root.display(),
            unit
        ))
    }
    fn blocked_text() -> &'static str {
        "[Unit]\nDescription=Retired PathWard role (start denied)\n[Service]\nType=oneshot\nExecStart=/usr/bin/false\n"
    }
    fn base_text<'a>(&self, contract: &'a Value, name: &str) -> &'a str {
        contract["old"]["units"][name]
            .as_str()
            .or_else(|| contract["new"]["units"][name].as_str())
            .unwrap_or(Self::blocked_text())
    }
    fn boot_text(&self, p: &Value) -> Result<String> {
        let before = p["bootstrap"]
            .as_array()
            .ok_or("bootstrap universe")?
            .iter()
            .map(|n| n.as_str().ok_or("bootstrap name"))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .join(" ");
        Ok(format!(
            "[Unit]\nDescription=PathWard native contract recovery\nAfter=local-fs.target\nBefore={} {}\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart={} --root {} boot\nTimeoutStartSec=600\nUMask=0077\nNoNewPrivileges=yes\n\n[Install]\nWantedBy=multi-user.target\n",
            before,
            LEGACY.join(" "),
            string(p, "engine")?,
            self.root.display()
        ))
    }
    fn fallback_text(&self, p: &Value) -> Result<String> {
        Ok(format!(
            "[Unit]\nDescription=PathWard native contract fallback\nAfter={BOOT}\nStartLimitIntervalSec=0\n\n[Service]\nType=exec\nExecStart={} --root {} fallback\nRuntimeMaxSec=600\nTimeoutStopSec=15\nRestartForceExitStatus=75\nRestartSec=2\nUMask=0077\nNoNewPrivileges=yes\n",
            string(p, "engine")?,
            self.root.display()
        ))
    }
    fn rescue_durable(&self, p: &Value) -> Result<bool> {
        Ok(
            f::bytes(&self.env.units.join(BOOT), false)? == self.boot_text(p)?.as_bytes()
                && f::bytes(&self.env.units.join(FALLBACK), false)?
                    == self.fallback_text(p)?.as_bytes()
                && f::bytes(&self.env.units.join(WATCHDOG), false)?
                    == self.watchdog_text(p)?.as_bytes()
                && f::bytes(&self.env.units.join(TIMER), false)? == Self::timer_text().as_bytes()
                && fs::read_link(self.env.units.join("multi-user.target.wants").join(BOOT))?
                    == self.env.units.join(BOOT),
        )
    }
    fn watchdog_text(&self, p: &Value) -> Result<String> {
        Ok(format!(
            "[Unit]\nDescription=PathWard interrupted migration recovery\nAfter={BOOT}\n[Service]\nType=oneshot\nExecStart={} --root {} watchdog\nTimeoutStartSec=600\nUMask=0077\nNoNewPrivileges=yes\n",
            string(p, "engine")?,
            self.root.display()
        ))
    }
    fn timer_text() -> &'static str {
        "[Unit]\nDescription=PathWard migration deadline\n[Timer]\nOnActiveSec=180\nOnUnitActiveSec=60\nAccuracySec=1\nUnit=pathward-role-watchdog.service\n"
    }
    fn bootstrap(&mut self, p: &Value, cp: Checkpoint<'_>) -> Result<()> {
        // The active plan and rescue enablement are durable before touching a
        // legacy guard, unit contract, service process or permit.
        for (name, text) in [
            (BOOT, self.boot_text(p)?),
            (FALLBACK, self.fallback_text(p)?),
            (WATCHDOG, self.watchdog_text(p)?),
            (TIMER, Self::timer_text().into()),
        ] {
            f::replace(&self.env.units.join(name), text.as_bytes(), 0o644, name, cp)?;
        }
        let wants = self.env.units.join("multi-user.target.wants");
        f::directory(&wants)?;
        f::link(
            &wants.join(BOOT),
            &self.env.units.join(BOOT),
            "rescue-enabled",
            cp,
        )?;
        require(
            self.rescue_durable(p)?,
            "rescue installation readback failed",
        )?;
        self.sys
            .checked(&words(&["/usr/bin/systemctl", "daemon-reload"]), 45)?;
        cp("rescue-loaded")
    }
    fn retire_legacy(&mut self, p: &Value, cp: Checkpoint<'_>) -> Result<()> {
        if p["legacy"].is_null() {
            return Ok(());
        }
        let store = Path::new(string(&p["legacy"], "store")?);
        let marker = json!({"schema":2,"native_root":self.root,"source_generation":p["legacy"]["generation"]});
        let id = codec::hash(&codec::canonical(&marker));
        let dir = store.join("generations").join(&id);
        f::directory(&dir)?;
        f::write_record(&dir.join("manifest.json"), &marker, "legacy-tombstone", cp)?;
        f::link(
            &store.join("current"),
            Path::new(&format!("generations/{id}")),
            "legacy-fenced",
            cp,
        )?;
        // Old Python administrator/update commands fail closed on schema 2.
        let _ = self.sys.control("stop", &LEGACY.map(String::from), true);
        for unit in LEGACY {
            f::link(
                &self.env.units.join(unit),
                Path::new("/dev/null"),
                "legacy-masked",
                cp,
            )?;
            let wants = self.env.units.join("multi-user.target.wants").join(unit);
            if wants.symlink_metadata().is_ok() {
                fs::remove_file(&wants)?;
                f::sync_dir(wants.parent().ok_or("wants parent")?)?;
            }
        }
        Ok(())
    }
    fn installed(&self, p: &Value, choice: Choice) -> Result<bool> {
        let contract = Self::selected_contract(p, choice)?;
        for unit in Self::universe(p)? {
            if f::bytes(&self.env.units.join(&unit), false)?
                != self.base_text(contract, &unit).as_bytes()
                || f::bytes(&self.env.units.join(format!("{unit}.d/{DROP}")), false)?
                    != self.gate_text(p, &unit)?.as_bytes()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn loaded(&mut self, p: &Value, choice: Choice) -> Result<bool> {
        if !self.installed(p, choice)? {
            return Ok(false);
        }
        for unit in Self::universe(p)? {
            let expected = self.env.units.join(format!("{unit}.d/{DROP}"));
            let paths = self.sys.property(&unit, "DropInPaths")?;
            if paths.split_whitespace().collect::<Vec<_>>()
                != vec![expected.to_str().ok_or("drop-in path")?]
            {
                return Ok(false);
            }
            let pre = self.sys.property(&unit, "ExecStartPre")?;
            if !pre.contains(string(p, "engine")?) || !pre.contains(&format!("gate {unit}")) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn install(&mut self, id: &str, p: &Value, choice: Choice, cp: Checkpoint<'_>) -> Result<()> {
        let quiet = self.quiet(p)?;
        let no_jobs = self.no_jobs(p)?;
        let verified = c::verified(&mut self.sys, Self::role(p, choice)?, false).is_ok();
        require(
            policy::contract_install_allowed(
                self.rescue_durable(p)?,
                quiet,
                no_jobs,
                self.permit_path().symlink_metadata().is_err(),
                self.current()?.as_deref() == Some(id),
                verified,
            ),
            "contract installation not authorized",
        )?;
        self.retire_legacy(p, cp)?;
        let contract = Self::selected_contract(p, choice)?;
        // All gates are installed before any changed application unit appears.
        for unit in Self::universe(p)? {
            let d = self.env.units.join(format!("{unit}.d"));
            f::directory(&d)?;
            f::replace(
                &d.join(DROP),
                self.gate_text(p, &unit)?.as_bytes(),
                0o644,
                &format!("gate-{unit}"),
                cp,
            )?;
        }
        for unit in Self::universe(p)? {
            f::replace(
                &self.env.units.join(&unit),
                self.base_text(contract, &unit).as_bytes(),
                0o644,
                &format!("unit-{unit}"),
                cp,
            )?;
        }
        self.sys
            .checked(&words(&["/usr/bin/systemctl", "daemon-reload"]), 45)?;
        cp("contract-reloaded")?;
        require(self.loaded(p, choice)?, "loaded contract differs")?;
        cp("contract-verified")
    }
    fn protect_sources(&mut self, p: &Value, cp: Checkpoint<'_>) -> Result<()> {
        // Close legacy restart/socket-activation paths before draining. The
        // durable rescue already exists; no application definition changes.
        for unit in Self::universe(p)? {
            let d = self.env.units.join(format!("{unit}.d"));
            f::directory(&d)?;
            f::replace(
                &d.join(DROP),
                self.gate_text(p, &unit)?.as_bytes(),
                0o644,
                &format!("protect-{unit}"),
                cp,
            )?;
        }
        self.sys
            .checked(&words(&["/usr/bin/systemctl", "daemon-reload"]), 45)?;
        for unit in Self::universe(p)? {
            if self.sys.property(&unit, "LoadState")? == "not-found" {
                continue;
            }
            let pre = self.sys.property(&unit, "ExecStartPre")?;
            require(
                pre.contains(string(p, "engine")?) && pre.contains(&format!("gate {unit}")),
                "source gate reload failed",
            )?;
        }
        cp("source-gates-loaded")
    }
    pub fn gate(&self, unit: &str) -> Result<bool> {
        require(c::unit_name(unit), "invalid gate unit")?;
        let id = self.current()?.ok_or("missing active request")?;
        let p = self.plan(&id)?;
        let state = self.state(&id)?;
        let permit = f::record(&self.permit_path())?;
        let choice = Self::choice_parse(string(&permit, "choice")?);
        let member = Self::role(&p, choice)
            .and_then(c::role_units)
            .is_ok_and(|v| v.iter().any(|n| n == unit));
        Ok(policy::contract_gate_allowed(
            choice,
            member,
            permit["boot"] == self.boot_id()?,
            permit["request"] == id,
            Self::phase_allows(string(&state, "phase")?, choice),
            self.installed(&p, choice).unwrap_or(false),
        ))
    }
    pub fn prepare(
        &mut self,
        input: &Value,
        executable: &Path,
        cp: Checkpoint<'_>,
    ) -> Result<String> {
        f::root_mount(&self.root)?;
        f::directory(&self.root)?;
        f::directory(&self.root.join("transactions"))?;
        let current = self.current()?;
        if current.is_none() {
            require(
                [BOOT, FALLBACK, WATCHDOG, TIMER]
                    .iter()
                    .all(|name| self.env.units.join(name).symlink_metadata().is_err()),
                "native recovery service belongs to another store",
            )?;
        }
        let target = c::materialize(&input["target"])?;
        require(
            target["selected"] == "new",
            "target primary must be explicit",
        )?;
        for side in ["old", "new"] {
            require(
                target[side]["files"]
                    .as_object()
                    .ok_or("resources")?
                    .keys()
                    .all(|p| !Path::new(p).starts_with(&self.env.units)),
                "live unit files cannot be sealed resources",
            )?;
        }
        for side in ["old", "new"] {
            c::verified(&mut self.sys, &target[side], true)?;
        }
        let (source, legacy, bootstrap, mut universe) = if let Some(ref id) = current {
            require(input["source_current"] == *id, "source identity changed")?;
            let prior = self.plan(id)?;
            let state = self.state(id)?;
            let choice = match string(&state, "phase")? {
                "committed" => Choice::Primary,
                "fallback" => Choice::Fallback,
                "source" => Choice::Source,
                _ => return Err("source transition not terminal".into()),
            };
            let mut source = Self::selected_contract(&prior, choice)?.clone();
            source["selected"] = match choice {
                Choice::Source => prior["source"]["selected"].clone(),
                Choice::Fallback => "old".into(),
                _ => "new".into(),
            };
            require(
                self.loaded(&prior, choice)?
                    && c::stable(
                        &mut self.sys,
                        &Self::universe(&prior)?,
                        Self::role(&prior, choice)?,
                    )?,
                "native source not stable",
            )?;
            (
                source,
                prior["legacy"].clone(),
                prior["bootstrap"].clone(),
                Self::universe(&prior)?,
            )
        } else if !input["source_fresh"].is_null() {
            let source = c::materialize(&input["source_fresh"])?;
            self.fresh_source(&source)?;
            let names = c::names(&source)?;
            (source, Value::Null, json!(names), names)
        } else {
            self.capture_legacy(input)?
        };
        c::validate(&source)?;
        for side in ["old", "new"] {
            c::verified(&mut self.sys, &source[side], true)?;
        }
        let previous = universe.clone();
        for name in c::names(&target)? {
            if !previous.contains(&name) {
                require(
                    self.sys.property(&name, "LoadState")? == "not-found"
                        && self.env.units.join(&name).symlink_metadata().is_err()
                        && self
                            .env
                            .units
                            .join(format!("{name}.d"))
                            .symlink_metadata()
                            .is_err(),
                    "target unit is already owned elsewhere",
                )?;
            }
            universe.push(name);
        }
        universe.sort();
        universe.dedup();
        require(universe.len() <= 24, "unit universe exhausted")?;
        let engine_hash = codec::hash(&f::bytes(executable, false)?);
        f::verified(executable, &engine_hash, true)?;
        let engine = self.root.join(format!("engine-{engine_hash}"));
        if let Some(ref id) = current {
            require(
                self.plan(id)?["engine_sha256"] == engine_hash,
                "native engine replacement requires a separate reviewed migration",
            )?;
        }
        if engine.exists() {
            f::verified(&engine, &engine_hash, true)?;
        } else {
            f::replace(&engine, &f::bytes(executable, false)?, 0o700, "engine", cp)?;
        }
        let p = json!({"schema":2,"root":self.root,"parent":current,"source":source,"target":target,
            "legacy":legacy,"bootstrap":bootstrap,"universe":universe,"engine":engine,"engine_sha256":engine_hash});
        let id = codec::hash(&codec::encode(&p));
        let dir = self.dir(&id)?;
        require(
            dir.exists() || fs::read_dir(self.root.join("transactions"))?.count() < 128,
            "native request retention limit; collect reviewed old generations first",
        )?;
        f::directory(&dir)?;
        // PID 1's own parser checks both complete contracts before a request
        // can be applied. Only immutable copies in this private staging area.
        for side in ["source", "target"] {
            let check = dir.join(side);
            f::directory(&check)?;
            let mut args = words(&["/usr/bin/systemd-analyze", "verify"]);
            for role in ["old", "new"] {
                for (unit, text) in p[side][role]["units"]
                    .as_object()
                    .ok_or("unit definitions")?
                {
                    let dest = check.join(unit);
                    f::replace(
                        &dest,
                        text.as_str().ok_or("unit text")?.as_bytes(),
                        0o644,
                        "verify-unit",
                        cp,
                    )?;
                    args.push(dest.to_str().ok_or("unit path")?.to_owned());
                }
            }
            self.sys.checked(&args, 45)?;
        }
        let path = dir.join("plan.json");
        if path.exists() {
            require(f::record(&path)? == p, "request conflict")?;
        } else {
            f::write_record(&path, &p, "request", cp)?;
        }
        f::verified(&path, &id, true)?;
        Ok(id)
    }
    fn capture_legacy(&mut self, input: &Value) -> Result<(Value, Value, Value, Vec<String>)> {
        let old = &input["source_legacy"];
        let store = Path::new(string(old, "store")?);
        f::root_mount(store)?;
        let link = fs::read_link(store.join("current"))?;
        let link = link.to_str().ok_or("legacy pointer")?;
        let generation = link
            .strip_prefix("generations/")
            .ok_or("legacy generation")?;
        require(codec::digest(generation), "legacy generation id")?;
        let g = f::record(&store.join(link).join("manifest.json"))?;
        require(
            g["schema"] == 1 && codec::hash(&codec::canonical(&g)) == generation,
            "legacy manifest mismatch",
        )?;
        f::verified(
            Path::new(string(&g, "helper")?),
            string(&g, "helper_sha256")?,
            true,
        )?;
        let path = Path::new(string(old, "plan")?);
        let sha = string(old, "sha256")?;
        require(
            g["plan"] == old["plan"] && g["plan_sha256"] == sha,
            "legacy plan binding",
        )?;
        f::verified(path, sha, true)?;
        let plan = f::record(path)?;
        require(plan["schema"] == 1, "legacy plan schema")?;
        let journal = f::record(Path::new(string(&plan, "journal")?))?;
        require(
            journal["transaction"] == plan["transaction"],
            "legacy journal transaction",
        )?;
        let selected = match string(&journal, "phase")? {
            "prepared" | "rolled_back" => "old",
            "committed" => "new",
            _ => return Err("legacy transaction not terminal".into()),
        };
        let permit = f::record(Path::new(string(&plan, "permit")?))?;
        require(
            permit["boot_id"] == self.boot_id()?
                && permit["plan_sha256"] == sha
                && permit["selection"] == selected.to_uppercase(),
            "legacy boot permit",
        )?;
        let receipt = f::record(&store.join("last-applied.json"))?;
        require(
            receipt["target"] == generation
                && receipt["plan_sha256"] == sha
                && receipt["epoch"] == g["epoch"],
            "legacy update incomplete",
        )?;
        let mut drops = Vec::new();
        for (name, text) in g["units"].as_object().ok_or("legacy unit manifest")? {
            let actual = store.join(link).join(name);
            require(
                codec::hash(&f::bytes(&actual, false)?)
                    == codec::hash(text.as_str().ok_or("legacy unit text")?.as_bytes()),
                "legacy unit changed",
            )?;
            require(
                fs::read_link(self.env.units.join(name))? == store.join("current").join(name),
                "legacy unit installation changed",
            )?;
            if name.ends_with(DROP) {
                drops.push(self.env.units.join(name).to_string_lossy().into_owned());
            }
        }
        let old_role = c::legacy_role(
            &mut self.sys,
            &plan["old"],
            &old["health"]["old"],
            &self.env.units,
            &drops,
        )?;
        let new_role = c::legacy_role(
            &mut self.sys,
            &plan["new"],
            &old["health"]["new"],
            &self.env.units,
            &drops,
        )?;
        let source = json!({"old":old_role,"new":new_role,"selected":selected});
        let names = c::names(&source)?;
        require(
            c::stable(&mut self.sys, &names, &source[selected])?,
            "legacy source not stable",
        )?;
        c::health(&mut self.sys, &source[selected])?;
        let legacy = json!({"store":store,"generation":generation,"plan":path,"sha256":sha,
            "journal":plan["journal"],"journal_sha256":codec::hash(&f::bytes(Path::new(string(&plan,"journal")?),true)?)});
        Ok((source, legacy, json!(names), names))
    }
    fn activate(&mut self, id: &str, p: &Value, cp: Checkpoint<'_>) -> Result<()> {
        if self.current()?.as_deref() == Some(id) {
            f::sync_dir(&self.root)?;
            return cp("active-request:confirmed");
        }
        require(
            self.current()?.map(Value::String).unwrap_or(Value::Null) == p["parent"],
            "stale request",
        )?;
        if p["parent"].is_null() && !p["legacy"].is_null() {
            let l = &p["legacy"];
            let store = Path::new(string(l, "store")?);
            require(
                fs::read_link(store.join("current"))?
                    == Path::new(&format!("generations/{}", string(l, "generation")?)),
                "legacy source moved",
            )?;
            require(
                codec::hash(&f::bytes(Path::new(string(l, "journal")?), true)?)
                    == l["journal_sha256"],
                "source application changed",
            )?;
        } else if p["parent"].is_null() {
            self.fresh_source(&p["source"])?;
        }
        let universe = Self::universe(p)?;
        require(
            c::stable(&mut self.sys, &universe, Self::role(p, Choice::Source)?)?
                && self.no_jobs(p)?,
            "source application is not quiet and stable",
        )?;
        c::verified(&mut self.sys, Self::role(p, Choice::Source)?, false)?;
        self.write_state(id, "prepared", cp)?;
        f::link(
            &self.root.join("active"),
            Path::new(&format!("transactions/{id}")),
            "active-request",
            cp,
        )
    }
    pub fn apply(&mut self, id: &str, cp: Checkpoint<'_>) -> Result<()> {
        f::root_mount(&self.root)?;
        let p = self.plan(id)?;
        self.activate(id, &p, cp)?;
        self.bootstrap(&p, cp)?;
        let phase = self
            .state(id)
            .ok()
            .and_then(|v| v["phase"].as_str().map(str::to_owned))
            .unwrap_or_default();
        if ["committed", "fallback"].contains(&phase.as_str()) {
            let choice = if phase == "committed" {
                Choice::Primary
            } else {
                Choice::Fallback
            };
            require(
                self.loaded(&p, choice)?
                    && c::stable(&mut self.sys, &Self::universe(&p)?, Self::role(&p, choice)?)?,
                "completed request needs recovery first",
            )?;
            return c::health(&mut self.sys, Self::role(&p, choice)?);
        }
        // Starting the rescue unit while holding the shared lock is safe only
        // with this boot's checked source permit. A cold boot has no such permit.
        if self.sys.property(BOOT, "ActiveState")? != "active" {
            self.write_state(id, "prepared", cp)?;
            self.publish(id, Choice::Source, cp)?;
            self.sys.control("start", &[BOOT.into()], true)?;
        }
        let result = (|| {
            self.protect_sources(&p, cp)?;
            self.write_state(id, "armed", cp)?;
            self.sys.control("restart", &[TIMER.into()], true)?;
            require(
                self.sys.property(TIMER, "ActiveState")? == "active",
                "migration watchdog did not arm",
            )?;
            cp("watchdog-armed")?;
            self.stop_all(&p, cp)?;
            self.install(id, &p, Choice::Primary, cp)?;
            c::verified(&mut self.sys, &p["target"]["old"], false)?;
            self.write_state(id, "trial", cp)?;
            self.publish(id, Choice::Primary, cp)?;
            self.start(&p, Choice::Primary, true)?;
            cp("target-started")?;
            let only = c::stable(
                &mut self.sys,
                &Self::universe(&p)?,
                Self::role(&p, Choice::Primary)?,
            )?;
            let healthy = c::health(&mut self.sys, Self::role(&p, Choice::Primary)?).is_ok();
            let fallback = c::verified(&mut self.sys, &p["target"]["old"], false).is_ok();
            let loaded = self.loaded(&p, Choice::Primary)?;
            require(
                policy::contract_commit_allowed(
                    self.state(id)?["phase"] == "trial",
                    self.current()?.as_deref() == Some(id),
                    only,
                    healthy,
                    fallback,
                    loaded,
                ),
                "commit conditions failed",
            )?;
            cp("health-verified")?;
            self.write_state(id, "committed", cp)?;
            self.sys.control("stop", &[TIMER.into()], true)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = self.recover(false, false, &mut |_| Ok(()));
        }
        result
    }
    fn start(&mut self, p: &Value, choice: Choice, blocking: bool) -> Result<()> {
        let units = c::role_units(Self::role(p, choice)?)?;
        let _ = self.sys.control("reset-failed", &units, true);
        self.sys.control("start", &units, blocking)
    }
    /// Before/After dependencies keep application jobs behind this boot unit.
    /// Queue starts without waiting for jobs that themselves wait for us.
    pub fn boot_fast_path(&mut self) -> Result<bool> {
        let id = self.current()?.ok_or("no request")?;
        let p = self.plan(&id)?;
        let state = self.state(&id)?;
        let permit = f::record(&self.permit_path())?;
        Ok(state["phase"] == "prepared"
            && permit["request"] == id
            && permit["boot"] == self.boot_id()?
            && permit["choice"] == "source"
            && c::stable(
                &mut self.sys,
                &Self::universe(&p)?,
                Self::role(&p, Choice::Source)?,
            )?)
    }
    pub fn recover(&mut self, boot: bool, failure: bool, cp: Checkpoint<'_>) -> Result<()> {
        f::root_mount(&self.root)?;
        let id = self.current()?.ok_or("missing request")?;
        let p = self.plan(&id)?;
        self.protect_sources(&p, cp)?;
        let state = self.state(&id).unwrap_or(json!({"phase":"source"}));
        let phase = state["phase"].as_str().unwrap_or("source");
        if phase == "held" {
            self.stop_all(&p, cp)?;
            return Err("recovery deliberately held".into());
        }
        let mut fallback_requested = phase == "fallback";
        if failure {
            let allowed = match phase {
                "trial" | "committed" => Choice::Primary,
                "fallback" => Choice::Fallback,
                "source" | "prepared" => Choice::Source,
                _ => return Ok(()),
            };
            let mut failed = false;
            for unit in c::role_units(Self::role(&p, allowed)?)? {
                failed |= self.sys.property(&unit, "ActiveState")? == "failed";
            }
            if !failed {
                return Ok(());
            }
            if allowed != Choice::Primary {
                self.write_state(&id, "held", cp)?;
                self.stop_all(&p, cp)?;
                return Err("selected fallback failed; held".into());
            }
            fallback_requested = true;
        }
        let committed = ["committed", "fallback"].contains(&phase);
        let primary = c::verified(&mut self.sys, Self::role(&p, Choice::Primary)?, false).is_ok();
        let fallback = c::verified(&mut self.sys, Self::role(&p, Choice::Fallback)?, false).is_ok();
        let source = c::verified(&mut self.sys, Self::role(&p, Choice::Source)?, false).is_ok();
        let choice = policy::contract_recovery_choice(
            committed,
            fallback_requested,
            primary,
            fallback,
            source,
        );
        self.stop_all(&p, cp)?;
        if choice == Choice::Hold {
            self.write_state(&id, "held", cp)?;
            return Err("no verified recovery contract".into());
        }
        self.install(&id, &p, choice, cp)?;
        let phase = match choice {
            Choice::Primary => "committed",
            Choice::Fallback => "fallback",
            _ => "source",
        };
        self.write_state(&id, phase, cp)?;
        self.publish(&id, choice, cp)?;
        self.start(&p, choice, !boot)?;
        if !boot {
            require(
                c::stable(&mut self.sys, &Self::universe(&p)?, Self::role(&p, choice)?)?,
                "recovery failed to settle",
            )?;
            c::health(&mut self.sys, Self::role(&p, choice)?)?;
        }
        Ok(())
    }
    pub fn status(&self) -> Result<Value> {
        let id = self.current()?.ok_or("no active request")?;
        Ok(json!({"request":id,"state":self.state(&id)?}))
    }
    pub fn watchdog(&mut self, cp: Checkpoint<'_>) -> Result<()> {
        let id = self.current()?.ok_or("missing active request")?;
        let state = self.state(&id).unwrap_or(json!({"phase":"armed"}));
        let phase = state["phase"].as_str().unwrap_or("armed");
        if policy::contract_watchdog_allowed(
            ["committed", "fallback"].contains(&phase),
            ["prepared", "armed", "trial"].contains(&phase),
            self.current()?.as_deref() == Some(&id),
        ) {
            self.recover(false, false, cp)?;
        }
        Ok(())
    }
}
