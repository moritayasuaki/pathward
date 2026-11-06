//! Initial native recovery installation: the selected source is never stopped.
use super::*;

impl<S: System> Engine<S> {
    pub(super) fn fresh_source(&mut self, source: &Value) -> Result<()> {
        c::validate(source)?;
        require(
            source["selected"] == "old",
            "initial source must select old",
        )?;
        require(
            LEGACY
                .iter()
                .all(|n| self.env.units.join(n).symlink_metadata().is_err()),
            "existing legacy guard requires migration",
        )?;
        for (name, text) in source["old"]["units"].as_object().ok_or("old units")? {
            require(
                self.sys.property(name, "Names")? == *name
                    && self.sys.property(name, "DropInPaths")?.is_empty()
                    && self.sys.property(name, "UnitFileState")? == "enabled"
                    && self.sys.property(name, "ActiveState")? == "active",
                "initial source not exclusively enabled and active",
            )?;
            let fragment = self.sys.property(name, "FragmentPath")?;
            f::root_mount(Path::new(&fragment))?;
            require(
                f::bytes(Path::new(&fragment), false)?
                    == text.as_str().ok_or("unit text")?.as_bytes(),
                "initial source template changed",
            )?;
            require(
                self.env
                    .units
                    .join(format!("{name}.d"))
                    .symlink_metadata()
                    .is_err(),
                "initial source has unmanaged drop-in directory",
            )?;
        }
        for name in c::role_units(&source["new"])? {
            require(
                self.sys.property(&name, "LoadState")? == "not-found"
                    && c::inactive(&self.sys.property(&name, "ActiveState")?)
                    && self.env.units.join(&name).symlink_metadata().is_err()
                    && self
                        .env
                        .units
                        .join(format!("{name}.d"))
                        .symlink_metadata()
                        .is_err(),
                "initial candidate already installed",
            )?;
        }
        c::verified(&mut self.sys, &source["old"], true)?;
        c::health(&mut self.sys, &source["old"])
    }

    /// Idempotent prepare-only entry point. Binding the input before activation
    /// prevents an interrupted installation from accepting a different request.
    pub fn initialize(&mut self, input: &Value, exe: &Path, cp: Checkpoint<'_>) -> Result<String> {
        f::root_mount(&self.root)?;
        f::directory(&self.root)?;
        let identity = codec::hash(&codec::canonical(input));
        let marker = self.root.join("initial.json");
        let id = if marker.symlink_metadata().is_ok() {
            let r = f::record(&marker)?;
            require(
                r["input"] == identity,
                "different initial preparation already owns this store",
            )?;
            string(&r, "request")?.to_owned()
        } else {
            require(
                self.current()?.is_none() && !input["source_fresh"].is_null(),
                "initial preparation requires a fresh source",
            )?;
            let id = self.prepare(input, exe, cp)?;
            f::write_record(
                &marker,
                &json!({"input":identity,"request":id}),
                "initial-request",
                cp,
            )?;
            id
        };
        let p = self.plan(&id)?;
        require(
            p["parent"].is_null()
                && p["legacy"].is_null()
                && p["source"]["selected"] == "old"
                && p["engine_sha256"] == codec::hash(&f::bytes(exe, false)?),
            "initial request authority",
        )?;
        if let Some(active) = self.current()? {
            require(active == id, "initial request is no longer current")?;
            let phase = self.state(&id)?;
            require(
                ["prepared", "source"].contains(&string(&phase, "phase")?),
                "initial request already transitioned",
            )?;
            if phase["phase"] == "source" {
                require(
                    self.loaded(&p, Choice::Source)?
                        && c::stable(
                            &mut self.sys,
                            &Self::universe(&p)?,
                            Self::role(&p, Choice::Source)?,
                        )?,
                    "prepared source requires recovery",
                )?;
                c::health(&mut self.sys, Self::role(&p, Choice::Source)?)?;
                return Ok(id);
            }
        }
        self.activate(&id, &p, cp)?;
        self.bootstrap(&p, cp)?;
        require(
            pathward::bootstrap::preparation_allowed(
                self.rescue_durable(&p)?,
                self.current()?.as_deref() == Some(&id),
                c::stable(
                    &mut self.sys,
                    &Self::universe(&p)?,
                    Self::role(&p, Choice::Source)?,
                )?,
                self.no_jobs(&p)?,
            ),
            "initial installation conditions changed",
        )?;
        // Only identical selected application text is installed. Candidate
        // gates precede every candidate unit; no candidate receives a permit.
        for name in Self::universe(&p)? {
            let d = self.env.units.join(format!("{name}.d"));
            f::directory(&d)?;
            let target = d.join(DROP);
            let text = self.gate_text(&p, &name)?;
            if target.symlink_metadata().is_ok() {
                require(
                    f::bytes(&target, false)? == text.as_bytes(),
                    "unexpected initial gate",
                )?;
            }
            f::replace(&target, text.as_bytes(), 0o644, "initial-gate", cp)?;
        }
        for name in Self::universe(&p)? {
            let target = self.env.units.join(&name);
            let text = self.base_text(&p["source"], &name);
            if target.symlink_metadata().is_ok() {
                require(
                    f::bytes(&target, false)? == text.as_bytes(),
                    "unexpected initial unit",
                )?;
            }
            f::replace(&target, text.as_bytes(), 0o644, "initial-unit", cp)?;
        }
        self.sys
            .checked(&words(&["/usr/bin/systemctl", "daemon-reload"]), 45)?;
        require(
            self.loaded(&p, Choice::Source)?,
            "initial loaded contract differs",
        )?;
        self.publish(&id, Choice::Source, cp)?;
        self.sys.control("start", &[BOOT.into()], true)?;
        require(
            c::stable(
                &mut self.sys,
                &Self::universe(&p)?,
                Self::role(&p, Choice::Source)?,
            )?,
            "initial preparation changed application state",
        )?;
        c::health(&mut self.sys, Self::role(&p, Choice::Source)?)?;
        self.write_state(&id, "source", cp)?;
        Ok(id)
    }
}
