//! Native collection of retired requests and tombstoned legacy guard generations.
//! Only exact, observed immutable members are moved; external resources stay put.
use super::*;
use crate::confined;
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;

fn tree(path: &Path) -> Result<BTreeMap<String, String>> {
    fn visit(root: &Path, p: &Path, out: &mut BTreeMap<String, String>) -> Result<()> {
        let m = fs::symlink_metadata(p)?;
        require(
            m.uid() == rustix::process::geteuid().as_raw()
                && !m.file_type().is_symlink()
                && m.mode() & 0o022 == 0,
            "foreign collection member",
        )?;
        if m.is_dir() {
            for e in fs::read_dir(p)? {
                visit(root, &e?.path(), out)?;
            }
        } else {
            require(m.is_file() && m.nlink() == 1, "special collection member")?;
            let name = p.strip_prefix(root)?.to_str().ok_or("collection name")?;
            require(confined::relative(name), "collection path")?;
            require(out.len() < 128, "collection member limit")?;
            out.insert(name.into(), codec::hash(&f::bytes(p, false)?));
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(path, path, &mut out)?;
    Ok(out)
}
fn ids(path: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for e in fs::read_dir(path)? {
        let e = e?;
        let s = e.file_name().into_string().map_err(|_| "generation name")?;
        // Unsealed interrupted staging directories remain quarantined.
        if s.starts_with(".stage-") {
            continue;
        }
        require(
            codec::digest(&s) && e.file_type()?.is_dir(),
            "unexpected generation entry",
        )?;
        out.push(s);
        require(out.len() <= 128, "generation inventory bound")?;
    }
    out.sort();
    Ok(out)
}
fn references(v: &Value, roots: &[PathBuf], found: &mut BTreeSet<PathBuf>) -> Result<()> {
    match v {
        Value::String(s) => {
            for root in roots {
                let prefix = root.to_str().ok_or("store path")?;
                if s.contains(prefix) {
                    // Paths embedded in a command/template require manual retention review.
                    require(
                        s.starts_with(&format!("{prefix}/")) && f::absolute(Path::new(s)),
                        "ambiguous managed-store reference",
                    )?;
                    found.insert(PathBuf::from(s));
                }
            }
        }
        Value::Array(a) => {
            for v in a {
                references(v, roots, found)?;
            }
        }
        Value::Object(m) => {
            for (k, v) in m {
                references(&json!(k), roots, found)?;
                references(v, roots, found)?;
            }
        }
        _ => (),
    }
    Ok(())
}
impl<S: System> Engine<S> {
    fn collection_fence(&mut self) -> Result<(String, Value)> {
        f::root_mount(&self.root)?;
        let id = self.current()?.ok_or("missing current request")?;
        let p = self.plan(&id)?;
        let state = self.state(&id)?;
        let choice = match string(&state, "phase")? {
            "committed" => Choice::Primary,
            "fallback" => Choice::Fallback,
            "source" => Choice::Source,
            _ => return Err("transition not terminal".into()),
        };
        let selected = Self::role(&p, choice)?["units"]
            .as_object()
            .ok_or("selected units")?
            .keys()
            .next()
            .ok_or("empty role")?;
        require(
            self.rescue_durable(&p)? && self.loaded(&p, choice)? && self.gate(selected)?,
            "recovery gate not stable",
        )?;
        require(
            c::stable(&mut self.sys, &Self::universe(&p)?, Self::role(&p, choice)?)?,
            "services not quiescent",
        )?;
        for side in [&p["source"], &p["target"]] {
            for role in ["old", "new"] {
                c::verified(&mut self.sys, &side[role], false)?;
            }
        }
        require(self.no_jobs(&p)?, "pending service jobs")?;
        c::health(&mut self.sys, Self::role(&p, choice)?)?;
        Ok((id, p))
    }
    fn collection_inventory(
        &self,
        current: &str,
        p: &Value,
        keep: &[String],
    ) -> Result<(Value, BTreeSet<String>)> {
        let mut entries = json!({});
        let mut protected = BTreeSet::new();
        let native = self.root.join("transactions");
        let mut roots = vec![native.clone()];
        let legacy = if p["legacy"].is_null() {
            None
        } else {
            Some(PathBuf::from(string(&p["legacy"], "store")?))
        };
        if let Some(root) = &legacy {
            f::root_mount(root)?;
            roots.push(root.join("generations"));
        }
        for id in ids(&native)? {
            let plan = self.plan(&id)?;
            let dir = native.join(&id);
            let members = tree(&dir)?;
            let mut allowed: BTreeSet<String> = ["plan.json".into(), "state.json".into()].into();
            for side in ["source", "target"] {
                for role in ["old", "new"] {
                    for (name, text) in plan[side][role]["units"]
                        .as_object()
                        .ok_or("unit members")?
                    {
                        let path = format!("{side}/{name}");
                        allowed.insert(path.clone());
                        require(
                            members.get(&path)
                                == Some(&codec::hash(text.as_str().ok_or("unit text")?.as_bytes())),
                            "request unit changed",
                        )?;
                    }
                }
            }
            require(
                members.keys().all(|k| allowed.contains(k)),
                "foreign request member",
            )?;
            let key = format!("native-{id}");
            let phase = self
                .state(&id)
                .ok()
                .and_then(|s| s["phase"].as_str().map(str::to_owned));
            if id == current
                || p["parent"] == id
                || keep.contains(&key)
                || !matches!(phase.as_deref(), Some("committed" | "source" | "fallback"))
            {
                protected.insert(key.clone());
            }
            entries[&key] =
                json!({"path":dir,"members":members,"references":[plan["source"],plan["target"]]});
        }
        if let Some(root) = &legacy {
            let source = string(&p["legacy"], "generation")?;
            let source_manifest =
                f::record(&root.join("generations").join(source).join("manifest.json"))?;
            let epoch = source_manifest["epoch"].as_u64().ok_or("legacy epoch")?;
            let marker = json!({"schema":2,"native_root":self.root,"source_generation":source});
            let tomb = codec::hash(&codec::canonical(&marker));
            require(
                fs::read_link(root.join("current"))? == Path::new(&format!("generations/{tomb}")),
                "legacy engine not retired",
            )?;
            require(
                f::record(&root.join("generations").join(&tomb).join("manifest.json"))? == marker,
                "legacy tombstone changed",
            )?;
            for id in ids(&root.join("generations"))? {
                let dir = root.join("generations").join(&id);
                let g = f::record(&dir.join("manifest.json"))?;
                require(codec::hash(&codec::canonical(&g)) == id, "legacy identity")?;
                let members = tree(&dir)?;
                let key = format!("legacy-{id}");
                if id == tomb {
                    require(members.len() == 1, "tombstone members")?;
                    protected.insert(key.clone());
                    entries[&key] = json!({"path":dir,"members":members,"references":[]});
                    continue;
                }
                require(g["schema"] == 1, "legacy schema")?;
                let mut wanted = BTreeSet::from(["manifest.json".to_owned()]);
                for (name, text) in g["units"].as_object().ok_or("legacy unit list")? {
                    require(confined::relative(name), "legacy member path")?;
                    wanted.insert(name.clone());
                    require(
                        members.get(name)
                            == Some(&codec::hash(text.as_str().ok_or("legacy unit")?.as_bytes())),
                        "legacy unit changed",
                    )?;
                }
                require(
                    members.keys().cloned().collect::<BTreeSet<_>>() == wanted,
                    "legacy membership",
                )?;
                f::verified(
                    Path::new(string(&g, "helper")?),
                    string(&g, "helper_sha256")?,
                    false,
                )?;
                f::verified(
                    Path::new(string(&g, "plan")?),
                    string(&g, "plan_sha256")?,
                    false,
                )?;
                let plan = f::record(Path::new(string(&g, "plan")?))?;
                if id == source
                    || source_manifest["parent"] == id
                    || g["epoch"].as_u64().ok_or("generation epoch")? >= epoch
                    || keep.contains(&key)
                {
                    protected.insert(key.clone());
                }
                entries[&key] =
                    json!({"path":dir,"members":members,"references":[plan,g["helper"]]});
            }
        }
        for k in keep {
            require(
                entries.get(k).is_some(),
                "explicit retention member missing",
            )?;
        }
        // Fixed point over every declared managed-store reference of retained records.
        loop {
            let before = protected.len();
            let mut found = BTreeSet::new();
            for k in &protected {
                references(&entries[k]["references"], &roots, &mut found)?;
            }
            for path in found {
                let mut matched = false;
                for (k, e) in entries.as_object().ok_or("inventory")? {
                    if path.starts_with(Path::new(string(e, "path")?)) {
                        protected.insert(k.clone());
                        matched = true;
                        break;
                    }
                }
                require(matched, "missing managed generation reference")?;
            }
            if protected.len() == before {
                break;
            }
        }
        Ok((entries, protected))
    }
    /// Must be repeated after changing the active request. A later boot is mandatory.
    pub fn observe_collection(&mut self, cp: Checkpoint<'_>) -> Result<Value> {
        let (current, p) = self.collection_fence()?;
        let (entries, _) = self.collection_inventory(&current, &p, &[])?;
        let value = json!({"schema":1,"current":current,"boot":self.boot_id()?,"entries":entries});
        f::write_record(
            &self.root.join("retention-observed.json"),
            &value,
            "retention-observed",
            cp,
        )?;
        Ok(value)
    }
    pub fn plan_collection(&mut self, keep: &[String], cp: Checkpoint<'_>) -> Result<String> {
        let (current, p) = self.collection_fence()?;
        let observed = f::record(&self.root.join("retention-observed.json"))?;
        require(
            observed["schema"] == 1
                && observed["current"] == current
                && observed["boot"].as_str().is_some()
                && observed["boot"] != self.boot_id()?,
            "collection needs the same current request after another boot",
        )?;
        let (entries, protected) = self.collection_inventory(&current, &p, keep)?;
        let mut selected = json!({});
        for (k, e) in entries.as_object().ok_or("entries")? {
            if pathward::publication::collection_allowed(
                true,
                true,
                observed["entries"].get(k).is_some(),
                protected.contains(k),
                observed["entries"][k] == *e,
            ) {
                selected[k] = e.clone();
                if selected.as_object().ok_or("selection")?.len() == 8 {
                    break;
                }
            }
        }
        require(
            !selected.as_object().ok_or("selection")?.is_empty(),
            "no collectible generations",
        )?;
        let value = json!({"schema":1,"kind":"native-retention","root":self.root,"current":current,"observation_sha256":codec::hash(&f::bytes(&self.root.join("retention-observed.json"),true)?),"keep":keep,"selected":selected});
        let raw = codec::encode(&value);
        require(raw.len() <= codec::LIMIT, "collection plan bound")?;
        let id = codec::hash(&raw);
        f::replace(
            &self.root.join(format!("collection-{id}.json")),
            &raw,
            0o600,
            "collection-plan",
            cp,
        )?;
        Ok(id)
    }
    pub fn apply_collection(&mut self, id: &str, cp: Checkpoint<'_>) -> Result<usize> {
        require(codec::digest(id), "collection identity")?;
        let raw = f::bytes(&self.root.join(format!("collection-{id}.json")), true)?;
        require(codec::hash(&raw) == id, "collection plan changed")?;
        let request = codec::decode(&raw)?;
        let (current, p) = self.collection_fence()?;
        require(
            request["schema"] == 1
                && request["kind"] == "native-retention"
                && request["root"] == self.root.to_str().ok_or("root")?
                && request["current"] == current,
            "stale collection request",
        )?;
        let observed_raw = f::bytes(&self.root.join("retention-observed.json"), true)?;
        require(
            request["observation_sha256"] == codec::hash(&observed_raw),
            "observation changed",
        )?;
        let observed = codec::decode(&observed_raw)?;
        require(
            observed["current"] == current
                && observed["boot"].as_str().is_some()
                && observed["boot"] != self.boot_id()?,
            "same-boot collection",
        )?;
        let keep: Vec<_> = request["keep"]
            .as_array()
            .ok_or("keep")?
            .iter()
            .map(|s| s.as_str().map(str::to_owned).ok_or("keep item"))
            .collect::<std::result::Result<_, _>>()?;
        let (entries, protected) = self.collection_inventory(&current, &p, &keep)?;
        let selected = request["selected"].as_object().ok_or("selection")?;
        require(
            !selected.is_empty() && selected.len() <= 8,
            "collection batch bound",
        )?;
        let trash = self.root.join("trash");
        f::directory(&trash)?;
        let batch = trash.join(id);
        f::directory(&batch)?;
        for (k, e) in selected {
            require(
                pathward::publication::collection_allowed(
                    true,
                    true,
                    observed["entries"].get(k).is_some(),
                    protected.contains(k),
                    observed["entries"][k] == *e,
                ),
                "protected or unobserved collection",
            )?;
            let source = Path::new(string(e, "path")?);
            let retired = batch.join(k);
            if let Some(live) = entries.get(k) {
                require(live == e && !retired.exists(), "collection input changed")?;
                require(
                    tree(source)? == serde_json::from_value(e["members"].clone())?,
                    "collection content changed",
                )?;
                fs::rename(source, &retired)?;
                cp("collection:moved")?;
            }
            f::sync_dir(source.parent().ok_or("generation parent")?)?;
            f::sync_dir(&batch)?;
            cp("collection:move-durable")?;
            if retired.exists() {
                let actual = tree(&retired)?;
                let wanted = e["members"].as_object().ok_or("members")?;
                require(
                    actual
                        .iter()
                        .all(|(n, h)| wanted.get(n).is_some_and(|v| v == h)),
                    "foreign or changed trash member",
                )?;
                for (n, _) in actual {
                    let path = retired.join(n);
                    fs::remove_file(&path)?;
                    cp("collection:unlinked")?;
                    f::sync_dir(path.parent().ok_or("member parent")?)?;
                }
                fn empty(p: &Path) -> Result<()> {
                    for item in fs::read_dir(p)? {
                        let p = item?.path();
                        require(fs::symlink_metadata(&p)?.is_dir(), "nonempty trash")?;
                        empty(&p)?;
                    }
                    fs::remove_dir(p)?;
                    f::sync_dir(p.parent().ok_or("trash parent")?)
                }
                empty(&retired)?;
                cp("collection:removed")?;
            }
        }
        require(
            self.current()?.as_deref() == Some(&current),
            "current changed during collection",
        )?;
        f::write_record(
            &batch.join("complete.json"),
            &json!({"request":id,"current":current}),
            "collection-complete",
            cp,
        )?;
        Ok(selected.len())
    }
}
