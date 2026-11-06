use pathward_admin::{
    Result, codec, confined,
    publication::{self as p, Bridge},
    storage as f,
    system::System,
};
use serde_json::{Value, json};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    policy: Value,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = std::env::temp_dir().canonicalize()?.join(format!(
            "pathward-publication-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for p in [
            root.clone(),
            root.join("source"),
            root.join("source/releases"),
            root.join("source/releases/one"),
            root.join("source/releases/one/public"),
            root.join("source/releases/one/public/docs"),
            root.join("state"),
            root.join("run"),
        ] {
            f::directory(&p)?;
        }
        for (n, t) in [
            ("index.html", "one"),
            ("docs/index.html", "documentation"),
            ("private.txt", "not selected"),
        ] {
            f::replace(
                &root.join("source/releases/one/public").join(n),
                t.as_bytes(),
                0o600,
                "fixture",
                &mut |_| Ok(()),
            )?;
        }
        symlink("releases/one", root.join("source/current"))?;
        let policy = json!({"schema":1,"capacity":"shared-nat","sites":[{"id":"portal","host":"example.test","source_base":root.join("source"),"index":"index.html","directory_indexes":["index.html"],"public_paths":null,"synthetic_files":{"robots.txt":"User-agent: *\nDisallow: /\n"},"directives":[["header","/","X-Content-Type-Options","nosniff"]]}]});
        Ok(Self { root, policy })
    }
    fn bridge(&self) -> Bridge<Mock> {
        Bridge {
            state: self.root.join("state"),
            binary: "/test/server".into(),
            control: self.root.join("control"),
            receipt: self.root.join("run/receipt.json"),
            sys: Mock {
                revision: format!("0:{}", "a".repeat(64)),
                interfere: false,
            },
        }
    }
    fn now() -> Value {
        json!({"boot":"test-boot","ns":100})
    }
    fn source(&self) -> PathBuf {
        self.root.join("source/releases/one/public")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
struct Mock {
    revision: String,
    interfere: bool,
}
impl System for Mock {
    fn run(&mut self, a: &[String], _: u64) -> Result<(bool, String)> {
        match a[1].as_str() {
            "check" => Ok((true, String::new())),
            "status" => Ok((true, self.revision.clone())),
            "activate" => {
                assert_eq!(a[4], "--expect");
                assert_eq!(a[5], self.revision);
                let digest = codec::hash(&fs::read(&a[6])?);
                let generation = p::revision(&self.revision)?.0 + 1;
                self.revision = format!("{generation}:{digest}");
                let answer = self.revision.clone();
                if self.interfere {
                    self.revision = format!("{}:{}", generation + 1, "b".repeat(64));
                }
                Ok((true, answer))
            }
            _ => Err("unexpected command".into()),
        }
    }
}
#[test]
fn captures_explicit_files_directory_aliases_and_synthetic_policy() -> Result<()> {
    let x = Fixture::new()?;
    let mut bridge = x.bridge();
    let _lock = p::lock(&bridge.state)?;
    let receipt = bridge.reconcile(&x.policy, &Fixture::now(), &mut |_| Ok(()))?;
    let manifest = &receipt["sites"]["portal"];
    assert_eq!(manifest["urls"]["/docs/"], "docs/index.html");
    assert_eq!(manifest["urls"]["/"], "index.html");
    let candidate = fs::read_to_string(bridge.state.join(format!(
        "candidate-{}.kdl",
        receipt["config_sha256"].as_str().unwrap()
    )))?;
    assert!(candidate.contains("redirect \"/docs\" \"example.test\" \"/docs/\" \"308\""));
    let next = bridge.reconcile(&x.policy, &Fixture::now(), &mut |_| Ok(()))?;
    assert_eq!(next, receipt);
    assert_eq!(
        fs::metadata(&bridge.receipt)?.permissions().mode() & 0o777,
        0o644
    );
    Ok(())
}
#[test]
fn receipt_rejects_wrong_boot_old_time_missing_extra_or_changed_files() -> Result<()> {
    let x = Fixture::new()?;
    let receipt = x
        .bridge()
        .reconcile(&x.policy, &Fixture::now(), &mut |_| Ok(()))?;
    let mut hashes = json!({});
    for (n, v) in receipt["sites"]["portal"]["files"].as_object().unwrap() {
        hashes[n] = v["sha256"].clone();
    }
    let stamp = json!({"policy_sha256":receipt["policy_sha256"],"boot":"test-boot","after":99});
    let now = json!({"boot":"test-boot","ns":101});
    assert!(p::acknowledged(
        &receipt,
        "portal",
        "releases/one",
        &hashes,
        &stamp,
        &now
    )?);
    for (field, value) in [
        ("boot", json!("other")),
        ("after", json!(101)),
        ("policy_sha256", json!("other")),
    ] {
        let mut bad = stamp.clone();
        bad[field] = value;
        assert!(!p::acknowledged(
            &receipt,
            "portal",
            "releases/one",
            &hashes,
            &bad,
            &now
        )?);
    }
    let mut bad = hashes.clone();
    bad["extra.txt"] = json!("0".repeat(64));
    assert!(!p::acknowledged(
        &receipt,
        "portal",
        "releases/one",
        &bad,
        &stamp,
        &now
    )?);
    bad = hashes.clone();
    bad.as_object_mut().unwrap().remove("index.html");
    assert!(!p::acknowledged(
        &receipt,
        "portal",
        "releases/one",
        &bad,
        &stamp,
        &now
    )?);
    bad = hashes;
    bad["index.html"] = json!("0".repeat(64));
    assert!(!p::acknowledged(
        &receipt,
        "portal",
        "releases/one",
        &bad,
        &stamp,
        &now
    )?);
    Ok(())
}
#[test]
fn confinement_refuses_links_escape_oversize_and_manifest_ambiguity() -> Result<()> {
    for kind in ["symlink", "hardlink", "oversize", "directory-link"] {
        let x = Fixture::new()?;
        let p = x.source().join("invalid");
        match kind {
            "symlink" => symlink("/etc/passwd", &p)?,
            "hardlink" => fs::hard_link(x.source().join("index.html"), &p)?,
            "oversize" => {
                let f = fs::File::create(&p)?;
                f.set_len((1 << 30) + 1)?;
            }
            _ => symlink("docs", &p)?,
        }
        assert!(
            x.bridge().build(&x.policy, &mut |_| Ok(())).is_err(),
            "{kind}"
        );
    }
    assert!(!confined::relative("../secret"));
    assert!(!confined::release("releases/../../secret"));
    assert!(codec::parse(br#"{"sites":[],"sites":[1]}"#).is_err());
    let x = Fixture::new()?;
    fs::write(
        x.root.join("manifest"),
        format!(
            "{}  public/index.html\n{}  public/index.html\n",
            "a".repeat(64),
            "a".repeat(64)
        ),
    )?;
    assert!(p::public_manifest(&x.root.join("manifest")).is_err());
    Ok(())
}
#[test]
fn private_files_are_not_copied_and_cached_snapshots_are_reverified() -> Result<()> {
    let mut x = Fixture::new()?;
    x.policy["sites"][0]["public_paths"] = json!(["/"]);
    let mut b = x.bridge();
    let (_, r) = b.build(&x.policy, &mut |_| Ok(()))?;
    let root = b
        .state
        .join("snapshots")
        .join(r["sites"]["portal"]["key"].as_str().unwrap())
        .join("public");
    assert!(!root.join("private.txt").exists());
    assert!(!root.join("docs").exists());
    let expected = p::selected_files(
        &x.policy,
        "portal",
        &json!({"index.html":codec::hash(b"one"),"private.txt":codec::hash(b"private")}),
    )?;
    assert_eq!(expected.as_object().unwrap().len(), 2);
    fs::write(root.join("index.html"), "tampered")?;
    assert!(b.build(&x.policy, &mut |_| Ok(())).is_err());
    Ok(())
}
#[test]
fn concurrent_activation_or_source_switch_cannot_issue_receipt() -> Result<()> {
    let x = Fixture::new()?;
    let mut b = x.bridge();
    b.sys.interfere = true;
    assert!(
        b.reconcile(&x.policy, &Fixture::now(), &mut |_| Ok(()))
            .is_err()
    );
    assert!(!b.receipt.exists());
    let x = Fixture::new()?;
    let mut b = x.bridge();
    let mut changed = false;
    assert!(
        b.build(&x.policy, &mut |label| {
            if label == "capture:file-synced" && !changed {
                changed = true;
                fs::remove_file(x.root.join("source/current"))?;
                symlink("releases/two", x.root.join("source/current"))?;
            }
            Ok(())
        })
        .is_err()
    );
    assert!(!b.receipt.exists());
    Ok(())
}
#[test]
fn interrupted_capture_and_receipt_writes_retry_without_partial_publication() -> Result<()> {
    let x = Fixture::new()?;
    let mut labels = Vec::new();
    x.bridge().reconcile(&x.policy, &Fixture::now(), &mut |s| {
        labels.push(s.to_owned());
        Ok(())
    })?;
    for point in 0..labels.len() {
        let x = Fixture::new()?;
        let mut b = x.bridge();
        let mut n = 0;
        assert!(
            b.reconcile(&x.policy, &Fixture::now(), &mut |_| {
                let hit = n == point;
                n += 1;
                if hit {
                    Err("simulated interruption".into())
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        if b.receipt.exists() {
            let r = codec::parse(&fs::read(&b.receipt)?)?;
            assert_eq!(r["config_sha256"], p::revision(&b.sys.revision)?.1);
        }
        b.reconcile(&x.policy, &Fixture::now(), &mut |_| Ok(()))?;
    }
    println!("publication interruption boundaries: {}", labels.len());
    Ok(())
}
#[test]
fn publisher_lock_and_unsafe_metadata_are_refused() -> Result<()> {
    let x = Fixture::new()?;
    let _guard = p::lock(&x.root.join("state"))?;
    assert!(p::lock(&x.root.join("state")).is_err());
    let p = x.root.join("metadata");
    fs::write(&p, "{}")?;
    fs::set_permissions(&p, fs::Permissions::from_mode(0o666))?;
    assert!(confined::metadata(&p, rustix::process::geteuid().as_raw()).is_err());
    fs::remove_file(&p)?;
    symlink("/etc/passwd", &p)?;
    assert!(confined::metadata(&p, 0).is_err());
    Ok(())
}
