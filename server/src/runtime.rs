//! Immutable owned configurations, prepared before the short commit lock.
use crate::files::DocumentRoot;
use pathward::rules::Publication;
use pathward_config::CompiledConfig;
use std::{io, path::Path};

pub(crate) struct Site {
    pub host: String,
    pub root: DocumentRoot,
    rules: Vec<(Vec<u8>, Vec<u8>)>,
}
impl Site {
    pub fn publications(&self) -> Vec<Publication<'_>> {
        self.rules
            .iter()
            .map(|(path, target)| Publication { path, target })
            .collect()
    }
}
pub(crate) struct Snapshot {
    pub sites: Vec<Site>,
}
impl Snapshot {
    pub fn prepare(config: &CompiledConfig<'_>, cache: Option<&Path>) -> io::Result<Self> {
        if !Self::isolated(config, cache) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "public root overlaps private cache",
            ));
        }
        let sites = config
            .sites()
            .iter()
            .map(|site| {
                Ok(Site {
                    host: site.host().to_owned(),
                    root: DocumentRoot::open(site.root())?,
                    rules: site
                        .publications()
                        .iter()
                        .map(|p| (p.path.to_vec(), p.target.to_vec()))
                        .collect(),
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { sites })
    }
    pub fn isolated(config: &CompiledConfig<'_>, cache: Option<&Path>) -> bool {
        cache.is_none_or(|cache| {
            config
                .sites()
                .iter()
                .all(|s| !cache.starts_with(s.root()) && !Path::new(s.root()).starts_with(cache))
        })
    }
    pub fn same_hosts(&self, config: &CompiledConfig<'_>) -> bool {
        self.sites.len() == config.sites().len()
            && self
                .sites
                .iter()
                .all(|s| config.sites().iter().any(|c| c.host() == s.host))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{Server, http};
    use pathward_config::ParsedConfig;
    use std::{
        fs,
        io::{Read, Write},
        sync::atomic::AtomicBool,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };
    struct Tree(std::path::PathBuf);
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tree() -> Tree {
        let path = std::env::temp_dir().join(format!(
            "pathward-runtime-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        for root in ["old", "new", "cache"] {
            fs::create_dir(path.join(root)).unwrap();
        }
        fs::write(path.join("old/old.txt"), "OLD").unwrap();
        fs::write(path.join("old/new.txt"), "MIXED").unwrap();
        fs::write(path.join("new/old.txt"), "MIXED").unwrap();
        fs::write(path.join("new/new.txt"), "NEW").unwrap();
        Tree(path)
    }
    fn config(path: &Path, host: &str, target: &str) -> ParsedConfig {
        ParsedConfig::parse(&format!(
            "site \"{host}\" {{\nroot \"{}\"\npublish \"/\" \"{target}\"\ntls \"auto\"\n}}",
            path.display()
        ))
        .unwrap()
    }
    struct Exchange<F: FnMut()> {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
        before_read: F,
    }
    impl<F: FnMut()> Read for Exchange<F> {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            (self.before_read)();
            self.input.read(b)
        }
    }
    impl<F: FnMut()> Write for Exchange<F> {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.output.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<F: FnMut()> http::Transport for Exchange<F> {
        fn deadline(&mut self, _: Instant) -> io::Result<()> {
            Ok(())
        }
        fn local_port(&self) -> io::Result<u16> {
            Ok(80)
        }
    }
    fn request(server: &Server, before_read: impl FnMut()) -> Vec<u8> {
        let mut stream = Exchange {
            input: io::Cursor::new(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()),
            output: Vec::new(),
            before_read,
        };
        server.handle(&mut stream, Instant::now(), None).unwrap();
        stream.output
    }
    #[test]
    fn request_pins_rules_and_root_across_commit_and_rejections_retain_previous() {
        let tree = tree();
        let old = config(&tree.0.join("old"), "example.com", "old.txt");
        let new = config(&tree.0.join("new"), "example.com", "new.txt");
        let server =
            Server::new_with_cache(&old.compile().unwrap(), Some(&tree.0.join("cache"))).unwrap();
        let stop = AtomicBool::new(false);
        let mut once = true;
        let response = request(&server, || {
            if once {
                once = false;
                assert_eq!(server.reload(&new.compile().unwrap(), &stop).unwrap(), 2);
            }
        });
        assert!(response.ends_with(b"OLD"));
        assert!(request(&server, || {}).ends_with(b"NEW"));
        for (path, host) in [
            (tree.0.join("missing"), "example.com"),
            (tree.0.join("old"), "other.example"),
            (tree.0.join("cache"), "example.com"),
            (tree.0.clone(), "example.com"),
        ] {
            let bad = config(&path, host, "old.txt");
            assert!(server.reload(&bad.compile().unwrap(), &stop).is_err());
            assert_eq!(server.generation(), 2);
            assert!(request(&server, || {}).ends_with(b"NEW"));
        }
        std::os::unix::fs::symlink(tree.0.join("old"), tree.0.join("linked")).unwrap();
        let linked = config(&tree.0.join("linked"), "example.com", "old.txt");
        assert!(server.reload(&linked.compile().unwrap(), &stop).is_err());
        server.begin_shutdown();
        assert!(server.reload(&old.compile().unwrap(), &stop).is_err());
        assert_eq!(server.generation(), 2);
    }
    #[test]
    fn concurrent_requests_only_observe_complete_generations() {
        let tree = tree();
        let old = config(&tree.0.join("old"), "example.com", "old.txt");
        let new = config(&tree.0.join("new"), "example.com", "new.txt");
        let server = Server::new(&old.compile().unwrap()).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let server = &server;
                scope.spawn(move || {
                    for _ in 0..100 {
                        let r = request(server, || {});
                        assert!(r.ends_with(b"OLD") || r.ends_with(b"NEW"));
                    }
                });
            }
            for i in 0..50 {
                let config = if i % 2 == 0 { &new } else { &old };
                server
                    .reload(&config.compile().unwrap(), &AtomicBool::new(false))
                    .unwrap();
            }
        });
        assert_eq!(server.generation(), 51);
    }
}
