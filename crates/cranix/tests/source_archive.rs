//! `cranix source-archive`: a bundle of a closure with a fetched and a
//! local source lists both with URL, hash and licence, lists a download
//! that fails as missing, and restores into an emptied store, from which
//! the package rebuilds while its upstream is gone.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const CRANIX: &str = env!("CARGO_BIN_EXE_cranix");

const EXPR: &str = r#"
{ upstream }:
let
  sh = name: args: extra: derivation ({
    inherit name; system = builtins.currentSystem; builder = "/bin/sh"; args = [ "-c" args ];
  } // extra);
  fixed = hash: {
    outputHashAlgo = "sha256";
    outputHashMode = "flat";
    outputHash = hash;
  };
  # Stands for a download: it reads a file outside the store.
  fetched = sh "hello.txt" "/bin/cat ${upstream} > $out"
    ({ url = "https://example.org/hello.txt"; } // fixed "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
  gone = sh "gone.tar.gz" "exit 1"
    ({ url = "https://example.org/gone.tar.gz"; } // fixed "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
  pkg = sh "pkg-1.0" "/bin/cat ${fetched} ${./src}/a.txt > $out" { } // { meta.license.spdxId = "MIT"; };
in { inherit pkg; all = [ pkg gone ]; }
"#;

struct Env {
    root: PathBuf,
}

impl Env {
    fn new(name: &str) -> Env {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!("cranix-source-archive-{name}-{}", std::process::id()));
        remove(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/a.txt"), " world\n").unwrap();
        fs::write(root.join("upstream.txt"), "hello").unwrap();
        fs::write(root.join("release.nix"), EXPR).unwrap();
        Env { root }
    }

    fn cmd(&self, args: &[&str]) -> Output {
        Command::new(CRANIX)
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("NIX_CONF_DIR", self.root.join("etc"))
            .env_remove("NIX_CONFIG")
            .env_remove("CRANIX_CONFIG")
            .arg("--store")
            .arg(self.root.join("store"))
            .args(["--option", "substituters", ""])
            .args(args)
            .output()
            .unwrap()
    }

    fn run(&self, args: &[&str]) -> Output {
        let o = self.cmd(args);
        assert!(o.status.success(), "cranix {args:?} failed:\n{}", String::from_utf8_lossy(&o.stderr));
        o
    }

    fn archive(&self, attr: &str, dest: &[&str]) -> Output {
        let file = self.path("release.nix");
        let upstream = self.path("upstream.txt");
        let mut args = vec![
            "source-archive", file.as_str(), "-A", attr, "--arg", "upstream", upstream.as_str(),
        ];
        args.extend_from_slice(dest);
        self.run(&args)
    }

    fn path(&self, name: &str) -> String {
        self.root.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        remove(&self.root);
    }
}

fn remove(p: &Path) {
    let _ = Command::new("/bin/chmod").args(["-R", "u+w"]).arg(p).status();
    let _ = fs::remove_dir_all(p);
}

fn index(dir: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(dir.join("sources.json")).unwrap()).unwrap()
}

fn find<'a>(idx: &'a Value, kind: &str, name: &str) -> &'a Value {
    idx["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["kind"] == kind && s["path"].as_str().unwrap().ends_with(name))
        .unwrap_or_else(|| panic!("no {kind} source '{name}' in {idx:#}"))
}

#[test]
fn lists_sources_and_missing_downloads() {
    let env = Env::new("list");
    let out = env.path("bundle");
    let o = env.archive("all", &["-o", &out]);
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("1 sources are not available"), "{stderr}");
    let idx = index(Path::new(&out));
    assert_eq!(idx["missing"], 1);
    let fetched = find(&idx, "fetched", "-hello.txt");
    assert_eq!(fetched["available"], true);
    assert_eq!(fetched["urls"][0], "https://example.org/hello.txt");
    assert_eq!(fetched["hash"]["algorithm"], "sha256");
    assert_eq!(fetched["hash"]["value"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    assert_eq!(fetched["licenses"][0]["id"], "MIT");
    assert!(fetched["fetcher"].as_str().unwrap().ends_with("-hello.txt.drv"));
    let local = find(&idx, "local", "-src");
    assert_eq!(local["available"], true);
    assert!(local["usedBy"][0].as_str().unwrap().ends_with("-pkg-1.0.drv"));
    let gone = find(&idx, "fetched", "-gone.tar.gz");
    assert_eq!(gone["available"], false);
    assert_eq!(gone["urls"][0], "https://example.org/gone.tar.gz");
    find(&idx, "derivation", "-pkg-1.0.drv");
    // Every available entry has a narinfo in the bundle.
    for s in idx["sources"].as_array().unwrap().iter().filter(|s| s["available"] == true) {
        let base = s["path"].as_str().unwrap().rsplit('/').next().unwrap();
        assert!(Path::new(&out).join(format!("{}.narinfo", &base[..32])).exists(), "{base}");
    }
}

#[test]
fn tarball_restores_and_rebuilds_offline() {
    let env = Env::new("rebuild");
    let tarball = env.path("release-src.tar.gz");
    env.archive("pkg", &["--tarball", &tarball]);
    let again = env.path("again.tar.gz");
    env.archive("pkg", &["--tarball", &again]);
    assert_eq!(fs::read(&tarball).unwrap(), fs::read(&again).unwrap(), "tarballs differ between runs");

    let dir = env.root.join("unpacked");
    fs::create_dir_all(&dir).unwrap();
    let st = Command::new("tar").arg("xzf").arg(&tarball).arg("-C").arg(&dir).status().unwrap();
    assert!(st.success());
    let idx = index(&dir);
    assert_eq!(idx["missing"], 0);
    let paths: Vec<String> = idx["sources"].as_array().unwrap().iter().map(|s| s["path"].as_str().unwrap().to_string()).collect();
    let drv = paths.iter().find(|p| p.ends_with("-pkg-1.0.drv")).unwrap().clone();

    // Empty the store and take the upstream away.
    env.run(&["store", "gc"]);
    fs::remove_file(env.root.join("upstream.txt")).unwrap();
    for p in &paths {
        let o = env.cmd(&["store", "path-info", p]);
        assert!(!o.status.success(), "'{p}' survived the collection");
    }

    let url = format!("file://{}", dir.display());
    let mut args = vec!["copy", "--from", url.as_str()];
    args.extend(paths.iter().map(String::as_str));
    env.run(&args);
    let target = format!("{drv}^out");
    let o = env.run(&["realisation", "info", &target]);
    let out = String::from_utf8_lossy(&o.stdout);
    let built = out.split_whitespace().find(|w| w.ends_with("-pkg-1.0")).unwrap_or_else(|| panic!("no output in {out}"));
    assert_eq!(fs::read_to_string(built).unwrap(), "hello world\n");
}
