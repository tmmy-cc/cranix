//! The filters of `copy` and of uploads while building, on a small graph:
//!
//! ```text
//! system (nixos-system-demo) ── app ── lib ── fod (from codeload.github.com)
//!    │                           │      └──── src (a source)
//!    └── unit (local only)       └ build input: project-config
//! demo-tests ── lib
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CRANIX: &str = env!("CARGO_BIN_EXE_cranix");

const GRAPH: &str = r#"
let
  sh = name: script: extra: derivation ({ inherit name; system = builtins.currentSystem; builder = "/bin/sh"; args = [ "-c" script ]; } // extra);
  src = builtins.toFile "src" "source text";
  fod = sh "fod" "printf hello > $out" {
    url = "https://codeload.github.com/owner/repo/tar.gz/v1";
    outputHashAlgo = "sha256";
    outputHash = "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
  };
  lib = sh "lib" "echo ${fod} ${src} > $out" { };
  config = sh "project-config" "echo project > $out" { };
  app = sh "app" "read x < ${config}; echo ${lib} > $out" { };
  unit = sh "unit-demo.service" "echo unit > $out" { preferLocalBuild = true; allowSubstitutes = false; };
  system = sh "nixos-system-demo" "echo ${app} ${unit} > $out" { };
  tests = sh "demo-tests" "echo ${lib} > $out" { };
  unbuilt = sh "unbuilt" "echo ${lib} > $out" { };
in { inherit src fod lib config app unit system tests unbuilt; }
"#;

struct Env {
    root: PathBuf,
    file: PathBuf,
}

impl Env {
    fn new(name: &str) -> Env {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!("cranix-filters-{name}-{}", std::process::id()));
        remove(&root);
        fs::create_dir_all(&root).unwrap();
        let file = root.join("graph.nix");
        fs::write(&file, GRAPH).unwrap();
        Env { root, file }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(CRANIX);
        c.env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("NIX_CONF_DIR", self.root.join("etc"))
            .env_remove("NIX_CONFIG")
            .env_remove("CRANIX_CONFIG")
            .env_remove("NIX_USER_CONF_FILES")
            .arg("--store")
            .arg(self.root.join("store"))
            .args(["--option", "substituters", ""]);
        c
    }

    fn run(&self, args: &[&str]) -> (String, String) {
        let o = self.cmd().args(args).output().unwrap();
        let (out, err) = (String::from_utf8(o.stdout).unwrap(), String::from_utf8(o.stderr).unwrap());
        assert!(o.status.success(), "cranix {args:?} failed:\n{err}");
        (out, err)
    }

    fn file(&self) -> &str {
        self.file.to_str().unwrap()
    }

    fn out(&self, attr: &str) -> String {
        self.run(&["eval", "--raw", "-A", &format!("{attr}.outPath"), self.file()]).0.trim().to_string()
    }

    fn drv(&self, attr: &str) -> String {
        self.run(&["instantiate", "-A", attr, self.file()]).0.trim().to_string()
    }

    fn build(&self, attrs: &[&str]) {
        for a in attrs {
            self.run(&["build", "--no-link", "-A", a, self.file()]);
        }
    }

    /// `copy --dry-run` with `args`: the names of the paths it copies, by
    /// the type that chose them, and of those it skips, with the reason.
    fn dry_run(&self, args: &[&str]) -> (BTreeMap<String, String>, BTreeMap<String, String>, String) {
        let mut a = vec!["copy", "--to-nars", "/nonexistent", "--dry-run"];
        a.extend(args);
        let (out, err) = self.run(&a);
        let (mut copy, mut skip) = (BTreeMap::new(), BTreeMap::new());
        for line in out.lines() {
            if let Some(rest) = line.strip_prefix("copy ") {
                let (p, ty) = rest.split_once(" (").unwrap();
                copy.insert(name(p), ty.trim_end_matches(')').to_string());
            } else if let Some(rest) = line.strip_prefix("skip ") {
                let (p, why) = rest.split_once(": ").unwrap();
                skip.insert(name(p), why.to_string());
            }
        }
        (copy, skip, err)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        remove(&self.root);
    }
}

fn remove(d: &Path) {
    if d.exists() {
        let _ = Command::new("chmod").args(["-R", "u+w"]).arg(d).status();
        let _ = fs::remove_dir_all(d);
    }
}

/// The name of a store path, after its hash.
fn name(p: &str) -> String {
    p.rsplit('/').next().unwrap()[33..].to_string()
}

fn keys(m: &BTreeMap<String, String>) -> Vec<&str> {
    m.keys().map(String::as_str).collect()
}

#[test]
fn filters_choose_what_is_copied() {
    let env = Env::new("copy");
    env.build(&["system", "tests"]);
    let system = env.out("system");
    let system_drv = env.drv("system");

    // Without filters a path goes with its closure.
    let (copy, skip, _) = env.dry_run(&[&system]);
    assert_eq!(keys(&copy), ["app", "fod", "lib", "nixos-system-demo", "src", "unit-demo.service"]);
    assert!(skip.is_empty());
    assert_eq!(copy["nixos-system-demo"], "reference");

    // Path types pick from the derivation graph.
    let types = |t: &str| env.dry_run(&["--type", t, &system_drv]).0;
    let c = types("source");
    assert_eq!(c["src"], "source");
    assert!(c.keys().all(|k| k == "src"), "{c:?}");
    let c = types("fixed-output-out-path");
    assert_eq!(keys(&c), ["fod"]);
    let c = types("build-out-path");
    assert_eq!(keys(&c), ["app", "fod", "lib", "nixos-system-demo", "project-config", "src", "unit-demo.service"]);
    assert_eq!((c["lib"].as_str(), c["fod"].as_str(), c["src"].as_str()), ("build-out-path", "reference", "reference"));
    let c = types("drv-out-path");
    assert_eq!((c["fod"].as_str(), c["lib"].as_str()), ("drv-out-path", "drv-out-path"));
    let c = types("fixed-output-drv");
    assert_eq!(keys(&c), ["fod.drv"]);
    let c = types("build-drv");
    assert_eq!(c["lib.drv"], "build-drv");
    assert_eq!(c["fod.drv"], "reference");
    let c = types("toplevel-drv");
    assert_eq!(c["nixos-system-demo.drv"], "toplevel-drv");
    assert_eq!(c["app.drv"], "reference");
    let c = types("drv");
    assert!(c.contains_key("nixos-system-demo.drv") && c.contains_key("fod.drv") && !c.contains_key("lib"), "{c:?}");

    // Downloads from a host, and what refers to them.
    let (copy, skip, _) = env.dry_run(&["--exclude-host", "*.github.com", &system]);
    assert_eq!(keys(&copy), ["src", "unit-demo.service"]);
    assert!(skip["fod"].contains("downloads from 'codeload.github.com'"), "{skip:?}");
    assert!(skip["lib"].starts_with("refers to"), "{skip:?}");

    // A name pattern leaves out what is built from it, also without a
    // runtime reference.
    let (copy, skip, _) = env.dry_run(&["--exclude-name", "project-*", "--type", "build-out-path", &system_drv]);
    assert_eq!(keys(&copy), ["fod", "lib", "src", "unit-demo.service"]);
    assert!(skip["project-config"].contains("matches 'project-*'"), "{skip:?}");
    assert!(skip["app"].starts_with("depends on '") && skip["app"].contains("project-config"), "{skip:?}");
    assert!(skip["nixos-system-demo"].contains("project-config"), "{skip:?}");

    // Closure classes.
    let (copy, skip, _) = env.dry_run(&["--exclude-class", "system", "--type", "build-out-path", &system_drv]);
    assert!(skip["nixos-system-demo"].contains("class 'system'"), "{skip:?}");
    assert!(skip["unit-demo.service"].contains("class 'system'"), "{skip:?}");
    assert!(copy.contains_key("app") && copy.contains_key("lib"), "{copy:?}");
    let tests = env.out("tests");
    let (copy, skip, _) = env.dry_run(&["--exclude-class", "test", &tests, &system]);
    assert!(skip["demo-tests"].contains("class 'test'") && copy.contains_key("nixos-system-demo"), "{skip:?}");

    // Derivations built locally.
    let (copy, skip, _) = env.dry_run(&["--exclude-local", &system]);
    assert!(skip["unit-demo.service"].contains("built locally"), "{skip:?}");
    assert!(skip["nixos-system-demo"].starts_with("refers to"), "{skip:?}");
    assert!(copy.contains_key("app"));

    // Outputs missing from the store, with a warning that lists them.
    let unbuilt = env.drv("unbuilt");
    let (copy, skip, err) = env.dry_run(&["--type", "build-out-path", &unbuilt]);
    assert_eq!(skip["unbuilt"], "not in the local store");
    assert!(copy.contains_key("lib"));
    assert!(err.contains("leaving out 1 paths that are not in the local store") && err.contains("-unbuilt"), "{err}");
}

#[test]
fn copy_exports_nars_and_uploads_selections() {
    let env = Env::new("export");
    env.build(&["system"]);
    let system = env.out("system");
    let dir = env.root.join("nars");
    env.run(&["copy", "--to-nars", dir.to_str().unwrap(), "--exclude-local", &system]);
    let index: serde_json::Value = serde_json::from_str(&fs::read_to_string(dir.join("index.json")).unwrap()).unwrap();
    let entries = index.as_array().unwrap();
    let names: Vec<String> = entries.iter().map(|e| name(e["path"].as_str().unwrap())).collect();
    assert_eq!(names.len(), 4, "{names:?}");
    // References come first.
    assert_eq!(names.last().unwrap(), "app");
    for e in entries {
        let nar = fs::read(dir.join(e["nar"].as_str().unwrap())).unwrap();
        assert_eq!(nar.len() as u64, e["narSize"].as_u64().unwrap());
        let restored = env.root.join("restored").join(e["nar"].as_str().unwrap());
        fs::create_dir_all(restored.parent().unwrap()).unwrap();
        cranix_core::nar::restore(&mut nar.as_slice(), &restored).unwrap();
    }

    let cache = env.root.join("cache");
    let url = format!("file://{}", cache.display());
    env.run(&["copy", "--to", &url, "--exclude-host", "*.github.com", &system]);
    let narinfos = fs::read_dir(&cache).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".narinfo")).count();
    assert_eq!(narinfos, 2);
}

#[test]
fn uploads_while_building_use_the_filters() {
    let env = Env::new("upload");
    let cache = env.root.join("cache");
    let url = format!("file://{}", cache.display());
    env.run(&["build", "--no-link", "-A", "system", "--upload-to", &url, "--upload-exclude-names", "project-*", "--upload-exclude-local", env.file()]);
    let have: Vec<String> = fs::read_dir(&cache)
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let text = fs::read_to_string(e.path()).ok()?;
            text.lines().find_map(|l| l.strip_prefix("StorePath: ").map(name))
        })
        .collect();
    let mut have = have;
    have.sort();
    assert_eq!(have, ["fod", "lib", "src"]);

    // Types limit what is taken; references follow.
    let cache2 = env.root.join("cache2");
    let (_, err) = env.run(&[
        "build",
        "--no-link",
        "-A",
        "app",
        "--upload-to",
        &format!("file://{}", cache2.display()),
        "--upload-types",
        "fixed-output-out-path",
        env.file(),
    ]);
    let n = fs::read_dir(&cache2).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".narinfo")).count();
    assert_eq!(n, 1, "{err}");
}
