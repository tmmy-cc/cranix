//! `cranix sbom` on a small built closure: components from derivations and
//! `meta`, crates and Go modules from vendored dependencies, binaries and
//! sources only on request, lock files, and identical output on every run.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CRANIX: &str = env!("CARGO_BIN_EXE_cranix");

const CLOSURE: &str = r#"
let
  sh = name: script: extra: derivation ({ inherit name; system = builtins.currentSystem; builder = "/bin/sh"; args = [ "-c" script ]; } // extra);
  pkg = attrs: meta: (sh "${attrs.pname}-${attrs.version}" attrs.script (removeAttrs attrs [ "script" "inputs" ])) // { inherit meta; buildInputs = attrs.inputs or [ ]; };
  vendor = sh "app-vendor" ''
    /bin/mkdir -p $out/app
    printf '[[package]]\nname = "app"\nversion = "2.0.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.200"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${builtins.concatStringsSep "" (builtins.genList (_: "ab") 32)}"\n' > $out/app/Cargo.lock
  '' { };
  gomods = sh "tool-go-modules" ''/bin/mkdir $out; printf '# golang.org/x/sys v0.1.0\n## explicit\n' > $out/modules.txt'' { };
  src = builtins.toFile "src" "source";
  lib = pkg { pname = "libfoo"; version = "1.2.3"; script = "echo lib > $out"; } { license = { spdxId = "BSD-3-Clause"; }; description = "A library"; };
  tool = pkg { pname = "tool"; version = "0.9"; script = "echo ${src} > $out"; goModules = gomods; } { license = { fullName = "Custom Licence"; }; };
  app = pkg {
    pname = "app"; version = "2.0.0"; inputs = [ lib tool ];
    cargoDeps = vendor;
    script = "echo ${lib} ${tool} > $out";
  } { license = [ { spdxId = "MIT"; } { spdxId = "Apache-2.0"; } ]; homepage = "https://example.org"; };
in app
"#;

struct Env {
    root: PathBuf,
}

impl Env {
    fn new(name: &str) -> Env {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!("cranix-sbom-{name}-{}", std::process::id()));
        remove(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("app.nix"), CLOSURE).unwrap();
        Env { root }
    }

    fn run(&self, args: &[&str]) -> String {
        let o = Command::new(CRANIX)
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("NIX_CONF_DIR", self.root.join("etc"))
            .env_remove("NIX_CONFIG")
            .env_remove("CRANIX_CONFIG")
            .env_remove("SOURCE_DATE_EPOCH")
            .arg("--store")
            .arg(self.root.join("store"))
            .args(["--option", "substituters", ""])
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success(), "cranix {args:?} failed:\n{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap()
    }

    fn sbom(&self, extra: &[&str]) -> serde_json::Value {
        let file = self.root.join("app.nix");
        let mut a = vec!["sbom", file.to_str().unwrap()];
        a.extend(extra);
        serde_json::from_str(&self.run(&a)).unwrap()
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

fn names(v: &serde_json::Value) -> Vec<String> {
    let mut n: Vec<String> = v.as_array().into_iter().flatten().map(|c| c["name"].as_str().unwrap().to_string()).collect();
    n.sort();
    n
}

#[test]
fn cyclonedx_of_a_closure() {
    let env = Env::new("cdx");
    let doc = env.sbom(&[]);
    let root = &doc["metadata"]["component"];
    assert_eq!((root["name"].as_str(), root["version"].as_str()), (Some("app"), Some("2.0.0")));
    assert_eq!(root["purl"], "pkg:cargo/app@2.0.0");
    let licences: Vec<&str> = root["licenses"].as_array().unwrap().iter().map(|l| l["license"]["id"].as_str().unwrap()).collect();
    assert_eq!(licences, ["Apache-2.0", "MIT"]);
    // The source is no component, having no version.
    assert_eq!(names(&doc["components"]), ["libfoo", "tool"]);
    // Crates and modules come from the vendored dependencies.
    assert_eq!(names(&root["components"]), ["serde"]);
    let tool = doc["components"].as_array().unwrap().iter().find(|c| c["name"] == "tool").unwrap();
    assert_eq!(tool["licenses"][0]["license"]["name"], "Custom Licence");
    assert_eq!(tool["components"][0]["purl"], "pkg:golang/golang.org/x/sys@v0.1.0");
    let deps = doc["dependencies"].as_array().unwrap();
    let app_deps = deps.iter().find(|d| d["ref"] == root["bom-ref"]).unwrap();
    assert_eq!(app_deps["dependsOn"].as_array().unwrap().len(), 2);
    assert!(doc["serialNumber"].as_str().unwrap().starts_with("urn:uuid:"));
    assert!(doc["metadata"].get("timestamp").is_none());
    // Two runs give the same document.
    assert_eq!(doc, env.sbom(&[]));
}

#[test]
fn spdx_and_lock_files() {
    let env = Env::new("spdx");
    let doc = env.sbom(&["--format", "spdx"]);
    assert_eq!(doc["spdxVersion"], "SPDX-2.3");
    assert_eq!(doc["creationInfo"]["created"], "1970-01-01T00:00:00Z");
    let pkgs = doc["packages"].as_array().unwrap();
    assert_eq!(names(&doc["packages"]), ["app", "libfoo", "serde", "golang.org/x/sys", "tool"].iter().map(|s| s.to_string()).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>());
    let app = pkgs.iter().find(|p| p["name"] == "app").unwrap();
    assert_eq!(app["licenseDeclared"], "Apache-2.0 AND MIT");
    let tool = pkgs.iter().find(|p| p["name"] == "tool").unwrap();
    assert_eq!(tool["licenseDeclared"], "LicenseRef-Custom-Licence");
    assert_eq!(doc["hasExtractedLicensingInfos"][0]["name"], "Custom Licence");
    let rels: Vec<&str> = doc["relationships"].as_array().unwrap().iter().map(|r| r["relationshipType"].as_str().unwrap()).collect();
    assert!(rels.contains(&"DESCRIBES") && rels.contains(&"DEPENDS_ON") && rels.contains(&"CONTAINS"));
    assert_eq!(doc, env.sbom(&["--format", "spdx"]));

    // A lock file, merged into the SBOM of the closure.
    let lock = env.root.join("Cargo.lock");
    fs::write(&lock, "[[package]]\nname = \"web\"\nversion = \"0.1.0\"\ndependencies = [\"rand\"]\n\n[[package]]\nname = \"rand\"\nversion = \"0.8.5\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n").unwrap();
    let cdx = env.root.join("lock.cdx.json");
    env.run(&["sbom", "lock", lock.to_str().unwrap(), "-o", cdx.to_str().unwrap()]);
    let lock_doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(&cdx).unwrap()).unwrap();
    assert_eq!(lock_doc["metadata"]["component"]["name"], "web");
    assert_eq!(names(&lock_doc["components"]), ["rand"]);
    let merged = env.sbom(&["--merge", cdx.to_str().unwrap()]);
    assert_eq!(names(&merged["components"]), ["libfoo", "rand", "tool", "web"]);
}

#[test]
fn build_time_needs_no_outputs() {
    let env = Env::new("buildtime");
    let doc = env.sbom(&["--build-time", "--no-fetch-deps"]);
    assert_eq!(doc["metadata"]["component"]["name"], "app");
    // Nothing was built.
    assert!(!env.root.join("store/store").read_dir().map(|mut d| d.any(|e| e.unwrap().file_name().to_string_lossy().ends_with("-app-2.0.0"))).unwrap_or(false));
    assert_eq!(names(&doc["components"]), ["libfoo", "tool"]);
    assert_eq!(doc, env.sbom(&["--build-time", "--no-fetch-deps"]));
}
