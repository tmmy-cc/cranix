//! `cranix provenance`: one statement per output with the derivation, its
//! inputs and the build settings, the same on every run; signed
//! envelopes that verify, fail once tampered with, and round-trip through
//! a binary cache.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

const CRANIX: &str = env!("CARGO_BIN_EXE_cranix");

const EXPR: &str = r#"
let
  dep = derivation { name = "dep"; system = builtins.currentSystem; builder = "/bin/sh"; args = [ "-c" "echo dep > $out" ]; };
in derivation {
  name = "demo-1.0"; system = builtins.currentSystem; builder = "/bin/sh";
  outputs = [ "out" "doc" ];
  src = builtins.toFile "src" "source";
  args = [ "-c" "echo ${dep} $src > $out; echo doc > $doc" ];
}
"#;

struct Env {
    root: PathBuf,
}

impl Env {
    fn new(name: &str) -> Env {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!("cranix-provenance-{name}-{}", std::process::id()));
        remove(&root);
        fs::create_dir_all(&root).unwrap();
        let o = Command::new(CRANIX).args(["key", "generate-secret", "--key-name", "test-1"]).output().unwrap();
        assert!(o.status.success());
        fs::write(root.join("key.sec"), &o.stdout).unwrap();
        Env { root }
    }

    fn cmd(&self, args: &[&str]) -> Output {
        Command::new(CRANIX)
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("NIX_CONF_DIR", self.root.join("etc"))
            .env_remove("NIX_CONFIG")
            .env_remove("CRANIX_CONFIG")
            .arg("--store")
            .arg(self.root.join("store"))
            .args(["--option", "substituters", ""])
            .arg("--option")
            .arg("secret-key-files")
            .arg(self.root.join("key.sec"))
            .args(args)
            .output()
            .unwrap()
    }

    fn run(&self, args: &[&str]) -> String {
        let o = self.cmd(args);
        assert!(o.status.success(), "cranix {args:?} failed:\n{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap()
    }

    fn public_key(&self) -> String {
        let o = Command::new(CRANIX)
            .arg("key")
            .arg("convert-secret-to-public")
            .stdin(fs::File::open(self.root.join("key.sec")).unwrap())
            .output()
            .unwrap();
        String::from_utf8(o.stdout).unwrap().trim().to_string()
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

fn remove(p: &std::path::Path) {
    let _ = Command::new("/bin/chmod").args(["-R", "u+w"]).arg(p).status();
    let _ = fs::remove_dir_all(p);
}

#[test]
fn statements_describe_each_output() {
    let env = Env::new("stmt");
    let text = env.run(&["provenance", "--expr", EXPR]);
    assert_eq!(env.run(&["provenance", "--expr", EXPR]), text, "statements differ between runs");
    let sts: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(sts.len(), 2);
    for (st, out) in sts.iter().zip(["doc", "out"]) {
        assert_eq!(st["_type"], "https://in-toto.io/Statement/v1");
        assert_eq!(st["predicateType"], "https://slsa.dev/provenance/v1");
        let name = st["subject"][0]["name"].as_str().unwrap();
        assert!(name.ends_with(&format!("-demo-1.0{}", if out == "out" { "" } else { "-doc" })), "{name}");
        assert_eq!(st["subject"][0]["digest"]["sha256"].as_str().unwrap().len(), 64);
        let def = &st["predicate"]["buildDefinition"];
        assert_eq!(def["externalParameters"]["output"], out);
        assert!(def["externalParameters"]["derivation"].as_str().unwrap().ends_with("-demo-1.0.drv"));
        let roles: Vec<&str> = def["resolvedDependencies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                assert_eq!(d["digest"]["sha256"].as_str().unwrap().len(), 64);
                d["annotations"]["role"].as_str().unwrap()
            })
            .collect();
        let mut sorted = roles.clone();
        sorted.sort();
        assert_eq!(sorted, ["derivation", "input", "source"]);
        let params = &def["internalParameters"];
        for k in ["sandbox", "timeout", "maxSilentTime", "system"] {
            assert!(params.get(k).is_some(), "missing {k}");
        }
        assert_eq!(st["predicate"]["runDetails"]["builder"]["id"], "https://github.com/tmmy-cc/cranix");
    }
}

#[test]
fn signatures_verify_and_tampering_fails() {
    let env = Env::new("sign");
    let signed = env.path("signed.jsonl");
    let cache = format!("file://{}", env.path("cache"));
    env.run(&["provenance", "--expr", EXPR, "--to", &cache, "-o", &signed]);
    let pk = env.public_key();
    let ok = env.run(&["provenance", "verify", &signed, "--public-key", &pk]);
    assert_eq!(ok.lines().count(), 2);
    assert!(ok.lines().all(|l| l.ends_with(": signed by test-1")), "{ok}");

    // Without the key, nothing verifies.
    let o = env.cmd(&["provenance", "verify", &signed]);
    assert!(!o.status.success());

    // A changed payload breaks the signature.
    let text = fs::read_to_string(&signed).unwrap();
    let line = text.lines().next().unwrap();
    let mut env_doc: Value = serde_json::from_str(line).unwrap();
    let payload = env_doc["payload"].as_str().unwrap().to_string();
    let changed = payload.replacen('A', "B", 1);
    assert_ne!(changed, payload);
    env_doc["payload"] = Value::String(changed);
    let bad = env.path("bad.jsonl");
    fs::write(&bad, serde_json::to_string(&env_doc).unwrap() + "\n").unwrap();
    let o = env.cmd(&["provenance", "verify", &bad, "--public-key", &pk]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("no valid signature by a trusted key"));

    // The cache holds each statement beside the narinfo.
    let subject = ok.lines().next().unwrap().strip_suffix(": signed by test-1").unwrap();
    let from = env.run(&["provenance", "verify", "--from", &cache, subject, "--public-key", &pk]);
    assert_eq!(from.trim(), format!("{subject}: signed by test-1"));
}
