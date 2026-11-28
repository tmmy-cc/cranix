//! `cranix build --check`: a reproducible derivation passes, one that
//! writes the time fails and names the differing file, and `--keep-failed`
//! keeps the rebuild beside the existing output.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const CRANIX: &str = env!("CARGO_BIN_EXE_cranix");

struct Env {
    root: PathBuf,
}

impl Env {
    fn new(name: &str) -> Env {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!("cranix-check-{name}-{}", std::process::id()));
        remove(&root);
        fs::create_dir_all(&root).unwrap();
        Env { root }
    }

    fn build(&self, expr: &str, extra: &[&str]) -> Output {
        Command::new(CRANIX)
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("NIX_CONF_DIR", self.root.join("etc"))
            .env_remove("NIX_CONFIG")
            .env_remove("CRANIX_CONFIG")
            .arg("--store")
            .arg(self.root.join("store"))
            .args(["--option", "substituters", "", "build", "--no-link", "--expr", expr])
            .args(extra)
            .output()
            .unwrap()
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

fn drv(name: &str, script: &str) -> String {
    format!(r#"derivation {{ name = "{name}"; system = builtins.currentSystem; builder = "/bin/sh"; args = [ "-c" "{script}" ]; }}"#)
}

#[test]
fn reproducible_derivation_passes() {
    let env = Env::new("same");
    let e = drv("same", "/bin/mkdir $out; echo hello > $out/greeting");
    let first = env.build(&e, &[]);
    assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));
    let o = env.build(&e, &["--check"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(o.stdout, first.stdout);
}

#[test]
fn timestamp_fails_with_the_difference() {
    let env = Env::new("date");
    let e = drv("stamp", "/bin/date +%s%N > $out; /bin/sleep 1");
    let first = env.build(&e, &[]);
    assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));
    let out = String::from_utf8(first.stdout).unwrap().trim().to_string();
    let before = fs::read(&out).unwrap();

    let o = env.build(&e, &["--check", "--keep-failed"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success());
    assert!(err.contains(&format!("output '{out}' of '")), "{err}");
    assert!(err.contains("differs from its rebuild:\n  (the output itself): contents differ at line 1\n    - "), "{err}");
    assert!(err.contains(&format!("the rebuild is kept at '{out}.check'")), "{err}");
    // The existing output is unchanged and still valid; the rebuild differs.
    assert_eq!(fs::read(&out).unwrap(), before);
    assert_ne!(fs::read(format!("{out}.check")).unwrap(), before);
    let again = env.build(&e, &[]);
    assert!(again.status.success());
    assert_eq!(String::from_utf8(again.stdout).unwrap().trim(), out);
}
