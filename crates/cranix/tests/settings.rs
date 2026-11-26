//! Settings precedence through the command line: the system and user
//! `nix.conf`, `cranix.conf`, `$CRANIX_CONFIG`, `$NIX_CONFIG`, then
//! `--option` and the flags derived from setting names.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const CRANIX: &str = env!("CARGO_BIN_EXE_cranix");

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(name: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("cranix-settings-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for d in ["etc", "home/nix", "home/cranix"] {
            fs::create_dir_all(dir.join(d)).unwrap();
        }
        Env { dir }
    }

    fn write(&self, rel: &str, text: &str) {
        fs::write(self.dir.join(rel), text).unwrap();
    }

    /// Runs `cranix ARGS` with only this environment's configuration.
    fn run(&self, env: &[(&str, &str)], args: &[&str]) -> (String, String) {
        let mut c = Command::new(CRANIX);
        c.args(args)
            .env("NIX_CONF_DIR", self.dir.join("etc"))
            .env("XDG_CONFIG_HOME", self.dir.join("home"))
            .env("XDG_CONFIG_DIRS", self.dir.join("xdg"))
            .env_remove("NIX_USER_CONF_FILES")
            .env_remove("NIX_CONFIG")
            .env_remove("CRANIX_CONFIG");
        for (k, v) in env {
            c.env(k, v);
        }
        let o = c.output().unwrap();
        assert!(o.status.success(), "cranix {args:?} failed:\n{}", String::from_utf8_lossy(&o.stderr));
        (String::from_utf8(o.stdout).unwrap().trim_end().to_string(), String::from_utf8(o.stderr).unwrap())
    }

    fn show(&self, env: &[(&str, &str)], args: &[&str], name: &str) -> String {
        let mut a = args.to_vec();
        a.extend(["config", "show", name]);
        self.run(env, &a).0
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn each_source_overrides_the_ones_before() {
    let e = Env::new("order");
    e.write("etc/nix.conf", "timeout = 1\nmax-silent-time = 1\ncores = 1\nkeep-failed = true\nsandbox = false\ntarball-ttl = 1\ninclude extra.conf\n");
    e.write("etc/extra.conf", "substituters = file:///system\n");
    e.write("home/nix/nix.conf", "max-silent-time = 2\ncores = 2\ntarball-ttl = 2\nextra-substituters = file:///user\n");
    e.write("home/cranix/cranix.conf", "cores = 3\ntarball-ttl = 3\n!include missing.conf\n");
    let cfg = [("CRANIX_CONFIG", "tarball-ttl = 4\nmax-jobs = 4"), ("NIX_CONFIG", "max-jobs = 5\ndownload-attempts = 5")];

    assert_eq!(e.show(&cfg, &[], "timeout"), "1");
    assert_eq!(e.show(&cfg, &[], "max-silent-time"), "2");
    assert_eq!(e.show(&cfg, &[], "cores"), "3");
    assert_eq!(e.show(&cfg, &[], "tarball-ttl"), "4");
    assert_eq!(e.show(&cfg, &[], "max-jobs"), "5");
    assert_eq!(e.show(&cfg, &[], "substituters"), "file:///system file:///user");

    // The command line comes last, in order.
    assert_eq!(e.show(&cfg, &["--option", "max-jobs", "6"], "max-jobs"), "6");
    assert_eq!(e.show(&cfg, &["--max-jobs", "7", "--option", "max-jobs", "8"], "max-jobs"), "8");
    assert_eq!(e.show(&cfg, &["--sandbox"], "sandbox"), "true");
    assert_eq!(e.show(&cfg, &["--relaxed-sandbox"], "sandbox"), "relaxed");
    assert_eq!(e.show(&cfg, &["--no-keep-failed"], "keep-failed"), "false");
    assert_eq!(e.show(&cfg, &["--extra-substituters", "file:///cli"], "substituters"), "file:///system file:///user file:///cli");
    assert_eq!(e.show(&cfg, &["--substituters", "file:///only"], "substituters"), "file:///only");
    assert_eq!(e.show(&cfg, &["--timeout", "9"], "timeout"), "9");
    assert_eq!(e.show(&cfg, &["--system", "x86_64-linux"], "system"), "x86_64-linux");
}

#[test]
fn experimental_features_and_user_files() {
    let e = Env::new("features");
    e.write("etc/nix.conf", "experimental-features = nix-command\n");
    e.write("home/nix/nix.conf", "extra-experimental-features = flakes\n");
    assert_eq!(e.show(&[], &[], "experimental-features"), "flakes nix-command");
    let env = [("NIX_CONFIG", "experimental-features = ca-derivations")];
    assert_eq!(e.show(&env, &[], "experimental-features"), "ca-derivations");
    assert_eq!(e.show(&env, &["--extra-experimental-features", "flakes"], "experimental-features"), "ca-derivations flakes");

    // $NIX_USER_CONF_FILES replaces the XDG files; the first one wins.
    e.write("a.conf", "timeout = 10\n");
    e.write("b.conf", "timeout = 20\nmax-silent-time = 20\n");
    let files = format!("{}:{}", e.dir.join("a.conf").display(), e.dir.join("b.conf").display());
    let env = [("NIX_USER_CONF_FILES", files.as_str())];
    assert_eq!(e.show(&env, &[], "timeout"), "10");
    assert_eq!(e.show(&env, &[], "max-silent-time"), "20");
    assert_eq!(e.show(&env, &[], "experimental-features"), "nix-command");
}

#[test]
fn unknown_settings_warn_once() {
    let e = Env::new("unknown");
    e.write("etc/nix.conf", "no-such-setting = 1\nauto-optimise-store = true\nbuild-users-group = nixbld\nextra-trusted-substituters = x\n");
    let (_, err) = e.run(&[("NIX_CONFIG", "no-such-setting = 2\nextra-timeout = 3")], &["--option", "no-such-setting", "3", "config", "show", "timeout"]);
    assert_eq!(err.matches("warning: unknown setting 'no-such-setting'").count(), 1, "{err}");
    assert_eq!(err.matches("warning: unknown setting 'extra-timeout'").count(), 1, "{err}");
    assert!(!err.contains("auto-optimise-store") && !err.contains("trusted-substituters"), "{err}");
}
