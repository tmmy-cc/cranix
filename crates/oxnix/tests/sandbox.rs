//! Build sandbox tests: `tests/build.nix` builds sandboxed, and the
//! derivations of `tests/sandbox.nix` show what a sandbox lets through.
//!
//! On Linux they need unprivileged user namespaces; where those are
//! missing the tests say so and pass without building.

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const OXNIX: &str = env!("CARGO_BIN_EXE_oxnix");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// Host paths the test builders run from.
fn sandbox_paths() -> &'static str {
    if cfg!(target_os = "macos") {
        "/bin/sh /bin/bash /bin/cat /bin/mkdir /bin/sleep"
    } else {
        "/bin /usr /lib /lib64? /lib32?"
    }
}

struct TempStore(PathBuf);

impl TempStore {
    fn new(name: &str) -> TempStore {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let p = base.join(format!("oxnix-sandbox-test-{name}-{}", std::process::id()));
        remove(&p);
        TempStore(p)
    }
}

/// Removes a store, whose objects are read-only.
fn remove(p: &Path) {
    if p.exists() {
        let _ = Command::new("chmod").arg("-R").arg("u+w").arg(p).status();
        let _ = std::fs::remove_dir_all(p);
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        remove(&self.0);
    }
}

fn build(store: &TempStore, args: &[&str]) -> Output {
    Command::new(OXNIX)
        .arg("--store")
        .arg(&store.0)
        .arg("build")
        .arg("--no-link")
        .args(args)
        .current_dir(repo())
        .env_remove("NIX_CONFIG")
        .output()
        .unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Output paths printed by a successful build.
fn outputs(o: &Output) -> Vec<String> {
    assert!(o.status.success(), "build failed:\n{}", stderr(o));
    String::from_utf8_lossy(&o.stdout).lines().map(String::from).collect()
}

/// Whether sandboxed builds can run here, judged by a build that may not
/// fall back to running unsandboxed.
fn sandbox_works(o: &Output) -> bool {
    let e = stderr(o);
    if e.contains("does not support the kernel features required for sandboxing") {
        eprintln!("skipping: this system cannot sandbox builds");
        return false;
    }
    true
}

/// Answers every connection with one line, like a minimal server a
/// fixed-output derivation fetches from.
fn serve() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let _ = s.write_all(b"hello from the network\n");
        }
    });
    port
}

const SANDBOX: &[&str] = &["--option", "sandbox", "true", "--option", "sandbox-fallback", "false"];

#[test]
fn build_nix_in_sandbox() {
    let store = TempStore::new("build");
    let mut args = vec!["tests/build.nix", "-j", "8", "--option", "sandbox-paths", sandbox_paths()];
    args.extend(SANDBOX);
    let o = build(&store, &args);
    if !sandbox_works(&o) {
        return;
    }
    let outs = outputs(&o);
    assert_eq!(outs.len(), 4);
    let all = std::fs::read_to_string(Path::new(&outs[0]).join("all")).unwrap();
    assert_eq!(all, "leaf 1\nleaf 2\nleaf 3\nleaf 4\n");
    assert_eq!(std::fs::read_to_string(&outs[1]).unwrap(), "passed as a file");
    assert_eq!(std::fs::read_to_string(&outs[3]).unwrap(), "hello");
}

fn probe_args<'a>(secret: &'a str, port: &'a str, tag: &'a str, attr: &'a str) -> Vec<&'a str> {
    vec![
        "tests/sandbox.nix",
        "-A",
        attr,
        "--argstr",
        "secret",
        secret,
        "--argstr",
        "port",
        port,
        "--argstr",
        "tag",
        tag,
        "--option",
        "sandbox-paths",
        sandbox_paths(),
    ]
}

#[test]
fn sandbox_isolates_builds() {
    let store = TempStore::new("isolation");
    let port = serve().to_string();
    // Outside the closure, the build directory and the temporary directory.
    let secret = repo().join("Cargo.toml").to_string_lossy().into_owned();

    let mut args = probe_args(&secret, &port, "", "probe");
    args.extend(SANDBOX);
    let o = build(&store, &args);
    if !sandbox_works(&o) {
        return;
    }
    let report = std::fs::read_to_string(&outputs(&o)[0]).unwrap();
    assert!(report.contains("read: denied\n"), "{report}");
    assert!(report.contains("network: denied\n"), "{report}");
    if cfg!(target_os = "linux") {
        assert!(report.contains("hostname: localhost\n"), "{report}");
        assert!(report.contains("uid: 1000\n"), "{report}");
        assert!(report.contains("build-top: /build\n"), "{report}");
    }

    // A fixed-output derivation keeps the network.
    let mut args = probe_args(&secret, &port, "", "fetch");
    args.extend(SANDBOX);
    let fetched = std::fs::read_to_string(&outputs(&build(&store, &args))[0]).unwrap();
    assert_eq!(fetched, "hello from the network\n");

    // The probe itself works: unsandboxed, both succeed.
    let mut args = probe_args(&secret, &port, "-unsandboxed", "probe");
    args.extend(["--option", "sandbox", "false"]);
    let report = std::fs::read_to_string(&outputs(&build(&store, &args))[0]).unwrap();
    assert!(report.contains("read: allowed\n"), "{report}");
    assert!(report.contains("network: allowed\n"), "{report}");
}

#[test]
fn no_chroot_needs_relaxed_mode() {
    let store = TempStore::new("nochroot");
    let secret = repo().join("Cargo.toml").to_string_lossy().into_owned();
    let mut args = probe_args(&secret, "1", "", "nochroot");
    args.extend(SANDBOX);
    let o = build(&store, &args);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("has '__noChroot' set, but that's not allowed when 'sandbox' is 'true'"), "{}", stderr(&o));

    let mut args = probe_args(&secret, "1", "", "nochroot");
    args.extend(["--option", "sandbox", "relaxed"]);
    let report = std::fs::read_to_string(&outputs(&build(&store, &args))[0]).unwrap();
    assert_eq!(report, "read: allowed\n");
}

/// The slow builder outlives a limit; the build fails promptly although a
/// background process keeps the log pipe open.
fn check_limit(sandboxed: bool, limit: &[&str], message: &str) {
    let store = TempStore::new(&format!("limit-{sandboxed}-{}", limit[0].trim_start_matches('-')));
    let mut args = probe_args("/", "1", "", "slow");
    args.extend(limit);
    if sandboxed {
        args.extend(SANDBOX);
    } else {
        args.extend(["--option", "sandbox", "false"]);
    }
    let start = Instant::now();
    let o = build(&store, &args);
    if sandboxed && !sandbox_works(&o) {
        return;
    }
    assert!(!o.status.success());
    assert!(stderr(&o).contains(message), "{}", stderr(&o));
    assert!(start.elapsed() < Duration::from_secs(30), "took {:?}", start.elapsed());
}

#[test]
fn timeout_kills_the_build() {
    check_limit(false, &["--timeout", "2"], "timed out after 2 seconds");
    check_limit(true, &["--timeout", "2"], "timed out after 2 seconds");
}

#[test]
fn max_silent_time_kills_the_build() {
    check_limit(false, &["--max-silent-time", "1"], "timed out after 1 seconds of silence");
    check_limit(true, &["--max-silent-time", "1"], "timed out after 1 seconds of silence");
}

/// The personality a Linux builder of `system` runs with, in either
/// sandbox mode (the default falls back to no sandbox where needed).
#[cfg(target_os = "linux")]
fn personality(store: &TempStore, system: &str) -> Option<u64> {
    let mut args = probe_args("/", "1", "", "personality");
    args.extend(["--argstr", "targetSystem", system]);
    let o = build(store, &args);
    // User-mode emulators such as qemu-user refuse the 32-bit personality.
    if stderr(&o).contains("setting the 32-bit personality: errno 22") {
        eprintln!("skipping {system}: this kernel or emulator refuses the 32-bit personality");
        return None;
    }
    let text = std::fs::read_to_string(&outputs(&o)[0]).unwrap();
    Some(u64::from_str_radix(text.trim(), 16).unwrap())
}

#[test]
#[cfg(target_os = "linux")]
fn builds_get_nix_personality() {
    const PER_LINUX32: u64 = 0x0008;
    const ADDR_NO_RANDOMIZE: u64 = 0x0040000;
    let store = TempStore::new("personality");
    let host = format!("{}-linux", std::env::consts::ARCH);
    let p = personality(&store, &host).unwrap();
    assert_eq!(p & ADDR_NO_RANDOMIZE, ADDR_NO_RANDOMIZE, "{p:#x}");
    assert_eq!(p & PER_LINUX32, 0, "{p:#x}");
    if host == "x86_64-linux" {
        if let Some(p) = personality(&store, "i686-linux") {
            assert_eq!(p & PER_LINUX32, PER_LINUX32, "{p:#x}");
        }
    }
}
