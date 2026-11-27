//! `build --upload-to`: outputs reach the cache while later builds run,
//! the cache holds complete closures at every moment, and failed uploads
//! warn, or fail the build with `--upload-required`.

#[path = "../../cranix-store/tests/cache_server/mod.rs"]
mod cache_server;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const CRANIX: &str = env!("CARGO_BIN_EXE_cranix");

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().canonicalize().unwrap().join(format!("cranix-upload-{name}-{}", std::process::id()));
    remove(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn remove(d: &Path) {
    if d.exists() {
        let _ = Command::new("chmod").args(["-R", "u+w"]).arg(d).status();
        let _ = fs::remove_dir_all(d);
    }
}

/// A chain `a <- b <- c`: `b` and `c` sleep for the given seconds and
/// refer to the output before them.
fn chain(root: &Path, b_secs: u32, c_secs: u32) -> PathBuf {
    let f = root.join("chain.nix");
    fs::write(
        &f,
        format!(
            r#"
let
  sh = name: script: derivation {{ inherit name; system = builtins.currentSystem; builder = "/bin/sh"; args = [ "-c" script ]; }};
  a = sh "a" "echo a > $out";
  b = sh "b" "/bin/sleep {b_secs}; echo ${{a}} > $out";
  c = sh "c" "/bin/sleep {c_secs}; echo ${{b}} > $out";
in {{ inherit a b c; }}
"#
        ),
    )
    .unwrap();
    f
}

fn cranix(root: &Path) -> Command {
    let mut c = Command::new(CRANIX);
    c.env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("NIX_CONF_DIR", root.join("etc"))
        .env_remove("NIX_CONFIG")
        .env_remove("CRANIX_CONFIG")
        .env_remove("NIX_USER_CONF_FILES")
        .args(["--store"])
        .arg(root.join("store"))
        .args(["--option", "substituters", ""]);
    c
}

fn out_path(root: &Path, file: &Path, attr: &str) -> String {
    let o = cranix(root).args(["eval", "--raw", "-A", &format!("{attr}.outPath")]).arg(file).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap()
}

fn hash_part(path: &str) -> String {
    path.rsplit('/').next().unwrap()[..32].to_string()
}

fn spawn_build(root: &Path, file: &Path, extra: &[&str]) -> Child {
    cranix(root)
        .args(extra)
        .args(["build", "--no-link", "-A", "c"])
        .arg(file)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_for(p: &Path, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if p.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Every narinfo in the file cache `dir` has its NAR, and every path it
/// references has a narinfo. Returns the hash parts present.
fn check_complete(dir: &Path) -> BTreeSet<String> {
    let mut have = BTreeSet::new();
    let mut infos = Vec::new();
    for e in fs::read_dir(dir).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some(h) = name.strip_suffix(".narinfo") {
            have.insert(h.to_string());
            infos.push(fs::read_to_string(e.path()).unwrap());
        }
    }
    for text in &infos {
        for line in text.lines() {
            if let Some(url) = line.strip_prefix("URL: ") {
                assert!(dir.join(url).exists(), "missing NAR {url}");
            }
            if let Some(refs) = line.strip_prefix("References: ") {
                for r in refs.split_whitespace() {
                    assert!(have.contains(&r[..32]), "missing reference {r}");
                }
            }
        }
    }
    have
}

#[test]
fn outputs_are_uploaded_while_later_builds_run() {
    let root = scratch("while");
    let file = chain(&root, 1, 2);
    let cache = root.join("cache");
    let (a, b, c) = (out_path(&root, &file, "a"), out_path(&root, &file, "b"), out_path(&root, &file, "c"));
    let url = format!("file://{}", cache.display());
    let mut child = spawn_build(&root, &file, &["--upload-to", &url, "--upload-jobs", "2"]);
    // `b` reaches the cache while `c` is still building.
    assert!(wait_for(&cache.join(format!("{}.narinfo", hash_part(&b))), Duration::from_secs(60)));
    assert!(child.try_wait().unwrap().is_none(), "the build finished before b was uploaded");
    let early = fs::metadata(cache.join(format!("{}.narinfo", hash_part(&a)))).unwrap().modified().unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let last = fs::metadata(cache.join(format!("{}.narinfo", hash_part(&c)))).unwrap().modified().unwrap();
    assert!(early < last);
    let have = check_complete(&cache);
    assert_eq!(have, [&a, &b, &c].iter().map(|p| hash_part(p)).collect());
    remove(&root);
}

#[test]
fn a_stopped_build_leaves_complete_closures() {
    let root = scratch("killed");
    let file = chain(&root, 1, 60);
    let cache = root.join("cache");
    let b = out_path(&root, &file, "b");
    let mut child = spawn_build(&root, &file, &["--upload-to", &format!("file://{}", cache.display())]);
    assert!(wait_for(&cache.join(format!("{}.narinfo", hash_part(&b))), Duration::from_secs(60)));
    child.kill().unwrap();
    child.wait().unwrap();
    let have = check_complete(&cache);
    let names: Vec<String> = fs::read_dir(&cache).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".narinfo")).map(|e| fs::read_to_string(e.path()).unwrap().lines().next().unwrap().to_string()).collect();
    assert_eq!(have.len(), 2, "{names:?}");
    remove(&root);
}

fn run(child: Child) -> Output {
    child.wait_with_output().unwrap()
}

#[test]
fn failed_uploads_warn_or_fail_the_build() {
    let root = scratch("fail");
    let file = chain(&root, 0, 0);
    let a = out_path(&root, &file, "a");
    let server = cache_server::CacheServer::start(&root.join("served"));
    server.state.lock().unwrap().fail_puts = Some(format!("/{}.narinfo", hash_part(&a)));
    let url = server.url.replace("http://", "http://user:glpat-TESTTOKEN0123456789@");

    let out = run(spawn_build(&root, &file, &["--upload-to", &url]));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("warning: uploading") && err.contains("user:***@") && !err.contains("TESTTOKEN"), "{err}");
    // Paths that refer to `a` stay out of the cache.
    let served: Vec<String> = fs::read_dir(root.join("served")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(!served.iter().any(|n| n.ends_with(".narinfo")), "{served:?}");

    remove(&root.join("store"));
    let out = run(spawn_build(&root, &file, &["--upload-to", &url, "--upload-required"]));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("HTTP status 500") && !err.contains("TESTTOKEN"), "{err}");
    remove(&root);
}
