//! `cranix run` and `cranix shell` build what is missing: through a daemon
//! given with `--store`, and with an explanation when nothing can build.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::Duration;

const CRANIX: &str = env!("CARGO_BIN_EXE_cranix");

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let p = base.join(format!("cranix-flake-build-{name}-{}", std::process::id()));
        remove(&p);
        fs::create_dir_all(p.join("flake")).unwrap();
        let system = format!("{}-{}", std::env::consts::ARCH, if cfg!(target_os = "macos") { "darwin" } else { "linux" });
        let script = format!("/bin/mkdir -p $out/bin; printf '#!/bin/sh\\necho hello from {name}\\n' > $out/bin/hello; /bin/chmod +x $out/bin/hello");
        fs::write(
            p.join("flake/flake.nix"),
            format!(
                "{{ outputs = {{ self }}: {{ packages.{system}.default = derivation {{ name = \"hello\"; system = \"{system}\"; \
                 builder = \"/bin/sh\"; args = [ \"-c\" \"{script}\" ]; }} // {{ meta.mainProgram = \"hello\"; }}; }}; }}"
            ),
        )
        .unwrap();
        Scratch(p)
    }

    /// `cranix ARGS` in the flake directory, with no substituters or
    /// remote builders and its data under this directory.
    fn cranix(&self, args: &[&str]) -> Command {
        let mut c = Command::new(CRANIX);
        c.args(args)
            .current_dir(self.0.join("flake"))
            .env("NIX_CONF_DIR", self.0.join("no-conf"))
            .env("NIX_USER_CONF_FILES", "")
            .env("NIX_CONFIG", "substituters =\nbuilders =")
            .env("XDG_DATA_HOME", self.0.join("data"))
            .env_remove("CRANIX_CONFIG");
        c
    }
}

fn remove(p: &Path) {
    if p.exists() {
        let _ = Command::new("chmod").arg("-R").arg("u+w").arg(p).status();
        let _ = fs::remove_dir_all(p);
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        remove(&self.0);
    }
}

fn text(o: &Output) -> (String, String) {
    (String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

#[test]
fn run_explains_when_nothing_can_build() {
    let s = Scratch::new("nobuilder");
    let o = s.cranix(&["run", "."]).output().unwrap();
    let (_, err) = text(&o);
    assert!(!o.status.success());
    assert!(err.contains("cannot build") && err.contains("--store daemon") && err.contains("'builders'"), "{err}");
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn run_and_shell_build_through_a_daemon() {
    let s = Scratch::new("daemon");
    let sock = s.0.join("daemon.sock");
    let store = s.0.join("d");
    let child = s
        .cranix(&["--store", store.to_str().unwrap(), "daemon", "--socket", sock.to_str().unwrap()])
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let _daemon = Daemon(child);
    for _ in 0..500 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let uri = format!("unix://{}?store={}", sock.display(), store.join("store").display());

    let o = s.cranix(&["--store", &uri, "run", "."]).output().unwrap();
    let (out, err) = text(&o);
    assert!(o.status.success(), "{err}");
    assert_eq!(out, "hello from daemon\n");
    assert!(err.contains("building '"), "{err}");

    // Built once: the second command finds the output.
    let o = s.cranix(&["--store", &uri, "shell", ".", "-c", "hello"]).output().unwrap();
    let (out, err) = text(&o);
    assert!(o.status.success(), "{err}");
    assert_eq!(out, "hello from daemon\n");
    assert!(!err.contains("building '"), "{err}");
}
