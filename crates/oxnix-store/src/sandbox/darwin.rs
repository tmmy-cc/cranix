//! macOS sandbox: the builder runs under `sandbox-exec` with a profile
//! generated like Nix's (`sandbox-defaults.sb`, `sandbox-network.sb` and
//! `sandbox-minimal.sb`): everything is denied except the input closure,
//! the outputs, the temporary directory and a fixed set of system services.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::Spec;
use crate::build::BuildOptions;
use crate::Result;

pub(crate) const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

const DEFAULTS: &str = r#"
(define TMPDIR (param "_GLOBAL_TMP_DIR"))

; Disallow creating setuid/setgid binaries, since that would allow breaking
; build user isolation.
(deny file-write-setugid)

(allow process-fork)

; Reading system information like the number of CPUs.
(allow sysctl-read)

; POSIX and SysV semaphores and shared memory.
(allow ipc-posix*)
(allow ipc-sysv*)

(allow system-socket)

; Signals within the sandbox.
(allow signal (target same-sandbox))

; getpwuid and friends.
(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))

; The temporary directory. Network access there covers Unix domain sockets;
; allowing them more broadly would make it possible to escape the sandbox.
(allow file* process-exec network-outbound network-inbound
       (literal "/tmp") (subpath TMPDIR))

; Some packages read the system version.
(allow file-read*
       (literal "/System/Library/CoreServices/SystemVersion.plist")
       (literal "/System/Library/CoreServices/SystemVersionCompat.plist"))

; Without this clang cannot write to /dev/null, which breaks configure tests.
(allow file-read-metadata (literal "/dev"))

; Local networking for test suites, when the derivation asks for it.
(if (param "_ALLOW_LOCAL_NETWORKING")
    (begin
      (allow network* (remote ip "localhost:*"))
      (allow network-inbound (local ip "*:*"))
      (allow file-read-metadata
             (literal "/var")
             (literal "/etc")
             (literal "/etc/resolv.conf")
             (literal "/private/etc/resolv.conf"))
      (allow file-read* (literal "/private/var/run/resolv.conf"))
      (allow file-read-metadata (literal "/etc/hosts"))
      (allow file-read* (literal "/private/etc/hosts"))
      (allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))))

; Standard devices.
(allow file*
       (literal "/dev/null")
       (literal "/dev/random")
       (literal "/dev/stderr")
       (literal "/dev/stdin")
       (literal "/dev/stdout")
       (literal "/dev/tty")
       (literal "/dev/urandom")
       (literal "/dev/zero")
       (subpath "/dev/fd"))

; Pseudo-terminals.
(allow file*
       (literal "/dev/ptmx")
       (regex #"^/dev/pty[a-z]+")
       (regex #"^/dev/ttys[0-9]+"))

; Does nothing, but reduces build noise.
(allow file* (literal "/dev/dtracehelper"))

; libSystem reads time zone and locale data.
(allow file-read* (subpath "/usr/share/zoneinfo"))
(allow file-read* (subpath "/usr/share/locale"))

; Rosetta 2, to run x86_64 builders on aarch64.
(allow file-read*
       (subpath "/Library/Apple/usr/libexec/oah")
       (subpath "/System/Library/Apple/usr/libexec/oah")
       (subpath "/System/Library/LaunchDaemons/com.apple.oahd.plist")
       (subpath "/Library/Apple/System/Library/LaunchDaemons/com.apple.oahd.plist"))
"#;

const NETWORK: &str = r#"
; Local and remote network traffic.
(allow network* (local ip) (remote ip))

; /etc/resolv.conf is a symlink to /private/var/run/resolv.conf.
(allow file-read-metadata
       (literal "/var")
       (literal "/etc")
       (literal "/etc/resolv.conf")
       (literal "/private/etc/resolv.conf"))
(allow file-read* (literal "/private/var/run/resolv.conf"))

; DNS lookups, which even localhost needs.
(allow file-read-metadata (literal "/etc/hosts"))
(allow file-read* (literal "/private/etc/hosts"))
(allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))

; Certificate trust evaluation and network configuration.
(allow mach-lookup (global-name "com.apple.trustd"))
(allow mach-lookup (global-name "com.apple.trustd.agent"))
(allow mach-lookup (global-name "com.apple.SystemConfiguration.DNSConfiguration"))
(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))
"#;

const MINIMAL: &str = r#"
(allow default)

; Disallow creating setuid/setgid binaries, since that would allow breaking
; build user isolation.
(deny file-write-setugid)
"#;

/// A profile written to the build directory, plus the parameters
/// `sandbox-exec` is invoked with.
pub(crate) struct Profile {
    file: PathBuf,
    params: Vec<String>,
}

/// Quotes `s` as a string literal of the sandbox profile language.
fn quote(s: &str) -> String {
    let mut q = String::with_capacity(s.len() + 2);
    q.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            q.push('\\');
        }
        q.push(c);
    }
    q.push('"');
    q
}

fn parent(p: &str) -> &str {
    match p.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &p[..i],
    }
}

/// Appends an `allow` rule for `filters`. A rule without filters would
/// match everything, so none is emitted then.
fn allow(sb: &mut String, ops: &str, filters: &str) {
    if !filters.is_empty() {
        let _ = write!(sb, "(allow {ops}\n{filters})\n");
    }
}

/// Generates the profile text for `spec`.
fn generate(spec: &Spec, store_dir: &str, outputs: &[String], log_violations: bool) -> Result<String> {
    let mut sb = String::from("(version 1)\n");
    if !spec.chroot {
        sb.push_str(MINIMAL);
        return Ok(sb);
    }

    // Many file functions fail when they cannot stat every ancestor of a
    // path, so each ancestor gets metadata access.
    let mut ancestry = BTreeSet::new();
    for target in spec.paths.keys() {
        let mut cur = target.as_str();
        while cur != "/" {
            cur = parent(cur);
            ancestry.insert(cur.to_string());
        }
    }
    let mut cur = store_dir;
    while cur != "/" {
        ancestry.insert(cur.to_string());
        cur = parent(cur);
    }

    sb.push_str(if log_violations { "(deny default)\n" } else { "(deny default (with no-log))\n" });
    sb.push_str(DEFAULTS);
    if spec.network {
        sb.push_str(NETWORK);
    }

    let mut writable = String::new();
    for o in outputs {
        let _ = writeln!(writable, "\t(subpath {})", quote(o));
    }
    allow(&mut sb, "file-read* file-write* process-exec", &writable);

    // Without file-write*, access() wrongly returns EPERM on inputs.
    let mut inputs = String::new();
    for (target, p) in &spec.paths {
        if *target != p.source {
            return Err(format!("can't map '{target}' to '{}': mismatched impure paths not supported on Darwin", p.source));
        }
        match fs::symlink_metadata(target) {
            Ok(md) if md.is_dir() => {
                let _ = writeln!(inputs, "\t(subpath {})", quote(target));
            }
            Ok(_) => {
                let _ = writeln!(inputs, "\t(literal {})", quote(target));
            }
            Err(_) if p.optional => {}
            Err(e) => return Err(format!("getting attributes of required path '{target}': {e}")),
        }
    }
    allow(&mut sb, "file-read* file-write* process-exec", &inputs);

    // Read access to the ancestors themselves makes realpath() work.
    let mut ancestors = String::new();
    for a in &ancestry {
        let _ = writeln!(ancestors, "\t(literal {})", quote(a));
    }
    allow(&mut sb, "file-read*", &ancestors);

    sb.push_str(&spec.extra_profile);
    sb.push('\n');
    Ok(sb)
}

impl Profile {
    pub fn write(spec: &Spec, store_dir: &str, outputs: &[String], top: &Path, opts: &BuildOptions) -> Result<Profile> {
        let text = generate(spec, store_dir, outputs, opts.darwin_log_sandbox_violations)?;
        let file = top.join(".sandbox.sb");
        fs::write(&file, text).map_err(|e| format!("writing sandbox profile: {e}"))?;

        // Builders also use the global temporary directory; the profile
        // matches it by its resolved path, without a trailing slash.
        let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let tmp = fs::canonicalize(&tmp).map(|p| p.to_string_lossy().into_owned()).unwrap_or(tmp);
        let mut params = vec!["-D".to_string(), format!("_GLOBAL_TMP_DIR={}", tmp.trim_end_matches('/'))];
        if spec.local_networking {
            params.extend(["-D".to_string(), "_ALLOW_LOCAL_NETWORKING=1".to_string()]);
        }
        Ok(Profile { file, params })
    }

    pub fn command(&self, builder: &str, args: &[String], top: &Path) -> Command {
        let mut c = Command::new(SANDBOX_EXEC);
        c.arg("-f").arg(&self.file).args(&self.params).arg(builder).args(args).current_dir(top);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::ChrootPath;

    #[test]
    fn profile_lists_inputs_outputs_and_ancestors() {
        let mut paths = std::collections::BTreeMap::new();
        paths.insert("/bin/sh".to_string(), ChrootPath { source: "/bin/sh".into(), optional: false });
        paths.insert("/no/such/dep".to_string(), ChrootPath { source: "/no/such/dep".into(), optional: true });
        let spec = Spec { chroot: true, network: false, paths, extra_profile: "(allow extra)".into(), local_networking: false };
        let sb = generate(&spec, "/private/tmp/s/store", &["/private/tmp/s/store/abc-out".into()], false).unwrap();
        assert!(sb.starts_with("(version 1)\n(deny default (with no-log))"));
        assert!(sb.contains("\t(subpath \"/private/tmp/s/store/abc-out\")"));
        assert!(sb.contains("\t(literal \"/bin/sh\")"));
        assert!(!sb.contains("/no/such/dep"));
        assert!(sb.contains("\t(literal \"/private/tmp/s/store\")"));
        assert!(sb.contains("\t(literal \"/bin\")"));
        assert!(!sb.contains("(allow network* (local ip) (remote ip))"));
        assert!(sb.trim_end().ends_with("(allow extra)"));

        let empty = Spec { chroot: true, network: false, paths: Default::default(), extra_profile: String::new(), local_networking: false };
        assert!(!generate(&empty, "/s", &[], false).unwrap().contains("(allow file-read* file-write* process-exec\n)"));

        let fod = Spec { chroot: true, network: true, paths: Default::default(), extra_profile: String::new(), local_networking: false };
        assert!(generate(&fod, "/s", &[], false).unwrap().contains("(allow network* (local ip) (remote ip))"));

        let mut bad = std::collections::BTreeMap::new();
        bad.insert("/bin/sh".to_string(), ChrootPath { source: "/x/sh".into(), optional: false });
        let spec = Spec { chroot: true, network: false, paths: bad, extra_profile: String::new(), local_networking: false };
        assert!(generate(&spec, "/s", &[], false).is_err());
    }
}
