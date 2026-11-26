//! Build sandboxing with Nix's semantics: which derivations get a sandbox,
//! which host paths they can see, and the platform mechanism that confines
//! them (namespaces and a chroot on Linux, `sandbox-exec` on macOS).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use cranix_core::{Derivation, StorePath};

use crate::build::BuildOptions;
use crate::{Result, Store};

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "linux")]
mod linux;

/// The `sandbox` setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxMode {
    Disabled,
    Enabled,
    /// Sandboxes derivations unless they set `__noChroot` or are
    /// fixed-output, and permits `__sandboxProfile` on macOS.
    Relaxed,
}

impl SandboxMode {
    pub fn parse(s: &str) -> Result<SandboxMode> {
        match s {
            "true" | "yes" | "1" => Ok(SandboxMode::Enabled),
            "false" | "no" | "0" => Ok(SandboxMode::Disabled),
            "relaxed" => Ok(SandboxMode::Relaxed),
            _ => Err(format!("option 'sandbox' has invalid value '{s}'; expected 'true', 'false' or 'relaxed'")),
        }
    }

    /// The setting's value as `nix.conf` spells it.
    pub fn name(self) -> &'static str {
        match self {
            SandboxMode::Disabled => "false",
            SandboxMode::Enabled => "true",
            SandboxMode::Relaxed => "relaxed",
        }
    }

    /// Nix enables the sandbox by default on Linux only.
    pub fn host_default() -> SandboxMode {
        if cfg!(target_os = "linux") {
            SandboxMode::Enabled
        } else {
            SandboxMode::Disabled
        }
    }
}

/// A host path made visible inside the sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChrootPath {
    pub source: String,
    /// Missing optional paths are skipped; missing required ones fail the
    /// build.
    pub optional: bool,
}

/// Parses `sandbox-paths` entries: `PATH`, `TARGET=SOURCE`, either with a
/// trailing `?` to mark it optional.
pub(crate) fn parse_sandbox_paths(entries: &[String]) -> BTreeMap<String, ChrootPath> {
    let mut m = BTreeMap::new();
    for e in entries {
        let (e, optional) = match e.strip_suffix('?') {
            Some(s) => (s, true),
            None => (e.as_str(), false),
        };
        if e.is_empty() {
            continue;
        }
        let (target, source) = e.split_once('=').unwrap_or((e, e));
        m.insert(target.to_string(), ChrootPath { source: source.to_string(), optional });
    }
    m
}

/// Derivation attributes as Nix's `ParsedDerivation` reads them: from
/// `__json` with structured attributes, otherwise from the environment.
pub(crate) struct DrvAttrs<'a> {
    drv: &'a Derivation,
    json: Option<serde_json::Map<String, serde_json::Value>>,
}

impl<'a> DrvAttrs<'a> {
    pub fn new(drv: &'a Derivation) -> Result<DrvAttrs<'a>> {
        let json = match drv.env.get("__json") {
            Some(s) => match serde_json::from_str(s) {
                Ok(serde_json::Value::Object(m)) => Some(m),
                _ => return Err(format!("derivation '{}' has malformed structured attributes", drv.name)),
            },
            None => None,
        };
        Ok(DrvAttrs { drv, json })
    }

    pub fn get_bool(&self, name: &str) -> bool {
        match &self.json {
            Some(m) => m.get(name).and_then(|v| v.as_bool()).unwrap_or(false),
            None => self.drv.env.get(name).is_some_and(|v| v == "1"),
        }
    }

    pub fn get_string(&self, name: &str) -> Option<String> {
        match &self.json {
            Some(m) => m.get(name).and_then(|v| v.as_str()).map(String::from),
            None => self.drv.env.get(name).cloned(),
        }
    }

    pub fn get_strings(&self, name: &str) -> Vec<String> {
        match &self.json {
            Some(m) => m
                .get(name)
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            None => self.drv.env.get(name).map(|v| v.split_whitespace().map(String::from).collect()).unwrap_or_default(),
        }
    }
}

/// What a build's sandbox allows.
#[derive(Debug)]
pub(crate) struct Spec {
    /// Confines the builder to its inputs and `paths`. In relaxed mode a
    /// derivation without it still runs under the minimal macOS profile.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub chroot: bool,
    /// Fixed-output derivations keep network access.
    pub network: bool,
    /// Host paths visible in the sandbox, keyed by their path inside it.
    pub paths: BTreeMap<String, ChrootPath>,
    /// `__sandboxProfile`, appended to the macOS profile.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub extra_profile: String,
    /// `__darwinAllowLocalNetworking`.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub local_networking: bool,
}

/// Decides how `drv` is sandboxed. Returns `None` when it runs unconfined.
pub(crate) fn plan(
    store: &Store,
    drv_path: &StorePath,
    drv: &Derivation,
    inputs: &BTreeSet<StorePath>,
    opts: &BuildOptions,
) -> Result<Option<Spec>> {
    if opts.sandbox == SandboxMode::Disabled {
        return Ok(None);
    }
    let attrs = DrvAttrs::new(drv)?;
    let printed = store.dir.print(drv_path);
    let no_chroot = attrs.get_bool("__noChroot");
    let extra_profile = attrs.get_string("__sandboxProfile").unwrap_or_default();
    // Fixed-output and impure derivations keep the network, as in Nix.
    let sandboxed = !drv.is_fixed_output() && !drv.is_impure();
    let chroot = match opts.sandbox {
        SandboxMode::Enabled => {
            if no_chroot {
                return Err(format!(
                    "derivation '{printed}' has '__noChroot' set, but that's not allowed when 'sandbox' is 'true'"
                ));
            }
            if cfg!(target_os = "macos") && !extra_profile.is_empty() {
                return Err(format!(
                    "derivation '{printed}' specifies a sandbox profile, but this is only allowed when 'sandbox' is 'relaxed'"
                ));
            }
            true
        }
        SandboxMode::Relaxed => sandboxed && !no_chroot,
        SandboxMode::Disabled => unreachable!(),
    };
    if !chroot && cfg!(target_os = "linux") {
        return Ok(None);
    }
    if !available() {
        if opts.sandbox_fallback {
            warn_unavailable();
            return Ok(None);
        }
        return Err(format!(
            "this system does not support the kernel features required for sandboxing (needed to build '{printed}'); use '--no-sandbox' to disable sandboxing"
        ));
    }

    let mut paths = parse_sandbox_paths(&opts.sandbox_paths);

    // Store paths among the sandbox paths bring their closure along.
    let mut extra_store_paths = BTreeSet::new();
    for p in paths.values() {
        if let Some((sp, _)) = store.dir.to_store_path(&p.source) {
            extra_store_paths.insert(sp);
        }
    }
    for sp in store.closure(extra_store_paths)? {
        let s = store.dir.print(&sp);
        paths.insert(s.clone(), ChrootPath { source: s, optional: false });
    }

    for dep in attrs.get_strings("__impureHostDeps") {
        let canon = canon_path(&dep);
        let allowed = opts.allowed_impure_host_deps.iter().any(|a| is_in_dir_or_eq(&canon, &canon_path(a)));
        if !allowed {
            return Err(format!(
                "derivation '{printed}' requested impure path '{dep}', but it was not in allowed-impure-host-deps"
            ));
        }
        // macOS 11+ has no /usr/lib/libSystem*.dylib on disk, so impure
        // host dependencies may be missing.
        paths.insert(dep.clone(), ChrootPath { source: dep, optional: true });
    }

    if !sandboxed && cfg!(target_os = "linux") {
        // Fixed-output derivations resolve names like the host does.
        for f in ["/etc/resolv.conf", "/etc/services", "/etc/hosts"] {
            paths.insert(f.into(), ChrootPath { source: f.into(), optional: true });
        }
    }

    for p in inputs {
        let s = store.dir.print(p);
        paths.insert(s.clone(), ChrootPath { source: s, optional: false });
    }

    Ok(Some(Spec {
        chroot,
        network: !sandboxed,
        paths,
        extra_profile,
        local_networking: attrs.get_bool("__darwinAllowLocalNetworking"),
    }))
}

/// Whether this machine can sandbox builds; probed once per process.
fn available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        #[cfg(target_os = "linux")]
        return linux::supported();
        #[cfg(target_os = "macos")]
        return Path::new(darwin::SANDBOX_EXEC).exists();
        #[allow(unreachable_code)]
        false
    })
}

fn warn_unavailable() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| eprintln!("warning: sandboxing is not supported on this system; building without a sandbox"));
}

/// Lexically normalises an absolute path (`.`, `..`, repeated slashes)
/// without resolving symlinks, so it reveals nothing about the host.
fn canon_path(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

fn is_in_dir_or_eq(p: &str, dir: &str) -> bool {
    p == dir || dir == "/" || p.strip_prefix(dir).is_some_and(|r| r.starts_with('/'))
}

/// A sandbox prepared for one build.
pub(crate) enum Sandbox {
    None,
    #[cfg(target_os = "macos")]
    Darwin(darwin::Profile),
    #[cfg(target_os = "linux")]
    Linux(linux::Chroot),
}

impl Sandbox {
    /// Sets up the sandbox for a build whose temporary directory is `top`.
    pub fn prepare(
        store: &Store,
        drv_path: &StorePath,
        spec: Option<Spec>,
        outputs: &[&StorePath],
        top: &Path,
        opts: &BuildOptions,
    ) -> Result<Sandbox> {
        let Some(spec) = spec else { return Ok(Sandbox::None) };
        #[cfg(target_os = "macos")]
        {
            let _ = drv_path;
            let outs: Vec<String> = outputs.iter().map(|p| store.dir.print(p)).collect();
            Ok(Sandbox::Darwin(darwin::Profile::write(&spec, store.dir.as_str(), &outs, top, opts)?))
        }
        #[cfg(target_os = "linux")]
        {
            let _ = outputs;
            let root = std::path::PathBuf::from(format!("{}.chroot", store.real_path(drv_path).display()));
            Ok(Sandbox::Linux(linux::Chroot::prepare(root, &spec, store.dir.as_str(), top, opts)?))
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (store, drv_path, spec, outputs, top, opts);
            Ok(Sandbox::None)
        }
    }

    /// The build directory as the builder sees it.
    pub fn build_dir(&self, top: &str) -> String {
        match self {
            #[cfg(target_os = "linux")]
            Sandbox::Linux(c) => c.build_dir.clone(),
            _ => top.to_string(),
        }
    }

    /// A command running `builder`, built for `platform`, inside the
    /// sandbox.
    pub fn command(&self, builder: &str, args: &[String], top: &Path, platform: &str) -> Command {
        #[cfg(target_os = "linux")]
        {
            let mut c = self.command_for(builder, args, top);
            linux::set_personality(&mut c, platform);
            c
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = platform;
            self.command_for(builder, args, top)
        }
    }

    fn command_for(&self, builder: &str, args: &[String], top: &Path) -> Command {
        match self {
            Sandbox::None => {
                let mut c = Command::new(builder);
                c.args(args).current_dir(top);
                c
            }
            #[cfg(target_os = "macos")]
            Sandbox::Darwin(p) => p.command(builder, args, top),
            #[cfg(target_os = "linux")]
            Sandbox::Linux(c) => c.command(builder, args),
        }
    }

    /// Moves the outputs a build left inside the sandbox into the store.
    pub fn collect_outputs(&self, store: &Store, outputs: &[&StorePath]) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Sandbox::Linux(c) => c.collect_outputs(store, outputs),
            _ => {
                let _ = (store, outputs);
                Ok(())
            }
        }
    }

    /// Removes what `prepare` created outside the build directory.
    pub fn cleanup(&self) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Sandbox::Linux(c) => c.cleanup(),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_paths_syntax() {
        let m = parse_sandbox_paths(&["/bin/sh=/nix/store/x-busybox/bin/sh".into(), "/usr?".into(), "/dev".into()]);
        assert_eq!(m["/bin/sh"], ChrootPath { source: "/nix/store/x-busybox/bin/sh".into(), optional: false });
        assert_eq!(m["/usr"], ChrootPath { source: "/usr".into(), optional: true });
        assert_eq!(m["/dev"], ChrootPath { source: "/dev".into(), optional: false });
    }

    #[test]
    fn impure_host_dep_prefixes() {
        assert_eq!(canon_path("/usr/lib/../lib//libSystem.dylib"), "/usr/lib/libSystem.dylib");
        assert!(is_in_dir_or_eq("/usr/lib/libSystem.dylib", "/usr/lib"));
        assert!(is_in_dir_or_eq("/bin/sh", "/bin/sh"));
        assert!(!is_in_dir_or_eq("/usr/libexec", "/usr/lib"));
    }
}
