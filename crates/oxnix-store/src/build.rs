//! Realisation: builds the derivations whose outputs are missing, in
//! dependency order, running independent builds in parallel.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use oxnix_core::hash::{Hash, HashAlgo, HashSink};
use oxnix_core::{nar, Derivation, FileIngestion, StorePath};

use crate::sandbox::{self, Sandbox, SandboxMode};
use crate::nar_import::PathLock;
use crate::{canonicalise, fsutil, refs, PathInfo, Result, Store};

#[derive(Clone, Debug)]
pub struct BuildOptions {
    /// Number of builds run concurrently.
    pub jobs: usize,
    /// Value of `NIX_BUILD_CORES` passed to each builder.
    pub cores: usize,
    /// Stream build logs to stderr.
    pub print_logs: bool,
    pub keep_failed: bool,
    pub system: String,
    pub system_features: Vec<String>,
    pub sandbox: SandboxMode,
    /// `sandbox-paths` entries: `PATH`, `TARGET=SOURCE`, optionally with a
    /// trailing `?`.
    pub sandbox_paths: Vec<String>,
    /// Build unsandboxed when the platform cannot sandbox.
    pub sandbox_fallback: bool,
    /// Where the build directory appears inside the Linux sandbox.
    pub sandbox_build_dir: String,
    pub sandbox_dev_shm_size: String,
    /// Prefixes a derivation's `__impureHostDeps` must lie under.
    pub allowed_impure_host_deps: Vec<String>,
    pub darwin_log_sandbox_violations: bool,
    /// Seconds a build may run; 0 for no limit.
    pub timeout: u64,
    /// Seconds a build may go without output; 0 for no limit.
    pub max_silent_time: u64,
    /// Consulted before every local build, e.g. to use remote builders.
    pub hook: Option<Arc<dyn BuildHook>>,
    /// Receives build progress and output in place of stderr.
    pub logger: Option<Arc<dyn BuildLogger>>,
}

/// Receives the activity of builds: one `start`, the builder's output
/// lines, and one `stop` per build.
pub trait BuildLogger: Send + Sync + std::fmt::Debug {
    fn start(&self, id: u64, drv_path: &str, text: &str);
    fn line(&self, id: u64, line: &str);
    fn stop(&self, id: u64);
}

/// Where the output of one build goes: the configured logger, or stderr
/// prefixed with the derivation name when logs are printed.
#[derive(Clone, Debug)]
pub struct BuildLog {
    logger: Option<Arc<dyn BuildLogger>>,
    id: u64,
    name: String,
    print: bool,
}

impl BuildLog {
    fn start(opts: &BuildOptions, drv_path: &str, name: &str, text: &str) -> BuildLog {
        static NEXT: AtomicUsize = AtomicUsize::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed) as u64;
        match &opts.logger {
            Some(l) => l.start(id, drv_path, text),
            None => eprintln!("{text}"),
        }
        BuildLog { logger: opts.logger.clone(), id, name: name.to_string(), print: opts.print_logs }
    }

    /// One line of build output.
    pub fn line(&self, line: &str) {
        match &self.logger {
            Some(l) => l.line(self.id, line),
            None if self.print => eprintln!("{}> {line}", self.name),
            None => {}
        }
    }

    /// A progress message about the build.
    pub fn info(&self, msg: &str) {
        match &self.logger {
            Some(l) => l.line(self.id, msg),
            None => eprintln!("{msg}"),
        }
    }
}

struct Activity<'a>(&'a BuildLog);

impl Drop for Activity<'_> {
    fn drop(&mut self) {
        if let Some(l) = &self.0.logger {
            l.stop(self.0.id);
        }
    }
}

/// Lets something else build a derivation in place of the local builder.
pub trait BuildHook: Send + Sync + std::fmt::Debug {
    /// Either builds `drv` and registers its outputs in `store`, or asks for
    /// a local build, which runs while the returned slot is held.
    fn build(&self, store: &Store, drv_path: &StorePath, drv: &Derivation, opts: &BuildOptions, log: &BuildLog) -> Result<HookOutcome>;
}

pub enum HookOutcome {
    Built,
    Local(Option<Box<dyn std::any::Any + Send>>),
}

impl Default for BuildOptions {
    fn default() -> Self {
        let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        BuildOptions {
            jobs: n,
            cores: n,
            print_logs: false,
            keep_failed: false,
            system: host_system(),
            system_features: Vec::new(),
            sandbox: SandboxMode::host_default(),
            sandbox_paths: option_env!("OXNIX_SANDBOX_SHELL").map(|sh| vec![format!("/bin/sh={sh}")]).unwrap_or_default(),
            sandbox_fallback: true,
            sandbox_build_dir: "/build".into(),
            sandbox_dev_shm_size: "50%".into(),
            allowed_impure_host_deps: if cfg!(target_os = "macos") {
                ["/System/Library", "/usr/lib", "/dev", "/bin/sh"].map(String::from).to_vec()
            } else {
                Vec::new()
            },
            darwin_log_sandbox_violations: false,
            timeout: 0,
            max_silent_time: 0,
            hook: None,
            logger: None,
        }
    }
}

fn parse_bool(name: &str, v: &str) -> Result<bool> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("option '{name}' has invalid value '{v}'; expected 'true' or 'false'")),
    }
}

fn parse_num<T: std::str::FromStr>(name: &str, v: &str) -> Result<T> {
    v.parse().map_err(|_| format!("option '{name}' has invalid value '{v}'; expected an integer"))
}

impl BuildOptions {
    /// Applies the Nix setting `name` (`--option NAME VALUE`, `NIX_CONFIG`).
    /// List settings also accept an `extra-` prefix, which appends. Returns
    /// `Ok(false)` for settings the builder does not use.
    pub fn set(&mut self, name: &str, value: &str) -> Result<bool> {
        let (base, append) = match name.strip_prefix("extra-") {
            Some(n) => (n, true),
            None => (name, false),
        };
        let words = || value.split_whitespace().map(String::from);
        let set_list = |l: &mut Vec<String>| {
            if !append {
                l.clear();
            }
            l.extend(words());
        };
        match base {
            "sandbox-paths" | "build-chroot-dirs" | "build-sandbox-paths" => set_list(&mut self.sandbox_paths),
            "allowed-impure-host-deps" => set_list(&mut self.allowed_impure_host_deps),
            "system-features" => set_list(&mut self.system_features),
            _ if append => return Ok(false),
            "sandbox" | "build-use-sandbox" | "build-use-chroot" => self.sandbox = SandboxMode::parse(value)?,
            "sandbox-fallback" => self.sandbox_fallback = parse_bool(name, value)?,
            "sandbox-build-dir" => {
                if !value.starts_with('/') || value == "/" {
                    return Err(format!("option 'sandbox-build-dir' must be an absolute path below '/', not '{value}'"));
                }
                self.sandbox_build_dir = value.trim_end_matches('/').to_string();
            }
            "sandbox-dev-shm-size" => self.sandbox_dev_shm_size = value.to_string(),
            "darwin-log-sandbox-violations" => self.darwin_log_sandbox_violations = parse_bool(name, value)?,
            "timeout" | "build-timeout" => self.timeout = parse_num(name, value)?,
            "max-silent-time" | "build-max-silent-time" => self.max_silent_time = parse_num(name, value)?,
            "keep-failed" => self.keep_failed = parse_bool(name, value)?,
            "max-jobs" | "build-max-jobs" => {
                self.jobs = if value == "auto" {
                    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
                } else {
                    parse_num(name, value)?
                }
            }
            "cores" | "build-cores" => {
                let n: usize = parse_num(name, value)?;
                self.cores = if n == 0 { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) } else { n };
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

pub fn host_system() -> String {
    let arch = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        a => a,
    };
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        o => o,
    };
    format!("{arch}-{os}")
}

impl Store {
    pub fn read_derivation(&self, drv: &StorePath) -> Result<Derivation> {
        let real = self.resolve(&self.dir.print(drv));
        let text = fs::read_to_string(&real).map_err(|e| format!("reading derivation '{drv}': {e}"))?;
        let name = drv.name().strip_suffix(".drv").ok_or_else(|| format!("'{drv}' is not a derivation"))?;
        Derivation::parse(&self.dir, name, &text)
    }

    fn missing_outputs(&self, d: &Derivation) -> bool {
        d.outputs.values().any(|o| o.path.as_ref().map_or(true, |p| !self.is_valid(p)))
    }

    /// The invalid output paths of `d`; `None` if an output's path is only
    /// known after building it.
    fn missing_output_paths(&self, d: &Derivation) -> Option<Vec<StorePath>> {
        let mut v = Vec::new();
        for o in d.outputs.values() {
            let p = o.path.as_ref()?;
            if !self.is_valid(p) {
                v.push(p.clone());
            }
        }
        Some(v)
    }

    /// Builds `drvs` and everything they need. Returns each derivation's
    /// output paths.
    pub fn realise(
        &self,
        drvs: &[StorePath],
        opts: &BuildOptions,
    ) -> Result<BTreeMap<StorePath, BTreeMap<String, StorePath>>> {
        // Discover the subgraph of derivations that have missing outputs.
        // Derivations whose outputs can all be substituted are fetched
        // instead, together with their closures, and their inputs are not
        // needed; those whose substitution fails are built after all.
        let mut loaded: HashMap<StorePath, Derivation> = HashMap::new();
        let mut no_subst: BTreeSet<StorePath> = BTreeSet::new();
        let needed = loop {
            let mut needed: BTreeSet<StorePath> = BTreeSet::new();
            let mut fetch: BTreeMap<StorePath, Vec<StorePath>> = BTreeMap::new();
            let mut seen: BTreeSet<StorePath> = BTreeSet::new();
            let mut frontier: Vec<StorePath> = drvs.to_vec();
            while !frontier.is_empty() {
                let mut missing = Vec::new();
                for p in &frontier {
                    if !loaded.contains_key(p) {
                        loaded.insert(p.clone(), self.read_derivation(p)?);
                    }
                    if !no_subst.contains(p) {
                        missing.extend(self.missing_output_paths(&loaded[p]).into_iter().flatten());
                    }
                }
                self.query_substitutable(&missing);
                let mut next = Vec::new();
                for p in frontier {
                    if !seen.insert(p.clone()) {
                        continue;
                    }
                    let d = &loaded[&p];
                    if !self.missing_outputs(d) {
                        continue;
                    }
                    match self.missing_output_paths(d) {
                        Some(outs) if !no_subst.contains(&p) && self.substitutable(&outs) => {
                            fetch.insert(p, outs);
                        }
                        _ => {
                            next.extend(d.input_drvs.keys().filter(|i| !seen.contains(*i)).cloned());
                            needed.insert(p);
                        }
                    }
                }
                frontier = next;
            }
            if fetch.is_empty() {
                break needed;
            }
            let all: Vec<StorePath> = fetch.values().flatten().cloned().collect();
            let failed = self.substitute_paths(&all)?;
            if failed.is_empty() {
                break needed;
            }
            for (drv, outs) in fetch {
                if outs.iter().any(|o| failed.contains(o)) {
                    no_subst.insert(drv);
                }
            }
        };

        if !needed.is_empty() {
            // Sources the builds need may be in a cache too.
            let srcs: Vec<StorePath> =
                needed.iter().flat_map(|p| loaded[p].input_srcs.iter()).filter(|s| !self.is_valid(s)).cloned().collect();
            if !srcs.is_empty() {
                self.substitute_paths(&srcs)?;
            }
        }

        if !needed.is_empty() {
            if !self.can_build() && opts.hook.is_none() {
                return Err(self.cannot_build());
            }
            self.run_scheduler(&loaded, &needed, opts)?;
        }

        let mut out = BTreeMap::new();
        for p in drvs {
            let d = &loaded[p];
            let m = d.outputs.iter().filter_map(|(n, o)| Some((n.clone(), o.path.clone()?))).collect();
            out.insert(p.clone(), m);
        }
        Ok(out)
    }

    fn cannot_build(&self) -> String {
        format!(
            "cannot build in this store: its objects live in '{}' but paths name '{}'; pass --store DIR to use a store that can build",
            self.real.display(),
            self.dir.as_str()
        )
    }

    /// Builds a derivation that is held in memory and may have no `.drv`
    /// file in this store (the daemon's `BuildDerivation`). Its inputs must
    /// all be listed in `input_srcs` and be valid.
    pub fn build_basic(&self, drv_path: &StorePath, drv: &Derivation, opts: &BuildOptions) -> Result<()> {
        if !self.missing_outputs(drv) {
            return Ok(());
        }
        if !self.can_build() && opts.hook.is_none() {
            return Err(self.cannot_build());
        }
        self.build_one(drv_path, drv, &HashMap::new(), opts, "")
    }

    fn run_scheduler(
        &self,
        drvs: &HashMap<StorePath, Derivation>,
        needed: &BTreeSet<StorePath>,
        opts: &BuildOptions,
    ) -> Result<()> {
        struct Sched {
            waiting: HashMap<StorePath, usize>,
            dependents: HashMap<StorePath, Vec<StorePath>>,
            ready: VecDeque<StorePath>,
            running: usize,
            failures: Vec<String>,
        }
        let mut s = Sched {
            waiting: HashMap::new(),
            dependents: HashMap::new(),
            ready: VecDeque::new(),
            running: 0,
            failures: Vec::new(),
        };
        for p in needed {
            let deps: Vec<_> = drvs[p].input_drvs.keys().filter(|d| needed.contains(*d)).cloned().collect();
            for d in &deps {
                s.dependents.entry(d.clone()).or_default().push(p.clone());
            }
            if deps.is_empty() {
                s.ready.push_back(p.clone());
            } else {
                s.waiting.insert(p.clone(), deps.len());
            }
        }
        let total = needed.len();
        let done = AtomicUsize::new(0);
        let state = Mutex::new(s);
        let cv = Condvar::new();

        std::thread::scope(|scope| {
            for _ in 0..opts.jobs.max(1).min(total) {
                scope.spawn(|| loop {
                    let next = {
                        let mut g = state.lock().unwrap();
                        loop {
                            if !g.failures.is_empty() {
                                break None;
                            }
                            if let Some(p) = g.ready.pop_front() {
                                g.running += 1;
                                break Some(p);
                            }
                            if g.running == 0 {
                                break None;
                            }
                            g = cv.wait(g).unwrap();
                        }
                    };
                    let Some(p) = next else {
                        cv.notify_all();
                        return;
                    };
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    let r = self.build_one(&p, &drvs[&p], drvs, opts, &format!(" ({n}/{total})"));
                    let mut g = state.lock().unwrap();
                    g.running -= 1;
                    match r {
                        Ok(()) => {
                            for dep in g.dependents.remove(&p).unwrap_or_default() {
                                let c = g.waiting.get_mut(&dep).unwrap();
                                *c -= 1;
                                if *c == 0 {
                                    g.waiting.remove(&dep);
                                    g.ready.push_back(dep);
                                }
                            }
                        }
                        Err(e) => g.failures.push(e),
                    }
                    cv.notify_all();
                });
            }
        });
        let s = state.into_inner().unwrap();
        if s.failures.is_empty() {
            Ok(())
        } else {
            Err(s.failures.join("\n"))
        }
    }

    fn build_one(
        &self,
        drv_path: &StorePath,
        drv: &Derivation,
        all: &HashMap<StorePath, Derivation>,
        opts: &BuildOptions,
        progress: &str,
    ) -> Result<()> {
        let outputs: Vec<(&String, &StorePath)> = drv
            .outputs
            .iter()
            .map(|(n, o)| o.path.as_ref().map(|p| (n, p)).ok_or_else(|| format!("output '{n}' of '{drv_path}' has no fixed path")))
            .collect::<Result<_>>()?;
        // Concurrent requests for the same derivation build it once: the
        // later ones wait here and then find the outputs valid.
        let mut keys: Vec<String> = outputs.iter().map(|(_, p)| format!("build:{}", self.real_path(p).display())).collect();
        keys.sort();
        let _locks: Vec<PathLock> = keys.into_iter().map(PathLock::take).collect();
        if !self.missing_outputs(drv) {
            return Ok(());
        }
        let drv_s = self.dir.print(drv_path);
        let log = BuildLog::start(opts, &drv_s, &drv.name, &format!("building '{drv_s}'{progress}"));
        let _activity = Activity(&log);
        for (_, p) in &outputs {
            fsutil::remove_all(&self.real_path(p))?;
        }

        let _slot = match &opts.hook {
            Some(h) if !drv.builder.starts_with("builtin:") => match h.build(self, drv_path, drv, opts, &log)? {
                HookOutcome::Built => return Ok(()),
                HookOutcome::Local(slot) => slot,
            },
            _ => None,
        };
        if !self.can_build() {
            return Err(self.cannot_build());
        }

        // The inputs' closure: what a sandboxed builder can see, and what
        // outputs may refer to besides each other.
        let mut inputs: BTreeSet<StorePath> = drv.input_srcs.clone();
        for (d, outs) in &drv.input_drvs {
            let dd = match all.get(d) {
                Some(dd) => dd.clone(),
                None => self.read_derivation(d)?,
            };
            for o in outs {
                if let Some(p) = dd.outputs.get(o).and_then(|x| x.path.clone()) {
                    inputs.insert(p);
                }
            }
        }
        let inputs = self.closure(inputs)?;

        if let Some(b) = drv.builder.strip_prefix("builtin:") {
            match b {
                "fetchurl" => self.builtin_fetchurl(drv, outputs[0].1)?,
                _ => return Err(format!("unsupported builtin builder '{}'", drv.builder)),
            }
        } else {
            if !platform_compatible(&drv.platform, &opts.system) {
                return Err(format!(
                    "a '{}' is required to build '{}', but this machine is a '{}'",
                    drv.platform,
                    self.dir.print(drv_path),
                    opts.system
                ));
            }
            let outs: Vec<&StorePath> = outputs.iter().map(|(_, p)| *p).collect();
            self.run_builder(drv_path, drv, &inputs, &outs, opts, &log)?;
        }

        let mut candidates = inputs;
        candidates.extend(outputs.iter().map(|(_, p)| (*p).clone()));

        for (name, p) in &outputs {
            let real = self.real_path(p);
            if real.symlink_metadata().is_err() {
                return Err(format!("builder for '{}' failed to produce output '{name}' at '{}'", self.dir.print(drv_path), self.dir.print(p)));
            }
            canonicalise(&real)?;
            let (nar_hash, nar_size) = Store::nar_hash(&real)?;
            let mut ca = None;
            if let Some((method, want)) = drv.outputs[*name].fixed() {
                let got = match method {
                    FileIngestion::Flat => {
                        Hash::digest(want.algo, &fs::read(&real).map_err(|e| format!("reading output: {e}"))?)
                    }
                    FileIngestion::Recursive if want.algo == HashAlgo::Sha256 => nar_hash.clone(),
                    FileIngestion::Recursive => {
                        let mut sink = HashSink::new(want.algo);
                        nar::dump(&real, &mut sink).map_err(|e| e.to_string())?;
                        sink.finish().0
                    }
                };
                if got != want {
                    fsutil::remove_all(&real)?;
                    return Err(format!(
                        "hash mismatch in fixed-output derivation '{}':\n  specified: {}\n     got:    {}",
                        self.dir.print(drv_path),
                        want.to_sri(),
                        got.to_sri()
                    ));
                }
                let r = if method == FileIngestion::Recursive { "r:" } else { "" };
                ca = Some(format!("fixed:{r}{}:{}", want.algo, want.to_nix32()));
            }
            let references = if ca.is_some() {
                BTreeSet::new()
            } else {
                refs::scan_path(&real, &candidates).map_err(|e| format!("scanning references: {e}"))?
            };
            self.register(&PathInfo { path: (*p).clone(), nar_hash, nar_size, references, deriver: Some(drv_path.clone()), ca })?;
        }
        Ok(())
    }

    fn run_builder(
        &self,
        drv_path: &StorePath,
        drv: &Derivation,
        inputs: &BTreeSet<StorePath>,
        outputs: &[&StorePath],
        opts: &BuildOptions,
        build_log: &BuildLog,
    ) -> Result<()> {
        let spec = sandbox::plan(self, drv_path, drv, inputs, opts)?;

        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let top = std::env::temp_dir().join(format!(
            "oxnix-build-{}-{}-{}",
            drv.name,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fsutil::remove_all(&top)?;
        fs::create_dir_all(&top).map_err(|e| format!("creating build directory: {e}"))?;
        // The macOS sandbox matches paths after resolving symlinks.
        let top = top.canonicalize().map_err(|e| format!("resolving build directory: {e}"))?;
        let top_s = top.to_string_lossy().into_owned();

        let sb = match Sandbox::prepare(self, drv_path, spec, outputs, &top, opts) {
            Ok(sb) => sb,
            Err(e) => {
                let _ = fsutil::remove_all(&top);
                return Err(e);
            }
        };
        let r = self.run_in(drv_path, drv, &sb, &top, &top_s, outputs, opts, build_log);
        let failed = r.is_err();
        let cleaned = sb.cleanup();
        if !failed || !opts.keep_failed {
            fsutil::remove_all(&top)?;
        }
        r.and(cleaned)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_in(
        &self,
        drv_path: &StorePath,
        drv: &Derivation,
        sb: &Sandbox,
        top: &Path,
        top_s: &str,
        outputs: &[&StorePath],
        opts: &BuildOptions,
        build_log: &BuildLog,
    ) -> Result<()> {
        // The build directory as the builder sees it.
        let tmp = sb.build_dir(top_s);

        let mut env: BTreeMap<String, String> = BTreeMap::new();
        env.insert("PATH".into(), "/path-not-set".into());
        env.insert("HOME".into(), "/homeless-shelter".into());
        env.insert("NIX_STORE".into(), self.dir.as_str().into());
        env.insert("NIX_BUILD_CORES".into(), opts.cores.to_string());

        let pass_as_file: BTreeSet<&str> =
            drv.env.get("passAsFile").map(|s| s.split_whitespace().collect()).unwrap_or_default();
        for (k, v) in &drv.env {
            if pass_as_file.contains(k.as_str()) {
                let f = format!(".attr-{}", Hash::sha256(k.as_bytes()).to_nix32());
                fs::write(top.join(&f), v).map_err(|e| format!("writing {f}: {e}"))?;
                env.insert(format!("{k}Path"), format!("{tmp}/{f}"));
            } else {
                env.insert(k.clone(), v.clone());
            }
        }
        if let Some(json) = drv.env.get("__json") {
            env.remove("__json");
            fs::write(top.join(".attrs.json"), json).map_err(|e| format!("writing .attrs.json: {e}"))?;
            env.insert("NIX_ATTRS_JSON_FILE".into(), format!("{tmp}/.attrs.json"));
        }
        if drv.is_fixed_output() {
            for v in drv.env.get("impureEnvVars").map(|s| s.split_whitespace()).into_iter().flatten() {
                if let Ok(val) = std::env::var(v) {
                    env.insert(v.to_string(), val);
                }
            }
        }
        for k in ["NIX_BUILD_TOP", "TMPDIR", "TEMPDIR", "TMP", "TEMP", "PWD"] {
            env.insert(k.into(), tmp.clone());
        }
        env.insert("NIX_LOG_FD".into(), "2".into());
        env.insert("TERM".into(), "xterm-256color".into());

        let log_path = self.log_path(drv_path);
        let log = Mutex::new(fs::File::create(&log_path).map_err(|e| format!("creating log: {e}"))?);
        let failure = |what: String| {
            let tail = tail_lines(&log_path, 25);
            let kept = if opts.keep_failed { format!("\nbuild directory kept at '{top_s}'") } else { String::new() };
            format!("{what}; last log lines:\n{tail}{kept}")
        };
        // One pipe carries stdout and stderr, so their lines interleave in
        // order, and messages from setting up the sandbox reach the log
        // even when the builder never starts.
        let (out_r, out_w) = log_pipe().map_err(|e| format!("creating log pipe: {e}"))?;
        let out_w2 = out_w.try_clone().map_err(|e| format!("creating log pipe: {e}"))?;
        let spawned = sb
            .command(&drv.builder, &drv.args, top, &drv.platform)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::null())
            .stdout(out_w)
            .stderr(out_w2)
            // Its own process group, so the whole build can be killed.
            .process_group(0)
            .spawn();
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => {
                let mut msg = Vec::new();
                let _ = (&out_r).read_to_end(&mut msg);
                let _ = log.lock().unwrap().write_all(&msg);
                let what = format!("executing builder '{}' of '{}': {e}", drv.builder, self.dir.print(drv_path));
                return Err(failure(what));
            }
        };
        let pgid = child.id() as libc::pid_t;

        let start = Instant::now();
        // Milliseconds since `start` at the last line of output.
        let last_output = AtomicU64::new(0);
        let finished = Mutex::new(false);
        let finished_cv = Condvar::new();
        let timed_out: Mutex<Option<String>> = Mutex::new(None);

        let pump = |r: fs::File| {
            let log = &log;
            let last_output = &last_output;
            move || {
                for line in BufReader::new(r).split(b'\n') {
                    let Ok(line) = line else { break };
                    last_output.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
                    let mut l = log.lock().unwrap();
                    let _ = l.write_all(&line);
                    let _ = l.write_all(b"\n");
                    drop(l);
                    build_log.line(&String::from_utf8_lossy(&line));
                }
            }
        };
        let watchdog = || {
            let mut done = finished.lock().unwrap();
            loop {
                if *done {
                    return;
                }
                let now = start.elapsed();
                let mut deadline: Option<Duration> = None;
                let mut fire = None;
                if opts.timeout > 0 {
                    let d = Duration::from_secs(opts.timeout);
                    if now >= d {
                        fire = Some(format!("timed out after {} seconds", opts.timeout));
                    }
                    deadline = Some(d);
                }
                if opts.max_silent_time > 0 {
                    let d = Duration::from_millis(last_output.load(Ordering::Relaxed)) + Duration::from_secs(opts.max_silent_time);
                    if now >= d {
                        fire = Some(format!("timed out after {} seconds of silence", opts.max_silent_time));
                    }
                    deadline = Some(deadline.map_or(d, |x| x.min(d)));
                }
                if let Some(why) = fire {
                    *timed_out.lock().unwrap() = Some(why);
                    kill_group(pgid);
                    return;
                }
                done = match deadline {
                    Some(d) => finished_cv.wait_timeout(done, d - now).unwrap().0,
                    None => finished_cv.wait(done).unwrap(),
                };
            }
        };
        let status = std::thread::scope(|s| {
            s.spawn(pump(out_r));
            s.spawn(watchdog);
            // Processes the builder left behind are killed with it, before
            // the builder is reaped so its process group still exists.
            let r = wait_exited(pgid).and_then(|()| {
                kill_group(pgid);
                child.wait()
            });
            *finished.lock().unwrap() = true;
            finished_cv.notify_all();
            r
        })
        .map_err(|e| format!("waiting for builder: {e}"))?;

        if let Some(why) = timed_out.into_inner().unwrap() {
            return Err(failure(format!("building of '{}' {why}", self.dir.print(drv_path))));
        }
        if !status.success() {
            return Err(failure(format!("builder for '{}' failed with {status}", self.dir.print(drv_path))));
        }
        sb.collect_outputs(self, outputs)
    }

    fn builtin_fetchurl(&self, drv: &Derivation, out: &StorePath) -> Result<()> {
        let url = drv.env.get("url").ok_or("builtin:fetchurl requires 'url'")?;
        let real = self.real_path(out);
        // With `unpack`, the download is a (possibly compressed) NAR that is
        // restored as the output.
        let unpack = drv.env.get("unpack").is_some_and(|v| v == "1");
        let dest = if unpack { real.with_extension("download") } else { real.clone() };
        eprintln!("downloading '{url}'");
        let st = Command::new("curl")
            .args(["--fail", "--location", "--silent", "--show-error", "--output"])
            .arg(&dest)
            .arg(url)
            .status()
            .map_err(|e| format!("running curl: {e}"))?;
        if !st.success() {
            return Err(format!("downloading '{url}' failed ({st})"));
        }
        if unpack {
            let r = unpack_nar(url, &dest, &real);
            let _ = fs::remove_file(&dest);
            return r;
        }
        if drv.env.get("executable").is_some_and(|v| v == "1") {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// Restores the NAR in `file` to `dest`, decompressing by the URL's
/// extension like Nix's builtin fetcher.
fn unpack_nar(url: &str, file: &Path, dest: &Path) -> Result<()> {
    let tool = [(".xz", "xz"), (".bz2", "bzip2"), (".zst", "zstd"), (".gz", "gzip"), (".br", "brotli")]
        .iter()
        .find(|(ext, _)| url.ends_with(ext))
        .map(|(_, t)| *t);
    let err = |e: std::io::Error| format!("unpacking '{url}': {e}");
    match tool {
        None => nar::restore(fs::File::open(file).map_err(err)?, dest).map_err(err),
        Some(t) => {
            let mut child = Command::new(t)
                .args(["-d", "-c"])
                .arg(file)
                .stdout(Stdio::piped())
                .spawn()
                .map_err(|e| format!("running {t}: {e}"))?;
            let r = nar::restore(child.stdout.take().unwrap(), dest).map_err(err);
            let st = child.wait().map_err(|e| format!("waiting for {t}: {e}"))?;
            if !st.success() {
                return Err(format!("decompressing '{url}' with {t} failed ({st})"));
            }
            r
        }
    }
}

/// A pipe whose ends are closed on exec.
fn log_pipe() -> std::io::Result<(fs::File, fs::File)> {
    use std::os::fd::FromRawFd;
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for both descriptors, which are owned by the
    // returned files.
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let files = (fs::File::from_raw_fd(fds[0]), fs::File::from_raw_fd(fds[1]));
        for fd in fds {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        Ok(files)
    }
}

/// Waits until `pid` has exited, leaving it unreaped.
fn wait_exited(pid: libc::pid_t) -> std::io::Result<()> {
    loop {
        // SAFETY: `info` is a valid out-pointer for waitid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

fn kill_group(pgid: libc::pid_t) {
    // SAFETY: kill has no memory-safety preconditions.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
}

pub fn platform_compatible(want: &str, have: &str) -> bool {
    want == have || (have == "aarch64-darwin" && want == "x86_64-darwin") || (have == "x86_64-linux" && want == "i686-linux")
}

fn tail_lines(p: &Path, n: usize) -> String {
    let text = fs::read_to_string(p).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].iter().map(|l| format!("  > {l}")).collect::<Vec<_>>().join("\n")
}

/// Location for a default per-user store root.
pub fn default_root() -> PathBuf {
    if let Ok(d) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(d).join("oxnix");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".local/share/oxnix")
}
