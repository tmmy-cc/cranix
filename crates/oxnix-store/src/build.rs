//! Realisation: builds the derivations whose outputs are missing, in
//! dependency order, running independent builds in parallel.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

use oxnix_core::hash::{Hash, HashAlgo, HashSink};
use oxnix_core::{nar, Derivation, FileIngestion, StorePath};

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
}

impl Default for BuildOptions {
    fn default() -> Self {
        let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        BuildOptions { jobs: n, cores: n, print_logs: false, keep_failed: false, system: host_system() }
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

    /// Builds `drvs` and everything they need. Returns each derivation's
    /// output paths.
    pub fn realise(
        &self,
        drvs: &[StorePath],
        opts: &BuildOptions,
    ) -> Result<BTreeMap<StorePath, BTreeMap<String, StorePath>>> {
        // Discover the subgraph of derivations that have missing outputs.
        let mut loaded: HashMap<StorePath, Derivation> = HashMap::new();
        let mut needed: BTreeSet<StorePath> = BTreeSet::new();
        let mut todo: Vec<StorePath> = drvs.to_vec();
        while let Some(p) = todo.pop() {
            if loaded.contains_key(&p) {
                continue;
            }
            let d = self.read_derivation(&p)?;
            if self.missing_outputs(&d) {
                needed.insert(p.clone());
                todo.extend(d.input_drvs.keys().cloned());
            }
            loaded.insert(p, d);
        }

        if !needed.is_empty() {
            if !self.can_build() {
                return Err(format!(
                    "cannot build in this store: its objects live in '{}' but paths name '{}'; pass --store DIR to use a store that can build",
                    self.real.display(),
                    self.dir.as_str()
                ));
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
                    eprintln!("building '{}' ({n}/{total})", self.dir.print(&p));
                    let r = self.build_one(&p, &drvs[&p], drvs, opts);
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
    ) -> Result<()> {
        let outputs: Vec<(&String, &StorePath)> = drv
            .outputs
            .iter()
            .map(|(n, o)| o.path.as_ref().map(|p| (n, p)).ok_or_else(|| format!("output '{n}' of '{drv_path}' has no fixed path")))
            .collect::<Result<_>>()?;
        for (_, p) in &outputs {
            fsutil::remove_all(&self.real_path(p))?;
        }

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
            self.run_builder(drv_path, drv, opts)?;
        }

        // References may only point into the inputs' closure or at outputs
        // of this derivation.
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
        let mut candidates = self.closure(inputs)?;
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

    fn run_builder(&self, drv_path: &StorePath, drv: &Derivation, opts: &BuildOptions) -> Result<()> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let top = std::env::temp_dir().join(format!(
            "oxnix-build-{}-{}-{}",
            drv.name,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fsutil::remove_all(&top)?;
        fs::create_dir_all(&top).map_err(|e| format!("creating build directory: {e}"))?;
        let top_s = top.to_string_lossy().into_owned();

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
                env.insert(format!("{k}Path"), format!("{top_s}/{f}"));
            } else {
                env.insert(k.clone(), v.clone());
            }
        }
        if let Some(json) = drv.env.get("__json") {
            env.remove("__json");
            let f = top.join(".attrs.json");
            fs::write(&f, json).map_err(|e| format!("writing .attrs.json: {e}"))?;
            env.insert("NIX_ATTRS_JSON_FILE".into(), f.to_string_lossy().into_owned());
        }
        if drv.is_fixed_output() {
            for v in drv.env.get("impureEnvVars").map(|s| s.split_whitespace()).into_iter().flatten() {
                if let Ok(val) = std::env::var(v) {
                    env.insert(v.to_string(), val);
                }
            }
        }
        for k in ["NIX_BUILD_TOP", "TMPDIR", "TEMPDIR", "TMP", "TEMP", "PWD"] {
            env.insert(k.into(), top_s.clone());
        }
        env.insert("NIX_LOG_FD".into(), "2".into());
        env.insert("TERM".into(), "xterm-256color".into());

        let log_path = self.log_path(drv_path);
        let log = Mutex::new(fs::File::create(&log_path).map_err(|e| format!("creating log: {e}"))?);
        let mut child = Command::new(&drv.builder)
            .args(&drv.args)
            .env_clear()
            .envs(&env)
            .current_dir(&top)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("executing builder '{}' of '{}': {e}", drv.builder, self.dir.print(drv_path)))?;

        let pump = |r: Box<dyn Read + Send>| {
            let log = &log;
            let name = &drv.name;
            move || {
                for line in BufReader::new(r).split(b'\n') {
                    let Ok(line) = line else { break };
                    let mut l = log.lock().unwrap();
                    let _ = l.write_all(&line);
                    let _ = l.write_all(b"\n");
                    drop(l);
                    if opts.print_logs {
                        eprintln!("{name}> {}", String::from_utf8_lossy(&line));
                    }
                }
            }
        };
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let status = std::thread::scope(|s| {
            s.spawn(pump(Box::new(stdout)));
            s.spawn(pump(Box::new(stderr)));
            child.wait()
        })
        .map_err(|e| format!("waiting for builder: {e}"))?;

        let failed = !status.success();
        if !failed || !opts.keep_failed {
            fsutil::remove_all(&top)?;
        }
        if failed {
            let tail = tail_lines(&log_path, 25);
            let kept = if opts.keep_failed { format!("\nbuild directory kept at '{top_s}'") } else { String::new() };
            return Err(format!("builder for '{}' failed with {status}; last log lines:\n{tail}{kept}", self.dir.print(drv_path)));
        }
        Ok(())
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

fn platform_compatible(want: &str, have: &str) -> bool {
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
