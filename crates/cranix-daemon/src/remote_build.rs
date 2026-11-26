//! Remote builders: a build hook that picks a machine from the `builders`
//! setting, copies the input closure there, builds with `BuildDerivation`
//! and copies the outputs back.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};

use cranix_core::{Derivation, StorePath};
use cranix_store::build::{platform_compatible, BuildHook, BuildLog, BuildOptions, HookOutcome};
use cranix_store::Store;

use crate::client::{ClientOptions, LogOptions};
use crate::machines::Machine;

#[derive(Debug, Default)]
struct State {
    running: Vec<usize>,
    /// Machines that could not be reached or set up; skipped from then on.
    failed: Vec<bool>,
    local_running: usize,
}

#[derive(Debug)]
struct Inner {
    machines: Vec<Machine>,
    local_jobs: usize,
    state: Mutex<State>,
    cv: Condvar,
}

#[derive(Debug, Clone)]
pub struct RemoteBuilders {
    inner: Arc<Inner>,
}

/// Held while a build runs locally; frees the local slot when dropped.
struct LocalSlot(Arc<Inner>);

impl Drop for LocalSlot {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().local_running -= 1;
        self.0.cv.notify_all();
    }
}

/// Held while a build runs on machine `.1`.
struct MachineSlot(Arc<Inner>, usize);

impl Drop for MachineSlot {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().running[self.1] -= 1;
        self.0.cv.notify_all();
    }
}

/// Failures on the way to a remote build count against the machine and
/// allow falling back; a failed build is final.
enum Failure {
    Machine(String),
    Build(String),
}

/// `requiredSystemFeatures` of a derivation, from its environment or its
/// structured attributes.
pub fn required_features(drv: &Derivation) -> BTreeSet<String> {
    if let Some(json) = drv.env.get("__json") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
            if let Some(a) = v.get("requiredSystemFeatures").and_then(|x| x.as_array()) {
                return a.iter().filter_map(|x| x.as_str().map(String::from)).collect();
            }
        }
    }
    drv.env.get("requiredSystemFeatures").map(|s| s.split_whitespace().map(String::from).collect()).unwrap_or_default()
}

impl RemoteBuilders {
    /// `local_jobs` is the number of builds allowed to run locally at once
    /// (`max-jobs`); 0 sends everything to the machines.
    pub fn new(machines: Vec<Machine>, local_jobs: usize) -> RemoteBuilders {
        let n = machines.len();
        RemoteBuilders {
            inner: Arc::new(Inner {
                machines,
                local_jobs,
                state: Mutex::new(State { running: vec![0; n], failed: vec![false; n], local_running: 0 }),
                cv: Condvar::new(),
            }),
        }
    }

    /// Concurrent builds the machines and the local host can take.
    pub fn total_slots(&self) -> usize {
        self.inner.local_jobs + self.inner.machines.iter().map(|m| m.max_jobs).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.machines.is_empty()
    }

    fn local_slot(&self, st: &mut State) -> Box<dyn std::any::Any + Send> {
        st.local_running += 1;
        Box::new(LocalSlot(Arc::clone(&self.inner)))
    }
}

impl BuildHook for RemoteBuilders {
    fn build(&self, store: &Store, drv_path: &StorePath, drv: &Derivation, opts: &BuildOptions, log: &BuildLog) -> Result<HookOutcome, String> {
        let inner = &self.inner;
        let features = required_features(drv);
        let local_ok = inner.local_jobs > 0 && store.can_build() && platform_compatible(&drv.platform, &opts.system);
        let prefer_local = local_ok && drv.env.get("preferLocalBuild").is_some_and(|v| v == "1");
        let mut errors = Vec::new();
        loop {
            let mut st = inner.state.lock().unwrap();
            let candidates: Vec<usize> =
                (0..inner.machines.len()).filter(|&i| !st.failed[i] && inner.machines[i].can_build(&drv.platform, &features)).collect();
            if candidates.is_empty() || prefer_local {
                if local_ok {
                    // Waits for a local slot like any other local build.
                    while st.local_running >= inner.local_jobs {
                        st = inner.cv.wait(st).unwrap();
                    }
                    return Ok(HookOutcome::Local(Some(self.local_slot(&mut st))));
                }
                if !errors.is_empty() {
                    return Err(format!("cannot build '{}' on any remote machine:\n{}", store.dir.print(drv_path), errors.join("\n")));
                }
                if inner.local_jobs == 0 {
                    let feats = features.iter().cloned().collect::<Vec<_>>().join(", ");
                    return Err(format!(
                        "unable to build '{}' with max-jobs = 0: no configured machine is a '{}' with features {{{feats}}}",
                        store.dir.print(drv_path),
                        drv.platform
                    ));
                }
                // The local builder reports why it cannot build this.
                return Ok(HookOutcome::Local(None));
            }
            let free = candidates
                .iter()
                .copied()
                .filter(|&i| st.running[i] < inner.machines[i].max_jobs)
                .min_by(|&a, &b| {
                    let la = st.running[a] as f64 / inner.machines[a].speed_factor;
                    let lb = st.running[b] as f64 / inner.machines[b].speed_factor;
                    la.total_cmp(&lb)
                });
            let Some(i) = free else {
                if local_ok && st.local_running < inner.local_jobs {
                    return Ok(HookOutcome::Local(Some(self.local_slot(&mut st))));
                }
                drop(inner.cv.wait(st).unwrap());
                continue;
            };
            st.running[i] += 1;
            drop(st);
            let _slot = MachineSlot(Arc::clone(inner), i);
            let m = &inner.machines[i];
            match build_on(m, store, drv_path, drv, opts, log) {
                Ok(()) => return Ok(HookOutcome::Built),
                Err(Failure::Build(e)) => return Err(e),
                Err(Failure::Machine(e)) => {
                    log.info(&format!("warning: remote builder '{}' failed, trying elsewhere: {e}", m.uri));
                    errors.push(format!("  {}: {e}", m.uri));
                    inner.state.lock().unwrap().failed[i] = true;
                }
            }
        }
    }
}

fn build_on(m: &Machine, store: &Store, drv_path: &StorePath, drv: &Derivation, opts: &BuildOptions, log: &BuildLog) -> Result<(), Failure> {
    let sd = &store.dir;
    let fail = Failure::Machine;
    let uri = m.store_uri().map_err(fail)?;
    log.info(&format!("building '{}' on '{}'", sd.print(drv_path), m.uri));
    let mut conn = crate::remote_store::open(&uri).map_err(fail)?;
    conn.set_store_dir(sd.clone());
    // The remote build's output becomes this build's output.
    let sink_log = log.clone();
    conn.set_log(LogOptions { build_logs: true, prefix: String::new(), sink: Some(std::sync::Arc::new(move |l: &str| sink_log.line(l))) });
    let copts = ClientOptions { keep_failed: opts.keep_failed, verbose_build: opts.print_logs, max_jobs: 1, cores: opts.cores as u64, ..Default::default() };
    conn.set_options(&copts).map_err(fail)?;

    // Inputs are the sources and the needed outputs of input derivations,
    // with everything they reference.
    let mut inputs = drv.input_srcs.clone();
    for (d, outs) in &drv.input_drvs {
        let dd = store.read_derivation(d).map_err(fail)?;
        inputs.extend(outs.iter().filter_map(|o| dd.outputs.get(o)?.path.clone()));
    }
    let closure = store.closure(inputs).map_err(fail)?;
    let present = conn.query_valid_paths(&closure).map_err(fail)?;
    let missing: BTreeSet<StorePath> = closure.difference(&present).cloned().collect();
    if !missing.is_empty() {
        let order = store.topo_sort(&missing).map_err(fail)?;
        let mut infos = Vec::new();
        for p in &order {
            infos.push(store.query_info(p).map_err(fail)?.ok_or_else(|| Failure::Machine(format!("input '{}' is not valid", sd.print(p))))?);
        }
        log.info(&format!("copying {} paths to '{}'", infos.len(), m.uri));
        let nar_of = |info: &cranix_store::PathInfo, w: &mut dyn Write| cranix_core::nar::dump(&store.real_path(&info.path), w);
        conn.add_paths(&infos, &nar_of).map_err(|e| Failure::Machine(format!("copying inputs: {e}")))?;
    }

    let mut basic = drv.clone();
    basic.input_drvs.clear();
    basic.input_srcs = closure;
    let res = conn.build_derivation(drv_path, &basic).map_err(fail)?;
    if !res.status.success() {
        return Err(Failure::Build(format!("build of '{}' on '{}' failed: {}", sd.print(drv_path), m.uri, res.error_msg)));
    }

    for (name, o) in &drv.outputs {
        let Some(p) = &o.path else { continue };
        if store.is_valid(p) {
            continue;
        }
        let info = conn
            .query_path_info(p)
            .map_err(Failure::Build)?
            .ok_or_else(|| Failure::Build(format!("remote builder '{}' did not produce output '{name}' of '{}'", m.uri, sd.print(drv_path))))?;
        let tmp = store.state_dir().join(format!("remote-{}-{}.nar", std::process::id(), p.hash_part()));
        let r = (|| {
            let mut f = fs::File::create(&tmp).map_err(|e| format!("creating '{}': {e}", tmp.display()))?;
            conn.nar_from_path(p, &mut f)?;
            f.flush().map_err(|e| e.to_string())?;
            drop(f);
            store.import_nar(&info, fs::File::open(&tmp).map_err(|e| e.to_string())?)
        })();
        let _ = fs::remove_file(&tmp);
        r.map_err(|e| Failure::Build(format!("copying '{}' back from '{}': {e}", sd.print(p), m.uri)))?;
    }
    Ok(())
}
