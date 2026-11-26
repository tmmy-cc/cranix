//! Daemon-related commands: `oxnix daemon`, building through a daemon store
//! (`--store daemon|unix://…|ssh-ng://…`) and the `builders` setting.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use oxnix_core::hash::Hash;
use oxnix_core::{StoreDir, StorePath};
use oxnix_daemon::client::{ClientOptions, LogOptions, StoreUri};
use oxnix_daemon::remote_store::RemoteStore;
use oxnix_daemon::proto::DerivedPath;
use oxnix_daemon::remote_build::RemoteBuilders;
use oxnix_daemon::server::{Daemon, DaemonConfig};
use oxnix_store::build::{default_root, BuildOptions};
use oxnix_store::Store;

fn conf_dir() -> PathBuf {
    PathBuf::from(std::env::var("NIX_CONF_DIR").unwrap_or_else(|_| "/etc/nix".into()))
}

/// The `builders` value from `nix.conf`, defaulting like Nix to the
/// machines file next to it.
pub fn default_builders() -> String {
    let conf = std::fs::read_to_string(conf_dir().join("nix.conf")).unwrap_or_default();
    for line in conf.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "builders" {
                return v.trim().to_string();
            }
        }
    }
    format!("@{}", conf_dir().join("machines").display())
}

/// Installs remote builders from `spec` into `opts`, raising the number of
/// concurrent builds by the machines' job slots.
pub fn configure_builders(opts: &mut BuildOptions, spec: &str) -> Result<(), String> {
    let machines = oxnix_daemon::machines::parse(spec, &opts.system)?;
    if machines.is_empty() {
        return Ok(());
    }
    let hook = RemoteBuilders::new(machines, opts.jobs);
    opts.jobs = hook.total_slots().max(1);
    opts.hook = Some(Arc::new(hook));
    Ok(())
}

/// The local store that evaluation writes `.drv` files and sources into
/// before they are copied to the daemon; it uses the daemon's store
/// directory.
pub fn eval_store(uri: &StoreUri) -> Result<Store, String> {
    let sd = uri.store_dir();
    if sd == StoreDir::default() {
        return Store::open_chroot(&default_root());
    }
    let key = Hash::sha256(sd.as_str().as_bytes()).to_nix32();
    let root = default_root().join("eval-stores").join(&key[..16]);
    Store::open(sd, root.join("store"), root.join("var"))
}

/// A connection to the store named by `--store`.
pub struct Session {
    conn: Box<dyn RemoteStore>,
}

impl Session {
    pub fn open(uri: &StoreUri) -> Result<Session, String> {
        Ok(Session { conn: oxnix_daemon::remote_store::open(uri)? })
    }

    /// Copies the closures of `drvs` from `eval` and builds them on the
    /// daemon. Returns each derivation's output paths.
    pub fn realise(
        &mut self,
        eval: &Store,
        drvs: &[StorePath],
        opts: &BuildOptions,
    ) -> Result<BTreeMap<StorePath, BTreeMap<String, StorePath>>, String> {
        let c = &mut self.conn;
        c.set_log(LogOptions { build_logs: opts.print_logs, ..Default::default() });
        let copts = ClientOptions {
            keep_failed: opts.keep_failed,
            max_jobs: opts.jobs as u64,
            cores: opts.cores as u64,
            verbose_build: opts.print_logs,
            ..Default::default()
        };
        c.set_options(&copts)?;

        let closure: BTreeSet<StorePath> = eval.closure(drvs.iter().cloned())?.into_iter().filter(|p| eval.is_valid(p)).collect();
        let present = c.query_valid_paths(&closure)?;
        let missing: BTreeSet<StorePath> = closure.difference(&present).cloned().collect();
        if !missing.is_empty() {
            let mut infos = Vec::new();
            for p in eval.topo_sort(&missing)? {
                infos.push(eval.query_info(&p)?.ok_or_else(|| format!("path '{}' is not valid", eval.dir.print(&p)))?);
            }
            let nar_of = |info: &oxnix_store::PathInfo, w: &mut dyn Write| oxnix_core::nar::dump(&eval.real_path(&info.path), w);
            c.add_paths(&infos, &nar_of)?;
        }

        let targets: Vec<DerivedPath> = drvs.iter().map(|d| DerivedPath::Built { drv: d.clone(), outputs: None }).collect();
        let mut out = BTreeMap::new();
        let mut errors = Vec::new();
        for (t, res) in c.build_paths(&targets)? {
            let DerivedPath::Built { drv, .. } = t else { continue };
            if !res.status.success() {
                errors.push(res.error_msg);
                continue;
            }
            let mut outs: BTreeMap<String, StorePath> = res.built_outputs.into_iter().map(|(n, r)| (n, r.out_path)).collect();
            // The serve protocol reports no outputs; they follow from the
            // derivation.
            if outs.is_empty() {
                let d = eval.read_derivation(&drv)?;
                outs = d.outputs.into_iter().filter_map(|(n, o)| Some((n, o.path?))).collect();
            }
            out.insert(drv, outs);
        }
        if !errors.is_empty() {
            return Err(errors.join("\n"));
        }
        Ok(out)
    }

    pub fn add_indirect_root(&mut self, link: &std::path::Path) -> Result<(), String> {
        let abs = std::path::absolute(link).map_err(|e| format!("resolving '{}': {e}", link.display()))?;
        self.conn.add_indirect_root(&abs.to_string_lossy())
    }
}

/// `oxnix store serve [--write]`, also reachable as `oxnix --serve [--write]`
/// so that `ssh://` clients can run it in place of `nix-store`.
pub fn cmd_serve(store: Store, args: &[String], mut opts: BuildOptions, builders: &str) -> Result<(), String> {
    let mut write = false;
    for a in args {
        match a.as_str() {
            "--write" => write = true,
            a => return Err(format!("unknown serve option '{a}'")),
        }
    }
    configure_builders(&mut opts, builders)?;
    oxnix_daemon::serve::serve(&store, std::io::stdin().lock(), std::io::stdout().lock(), write, &opts)
}

/// `oxnix daemon [--stdio] [--socket PATH] [--trusted-users U] [--allowed-users U] [--force-trusted|--force-untrusted]`
pub fn cmd_daemon(store: Store, args: &[String], opts: BuildOptions, builders: &str) -> Result<(), String> {
    let mut config = DaemonConfig { build: opts, ..Default::default() };
    let mut stdio = false;
    let mut socket = store.state_dir().join("daemon-socket/socket");
    let list = |s: &str| s.split([' ', ',']).filter(|x| !x.is_empty()).map(String::from).collect::<Vec<_>>();
    let mut force: Option<bool> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| format!("{a} requires an argument"));
        match a.as_str() {
            "--stdio" => stdio = true,
            "--socket" => socket = PathBuf::from(val()?),
            "--trusted-users" => config.trusted_users = list(&val()?),
            "--allowed-users" => config.allowed_users = list(&val()?),
            "--force-trusted" => force = Some(true),
            "--force-untrusted" => force = Some(false),
            "-j" | "--max-jobs" => config.build.jobs = val()?.parse().map_err(|_| "invalid --max-jobs value")?,
            "--cores" => config.build.cores = val()?.parse().map_err(|_| "invalid --cores value")?,
            a => return Err(format!("unknown daemon option '{a}'")),
        }
    }
    match force {
        Some(true) => config.trusted_users = vec!["*".into()],
        Some(false) => {
            config.trusted_users.clear();
            config.trust_own_user = false;
        }
        None => {}
    }
    configure_builders(&mut config.build, builders)?;
    let daemon = Arc::new(Daemon::new(store, config));
    if stdio {
        daemon.serve_stdio(force != Some(false))
    } else {
        daemon.serve_socket(&socket)
    }
}
