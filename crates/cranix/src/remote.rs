//! Daemon-related commands: `cranix daemon`, building through a daemon store
//! (`--store daemon|unix://…|ssh-ng://…`) and the `builders` setting.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use cranix_core::hash::Hash;
use cranix_core::{StoreDir, StorePath};
use cranix_daemon::client::{ClientOptions, LogOptions, StoreUri};
use cranix_daemon::remote_store::RemoteStore;
use cranix_daemon::proto::DerivedPath;
use cranix_daemon::remote_build::RemoteBuilders;
use cranix_daemon::server::{Daemon, DaemonConfig};
use cranix_store::build::{default_root, BuildOptions};
use cranix_store::settings::Settings;
use cranix_store::Store;

/// Installs remote builders from `spec` into `opts`, raising the number of
/// concurrent builds by the machines' job slots.
pub fn configure_builders(opts: &mut BuildOptions, spec: &str) -> Result<(), String> {
    let machines = cranix_daemon::machines::parse(spec, &opts.system)?;
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
        Ok(Session { conn: cranix_daemon::remote_store::open(uri)? })
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
            let nar_of = |info: &cranix_store::PathInfo, w: &mut dyn Write| cranix_core::nar::dump(&eval.real_path(&info.path), w);
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

/// `cranix store serve [--write]`, also reachable as `cranix --serve [--write]`
/// so that `ssh://` clients can run it in place of `nix-store`.
pub fn cmd_serve(store: Store, args: &[String], settings: &Settings) -> Result<(), String> {
    let mut write = false;
    for a in args {
        match a.as_str() {
            "--write" => write = true,
            a => return Err(format!("unknown serve option '{a}'")),
        }
    }
    let mut opts = settings.build_options();
    configure_builders(&mut opts, &settings.builders)?;
    cranix_daemon::serve::serve(&store, std::io::stdin().lock(), std::io::stdout().lock(), write, &opts)
}

/// `cranix daemon [--stdio] [--socket PATH] [--force-trusted|--force-untrusted]`;
/// `trusted-users`, `allowed-users` and the build settings come from
/// `settings`.
pub fn cmd_daemon(store: Store, args: &[String], settings: &Settings) -> Result<(), String> {
    let mut config = DaemonConfig {
        trusted_users: settings.trusted_users.clone(),
        allowed_users: settings.allowed_users.clone(),
        build: settings.build_options(),
        ..Default::default()
    };
    let mut stdio = false;
    let mut socket = store.state_dir().join("daemon-socket/socket");
    let mut force: Option<bool> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| format!("{a} requires an argument"));
        match a.as_str() {
            "--stdio" => stdio = true,
            "--socket" => socket = PathBuf::from(val()?),
            "--force-trusted" => force = Some(true),
            "--force-untrusted" => force = Some(false),
            "-j" => config.build.jobs = val()?.parse().map_err(|_| "invalid -j value")?,
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
    configure_builders(&mut config.build, &settings.builders)?;
    let daemon = Arc::new(Daemon::new(store, config));
    if stdio {
        daemon.serve_stdio(force != Some(false))
    } else {
        daemon.serve_socket(&socket)
    }
}
