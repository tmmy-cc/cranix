//! `cranix daemon`: serves a local store to Nix clients over a Unix socket
//! or over stdin/stdout (for `ssh-ng://` access), one thread per client.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use cranix_core::hash::{Hash, HashAlgo, HashSink};
use cranix_core::{nar, Derivation, DrvHash, FileIngestion, NarInfo, StoreDir, StorePath};
use cranix_store::build::BuildOptions;
use cranix_store::gc_roots::GcAction;
use cranix_store::realisation::DrvOutput;
use cranix_store::{PathInfo, Store};

use crate::proto::{self, minor, BuildResult, BuildStatus, DerivedPath, Op, Realisation};
use crate::wire::{bad, FramedReader, ReadExt, WriteExt};

pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    /// Users (or `@group`s, or `*`) whose requests are trusted: they may add
    /// unsigned input-addressed paths and build arbitrary derivations. The
    /// daemon's own user is always trusted.
    pub trusted_users: Vec<String>,
    /// Users allowed to connect at all.
    pub allowed_users: Vec<String>,
    /// Trusts clients running as the daemon's own user.
    pub trust_own_user: bool,
    pub build: BuildOptions,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig { trusted_users: vec!["root".into()], allowed_users: vec!["*".into()], trust_own_user: true, build: BuildOptions::default() }
    }
}

pub struct Daemon {
    pub store: Store,
    pub config: DaemonConfig,
    /// Temporary GC roots of each open connection.
    temp_roots: Mutex<HashMap<u64, BTreeSet<StorePath>>>,
    /// Held shared by operations that add paths and exclusively by the
    /// collector, so new paths are rooted before a collection can see them.
    gc: RwLock<()>,
    next_id: AtomicU64,
}

fn peer_uid(s: &UnixStream) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: cred and len are valid for the duration of the call.
        let r = unsafe {
            libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len)
        };
        (r == 0).then_some(cred.uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: getpeereid writes to the two integers only.
        let r = unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
        (r == 0).then_some(uid)
    }
}

/// Name and primary group of a user id.
fn user_info(uid: u32) -> Option<(String, u32)> {
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res = std::ptr::null_mut();
    // SAFETY: all pointers refer to live buffers of the stated sizes.
    let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut res) };
    if r != 0 || res.is_null() {
        return None;
    }
    // SAFETY: pw_name points into buf, NUL-terminated by getpwuid_r.
    let name = unsafe { CStr::from_ptr(pw.pw_name) }.to_string_lossy().into_owned();
    Some((name, pw.pw_gid))
}

fn in_group(user: &str, primary_gid: u32, group: &str) -> bool {
    let Ok(g) = CString::new(group) else { return false };
    let mut buf = vec![0 as libc::c_char; 1 << 16];
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut res = std::ptr::null_mut();
    // SAFETY: all pointers refer to live buffers of the stated sizes.
    let r = unsafe { libc::getgrnam_r(g.as_ptr(), &mut gr, buf.as_mut_ptr(), buf.len(), &mut res) };
    if r != 0 || res.is_null() {
        return false;
    }
    if gr.gr_gid == primary_gid {
        return true;
    }
    let mut p = gr.gr_mem;
    // SAFETY: gr_mem is a NULL-terminated array of C strings inside buf.
    unsafe {
        while !p.is_null() && !(*p).is_null() {
            if CStr::from_ptr(*p).to_bytes() == user.as_bytes() {
                return true;
            }
            p = p.add(1);
        }
    }
    false
}

fn matches_users(list: &[String], uid: u32) -> bool {
    let info = user_info(uid);
    list.iter().any(|e| {
        if e == "*" {
            return true;
        }
        match (&info, e.strip_prefix('@')) {
            (Some((name, gid)), Some(group)) => in_group(name, *gid, group),
            (Some((name, _)), None) => name == e,
            (None, None) => e.parse::<u32>().is_ok_and(|n| n == uid),
            _ => false,
        }
    })
}

type R = BufReader<Box<dyn Read + Send>>;
type W = BufWriter<Box<dyn Write + Send>>;

struct Conn<'d> {
    d: &'d Daemon,
    r: R,
    /// Shared with the threads of running builds, which send log messages.
    w: Arc<Mutex<W>>,
    version: u64,
    trusted: bool,
    id: u64,
    opts: BuildOptions,
    /// The client's `useSubstitutes`: whether its requests may download
    /// from the daemon's substituters.
    substitute: bool,
}

/// Outcome of an operation: an error goes to the client as `STDERR_ERROR`,
/// a reply is written after `STDERR_LAST`.
type Reply = Result<Box<dyn FnOnce(&mut W, &StoreDir, u64) -> io::Result<()>>>;

fn reply(f: impl FnOnce(&mut W, &StoreDir, u64) -> io::Result<()> + 'static) -> Reply {
    Ok(Box::new(f))
}

fn reply_u64(n: u64) -> Reply {
    reply(move |w, _, _| w.write_u64(n))
}

fn reply_paths(ps: BTreeSet<StorePath>) -> Reply {
    reply(move |w, sd, _| proto::write_paths(w, sd, &ps))
}

fn reply_none() -> Reply {
    reply(|_, _, _| Ok(()))
}

impl Daemon {
    pub fn new(store: Store, config: DaemonConfig) -> Daemon {
        Daemon {
            store,
            config,
            temp_roots: Mutex::new(HashMap::new()),
            gc: RwLock::new(()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Accepts clients on `socket` forever.
    pub fn serve_socket(self: &Arc<Self>, socket: &Path) -> Result<()> {
        if let Some(dir) = socket.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("creating '{}': {e}", dir.display()))?;
        }
        let _ = fs::remove_file(socket);
        let l = UnixListener::bind(socket).map_err(|e| format!("binding '{}': {e}", socket.display()))?;
        // Access is decided per connection by `allowed-users`.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o666)).map_err(|e| format!("setting socket permissions: {e}"))?;
        eprintln!("cranix daemon listening on '{}'", socket.display());
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        for s in l.incoming() {
            let s = match s {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("accepting connection: {e}");
                    continue;
                }
            };
            let uid = peer_uid(&s);
            let allowed = uid.is_some_and(|u| u == me || u == 0 || matches_users(&self.config.allowed_users, u));
            if !allowed {
                eprintln!("refusing connection from user {uid:?}: not in allowed-users");
                continue;
            }
            let trusted = uid.is_some_and(|u| (u == me && self.config.trust_own_user) || matches_users(&self.config.trusted_users, u));
            let d = Arc::clone(self);
            std::thread::spawn(move || {
                let r = s.try_clone().map_err(|e| e.to_string()).and_then(|r| d.serve(Box::new(r), Box::new(s), trusted));
                if let Err(e) = r {
                    eprintln!("connection from user {uid:?} failed: {e}");
                }
            });
        }
        Ok(())
    }

    /// Serves one client on stdin/stdout.
    pub fn serve_stdio(&self, trusted: bool) -> Result<()> {
        self.serve(Box::new(io::stdin()), Box::new(io::stdout()), trusted)
    }

    pub fn serve(&self, r: Box<dyn Read + Send>, w: Box<dyn Write + Send>, trusted: bool) -> Result<()> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut c = Conn {
            d: self,
            r: BufReader::with_capacity(1 << 16, r),
            w: Arc::new(Mutex::new(BufWriter::with_capacity(1 << 16, w))),
            version: 0,
            trusted,
            id,
            opts: self.config.build.clone(),
            substitute: true,
        };
        let res = c.run();
        self.temp_roots.lock().unwrap().remove(&id);
        match res {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            r => r.map_err(|e| e.to_string()),
        }
    }

    fn all_temp_roots(&self) -> BTreeSet<StorePath> {
        self.temp_roots.lock().unwrap().values().flatten().cloned().collect()
    }
}

impl Conn<'_> {
    fn sd(&self) -> StoreDir {
        self.d.store.dir.clone()
    }

    fn store(&self) -> &Store {
        &self.d.store
    }

    fn add_temp_root(&self, p: &StorePath) {
        self.d.temp_roots.lock().unwrap().entry(self.id).or_default().insert(p.clone());
    }

    fn run(&mut self) -> io::Result<()> {
        if self.r.read_u64()? != proto::WORKER_MAGIC_1 {
            return Err(bad("protocol mismatch"));
        }
        let w = Arc::clone(&self.w);
        let mut w = w.lock().unwrap();
        w.write_u64(proto::WORKER_MAGIC_2)?;
        w.write_u64(proto::PROTOCOL_VERSION)?;
        w.flush()?;
        let client = self.r.read_u64()?;
        if client >> 8 != 1 || client < proto::MIN_CLIENT_VERSION {
            return Err(bad(format!("unsupported client protocol version {}.{}", client >> 8, minor(client))));
        }
        self.version = client.min(proto::PROTOCOL_VERSION);
        if minor(self.version) >= 14 && self.r.read_u64()? != 0 {
            self.r.read_u64()?; // obsolete CPU affinity
        }
        if minor(self.version) >= 11 {
            self.r.read_u64()?; // obsolete reserveSpace
        }
        if minor(self.version) >= 33 {
            w.write_str(proto::NIX_VERSION)?;
        }
        if minor(self.version) >= 35 {
            w.write_u64(if self.trusted { 1 } else { 2 })?;
        }
        w.write_u64(proto::STDERR_LAST)?;
        w.flush()?;
        drop(w);

        loop {
            let op = match self.r.read_u64() {
                Ok(op) => op,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            let Some(op) = Op::from_u64(op) else {
                return Err(bad(format!("invalid operation {op}")));
            };
            let res = self.op(op)?;
            let sd = self.sd();
            let mut w = self.w.lock().unwrap();
            match res {
                Ok(f) => {
                    w.write_u64(proto::STDERR_LAST)?;
                    f(&mut w, &sd, self.version)?;
                }
                Err(e) => proto::write_error(&mut *w, &e, self.version)?,
            }
            w.flush()?;
        }
    }

    fn path(&mut self) -> io::Result<StorePath> {
        proto::read_path(&mut self.r, &self.d.store.dir)
    }

    fn paths(&mut self) -> io::Result<BTreeSet<StorePath>> {
        proto::read_paths(&mut self.r, &self.d.store.dir)
    }

    fn info(&self, p: &StorePath) -> Result<PathInfo> {
        self.store().query_info(p)?.ok_or_else(|| format!("path '{}' is not valid", self.store().dir.print(p)))
    }

    /// Reads the operation's arguments, then performs it. I/O errors end
    /// the connection; other failures are reported to the client.
    fn op(&mut self, op: Op) -> io::Result<Reply> {
        let sd = self.sd();
        Ok(match op {
            Op::IsValidPath => {
                let p = self.path()?;
                reply_u64(self.store().is_valid(&p) as u64)
            }
            Op::QueryValidPaths => {
                let ps = self.paths()?;
                if minor(self.version) >= 27 {
                    self.r.read_bool()?; // substitute
                }
                reply_paths(ps.into_iter().filter(|p| self.store().is_valid(p)).collect())
            }
            Op::QuerySubstitutablePaths => {
                let ps: Vec<StorePath> = self.paths()?.into_iter().collect();
                reply_paths(self.substitutable_infos(&ps).into_keys().collect())
            }
            Op::HasSubstitutes => {
                let p = self.path()?;
                reply_u64(!self.substitutable_infos(&[p]).is_empty() as u64)
            }
            Op::QueryPathHash => {
                let p = self.path()?;
                self.info(&p).and_then(|i| reply(move |w, _, _| w.write_str(&i.nar_hash.to_base16())))
            }
            Op::QueryReferences => {
                let p = self.path()?;
                self.info(&p).and_then(|i| reply_paths(i.references))
            }
            Op::QueryReferrers => {
                let p = self.path()?;
                self.referrers(&p).and_then(reply_paths)
            }
            Op::QueryValidDerivers | Op::QueryDeriver => {
                let p = self.path()?;
                let deriver = self.info(&p).map(|i| i.deriver);
                match op {
                    Op::QueryDeriver => deriver.and_then(|d| reply(move |w, sd, _| proto::write_opt_path(w, sd, d.as_ref()))),
                    _ => deriver.and_then(|d| reply_paths(d.into_iter().collect())),
                }
            }
            Op::QueryDerivationOutputs | Op::QueryDerivationOutputNames | Op::QueryDerivationOutputMap => {
                let p = self.path()?;
                match self.store().read_derivation(&p) {
                    Err(e) => Err(e),
                    Ok(d) => match op {
                        Op::QueryDerivationOutputs => reply_paths(d.outputs.values().filter_map(|o| o.path.clone()).collect()),
                        Op::QueryDerivationOutputNames => {
                            let names: Vec<String> = d.outputs.keys().cloned().collect();
                            reply(move |w, _, _| w.write_strings(names.iter().map(String::as_str)))
                        }
                        _ => {
                            let mut map = Vec::new();
                            for (name, o) in &d.outputs {
                                let p = match &o.path {
                                    Some(p) => Some(p.clone()),
                                    None => self.store().query_output_realisation(&d, name).ok().flatten().map(|r| r.out_path),
                                };
                                map.push((name.clone(), p));
                            }
                            reply(move |w, sd, _| {
                                w.write_u64(map.len() as u64)?;
                                for (name, p) in &map {
                                    w.write_str(name)?;
                                    proto::write_opt_path(w, sd, p.as_ref())?;
                                }
                                Ok(())
                            })
                        }
                    },
                }
            }
            Op::QueryPathFromHashPart => {
                let h = self.r.read_string()?;
                let found = self.store().valid_paths().map(|v| v.into_iter().find(|p| p.hash_part() == h));
                found.and_then(|p| reply(move |w, sd, _| proto::write_opt_path(w, sd, p.as_ref())))
            }
            Op::QueryPathInfo => {
                let p = self.path()?;
                match self.store().query_info(&p) {
                    Err(e) => Err(e),
                    Ok(None) if minor(self.version) < 17 => Err(format!("path '{}' is not valid", sd.print(&p))),
                    Ok(None) => reply_u64(0),
                    Ok(Some(info)) => reply(move |w, sd, v| {
                        if minor(v) >= 17 {
                            w.write_u64(1)?;
                        }
                        proto::write_path_info_unkeyed(w, sd, &info, v)
                    }),
                }
            }
            Op::QueryAllValidPaths => self.store().valid_paths().and_then(|v| reply_paths(v.into_iter().collect())),
            Op::QuerySubstitutablePathInfo => {
                let p = self.path()?;
                let info = self.substitutable_infos(&[p]).into_values().next();
                reply(move |w, sd, _| match &info {
                    None => w.write_u64(0),
                    Some(ni) => {
                        w.write_u64(1)?;
                        write_substitutable(w, sd, ni)
                    }
                })
            }
            Op::QuerySubstitutablePathInfos => {
                let mut ps = Vec::new();
                if minor(self.version) < 22 {
                    ps.extend(self.paths()?);
                } else {
                    let n = self.r.read_u64()?;
                    for _ in 0..n {
                        ps.push(self.path()?);
                        self.r.read_string()?; // content address
                    }
                }
                let infos = self.substitutable_infos(&ps);
                reply(move |w, sd, _| {
                    w.write_u64(infos.len() as u64)?;
                    for (p, ni) in &infos {
                        proto::write_path(w, sd, p)?;
                        write_substitutable(w, sd, ni)?;
                    }
                    Ok(())
                })
            }
            Op::AddToStore => self.add_to_store()?,
            Op::AddTextToStore => {
                let name = self.r.read_string()?;
                let text = self.r.read_bytes()?;
                let refs = self.paths()?;
                let _g = self.d.gc.read().unwrap();
                let r = self.store().add_text(&name, &text, &refs);
                if let Ok(p) = &r {
                    self.add_temp_root(p);
                }
                r.and_then(|p| reply(move |w, sd, _| proto::write_path(w, sd, &p)))
            }
            Op::AddToStoreNar => self.add_to_store_nar()?,
            Op::AddMultipleToStore => self.add_multiple_to_store()?,
            Op::AddBuildLog => {
                let p = self.path()?;
                let mut log = Vec::new();
                FramedReader::new(&mut self.r).read_to_end(&mut log)?;
                fs::write(self.store().log_path(&p), log).map_err(|e| format!("writing build log: {e}")).and_then(|()| reply_u64(1))
            }
            Op::BuildPaths => {
                let targets = proto::read_derived_paths(&mut self.r, &sd)?;
                let mode = if minor(self.version) >= 15 { self.r.read_u64()? } else { 0 };
                self.check_mode(mode).and_then(|()| self.build_targets(&targets)).and_then(|_| reply_u64(1))
            }
            Op::BuildPathsWithResults => {
                let targets = proto::read_derived_paths(&mut self.r, &sd)?;
                let mode = self.r.read_u64()?;
                self.check_mode(mode).and_then(|()| self.build_with_results(&targets)).and_then(|results| {
                    reply(move |w, sd, v| {
                        w.write_u64(results.len() as u64)?;
                        for (t, res) in &results {
                            w.write_str(&t.render(sd))?;
                            res.write(w, v)?;
                        }
                        Ok(())
                    })
                })
            }
            Op::BuildDerivation => {
                let drv_path = self.path()?;
                let name = drv_path.name().strip_suffix(".drv").unwrap_or(drv_path.name()).to_string();
                let drv = proto::read_basic_derivation(&mut self.r, &sd, &name)?;
                let mode = self.r.read_u64()?;
                let res = self.check_mode(mode).and_then(|()| self.build_derivation(&drv_path, &drv));
                res.and_then(|res| reply(move |w, _, v| res.write(w, v)))
            }
            Op::EnsurePath => {
                let p = self.path()?;
                let res = self.substitute(&[p.clone()]);
                if self.store().is_valid(&p) {
                    self.add_temp_root(&p);
                    reply_u64(1)
                } else {
                    Err(res.err().unwrap_or_else(|| format!("path '{}' is not valid", sd.print(&p))))
                }
            }
            Op::AddTempRoot => {
                let p = self.path()?;
                self.add_temp_root(&p);
                reply_u64(1)
            }
            Op::AddPermRoot => {
                let p = self.path()?;
                let link = self.r.read_string()?;
                self.add_perm_root(&p, &link).and_then(|()| reply(move |w, _, _| w.write_str(&link)))
            }
            Op::AddIndirectRoot => {
                let link = self.r.read_string()?;
                self.store().add_indirect_root(Path::new(&link)).and_then(|()| reply_u64(1))
            }
            Op::SyncWithGC => reply_u64(1),
            Op::FindRoots => {
                let temp = self.d.temp_roots.lock().unwrap().clone();
                self.store().list_roots().and_then(|roots| {
                    reply(move |w, sd, _| {
                        let mut all: Vec<(String, &StorePath)> =
                            roots.iter().map(|(l, p)| (l.to_string_lossy().into_owned(), p)).collect();
                        for (id, ps) in &temp {
                            all.extend(ps.iter().map(|p| (format!("{{temp:{id}}}"), p)));
                        }
                        w.write_u64(all.len() as u64)?;
                        for (l, p) in all {
                            w.write_str(&l)?;
                            proto::write_path(w, sd, p)?;
                        }
                        Ok(())
                    })
                })
            }
            Op::CollectGarbage => {
                let action = self.r.read_u64()?;
                let specific = self.paths()?;
                let ignore_liveness = self.r.read_bool()?;
                let max_freed = self.r.read_u64()?;
                for _ in 0..3 {
                    self.r.read_u64()?;
                }
                self.collect_garbage(action, &specific, ignore_liveness, max_freed).and_then(|(paths, freed)| {
                    reply(move |w, sd, _| {
                        let v: Vec<String> = paths.iter().map(|p| sd.print(p)).collect();
                        w.write_strings(v.iter().map(String::as_str))?;
                        w.write_u64(freed)?;
                        w.write_u64(0)
                    })
                })
            }
            Op::SetOptions => {
                self.opts.keep_failed = self.r.read_bool()?;
                self.r.read_u64()?; // keepGoing
                self.r.read_u64()?; // tryFallback
                self.r.read_u64()?; // verbosity
                let jobs = self.r.read_u64()?;
                let max_silent = self.r.read_u64()?;
                self.r.read_u64()?; // obsolete useBuildHook
                self.r.read_u64()?; // verboseBuild
                self.r.read_u64()?; // obsolete logType
                self.r.read_u64()?; // obsolete printBuildTrace
                let cores = self.r.read_u64()?;
                self.substitute = self.r.read_bool()?;
                self.opts.max_silent_time = max_silent;
                if minor(self.version) >= 12 {
                    let n = self.r.read_u64()?;
                    for _ in 0..n {
                        let k = self.r.read_string()?;
                        let v = self.r.read_string()?;
                        self.client_setting(&k, &v);
                    }
                }
                if jobs > 0 {
                    self.opts.jobs = jobs as usize;
                }
                if cores > 0 {
                    self.opts.cores = cores as usize;
                }
                reply_none()
            }
            Op::QueryMissing => {
                let targets = proto::read_derived_paths(&mut self.r, &sd)?;
                self.query_missing(&targets).and_then(|m| {
                    reply(move |w, sd, _| {
                        proto::write_paths(w, sd, &m.build)?;
                        proto::write_paths(w, sd, &m.substitute)?;
                        proto::write_paths(w, sd, &m.unknown)?;
                        w.write_u64(m.download_size)?;
                        w.write_u64(m.nar_size)
                    })
                })
            }
            Op::NarFromPath => {
                let p = self.path()?;
                let real = self.store().real_path(&p);
                self.info(&p).and_then(|_| {
                    self.add_temp_root(&p);
                    reply(move |w, _, _| nar::dump(&real, w))
                })
            }
            Op::QueryRealisation => {
                let id = self.r.read_string()?;
                let found = DrvOutput::parse(&id).and_then(|id| self.store().query_realisation(&id));
                found.and_then(|r| {
                    reply(move |w, sd, v| {
                        if minor(v) < 31 {
                            let paths: BTreeSet<StorePath> = r.iter().map(|r| r.out_path.clone()).collect();
                            proto::write_paths(w, sd, &paths)
                        } else {
                            w.write_strings(r.iter().map(|r| Realisation::from(r).to_json()).collect::<Vec<_>>().iter().map(String::as_str))
                        }
                    })
                })
            }
            Op::RegisterDrvOutput => {
                let r = if minor(self.version) < 31 {
                    let id = self.r.read_string()?;
                    let p = self.path()?;
                    DrvOutput::parse(&id).map(|id| cranix_store::realisation::Realisation::new(id, p))
                } else {
                    let json = self.r.read_string()?;
                    Realisation::from_json(&json)?.to_store()
                };
                r.and_then(|r| self.register_drv_output(r)).and_then(|()| reply_none())
            }
            Op::AddSignatures => {
                self.path()?;
                self.r.read_strings()?;
                reply_u64(1)
            }
            Op::OptimiseStore => reply_u64(1),
            Op::VerifyStore => {
                let check = self.r.read_bool()?;
                let _repair = self.r.read_bool()?;
                let mut errors = false;
                if check {
                    for p in self.store().valid_paths().unwrap_or_default() {
                        if !self.store().verify(&p).unwrap_or(false) {
                            self.log(&format!("path '{}' was modified! expected hash differs", sd.print(&p)))?;
                            errors = true;
                        }
                    }
                }
                reply_u64(errors as u64)
            }
            Op::ExportPath | Op::ImportPaths | Op::QueryFailedPaths | Op::ClearFailedPaths => {
                return Err(bad(format!("operation {op:?} is not supported")));
            }
        })
    }

    fn log(&mut self, msg: &str) -> io::Result<()> {
        let mut w = self.w.lock().unwrap();
        w.write_u64(proto::STDERR_NEXT)?;
        w.write_str(&format!("{msg}\n"))?;
        w.flush()
    }

    /// The client's build options, with build output sent to the client.
    fn build_opts(&self) -> BuildOptions {
        let logger = ClientLogger { w: Arc::clone(&self.w), version: self.version };
        BuildOptions { logger: Some(Arc::new(logger)), ..self.opts.clone() }
    }

    fn referrers(&self, p: &StorePath) -> Result<BTreeSet<StorePath>> {
        let mut out = BTreeSet::new();
        for q in self.store().valid_paths()? {
            if self.store().query_info(&q)?.is_some_and(|i| i.references.contains(p)) {
                out.insert(q);
            }
        }
        Ok(out)
    }

    fn check_mode(&self, mode: u64) -> Result<()> {
        if mode == 2 && !self.trusted {
            return Err("repairing or checking is not allowed because you are not in 'trusted-users'".into());
        }
        Ok(())
    }

    fn add_to_store(&mut self) -> io::Result<Reply> {
        if minor(self.version) < 25 {
            return Err(bad("AddToStore from clients older than protocol 1.25 is not supported"));
        }
        let name = self.r.read_string()?;
        let cam = self.r.read_string()?;
        let refs = self.paths()?;
        let _repair = self.r.read_bool()?;
        let tmp = self.store().state_dir().join(format!("add-{}-{}.tmp", std::process::id(), self.id));
        let res = (|| -> Result<PathInfo> {
            let mut f = fs::File::create(&tmp).map_err(|e| format!("creating '{}': {e}", tmp.display()))?;
            io::copy(&mut FramedReader::new(&mut self.r), &mut f).map_err(|e| format!("receiving data: {e}"))?;
            drop(f);
            let _g = self.d.gc.read().unwrap();
            let info = self.add_dump(&name, &cam, &refs, &tmp)?;
            self.add_temp_root(&info.path);
            Ok(info)
        })();
        let _ = fs::remove_file(&tmp);
        Ok(res.and_then(|info| reply(move |w, sd, v| proto::write_path_info(w, sd, &info, v))))
    }

    /// Adds the data `AddToStore` received: the contents of a text or flat
    /// file, or the NAR of a recursively hashed tree.
    fn add_dump(&self, name: &str, cam: &str, refs: &BTreeSet<StorePath>, data: &Path) -> Result<PathInfo> {
        let s = self.store();
        let read = || fs::read(data).map_err(|e| format!("reading upload: {e}"));
        if cam == "text:sha256" {
            let p = s.add_text(name, &read()?, refs)?;
            return self.info(&p);
        }
        let (method, algo) = match cam.strip_prefix("fixed:") {
            Some(a) => match a.strip_prefix("r:") {
                Some(a) => (FileIngestion::Recursive, a),
                None => (FileIngestion::Flat, a),
            },
            None => return Err(format!("unsupported content-address method '{cam}'")),
        };
        let algo = HashAlgo::parse(algo).ok_or_else(|| format!("unsupported content-address method '{cam}'"))?;
        let (ca_hash, nar_bytes): (Hash, Option<Vec<u8>>) = match method {
            FileIngestion::Flat => {
                let bytes = read()?;
                let mut nar_buf = Vec::new();
                nar::dump_bytes(&bytes, false, &mut nar_buf).map_err(|e| e.to_string())?;
                (Hash::digest(algo, &bytes), Some(nar_buf))
            }
            FileIngestion::Recursive => {
                let mut sink = HashSink::new(algo);
                io::copy(&mut fs::File::open(data).map_err(|e| e.to_string())?, &mut sink).map_err(|e| e.to_string())?;
                (sink.finish().0, None)
            }
        };
        let mut refs = refs.clone();
        let p0 = s.dir.make_fixed_output_path(method, &ca_hash, name, &refs, false)?;
        let self_ref = refs.remove(&p0);
        let p = if self_ref { s.dir.make_fixed_output_path(method, &ca_hash, name, &refs, true)? } else { p0 };
        if self_ref {
            refs.insert(p.clone());
        }
        let r = if method == FileIngestion::Recursive { "r:" } else { "" };
        let mut info = PathInfo {
            path: p,
            nar_hash: Hash::sha256(b""),
            nar_size: 0,
            references: refs,
            deriver: None,
            ca: Some(format!("fixed:{r}{algo}:{}", ca_hash.to_nix32())),
        };
        match nar_bytes {
            Some(b) => {
                info.nar_hash = Hash::sha256(&b);
                info.nar_size = b.len() as u64;
                s.import_nar(&info, &b[..])?;
            }
            None => {
                let mut sink = HashSink::new(HashAlgo::Sha256);
                io::copy(&mut fs::File::open(data).map_err(|e| e.to_string())?, &mut sink).map_err(|e| e.to_string())?;
                (info.nar_hash, info.nar_size) = sink.finish();
                s.import_nar(&info, fs::File::open(data).map_err(|e| e.to_string())?)?;
            }
        }
        self.info(&info.path)
    }

    fn add_to_store_nar(&mut self) -> io::Result<Reply> {
        let sd = self.sd();
        let path = self.path()?;
        let info = proto::read_path_info_unkeyed(&mut self.r, &sd, path, self.version.max(1 << 8 | 16))?;
        let _repair = self.r.read_bool()?;
        let _dont_check_sigs = self.r.read_bool()?;
        let _g = self.d.gc.read().unwrap();
        let mut f = FramedReader::new(&mut self.r);
        let res = Conn::import_with(self.d, self.trusted, self.id, &info, &mut f);
        drop(f);
        Ok(res.and_then(|()| reply_none()))
    }

    fn add_multiple_to_store(&mut self) -> io::Result<Reply> {
        let sd = self.sd();
        let _repair = self.r.read_bool()?;
        let _dont_check_sigs = self.r.read_bool()?;
        let _g = self.d.gc.read().unwrap();
        let (d, trusted, id) = (self.d, self.trusted, self.id);
        let mut f = FramedReader::new(&mut self.r);
        let n = f.read_u64()?;
        let mut res = Ok(());
        for _ in 0..n {
            let info = proto::read_path_info(&mut f, &sd, 1 << 8 | 16)?;
            let mut nar = (&mut f).take(info.nar_size);
            let r = if res.is_ok() { Conn::import_with(d, trusted, id, &info, &mut nar) } else { Ok(()) };
            io::copy(&mut nar, &mut io::sink())?;
            if res.is_ok() {
                res = r;
            }
        }
        drop(f);
        Ok(res.and_then(|()| reply_none()))
    }

    fn import_with(d: &Daemon, trusted: bool, id: u64, info: &PathInfo, nar: &mut dyn Read) -> Result<()> {
        let c = ImportCtx { d, trusted, id };
        c.import(info, nar)
    }

    fn add_perm_root(&self, p: &StorePath, link: &str) -> Result<()> {
        let s = self.store();
        let link_path = PathBuf::from(link);
        if let Ok(md) = fs::symlink_metadata(&link_path) {
            if !md.file_type().is_symlink() {
                return Err(format!("cannot create symlink '{link}'; already exists"));
            }
            fs::remove_file(&link_path).map_err(|e| format!("removing '{link}': {e}"))?;
        }
        std::os::unix::fs::symlink(s.dir.print(p), &link_path).map_err(|e| format!("creating '{link}': {e}"))?;
        s.add_indirect_root(&link_path)
    }

    fn collect_garbage(&self, action: u64, specific: &BTreeSet<StorePath>, ignore_liveness: bool, max_freed: u64) -> Result<(Vec<StorePath>, u64)> {
        if ignore_liveness {
            return Err("you are not allowed to ignore liveness".into());
        }
        let action = match action {
            0 => GcAction::ReturnLive,
            1 => GcAction::ReturnDead,
            2 => GcAction::DeleteDead,
            3 => GcAction::DeleteSpecific,
            a => return Err(format!("invalid garbage collector action {a}")),
        };
        let _g = self.d.gc.write().unwrap();
        let max = if max_freed == u64::MAX { 0 } else { max_freed };
        self.store().collect_garbage_with(action, specific, &self.d.all_temp_roots(), max)
    }

    /// The client's logger for messages of this request.
    fn logger(&self) -> Arc<dyn cranix_store::build::BuildLogger> {
        Arc::new(ClientLogger { w: Arc::clone(&self.w), version: self.version })
    }

    /// The narinfos the daemon's substituters offer for `paths`, if the
    /// client allows substitution.
    fn substitutable_infos(&self, paths: &[StorePath]) -> BTreeMap<StorePath, NarInfo> {
        if !self.substitute {
            return BTreeMap::new();
        }
        self.store().substitutable_infos(paths)
    }

    /// Substitutes the invalid ones among `paths`, with progress sent to
    /// the client, and roots them for this connection.
    fn substitute(&self, paths: &[StorePath]) -> Result<()> {
        let missing: Vec<StorePath> = paths.iter().filter(|p| !self.store().is_valid(p)).cloned().collect();
        if missing.is_empty() || !self.substitute {
            return Ok(());
        }
        let _g = self.d.gc.read().unwrap();
        let failed = self.store().substitute_paths_logged(&missing, Some(&self.logger()))?;
        for p in paths.iter().filter(|p| !failed.contains(*p)) {
            self.add_temp_root(p);
        }
        match failed.first() {
            Some(p) => Err(format!("path '{}' does not exist and cannot be created", self.store().dir.print(p))),
            None => Ok(()),
        }
    }

    /// Applies one setting a client sends with `SetOptions`. The build
    /// limits apply to every client; trusted clients may also enable the
    /// experimental features the builder uses. The daemon's own settings
    /// decide everything else, such as the sandbox and the substituters.
    fn client_setting(&mut self, name: &str, value: &str) {
        let num = || value.parse::<u64>().ok();
        match name {
            "cores" => {
                if let Some(n) = num().filter(|n| *n > 0) {
                    self.opts.cores = n as usize;
                }
            }
            "timeout" | "build-timeout" => self.opts.timeout = num().unwrap_or(self.opts.timeout),
            "max-silent-time" | "build-max-silent-time" => self.opts.max_silent_time = num().unwrap_or(self.opts.max_silent_time),
            "experimental-features" | "extra-experimental-features" if self.trusted => {
                let f: BTreeSet<&str> = value.split_whitespace().collect();
                self.opts.ca_derivations |= f.contains("ca-derivations");
                self.opts.impure_derivations |= f.contains("impure-derivations");
            }
            _ => {}
        }
    }

    /// Records a realisation sent by the client. Untrusted clients need a
    /// signature by one of the daemon's trusted keys.
    fn register_drv_output(&self, r: cranix_store::realisation::Realisation) -> Result<()> {
        let s = self.store();
        if !self.trusted && !s.realisation_is_trusted(&r) {
            return Err(format!(
                "cannot register realisation '{}' because it lacks a signature by a trusted key",
                s.dir.print(&r.out_path)
            ));
        }
        if !s.is_valid(&r.out_path) {
            return Err(format!("cannot register realisation '{}': its output path is not valid", r.id));
        }
        s.register_realisation(&r)
    }

    /// Derivations (with the outputs asked for) among `targets`; opaque
    /// paths are substituted when they are missing.
    fn drvs_of(&self, targets: &[DerivedPath]) -> Result<Vec<StorePath>> {
        let mut drvs = Vec::new();
        let mut opaque = Vec::new();
        for t in targets {
            match t {
                DerivedPath::Opaque(p) => opaque.push(p.clone()),
                DerivedPath::Built { drv, .. } => drvs.push(drv.clone()),
            }
        }
        self.substitute(&opaque)?;
        for p in &opaque {
            if !self.store().is_valid(p) {
                return Err(format!("path '{}' is not valid", self.store().dir.print(p)));
            }
            self.add_temp_root(p);
        }
        Ok(drvs)
    }

    fn realise(&self, drvs: &[StorePath]) -> Result<BTreeMap<StorePath, BTreeMap<String, StorePath>>> {
        let _g = self.d.gc.read().unwrap();
        let mut opts = self.build_opts();
        if !self.substitute {
            opts.substitute = false;
        }
        let res = self.store().realise(drvs, &opts)?;
        for outs in res.values() {
            for p in outs.values() {
                self.add_temp_root(p);
            }
        }
        Ok(res)
    }

    fn build_targets(&self, targets: &[DerivedPath]) -> Result<BTreeMap<StorePath, BTreeMap<String, StorePath>>> {
        let drvs = self.drvs_of(targets)?;
        self.realise(&drvs)
    }

    /// The outputs of `drv` that are valid, by name.
    fn present_outputs(&self, drv: &Derivation) -> BTreeMap<String, StorePath> {
        let s = self.store();
        let mut out = BTreeMap::new();
        for (n, o) in &drv.outputs {
            let p = match &o.path {
                Some(p) => Some(p.clone()),
                None => s.query_output_realisation(drv, n).ok().flatten().map(|r| r.out_path),
            };
            if let Some(p) = p.filter(|p| s.is_valid(p)) {
                out.insert(n.clone(), p);
            }
        }
        out
    }

    fn build_with_results(&self, targets: &[DerivedPath]) -> Result<Vec<(DerivedPath, BuildResult)>> {
        let s = self.store();
        let mut before = BTreeMap::new();
        for t in targets {
            match t {
                DerivedPath::Built { drv, .. } => {
                    let d = s.read_derivation(drv)?;
                    before.insert(drv.clone(), self.present_outputs(&d).len() == d.outputs.len());
                }
                DerivedPath::Opaque(p) => {
                    before.insert(p.clone(), s.is_valid(p));
                }
            }
        }
        let all = self.build_targets(targets);
        let mut out = Vec::new();
        for t in targets {
            let res = match t {
                DerivedPath::Opaque(p) if s.is_valid(p) => {
                    BuildResult::new(if before[p] { BuildStatus::AlreadyValid } else { BuildStatus::Substituted })
                }
                DerivedPath::Opaque(p) => {
                    let msg = all.as_ref().err().cloned().unwrap_or_else(|| format!("path '{}' is not valid", s.dir.print(p)));
                    BuildResult { status: BuildStatus::NoSubstituters, ..BuildResult::failure(msg) }
                }
                DerivedPath::Built { drv, outputs } => {
                    let d = s.read_derivation(drv)?;
                    let present = self.present_outputs(&d);
                    let wanted: Vec<&String> = d.outputs.keys().filter(|n| outputs.as_ref().map_or(true, |o| o.contains(*n))).collect();
                    if wanted.iter().all(|n| present.contains_key(*n)) {
                        let built_here = wanted.iter().any(|n| s.is_ultimate(&present[*n]).unwrap_or(false));
                        let status = match before.get(drv) {
                            Some(true) => BuildStatus::AlreadyValid,
                            _ if built_here => BuildStatus::Built,
                            _ => BuildStatus::Substituted,
                        };
                        let mut res = BuildResult::new(status);
                        res.times_built = (status == BuildStatus::Built) as u64;
                        let h = s.static_output_hash(&d)?;
                        for n in wanted {
                            let id = cranix_store::realisation::DrvOutput { drv_hash: h.clone(), output: n.clone() };
                            let r = match s.query_realisation(&id)? {
                                Some(r) if r.out_path == present[n] => Realisation::from(&r),
                                _ => Realisation::new(id.to_string(), present[n].clone()),
                            };
                            res.built_outputs.insert(n.clone(), r);
                        }
                        res
                    } else {
                        let msg = all.as_ref().err().cloned().unwrap_or_else(|| "build failed".into());
                        BuildResult { status: BuildStatus::PermanentFailure, ..BuildResult::failure(msg) }
                    }
                }
            };
            out.push((t.clone(), res));
        }
        Ok(out)
    }

    fn build_derivation(&self, drv_path: &StorePath, drv: &Derivation) -> Result<BuildResult> {
        if !self.trusted && !drv.is_fixed_output() {
            return Err("you are not privileged to build input-addressed derivations".into());
        }
        let res = {
            let _g = self.d.gc.read().unwrap();
            let mut opts = self.build_opts();
            opts.substitute &= self.substitute;
            build_basic_result(self.store(), drv_path, drv, &opts)
        };
        for r in res.built_outputs.values() {
            self.add_temp_root(&r.out_path);
        }
        Ok(res)
    }

    /// What realising `targets` would do: the derivations it would build,
    /// the paths it would substitute (with their download and unpacked
    /// sizes), and the targets that are neither valid nor obtainable.
    fn query_missing(&self, targets: &[DerivedPath]) -> Result<Missing> {
        let s = self.store();
        let mut m = Missing::default();
        let mut todo: Vec<StorePath> = Vec::new();
        let mut want_subst: Vec<StorePath> = Vec::new();
        for t in targets {
            match t {
                DerivedPath::Opaque(p) if !s.is_valid(p) => want_subst.push(p.clone()),
                DerivedPath::Opaque(_) => {}
                DerivedPath::Built { drv, .. } => todo.push(drv.clone()),
            }
        }
        let mut seen = BTreeSet::new();
        while let Some(p) = todo.pop() {
            if !seen.insert(p.clone()) {
                continue;
            }
            let Ok(d) = s.read_derivation(&p) else {
                // A missing derivation may itself come from a cache.
                want_subst.push(p);
                continue;
            };
            if self.present_outputs(&d).len() == d.outputs.len() {
                continue;
            }
            let static_outs: Option<Vec<StorePath>> = d.outputs.values().map(|o| o.path.clone()).collect();
            if let Some(outs) = static_outs.filter(|_| self.substitute) {
                if let Some(plan) = s.substitution_plan(&outs) {
                    m.add_plan(plan);
                    continue;
                }
            }
            m.build.insert(p);
            todo.extend(d.input_drvs.keys().cloned());
            want_subst.extend(d.input_srcs.iter().filter(|q| !s.is_valid(q)).cloned());
        }
        for p in want_subst {
            match s.substitution_plan(std::slice::from_ref(&p)).filter(|_| self.substitute) {
                Some(plan) => m.add_plan(plan),
                None => {
                    m.unknown.insert(p);
                }
            }
        }
        Ok(m)
    }
}

/// The answer to `QueryMissing`.
#[derive(Default)]
struct Missing {
    build: BTreeSet<StorePath>,
    substitute: BTreeSet<StorePath>,
    unknown: BTreeSet<StorePath>,
    download_size: u64,
    nar_size: u64,
}

impl Missing {
    fn add_plan(&mut self, plan: BTreeMap<StorePath, NarInfo>) {
        for (p, ni) in plan {
            if self.substitute.insert(p) {
                self.download_size += ni.file_size.unwrap_or(0);
                self.nar_size += ni.nar_size;
            }
        }
    }
}

/// A `SubstitutablePathInfo`: deriver, references, download and NAR size.
fn write_substitutable(w: &mut W, sd: &StoreDir, ni: &NarInfo) -> io::Result<()> {
    proto::write_opt_path(w, sd, ni.deriver.as_ref())?;
    proto::write_paths(w, sd, &ni.references)?;
    w.write_u64(ni.file_size.unwrap_or(0))?;
    w.write_u64(ni.nar_size)
}

/// Sends build activity to a client as Nix does: an activity of type
/// `actBuild` per build with one `resBuildLogLine` result per output line.
/// Clients older than protocol 1.20 get plain `STDERR_NEXT` lines.
struct ClientLogger {
    w: Arc<Mutex<W>>,
    version: u64,
}

impl std::fmt::Debug for ClientLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientLogger")
    }
}

const ACT_BUILD: u64 = 105;
const LVL_INFO: u64 = 3;

impl ClientLogger {
    /// A client that went away fails its request on the next reply, so
    /// errors from log messages are left to that.
    fn send(&self, f: impl FnOnce(&mut W) -> io::Result<()>) {
        let mut w = self.w.lock().unwrap();
        let _ = f(&mut w).and_then(|()| w.flush());
    }

    fn activities(&self) -> bool {
        minor(self.version) >= 20
    }
}

impl cranix_store::build::BuildLogger for ClientLogger {
    fn start(&self, id: u64, drv_path: &str, text: &str) {
        if !self.activities() {
            return self.send(|w| {
                w.write_u64(proto::STDERR_NEXT)?;
                w.write_str(&format!("{text}\n"))
            });
        }
        self.send(|w| {
            w.write_u64(proto::STDERR_START_ACTIVITY)?;
            w.write_u64(id)?;
            w.write_u64(LVL_INFO)?;
            w.write_u64(ACT_BUILD)?;
            w.write_str(text)?;
            // Fields of actBuild: derivation, machine, round, total rounds.
            w.write_u64(4)?;
            w.write_u64(1)?;
            w.write_str(drv_path)?;
            w.write_u64(1)?;
            w.write_str("")?;
            for _ in 0..2 {
                w.write_u64(0)?;
                w.write_u64(1)?;
            }
            w.write_u64(0) // parent
        })
    }

    fn line(&self, id: u64, line: &str) {
        if !self.activities() {
            return self.send(|w| {
                w.write_u64(proto::STDERR_NEXT)?;
                w.write_str(&format!("{line}\n"))
            });
        }
        self.send(|w| {
            w.write_u64(proto::STDERR_RESULT)?;
            w.write_u64(id)?;
            w.write_u64(proto::RES_BUILD_LOG_LINE)?;
            w.write_u64(1)?;
            w.write_u64(1)?;
            w.write_str(line)
        })
    }

    fn message(&self, text: &str) {
        self.send(|w| {
            w.write_u64(proto::STDERR_NEXT)?;
            w.write_str(&format!("{text}\n"))
        });
    }

    fn stop(&self, id: u64) {
        if self.activities() {
            self.send(|w| {
                w.write_u64(proto::STDERR_STOP_ACTIVITY)?;
                w.write_u64(id)
            });
        }
    }
}

/// The parts of a connection that importing needs, borrowed apart from its
/// reader (which supplies the data).
struct ImportCtx<'d> {
    d: &'d Daemon,
    trusted: bool,
    id: u64,
}

impl ImportCtx<'_> {
    /// Imports one path received with its metadata. Untrusted clients may
    /// only add content-addressed paths, whose names are checked against
    /// their contents.
    fn import(&self, info: &PathInfo, nar: &mut dyn Read) -> Result<()> {
        let s = &self.d.store;
        if !self.trusted && info.ca.is_none() {
            io::copy(nar, &mut io::sink()).map_err(|e| e.to_string())?;
            return Err(format!("cannot add path '{}' because it lacks a signature by a trusted key", s.dir.print(&info.path)));
        }
        let was_valid = s.is_valid(&info.path);
        s.import_nar(info, nar)?;
        self.d.temp_roots.lock().unwrap().entry(self.id).or_default().insert(info.path.clone());
        if !self.trusted && !was_valid {
            if let Err(e) = s.check_content_address(info) {
                let _ = s.collect_garbage_with(GcAction::DeleteSpecific, &[info.path.clone()].into(), &BTreeSet::new(), 0);
                return Err(e);
            }
        }
        Ok(())
    }
}

/// Builds a derivation sent with `BuildDerivation` and describes the
/// outcome as a `BuildResult`.
pub fn build_basic_result(s: &Store, drv_path: &StorePath, drv: &Derivation, opts: &BuildOptions) -> BuildResult {
    let valid = s.output_paths(drv_path, drv).is_ok_and(|o| o.values().all(|p| s.is_valid(p)));
    let start = now();
    let (mut res, outputs) = if valid {
        (BuildResult::new(BuildStatus::AlreadyValid), s.output_paths(drv_path, drv).unwrap_or_default())
    } else {
        match s.build_basic(drv_path, drv, opts) {
            Ok(o) => (BuildResult { times_built: 1, ..BuildResult::new(BuildStatus::Built) }, o),
            Err(e) => (BuildResult { status: BuildStatus::PermanentFailure, ..BuildResult::failure(e) }, BTreeMap::new()),
        }
    };
    res.start_time = start;
    res.stop_time = now();
    if res.status.success() {
        // Input derivations are not part of a basic derivation, so its hash
        // needs no lookups.
        let h = drv.hash_modulo(&s.dir, true, &mut |p| Err(format!("unexpected input derivation '{p}'")));
        let id = |n: &str| match &h {
            Ok(h) => format!("sha256:{}!{n}", h.hash.to_base16()),
            Err(_) => format!("!{n}"),
        };
        for (n, p) in &outputs {
            let r = DrvOutput::parse(&id(n)).ok().and_then(|i| s.query_realisation(&i).ok().flatten()).filter(|r| r.out_path == *p);
            let r = r.map(|r| Realisation::from(&r)).unwrap_or_else(|| Realisation::new(id(n), p.clone()));
            res.built_outputs.insert(n.clone(), r);
        }
    }
    res
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `hashDerivationModulo` of a derivation in the store, memoised.
pub fn drv_hash(s: &Store, drv: &StorePath, memo: &mut HashMap<StorePath, DrvHash>) -> Result<DrvHash> {
    if let Some(h) = memo.get(drv) {
        return Ok(h.clone());
    }
    let d = s.read_derivation(drv)?;
    let mut inputs = BTreeMap::new();
    for p in d.input_drvs.keys() {
        inputs.insert(p.clone(), drv_hash(s, p, memo)?);
    }
    let h = d.hash_modulo(&s.dir, false, &mut |p| inputs.get(p).cloned().ok_or_else(|| format!("missing input '{p}'")))?;
    memo.insert(drv.clone(), h.clone());
    Ok(h)
}
