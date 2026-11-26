//! The `nix-store --serve` protocol behind `ssh://` stores and builders:
//! a plain request/reply exchange over the stdin and stdout of a remote
//! `nix-store --serve --write`, whose stderr carries its log.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};

use oxnix_core::hash::{Hash, HashAlgo, HashSink};
use oxnix_core::{nar, Derivation, StoreDir, StorePath};
use oxnix_store::build::BuildOptions;
use oxnix_store::{PathInfo, Store};

use crate::client::{ssh_command, LogOptions, StoreUri, UriKind};
use crate::proto::{self, BuildResult, BuildStatus, DerivedPath, Realisation};
use crate::wire::{bad, copy_nar, ReadExt, WriteExt};

pub type Result<T> = std::result::Result<T, String>;

pub const SERVE_MAGIC_1: u64 = 0x390c9deb;
pub const SERVE_MAGIC_2: u64 = 0x5452eecb;
pub const SERVE_PROTOCOL_VERSION: u64 = 2 << 8 | 7;
const EXPORT_MAGIC: u64 = 0x4558494e;

fn minor(v: u64) -> u64 {
    v & 0xff
}

pub mod cmd {
    pub const QUERY_VALID_PATHS: u64 = 1;
    pub const QUERY_PATH_INFOS: u64 = 2;
    pub const DUMP_STORE_PATH: u64 = 3;
    pub const IMPORT_PATHS: u64 = 4;
    pub const EXPORT_PATHS: u64 = 5;
    pub const BUILD_PATHS: u64 = 6;
    pub const QUERY_CLOSURE: u64 = 7;
    pub const BUILD_DERIVATION: u64 = 8;
    pub const ADD_TO_STORE_NAR: u64 = 9;
}

/// `ValidPathInfo` without its path, in the serve protocol's layout.
pub fn write_info(w: &mut (impl Write + ?Sized), sd: &StoreDir, info: &PathInfo, version: u64) -> io::Result<()> {
    proto::write_opt_path(w, sd, info.deriver.as_ref())?;
    proto::write_paths(w, sd, &info.references)?;
    w.write_u64(info.nar_size)?; // download size
    w.write_u64(info.nar_size)?;
    if minor(version) >= 4 {
        w.write_str(&format!("sha256:{}", info.nar_hash.to_nix32()))?;
        w.write_str(info.ca.as_deref().unwrap_or(""))?;
        w.write_u64(0)?; // signatures
    }
    Ok(())
}

pub fn read_info(r: &mut (impl Read + ?Sized), sd: &StoreDir, path: StorePath, version: u64) -> io::Result<PathInfo> {
    let deriver = proto::read_opt_path(r, sd)?;
    let references = proto::read_paths(r, sd)?;
    let _download_size = r.read_u64()?;
    let nar_size = r.read_u64()?;
    let mut info = PathInfo { path, nar_hash: Hash::sha256(b""), nar_size, references, deriver, ca: None };
    if minor(version) >= 4 {
        info.nar_hash = Hash::parse(&r.read_string()?, Some(HashAlgo::Sha256)).map_err(bad)?;
        let ca = r.read_string()?;
        info.ca = (!ca.is_empty()).then_some(ca);
        r.read_strings()?;
    }
    Ok(info)
}

pub fn write_build_result(w: &mut (impl Write + ?Sized), res: &BuildResult, version: u64) -> io::Result<()> {
    w.write_u64(res.status as u64)?;
    w.write_str(&res.error_msg)?;
    if minor(version) >= 3 {
        w.write_u64(res.times_built)?;
        w.write_bool(res.is_non_deterministic)?;
        w.write_u64(res.start_time)?;
        w.write_u64(res.stop_time)?;
    }
    if minor(version) >= 6 {
        w.write_u64(res.built_outputs.len() as u64)?;
        for r in res.built_outputs.values() {
            w.write_str(&r.id)?;
            w.write_str(&r.to_json())?;
        }
    }
    Ok(())
}

pub fn read_build_result(r: &mut (impl Read + ?Sized), version: u64) -> io::Result<BuildResult> {
    let mut res = BuildResult::new(BuildStatus::from_u64(r.read_u64()?));
    res.error_msg = r.read_string()?;
    if minor(version) >= 3 {
        res.times_built = r.read_u64()?;
        res.is_non_deterministic = r.read_bool()?;
        res.start_time = r.read_u64()?;
        res.stop_time = r.read_u64()?;
    }
    if minor(version) >= 6 {
        let n = r.read_u64()?;
        for _ in 0..n {
            let id = r.read_string()?;
            let real = Realisation::from_json(&r.read_string()?)?;
            let name = id.rsplit_once('!').map(|(_, o)| o.to_string()).ok_or_else(|| bad("invalid output id"))?;
            res.built_outputs.insert(name, real);
        }
    }
    Ok(res)
}

/// Build settings sent after `BuildPaths` and `BuildDerivation`.
fn write_build_options(w: &mut (impl Write + ?Sized), version: u64, keep_failed: bool) -> io::Result<()> {
    w.write_u64(0)?; // maxSilentTime
    w.write_u64(0)?; // buildTimeout
    if minor(version) >= 2 {
        w.write_u64(0)?; // maxLogSize
    }
    if minor(version) >= 3 {
        w.write_u64(0)?; // nrRepeats
        w.write_u64(0)?; // obsolete enforceDeterminism
    }
    if minor(version) >= 7 {
        w.write_bool(keep_failed)?;
    }
    Ok(())
}

/// Reads the build settings; returns `keepFailed`.
fn read_build_options(r: &mut (impl Read + ?Sized), version: u64) -> io::Result<bool> {
    r.read_u64()?;
    r.read_u64()?;
    if minor(version) >= 2 {
        r.read_u64()?;
    }
    if minor(version) >= 3 {
        if r.read_u64()? != 0 {
            return Err(bad("client requested repeating builds, which are not supported"));
        }
        r.read_u64()?;
    }
    Ok(minor(version) >= 7 && r.read_bool()?)
}

/// Client of a remote `nix-store --serve --write`.
pub struct ServeConnection {
    r: BufReader<Box<dyn Read + Send>>,
    w: BufWriter<Box<dyn Write + Send>>,
    pub version: u64,
    pub sd: StoreDir,
    pub keep_failed: bool,
    child: Option<Child>,
    /// Last lines the remote side wrote to stderr, for error messages.
    tail: Arc<Mutex<VecDeque<String>>>,
    log: Arc<Mutex<LogOptions>>,
    what: String,
}

impl Drop for ServeConnection {
    fn drop(&mut self) {
        let _ = self.w.flush();
        if let Some(mut c) = self.child.take() {
            drop(std::mem::replace(&mut self.w, BufWriter::new(Box::new(io::sink()))));
            let _ = c.wait();
        }
    }
}

impl ServeConnection {
    pub fn open(uri: &StoreUri) -> Result<ServeConnection> {
        let UriKind::Ssh { host, port } = &uri.kind else {
            return Err(format!("'{uri}' is not an ssh:// store"));
        };
        let mut c = ssh_command(host, *port, &uri.params, "nix-store", &["--serve", "--write"])?;
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("connecting to '{uri}': running ssh: {e}"))?;
        let r = child.stdout.take().unwrap();
        let w = child.stdin.take().unwrap();
        let err = child.stderr.take().unwrap();
        let mut conn = ServeConnection::from_streams(Box::new(r), Box::new(w), uri.store_dir(), Some(Box::new(err)), uri.to_string());
        conn.child = Some(child);
        conn.handshake()?;
        Ok(conn)
    }

    /// Wraps a duplex stream; `stderr`, when given, is the remote side's
    /// log.
    pub fn from_streams(
        r: Box<dyn Read + Send>,
        w: Box<dyn Write + Send>,
        sd: StoreDir,
        stderr: Option<Box<dyn Read + Send>>,
        what: String,
    ) -> ServeConnection {
        let tail = Arc::new(Mutex::new(VecDeque::new()));
        let log = Arc::new(Mutex::new(LogOptions::default()));
        if let Some(e) = stderr {
            let (tail, log) = (Arc::clone(&tail), Arc::clone(&log));
            std::thread::spawn(move || {
                for line in BufReader::new(e).lines() {
                    let Ok(line) = line else { break };
                    {
                        let mut t = tail.lock().unwrap();
                        if t.len() == 25 {
                            t.pop_front();
                        }
                        t.push_back(line.clone());
                    }
                    let l = log.lock().unwrap().clone();
                    match &l.sink {
                        Some(f) => f(&line),
                        None => eprintln!("{}{line}", l.prefix),
                    }
                }
            });
        }
        ServeConnection {
            r: BufReader::with_capacity(1 << 16, r),
            w: BufWriter::with_capacity(1 << 16, w),
            version: 0,
            sd,
            keep_failed: false,
            child: None,
            tail,
            log,
            what,
        }
    }

    pub fn set_log(&mut self, log: LogOptions) {
        *self.log.lock().unwrap() = log;
    }

    /// Describes a failed exchange, with what the remote side logged.
    fn err(&self, e: io::Error) -> String {
        // Give the stderr reader a moment to pick up the remote's last words.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let tail: Vec<String> = self.tail.lock().unwrap().iter().cloned().collect();
        let mut msg = format!("talking to '{}': {e}", self.what);
        if !tail.is_empty() {
            msg.push_str("; the remote side said:\n");
            msg.push_str(&tail.join("\n"));
        }
        msg
    }

    pub fn handshake(&mut self) -> Result<()> {
        let r = (|| {
            self.w.write_u64(SERVE_MAGIC_1)?;
            self.w.write_u64(SERVE_PROTOCOL_VERSION)?;
            self.w.flush()?;
            if self.r.read_u64()? != SERVE_MAGIC_2 {
                return Err(bad("protocol mismatch: the peer is not 'nix-store --serve'"));
            }
            let v = self.r.read_u64()?;
            if v >> 8 != 2 {
                return Err(bad(format!("unsupported serve protocol version {:#x}", v)));
            }
            self.version = v.min(SERVE_PROTOCOL_VERSION);
            Ok(())
        })();
        r.map_err(|e| self.err(e))
    }

    fn call<T>(&mut self, f: impl FnOnce(&mut BufWriter<Box<dyn Write + Send>>, &mut BufReader<Box<dyn Read + Send>>, &StoreDir, u64) -> io::Result<T>) -> Result<T> {
        let sd = self.sd.clone();
        let v = self.version;
        let r = f(&mut self.w, &mut self.r, &sd, v);
        r.map_err(|e| self.err(e))
    }

    pub fn query_valid_paths(&mut self, ps: &BTreeSet<StorePath>) -> Result<BTreeSet<StorePath>> {
        self.call(|w, r, sd, _| {
            w.write_u64(cmd::QUERY_VALID_PATHS)?;
            w.write_bool(false)?; // lock
            w.write_bool(false)?; // substitute
            proto::write_paths(w, sd, ps)?;
            w.flush()?;
            proto::read_paths(r, sd)
        })
    }

    pub fn query_path_info(&mut self, p: &StorePath) -> Result<Option<PathInfo>> {
        self.call(|w, r, sd, v| {
            w.write_u64(cmd::QUERY_PATH_INFOS)?;
            proto::write_paths(w, sd, [p])?;
            w.flush()?;
            let mut found = None;
            loop {
                let s = r.read_string()?;
                if s.is_empty() {
                    return Ok(found);
                }
                let q = sd.parse(&s).map_err(bad)?;
                found = Some(read_info(r, sd, q, v)?);
            }
        })
    }

    pub fn add_paths(&mut self, infos: &[PathInfo], nar_of: &crate::remote_store::NarOf<'_>) -> Result<()> {
        if minor(self.version) < 5 {
            return Err(format!("'{}' speaks serve protocol 2.{}, which cannot receive paths", self.what, minor(self.version)));
        }
        for info in infos {
            self.call(|w, r, sd, _| {
                w.write_u64(cmd::ADD_TO_STORE_NAR)?;
                proto::write_path(w, sd, &info.path)?;
                proto::write_opt_path(w, sd, info.deriver.as_ref())?;
                w.write_str(&info.nar_hash.to_base16())?;
                proto::write_paths(w, sd, &info.references)?;
                w.write_u64(0)?; // registration time
                w.write_u64(info.nar_size)?;
                w.write_bool(false)?; // ultimate
                w.write_u64(0)?; // signatures
                w.write_str(info.ca.as_deref().unwrap_or(""))?;
                nar_of(info, w)?;
                w.flush()?;
                r.read_u64().map(|_| ())
            })?;
        }
        Ok(())
    }

    pub fn nar_from_path(&mut self, p: &StorePath, out: &mut dyn Write) -> Result<()> {
        self.call(|w, r, sd, _| {
            w.write_u64(cmd::DUMP_STORE_PATH)?;
            proto::write_path(w, sd, p)?;
            w.flush()?;
            copy_nar(r, out)
        })
    }

    pub fn build_derivation(&mut self, drv_path: &StorePath, drv: &Derivation) -> Result<BuildResult> {
        let keep = self.keep_failed;
        self.call(|w, r, sd, v| {
            w.write_u64(cmd::BUILD_DERIVATION)?;
            proto::write_path(w, sd, drv_path)?;
            proto::write_basic_derivation(w, sd, drv)?;
            write_build_options(w, v, keep)?;
            w.flush()?;
            read_build_result(r, v)
        })
    }

    /// Builds `targets`; the protocol reports one status for all of them.
    pub fn build_paths(&mut self, targets: &[DerivedPath]) -> Result<Vec<(DerivedPath, BuildResult)>> {
        let keep = self.keep_failed;
        let res = self.call(|w, r, sd, v| {
            w.write_u64(cmd::BUILD_PATHS)?;
            // A bare derivation path asks for all of its outputs.
            let v_s: Vec<String> = targets
                .iter()
                .map(|t| match t {
                    DerivedPath::Built { drv, outputs: None } => sd.print(drv),
                    t => t.render(sd),
                })
                .collect();
            w.write_strings(v_s.iter().map(String::as_str))?;
            write_build_options(w, v, keep)?;
            w.flush()?;
            let status = r.read_u64()?;
            if status == 0 {
                Ok(BuildResult::new(BuildStatus::Built))
            } else {
                // The reply carries an exit status rather than a BuildStatus.
                Ok(BuildResult { status: BuildStatus::PermanentFailure, ..BuildResult::failure(r.read_string()?) })
            }
        })?;
        Ok(targets.iter().map(|t| (t.clone(), res.clone())).collect())
    }

    pub fn query_closure(&mut self, ps: &BTreeSet<StorePath>, include_outputs: bool) -> Result<BTreeSet<StorePath>> {
        self.call(|w, r, sd, _| {
            w.write_u64(cmd::QUERY_CLOSURE)?;
            w.write_bool(include_outputs)?;
            proto::write_paths(w, sd, ps)?;
            w.flush()?;
            proto::read_paths(r, sd)
        })
    }
}

/// Serves `nix-store --serve` for one client on `r`/`w`. Without `write`,
/// only queries and NAR downloads are allowed. Build output goes to this
/// process's stderr, which ssh passes back to the client.
pub fn serve(store: &Store, r: impl Read, w: impl Write, write: bool, opts: &BuildOptions) -> Result<()> {
    let mut r = BufReader::with_capacity(1 << 16, r);
    let mut w = BufWriter::with_capacity(1 << 16, w);
    match serve_loop(store, &mut r, &mut w, write, opts) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        r => r.map_err(|e| e.to_string()),
    }
}

fn other(e: String) -> io::Error {
    io::Error::other(e)
}

fn serve_loop(store: &Store, r: &mut impl Read, w: &mut impl Write, write: bool, opts: &BuildOptions) -> io::Result<()> {
    let sd = &store.dir;
    if r.read_u64()? != SERVE_MAGIC_1 {
        return Err(bad("protocol mismatch"));
    }
    w.write_u64(SERVE_MAGIC_2)?;
    w.write_u64(SERVE_PROTOCOL_VERSION)?;
    w.flush()?;
    let client = r.read_u64()?;
    let v = client.min(SERVE_PROTOCOL_VERSION);
    let need_write = |what: &str| if write { Ok(()) } else { Err(other(format!("{what} is not allowed without --write"))) };
    loop {
        let c = match r.read_u64() {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        match c {
            cmd::QUERY_VALID_PATHS => {
                let _lock = r.read_bool()?;
                let _substitute = r.read_bool()?;
                let ps = proto::read_paths(r, sd)?;
                let valid: BTreeSet<StorePath> = ps.into_iter().filter(|p| store.is_valid(p)).collect();
                proto::write_paths(w, sd, &valid)?;
            }
            cmd::QUERY_PATH_INFOS => {
                for p in proto::read_paths(r, sd)? {
                    if let Some(info) = store.query_info(&p).map_err(other)? {
                        proto::write_path(w, sd, &p)?;
                        write_info(w, sd, &info, v)?;
                    }
                }
                w.write_str("")?;
            }
            cmd::DUMP_STORE_PATH => {
                let p = proto::read_path(r, sd)?;
                if !store.is_valid(&p) {
                    return Err(other(format!("path '{}' is not valid", sd.print(&p))));
                }
                nar::dump(&store.real_path(&p), &mut *w)?;
            }
            cmd::IMPORT_PATHS => {
                need_write("importing paths")?;
                import_paths(store, r)?;
                w.write_u64(1)?;
            }
            cmd::EXPORT_PATHS => {
                r.read_u64()?; // obsolete
                for p in proto::read_paths(r, sd)? {
                    let info = store.query_info(&p).map_err(other)?.ok_or_else(|| other(format!("path '{}' is not valid", sd.print(&p))))?;
                    w.write_u64(1)?;
                    nar::dump(&store.real_path(&p), &mut *w)?;
                    w.write_u64(EXPORT_MAGIC)?;
                    proto::write_path(w, sd, &p)?;
                    proto::write_paths(w, sd, &info.references)?;
                    proto::write_opt_path(w, sd, info.deriver.as_ref())?;
                    w.write_u64(0)?;
                }
                w.write_u64(0)?;
            }
            cmd::BUILD_PATHS => {
                need_write("building paths")?;
                let targets: Vec<DerivedPath> =
                    r.read_strings()?.iter().map(|s| parse_path_with_outputs(sd, s)).collect::<std::result::Result<_, _>>().map_err(other)?;
                let keep_failed = read_build_options(r, v)?;
                let opts = serve_build_options(opts, keep_failed);
                let drvs: Vec<StorePath> = targets
                    .iter()
                    .filter_map(|t| match t {
                        DerivedPath::Built { drv, .. } => Some(drv.clone()),
                        DerivedPath::Opaque(_) => None,
                    })
                    .collect();
                let missing = targets.iter().find_map(|t| match t {
                    DerivedPath::Opaque(p) if !store.is_valid(p) => Some(format!("path '{}' is not valid", sd.print(p))),
                    _ => None,
                });
                match missing.map_or_else(|| store.realise(&drvs, &opts).map(|_| ()), Err) {
                    Ok(()) => w.write_u64(0)?,
                    Err(e) => {
                        w.write_u64(1)?;
                        w.write_str(&e)?;
                    }
                }
            }
            cmd::BUILD_DERIVATION => {
                need_write("building paths")?;
                let drv_path = proto::read_path(r, sd)?;
                let name = drv_path.name().strip_suffix(".drv").unwrap_or(drv_path.name()).to_string();
                let drv = proto::read_basic_derivation(r, sd, &name)?;
                let keep_failed = read_build_options(r, v)?;
                let opts = serve_build_options(opts, keep_failed);
                let res = crate::server::build_basic_result(store, &drv_path, &drv, &opts);
                write_build_result(w, &res, v)?;
            }
            cmd::QUERY_CLOSURE => {
                let include_outputs = r.read_bool()?;
                let ps = proto::read_paths(r, sd)?;
                let mut roots = ps.clone();
                if include_outputs {
                    for p in ps.iter().filter(|p| p.is_derivation()) {
                        if let Ok(d) = store.read_derivation(p) {
                            roots.extend(d.outputs.values().filter_map(|o| o.path.clone()).filter(|o| store.is_valid(o)));
                        }
                    }
                }
                let closure = store.closure(roots).map_err(other)?;
                proto::write_paths(w, sd, &closure)?;
            }
            cmd::ADD_TO_STORE_NAR => {
                need_write("importing paths")?;
                let p = proto::read_path(r, sd)?;
                let info = proto::read_path_info_unkeyed(r, sd, p, 1 << 8 | 16)?;
                if info.nar_size == 0 {
                    return Err(other("the NAR size of the path is missing".into()));
                }
                let mut nar = (&mut *r).take(info.nar_size);
                store.import_nar(&info, &mut nar).map_err(other)?;
                io::copy(&mut nar, &mut io::sink())?;
                w.write_u64(1)?;
            }
            c => return Err(other(format!("unknown serve command {c}"))),
        }
        w.flush()?;
    }
}

/// Writes build output to stderr unprefixed, like `nix-store --serve`; the
/// client adds its own prefix.
#[derive(Debug)]
struct StderrLogger;

impl oxnix_store::build::BuildLogger for StderrLogger {
    fn start(&self, _id: u64, _drv_path: &str, text: &str) {
        eprintln!("{text}");
    }
    fn line(&self, _id: u64, line: &str) {
        eprintln!("{line}");
    }
    fn stop(&self, _id: u64) {}
}

fn serve_build_options(opts: &BuildOptions, keep_failed: bool) -> BuildOptions {
    BuildOptions { keep_failed, logger: Some(Arc::new(StderrLogger)), ..opts.clone() }
}

/// `path!out1,out2` (or a bare path) as given to `BuildPaths`.
fn parse_path_with_outputs(sd: &StoreDir, s: &str) -> Result<DerivedPath> {
    match s.split_once('!') {
        Some((p, outs)) => {
            let drv = sd.parse(p)?;
            let outputs = if outs == "*" { None } else { Some(outs.split(',').map(String::from).collect()) };
            Ok(DerivedPath::Built { drv, outputs })
        }
        None => {
            let p = sd.parse(s)?;
            Ok(if p.is_derivation() { DerivedPath::Built { drv: p, outputs: None } } else { DerivedPath::Opaque(p) })
        }
    }
}

/// Reads paths in `nix-store --export` format and adds them.
fn import_paths(store: &Store, r: &mut impl Read) -> io::Result<()> {
    let sd = &store.dir;
    let tmp = store.state_dir().join(format!("import-{}.nar", std::process::id()));
    loop {
        match r.read_u64()? {
            0 => break,
            1 => {}
            n => return Err(bad(format!("invalid export stream marker {n}"))),
        }
        let mut f = fs::File::create(&tmp)?;
        let mut sink = HashSink::new(HashAlgo::Sha256);
        {
            struct Tee<'a>(&'a mut fs::File, &'a mut HashSink);
            impl Write for Tee<'_> {
                fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                    self.0.write_all(b)?;
                    self.1.write_all(b)?;
                    Ok(b.len())
                }
                fn flush(&mut self) -> io::Result<()> {
                    self.0.flush()
                }
            }
            copy_nar(r, &mut Tee(&mut f, &mut sink))?;
        }
        drop(f);
        if r.read_u64()? != EXPORT_MAGIC {
            return Err(bad("export stream lacks its magic number"));
        }
        let path = proto::read_path(r, sd)?;
        let references = proto::read_paths(r, sd)?;
        let deriver = proto::read_opt_path(r, sd)?;
        if r.read_u64()? != 0 {
            r.read_string()?; // signature
        }
        let (nar_hash, nar_size) = sink.finish();
        let info = PathInfo { path, nar_hash, nar_size, references, deriver, ca: None };
        let res = store.import_nar(&info, fs::File::open(&tmp)?);
        let _ = fs::remove_file(&tmp);
        res.map_err(other)?;
    }
    Ok(())
}
