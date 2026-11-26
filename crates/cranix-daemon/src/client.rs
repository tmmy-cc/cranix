//! Client side of the worker protocol: talks to `nix-daemon` (or `cranix
//! daemon`) over a Unix socket or over `ssh … nix-daemon --stdio`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use cranix_core::{Derivation, StoreDir, StorePath};
use cranix_store::PathInfo;

use crate::proto::{self, minor, BuildResult, DerivedPath, Field, Op};
use crate::wire::{FramedWriter, ReadExt, WriteExt};

pub type Result<T> = std::result::Result<T, String>;

pub const DEFAULT_SOCKET: &str = "/nix/var/nix/daemon-socket/socket";

/// A parsed store URI: `daemon`, `unix:///path`, `ssh-ng://[user@]host` or
/// `ssh://[user@]host` (the `nix-store --serve` protocol),
/// each with optional `?key=value&…` parameters (e.g. `store=/nix/store`,
/// `remote-program=…`, `remote-store=…`, `ssh-key=…`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreUri {
    pub kind: UriKind,
    pub params: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UriKind {
    Unix(PathBuf),
    SshNg { host: String, port: Option<u16> },
    /// The legacy `ssh://` store, spoken with `nix-store --serve`.
    Ssh { host: String, port: Option<u16> },
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl StoreUri {
    /// Recognises the URIs served by this module; `None` for anything else
    /// (such as a local store directory).
    pub fn parse(s: &str) -> Option<StoreUri> {
        let (base, query) = s.split_once('?').unwrap_or((s, ""));
        let mut params = BTreeMap::new();
        for kv in query.split('&').filter(|x| !x.is_empty()) {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            params.insert(percent_decode(k), percent_decode(v));
        }
        let kind = if base == "daemon" || base == "unix://" {
            let sock = std::env::var("NIX_DAEMON_SOCKET_PATH").unwrap_or_else(|_| DEFAULT_SOCKET.into());
            UriKind::Unix(PathBuf::from(sock))
        } else if let Some(p) = base.strip_prefix("unix://") {
            UriKind::Unix(PathBuf::from(percent_decode(p)))
        } else if let Some((legacy, h)) = base.strip_prefix("ssh-ng://").map(|h| (false, h)).or(base.strip_prefix("ssh://").map(|h| (true, h))) {
            let h = h.trim_end_matches('/');
            let (host, port) = match h.rsplit_once(':').map(|(host, p)| (host, p.parse::<u16>())) {
                Some((host, Ok(port))) => (host.to_string(), Some(port)),
                _ => (h.to_string(), None),
            };
            if host.is_empty() {
                return None;
            }
            if legacy {
                UriKind::Ssh { host, port }
            } else {
                UriKind::SshNg { host, port }
            }
        } else {
            return None;
        };
        Some(StoreUri { kind, params })
    }

    pub fn store_dir(&self) -> StoreDir {
        StoreDir::new(self.params.get("store").cloned().unwrap_or_else(|| "/nix/store".into()))
    }
}

impl std::fmt::Display for StoreUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            UriKind::Unix(p) => write!(f, "unix://{}", p.display()),
            UriKind::SshNg { host, port: None } => write!(f, "ssh-ng://{host}"),
            UriKind::SshNg { host, port: Some(p) } => write!(f, "ssh-ng://{host}:{p}"),
            UriKind::Ssh { host, port: None } => write!(f, "ssh://{host}"),
            UriKind::Ssh { host, port: Some(p) } => write!(f, "ssh://{host}:{p}"),
        }
    }
}

/// Receives log output from the remote side.
pub type LogSink = Arc<dyn Fn(&str) + Send + Sync>;

/// How log output from the daemon is shown.
#[derive(Clone, Default)]
pub struct LogOptions {
    /// Print build output lines (`-L`).
    pub build_logs: bool,
    /// Prefix for every printed line, e.g. the remote machine's name.
    pub prefix: String,
    /// Takes build output and messages in place of stderr, e.g. to pass a
    /// remote build's log on to the local build's log.
    pub sink: Option<LogSink>,
}

pub struct Connection {
    r: BufReader<Box<dyn Read + Send>>,
    w: BufWriter<Box<dyn Write + Send>>,
    pub version: u64,
    pub daemon_version: Option<String>,
    /// Whether the daemon trusts this client, when it says.
    pub trusted: Option<bool>,
    pub sd: StoreDir,
    pub log: LogOptions,
    child: Option<Child>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.w.flush();
        if let Some(mut c) = self.child.take() {
            // Closing stdin makes the remote daemon exit.
            drop(std::mem::replace(&mut self.w, BufWriter::new(Box::new(io::sink()))));
            let _ = c.wait();
        }
    }
}

fn ioe(ctx: &str) -> impl Fn(io::Error) -> String + '_ {
    move |e| format!("{ctx}: {e}")
}

/// `ssh … HOST -- PROGRAM ARGS…`, with the key, port and host key from the
/// URI. `program` is the default for the `remote-program` parameter.
pub(crate) fn ssh_command(host: &str, port: Option<u16>, params: &BTreeMap<String, String>, program: &str, args: &[&str]) -> Result<Command> {
    let program = params.get("remote-program").map(String::as_str).unwrap_or(program);
    // Like Nix, `localhost` runs the command directly through the shell.
    if host == "localhost" {
        let mut line: Vec<String> = program.split_whitespace().map(String::from).collect();
        line.extend(args.iter().map(|a| shell_quote(a)));
        if let Some(s) = params.get("remote-store") {
            line.push("--store".into());
            line.push(shell_quote(s));
        }
        let mut c = Command::new("sh");
        c.arg("-c").arg(line.join(" "));
        return Ok(c);
    }
    let mut c = Command::new("ssh");
    c.arg("-x").arg("-a");
    if let Ok(opts) = std::env::var("NIX_SSHOPTS") {
        c.args(opts.split_whitespace());
    }
    if let Some(k) = params.get("ssh-key").filter(|k| !k.is_empty() && *k != "-") {
        c.arg("-i").arg(k);
    }
    if let Some(p) = port {
        c.arg("-p").arg(p.to_string());
    }
    if let Some(key) = params.get("base64-ssh-public-host-key").filter(|k| !k.is_empty() && *k != "-") {
        let decoded = cranix_core::hash::base64_decode(key).ok_or("invalid base64 SSH host key")?;
        let bare = host.rsplit('@').next().unwrap_or(host);
        let f = std::env::temp_dir().join(format!("cranix-known-hosts-{}-{bare}", std::process::id()));
        let mut line = format!("{bare} ").into_bytes();
        line.extend_from_slice(decoded.trim_ascii());
        line.push(b'\n');
        std::fs::write(&f, line).map_err(ioe("writing known hosts file"))?;
        c.arg("-o").arg(format!("UserKnownHostsFile={}", f.display()));
    }
    // ssh runs the command through the remote shell, so it is passed as
    // one quoted line.
    let mut line: Vec<String> = program.split_whitespace().map(String::from).collect();
    line.extend(args.iter().map(|a| shell_quote(a)));
    if let Some(s) = params.get("remote-store") {
        line.push("--store".into());
        line.push(shell_quote(s));
    }
    c.arg(host).arg("--").arg(line.join(" "));
    Ok(c)
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./=:@%+,".contains(&b)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

impl Connection {
    pub fn open(uri: &StoreUri) -> Result<Connection> {
        let ctx = format!("connecting to '{uri}'");
        let (r, w, child): (Box<dyn Read + Send>, Box<dyn Write + Send>, _) = match &uri.kind {
            UriKind::Unix(p) => {
                let s = UnixStream::connect(p).map_err(|e| format!("cannot connect to socket at '{}': {e}", p.display()))?;
                let s2 = s.try_clone().map_err(ioe(&ctx))?;
                (Box::new(s), Box::new(s2), None)
            }
            UriKind::SshNg { host, port } => {
                let mut c = ssh_command(host, *port, &uri.params, "nix-daemon", &["--stdio"])?;
                let mut child = c
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("{ctx}: running ssh: {e}"))?;
                let out = child.stdout.take().unwrap();
                let inp = child.stdin.take().unwrap();
                (Box::new(out), Box::new(inp), Some(child))
            }
            UriKind::Ssh { .. } => return Err(format!("{ctx}: ssh:// stores speak the serve protocol; use serve::ServeConnection")),
        };
        let mut c = Connection {
            r: BufReader::with_capacity(1 << 16, r),
            w: BufWriter::with_capacity(1 << 16, w),
            version: 0,
            daemon_version: None,
            trusted: None,
            sd: uri.store_dir(),
            log: LogOptions::default(),
            child,
        };
        c.handshake().map_err(|e| format!("{ctx}: {e}"))?;
        Ok(c)
    }

    /// Wraps an existing duplex stream (used by tests and in-process peers).
    pub fn from_streams(r: Box<dyn Read + Send>, w: Box<dyn Write + Send>, sd: StoreDir) -> Result<Connection> {
        let mut c = Connection {
            r: BufReader::new(r),
            w: BufWriter::new(w),
            version: 0,
            daemon_version: None,
            trusted: None,
            sd,
            log: LogOptions::default(),
            child: None,
        };
        c.handshake()?;
        Ok(c)
    }

    fn handshake(&mut self) -> Result<()> {
        let e = ioe("protocol handshake");
        self.w.write_u64(proto::WORKER_MAGIC_1).map_err(&e)?;
        self.w.flush().map_err(&e)?;
        let magic = self.r.read_u64().map_err(|err| {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                "the daemon closed the connection during the handshake (is it running?)".to_string()
            } else {
                e(err)
            }
        })?;
        if magic != proto::WORKER_MAGIC_2 {
            return Err("protocol mismatch: the peer is not a Nix daemon".into());
        }
        let daemon = self.r.read_u64().map_err(&e)?;
        if daemon >> 8 != 1 || minor(daemon) < 21 {
            return Err(format!("daemon protocol version {}.{} is not supported", daemon >> 8, minor(daemon)));
        }
        self.version = daemon.min(proto::PROTOCOL_VERSION);
        self.w.write_u64(proto::PROTOCOL_VERSION).map_err(&e)?;
        if minor(self.version) >= 14 {
            self.w.write_u64(0).map_err(&e)?; // obsolete CPU affinity
        }
        if minor(self.version) >= 11 {
            self.w.write_u64(0).map_err(&e)?; // obsolete reserveSpace
        }
        self.w.flush().map_err(&e)?;
        if minor(self.version) >= 33 {
            self.daemon_version = Some(self.r.read_string().map_err(&e)?);
        }
        if minor(self.version) >= 35 {
            self.trusted = match self.r.read_u64().map_err(&e)? {
                1 => Some(true),
                2 => Some(false),
                _ => None,
            };
        }
        self.stderr()
    }

    /// Consumes log messages until the daemon signals the end of work.
    fn stderr(&mut self) -> Result<()> {
        process_stderr(&mut self.r, self.version, &self.log)
    }

    fn start(&mut self, op: Op) -> Result<&mut BufWriter<Box<dyn Write + Send>>> {
        self.w.write_u64(op as u64).map_err(ioe("sending request"))?;
        Ok(&mut self.w)
    }

    /// Flushes the request and waits for the daemon to finish working.
    fn finish(&mut self) -> Result<&mut BufReader<Box<dyn Read + Send>>> {
        self.w.flush().map_err(ioe("sending request"))?;
        self.stderr()?;
        Ok(&mut self.r)
    }

    fn simple(&mut self, op: Op, args: impl FnOnce(&mut dyn Write, &StoreDir) -> io::Result<()>) -> Result<&mut BufReader<Box<dyn Read + Send>>> {
        let sd = self.sd.clone();
        let w = self.start(op)?;
        args(w, &sd).map_err(ioe("sending request"))?;
        self.finish()
    }

    pub fn set_options(&mut self, opts: &ClientOptions) -> Result<()> {
        let ov: Vec<(String, String)> = opts.overrides.clone();
        self.simple(Op::SetOptions, |w, _| {
            w.write_bool(opts.keep_failed)?;
            w.write_bool(opts.keep_going)?;
            w.write_bool(false)?; // tryFallback
            w.write_u64(opts.verbosity)?;
            w.write_u64(opts.max_jobs)?;
            w.write_u64(0)?; // maxSilentTime
            w.write_bool(true)?; // obsolete useBuildHook
            w.write_u64(if opts.verbose_build { 0 } else { 7 })?;
            w.write_u64(0)?; // obsolete logType
            w.write_u64(0)?; // obsolete printBuildTrace
            w.write_u64(opts.cores)?;
            w.write_bool(opts.use_substitutes)?;
            w.write_u64(ov.len() as u64)?;
            for (k, v) in &ov {
                w.write_str(k)?;
                w.write_str(v)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    pub fn is_valid_path(&mut self, p: &StorePath) -> Result<bool> {
        let r = self.simple(Op::IsValidPath, |w, sd| proto::write_path(w, sd, p))?;
        r.read_bool().map_err(ioe("reading reply"))
    }

    pub fn query_valid_paths(&mut self, ps: &BTreeSet<StorePath>) -> Result<BTreeSet<StorePath>> {
        let v = self.version;
        let sd = self.sd.clone();
        let r = self.simple(Op::QueryValidPaths, |w, sd| {
            proto::write_paths(w, sd, ps)?;
            if minor(v) >= 27 {
                w.write_bool(false)?;
            }
            Ok(())
        })?;
        proto::read_paths(r, &sd).map_err(ioe("reading reply"))
    }

    pub fn query_path_info(&mut self, p: &StorePath) -> Result<Option<PathInfo>> {
        let v = self.version;
        let sd = self.sd.clone();
        let r = self.simple(Op::QueryPathInfo, |w, sd| proto::write_path(w, sd, p))?;
        if !r.read_bool().map_err(ioe("reading reply"))? {
            return Ok(None);
        }
        proto::read_path_info_unkeyed(r, &sd, p.clone(), v).map(Some).map_err(ioe("reading reply"))
    }

    pub fn query_referrers(&mut self, p: &StorePath) -> Result<BTreeSet<StorePath>> {
        let sd = self.sd.clone();
        let r = self.simple(Op::QueryReferrers, |w, sd| proto::write_path(w, sd, p))?;
        proto::read_paths(r, &sd).map_err(ioe("reading reply"))
    }

    pub fn query_derivation_output_map(&mut self, drv: &StorePath) -> Result<BTreeMap<String, Option<StorePath>>> {
        let sd = self.sd.clone();
        let r = self.simple(Op::QueryDerivationOutputMap, |w, sd| proto::write_path(w, sd, drv))?;
        let n = r.read_u64().map_err(ioe("reading reply"))?;
        let mut m = BTreeMap::new();
        for _ in 0..n {
            let name = r.read_string().map_err(ioe("reading reply"))?;
            m.insert(name, proto::read_opt_path(r, &sd).map_err(ioe("reading reply"))?);
        }
        Ok(m)
    }

    /// `(will build, will substitute, unknown, download size, NAR size)`.
    pub fn query_missing(&mut self, targets: &[DerivedPath]) -> Result<(BTreeSet<StorePath>, BTreeSet<StorePath>, BTreeSet<StorePath>, u64, u64)> {
        let sd = self.sd.clone();
        let r = self.simple(Op::QueryMissing, |w, sd| proto::write_derived_paths(w, sd, targets))?;
        let e = ioe("reading reply");
        Ok((
            proto::read_paths(r, &sd).map_err(&e)?,
            proto::read_paths(r, &sd).map_err(&e)?,
            proto::read_paths(r, &sd).map_err(&e)?,
            r.read_u64().map_err(&e)?,
            r.read_u64().map_err(&e)?,
        ))
    }

    pub fn add_temp_root(&mut self, p: &StorePath) -> Result<()> {
        let r = self.simple(Op::AddTempRoot, |w, sd| proto::write_path(w, sd, p))?;
        r.read_u64().map_err(ioe("reading reply"))?;
        Ok(())
    }

    pub fn add_indirect_root(&mut self, link: &str) -> Result<()> {
        let r = self.simple(Op::AddIndirectRoot, |w, _| w.write_str(link))?;
        r.read_u64().map_err(ioe("reading reply"))?;
        Ok(())
    }

    pub fn ensure_path(&mut self, p: &StorePath) -> Result<()> {
        let r = self.simple(Op::EnsurePath, |w, sd| proto::write_path(w, sd, p))?;
        r.read_u64().map_err(ioe("reading reply"))?;
        Ok(())
    }

    /// Link (or `{temp:…}` placeholder) to store path for every GC root.
    pub fn find_roots(&mut self) -> Result<Vec<(String, StorePath)>> {
        let sd = self.sd.clone();
        let r = self.simple(Op::FindRoots, |_, _| Ok(()))?;
        let n = r.read_u64().map_err(ioe("reading reply"))?;
        let mut v = Vec::new();
        for _ in 0..n {
            let link = r.read_string().map_err(ioe("reading reply"))?;
            v.push((link, proto::read_path(r, &sd).map_err(ioe("reading reply"))?));
        }
        Ok(v)
    }

    /// Runs the collector with Nix's `GCAction` numbering: 0 returns live
    /// paths, 1 dead ones, 2 deletes the dead, 3 deletes `paths`.
    pub fn collect_garbage(&mut self, action: u64, paths: &BTreeSet<StorePath>, max_freed: u64) -> Result<(Vec<String>, u64)> {
        let r = self.simple(Op::CollectGarbage, |w, sd| {
            w.write_u64(action)?;
            proto::write_paths(w, sd, paths)?;
            w.write_bool(false)?;
            w.write_u64(max_freed)?;
            for _ in 0..3 {
                w.write_u64(0)?;
            }
            Ok(())
        })?;
        let e = ioe("reading reply");
        let paths = r.read_strings().map_err(&e)?;
        let freed = r.read_u64().map_err(&e)?;
        r.read_u64().map_err(&e)?;
        Ok((paths, freed))
    }

    pub fn build_paths(&mut self, targets: &[DerivedPath], mode: u64) -> Result<()> {
        let r = self.simple(Op::BuildPaths, |w, sd| {
            proto::write_derived_paths(w, sd, targets)?;
            w.write_u64(mode)
        })?;
        r.read_u64().map_err(ioe("reading reply"))?;
        Ok(())
    }

    /// `BuildPathsWithResults`, emulated with `BuildPaths` and output map
    /// queries on daemons older than protocol 1.34.
    pub fn build_paths_with_results(&mut self, targets: &[DerivedPath]) -> Result<Vec<(DerivedPath, BuildResult)>> {
        if minor(self.version) < 34 {
            self.build_paths(targets, 0)?;
            let mut out = Vec::new();
            for t in targets {
                let mut res = BuildResult::new(proto::BuildStatus::Built);
                if let DerivedPath::Built { drv, outputs } = t {
                    for (name, p) in self.query_derivation_output_map(drv)? {
                        if outputs.as_ref().map_or(true, |o| o.contains(&name)) {
                            if let Some(p) = p {
                                res.built_outputs.insert(name.clone(), proto::Realisation::new(format!("!{name}"), p));
                            }
                        }
                    }
                }
                out.push((t.clone(), res));
            }
            return Ok(out);
        }
        let v = self.version;
        let sd = self.sd.clone();
        let r = self.simple(Op::BuildPathsWithResults, |w, sd| {
            proto::write_derived_paths(w, sd, targets)?;
            w.write_u64(0)
        })?;
        let e = ioe("reading reply");
        let n = r.read_u64().map_err(&e)?;
        let mut out = Vec::new();
        for _ in 0..n {
            let p = DerivedPath::parse(&sd, &r.read_string().map_err(&e)?)?;
            out.push((p, BuildResult::read(r, v).map_err(&e)?));
        }
        Ok(out)
    }

    pub fn build_derivation(&mut self, drv_path: &StorePath, drv: &Derivation) -> Result<BuildResult> {
        let v = self.version;
        let r = self.simple(Op::BuildDerivation, |w, sd| {
            proto::write_path(w, sd, drv_path)?;
            proto::write_basic_derivation(w, sd, drv)?;
            w.write_u64(0)
        })?;
        BuildResult::read(r, v).map_err(ioe("reading build result"))
    }

    /// Streams the NAR of `p` into `out`.
    pub fn nar_from_path(&mut self, p: &StorePath, out: &mut dyn Write) -> Result<()> {
        let r = self.simple(Op::NarFromPath, |w, sd| proto::write_path(w, sd, p))?;
        crate::wire::copy_nar(r, out).map_err(ioe("receiving NAR"))
    }

    /// Uploads one path from its NAR.
    pub fn add_to_store_nar(&mut self, info: &PathInfo, nar: &mut (dyn Read + Send), check_sigs: bool) -> Result<()> {
        let v = self.version;
        let sd = self.sd.clone();
        let w = self.start(Op::AddToStoreNar)?;
        (|| {
            proto::write_path(w, &sd, &info.path)?;
            proto::write_path_info_unkeyed(w, &sd, info, v.max(1 << 8 | 16))?;
            w.write_bool(false)?; // repair
            w.write_bool(!check_sigs)
        })()
        .map_err(ioe("sending request"))?;
        self.framed(|f| io::copy(nar, f).map(|_| ()))
    }

    /// Uploads several paths in one framed stream; `paths` must be in
    /// dependency order. Each NAR is produced by `nar_of`.
    pub fn add_multiple_to_store(
        &mut self,
        paths: &[PathInfo],
        nar_of: &(dyn Fn(&PathInfo, &mut dyn Write) -> io::Result<()> + Sync),
        check_sigs: bool,
    ) -> Result<()> {
        if minor(self.version) < 32 {
            for info in paths {
                let mut buf = Vec::new();
                nar_of(info, &mut buf).map_err(ioe("archiving path"))?;
                self.add_to_store_nar(info, &mut &buf[..], check_sigs)?;
            }
            return Ok(());
        }
        let sd = self.sd.clone();
        let w = self.start(Op::AddMultipleToStore)?;
        (|| {
            w.write_bool(false)?;
            w.write_bool(!check_sigs)
        })()
        .map_err(ioe("sending request"))?;
        self.framed(|f| {
            f.write_u64(paths.len() as u64)?;
            for info in paths {
                proto::write_path_info(f, &sd, info, 1 << 8 | 16)?;
                nar_of(info, f)?;
            }
            Ok(())
        })
    }

    /// Sends `body` as a framed stream while reading the daemon's log
    /// messages, so a daemon that logs while receiving cannot deadlock us.
    fn framed(&mut self, body: impl FnOnce(&mut FramedWriter<'_, BufWriter<Box<dyn Write + Send>>>) -> io::Result<()> + Send) -> Result<()> {
        self.w.flush().map_err(ioe("sending request"))?;
        let (r, w, v, log) = (&mut self.r, &mut self.w, self.version, &self.log);
        let (sent, got) = std::thread::scope(|s| {
            let h = s.spawn(move || {
                let mut f = FramedWriter::new(w);
                body(&mut f)?;
                f.finish()
            });
            let got = process_stderr(r, v, log);
            (h.join().unwrap_or_else(|_| Err(io::Error::other("sender panicked"))), got)
        });
        got?;
        sent.map_err(ioe("sending data"))
    }
}

/// Options sent with `SetOptions`.
#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub keep_failed: bool,
    pub keep_going: bool,
    pub verbosity: u64,
    pub max_jobs: u64,
    pub cores: u64,
    pub verbose_build: bool,
    pub use_substitutes: bool,
    pub overrides: Vec<(String, String)>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            keep_failed: false,
            keep_going: false,
            verbosity: 3,
            max_jobs: 1,
            cores: 0,
            verbose_build: false,
            use_substitutes: true,
            overrides: Vec::new(),
        }
    }
}

fn process_stderr(r: &mut (impl Read + ?Sized), version: u64, log: &LogOptions) -> Result<()> {
    let e = ioe("reading from the daemon");
    let print = |s: &str| {
        let s = s.strip_suffix('\n').unwrap_or(s);
        match &log.sink {
            Some(f) => f(s),
            None => eprintln!("{}{s}", log.prefix),
        }
    };
    loop {
        match r.read_u64().map_err(&e)? {
            proto::STDERR_LAST => return Ok(()),
            proto::STDERR_NEXT => print(&r.read_string().map_err(&e)?),
            proto::STDERR_ERROR => return Err(proto::read_error(r, version).map_err(&e)?),
            proto::STDERR_START_ACTIVITY => {
                let _id = r.read_u64().map_err(&e)?;
                let level = r.read_u64().map_err(&e)?;
                let _ty = r.read_u64().map_err(&e)?;
                let text = r.read_string().map_err(&e)?;
                proto::read_fields(r).map_err(&e)?;
                let _parent = r.read_u64().map_err(&e)?;
                if level <= 3 && !text.is_empty() && log.sink.is_none() {
                    print(&text);
                }
            }
            proto::STDERR_STOP_ACTIVITY => {
                r.read_u64().map_err(&e)?;
            }
            proto::STDERR_RESULT => {
                let _id = r.read_u64().map_err(&e)?;
                let ty = r.read_u64().map_err(&e)?;
                let fields = proto::read_fields(r).map_err(&e)?;
                if ty == proto::RES_BUILD_LOG_LINE && (log.build_logs || log.sink.is_some()) {
                    if let Some(Field::Str(s)) = fields.first() {
                        print(s);
                    }
                }
            }
            proto::STDERR_READ | proto::STDERR_WRITE => {
                return Err("the daemon asked for an unsupported legacy data transfer".into());
            }
            m => return Err(format!("unexpected message {m:#x} from the daemon")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uris() {
        let u = StoreUri::parse("unix:///tmp/x.sock?store=/tmp/s").unwrap();
        assert_eq!(u.kind, UriKind::Unix("/tmp/x.sock".into()));
        assert_eq!(u.store_dir().as_str(), "/tmp/s");
        let u = StoreUri::parse("ssh-ng://me@host:2222?remote-program=cranix%20daemon").unwrap();
        assert_eq!(u.kind, UriKind::SshNg { host: "me@host".into(), port: Some(2222) });
        assert_eq!(u.params["remote-program"], "cranix daemon");
        assert!(StoreUri::parse("/some/dir").is_none());
        assert!(matches!(StoreUri::parse("daemon").unwrap().kind, UriKind::Unix(_)));
    }
}
