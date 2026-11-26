//! Messages of the Nix worker protocol (the protocol `nix-daemon` speaks
//! over its socket and over `--stdio`), up to protocol version 1.37.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};

use cranix_core::hash::{Hash, HashAlgo};
use cranix_core::{Derivation, Output, StoreDir, StorePath};
use cranix_store::PathInfo;

use crate::wire::{bad, ReadExt, WriteExt};

pub const WORKER_MAGIC_1: u64 = 0x6e697863;
pub const WORKER_MAGIC_2: u64 = 0x6478696f;
pub const PROTOCOL_VERSION: u64 = 1 << 8 | 37;
/// Oldest client version served; 1.23 introduced framed NAR transfers,
/// which every operation here relies on.
pub const MIN_CLIENT_VERSION: u64 = 1 << 8 | 23;

/// The Nix release whose protocol this implements, reported to clients.
pub const NIX_VERSION: &str = "2.24.10";

pub fn minor(v: u64) -> u64 {
    v & 0xff
}

pub const STDERR_NEXT: u64 = 0x6f6c6d67;
pub const STDERR_READ: u64 = 0x64617461;
pub const STDERR_WRITE: u64 = 0x64617416;
pub const STDERR_LAST: u64 = 0x616c7473;
pub const STDERR_ERROR: u64 = 0x63787470;
pub const STDERR_START_ACTIVITY: u64 = 0x53545254;
pub const STDERR_STOP_ACTIVITY: u64 = 0x53544f50;
pub const STDERR_RESULT: u64 = 0x52534c54;

/// Activity result type carrying one line of build output.
pub const RES_BUILD_LOG_LINE: u64 = 101;

macro_rules! ops {
    ($($name:ident = $n:expr,)*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Op { $($name = $n,)* }
        impl Op {
            pub fn from_u64(n: u64) -> Option<Op> {
                match n { $($n => Some(Op::$name),)* _ => None }
            }
        }
    };
}

ops! {
    IsValidPath = 1,
    HasSubstitutes = 3,
    QueryPathHash = 4,
    QueryReferences = 5,
    QueryReferrers = 6,
    AddToStore = 7,
    AddTextToStore = 8,
    BuildPaths = 9,
    EnsurePath = 10,
    AddTempRoot = 11,
    AddIndirectRoot = 12,
    SyncWithGC = 13,
    FindRoots = 14,
    ExportPath = 16,
    QueryDeriver = 18,
    SetOptions = 19,
    CollectGarbage = 20,
    QuerySubstitutablePathInfo = 21,
    QueryDerivationOutputs = 22,
    QueryAllValidPaths = 23,
    QueryFailedPaths = 24,
    ClearFailedPaths = 25,
    QueryPathInfo = 26,
    ImportPaths = 27,
    QueryDerivationOutputNames = 28,
    QueryPathFromHashPart = 29,
    QuerySubstitutablePathInfos = 30,
    QueryValidPaths = 31,
    QuerySubstitutablePaths = 32,
    QueryValidDerivers = 33,
    OptimiseStore = 34,
    VerifyStore = 35,
    BuildDerivation = 36,
    AddSignatures = 37,
    NarFromPath = 38,
    AddToStoreNar = 39,
    QueryMissing = 40,
    QueryDerivationOutputMap = 41,
    RegisterDrvOutput = 42,
    QueryRealisation = 43,
    AddMultipleToStore = 44,
    AddBuildLog = 45,
    BuildPathsWithResults = 46,
    AddPermRoot = 47,
}

/// Store paths travel as their printed absolute form.
pub fn read_path(r: &mut (impl Read + ?Sized), sd: &StoreDir) -> io::Result<StorePath> {
    let s = r.read_string()?;
    sd.parse(&s).map_err(bad)
}

pub fn read_opt_path(r: &mut (impl Read + ?Sized), sd: &StoreDir) -> io::Result<Option<StorePath>> {
    let s = r.read_string()?;
    if s.is_empty() {
        Ok(None)
    } else {
        sd.parse(&s).map(Some).map_err(bad)
    }
}

pub fn read_paths(r: &mut (impl Read + ?Sized), sd: &StoreDir) -> io::Result<BTreeSet<StorePath>> {
    let n = r.read_u64()?;
    (0..n).map(|_| read_path(r, sd)).collect()
}

pub fn write_path(w: &mut (impl Write + ?Sized), sd: &StoreDir, p: &StorePath) -> io::Result<()> {
    w.write_str(&sd.print(p))
}

pub fn write_opt_path(w: &mut (impl Write + ?Sized), sd: &StoreDir, p: Option<&StorePath>) -> io::Result<()> {
    w.write_str(&p.map(|p| sd.print(p)).unwrap_or_default())
}

pub fn write_paths<'a>(
    w: &mut (impl Write + ?Sized),
    sd: &StoreDir,
    ps: impl IntoIterator<Item = &'a StorePath>,
) -> io::Result<()> {
    let ps: Vec<&StorePath> = ps.into_iter().collect();
    w.write_u64(ps.len() as u64)?;
    for p in ps {
        write_path(w, sd, p)?;
    }
    Ok(())
}

/// `ValidPathInfo` without its path. Signatures, the registration time and
/// the `ultimate` flag are not tracked by the store, so they are written
/// as empty and dropped on reading.
pub fn write_path_info_unkeyed(w: &mut (impl Write + ?Sized), sd: &StoreDir, info: &PathInfo, version: u64) -> io::Result<()> {
    write_opt_path(w, sd, info.deriver.as_ref())?;
    w.write_str(&info.nar_hash.to_base16())?;
    write_paths(w, sd, &info.references)?;
    w.write_u64(0)?;
    w.write_u64(info.nar_size)?;
    if minor(version) >= 16 {
        w.write_bool(false)?;
        w.write_u64(0)?;
        w.write_str(info.ca.as_deref().unwrap_or(""))?;
    }
    Ok(())
}

pub fn read_path_info_unkeyed(r: &mut (impl Read + ?Sized), sd: &StoreDir, path: StorePath, version: u64) -> io::Result<PathInfo> {
    let deriver = read_opt_path(r, sd)?;
    let nar_hash = Hash::parse(&r.read_string()?, Some(HashAlgo::Sha256)).map_err(bad)?;
    let references = read_paths(r, sd)?;
    let _registration_time = r.read_u64()?;
    let nar_size = r.read_u64()?;
    let mut ca = None;
    if minor(version) >= 16 {
        let _ultimate = r.read_bool()?;
        let _sigs = r.read_strings()?;
        let s = r.read_string()?;
        if !s.is_empty() {
            ca = Some(s);
        }
    }
    Ok(PathInfo { path, nar_hash, nar_size, references, deriver, ca })
}

pub fn write_path_info(w: &mut (impl Write + ?Sized), sd: &StoreDir, info: &PathInfo, version: u64) -> io::Result<()> {
    write_path(w, sd, &info.path)?;
    write_path_info_unkeyed(w, sd, info, version)
}

pub fn read_path_info(r: &mut (impl Read + ?Sized), sd: &StoreDir, version: u64) -> io::Result<PathInfo> {
    let p = read_path(r, sd)?;
    read_path_info_unkeyed(r, sd, p, version)
}

/// What `BuildPaths` and friends are asked to realise: a store path, or
/// outputs of a derivation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DerivedPath {
    Opaque(StorePath),
    /// `None` selects all outputs (`drv!*`).
    Built { drv: StorePath, outputs: Option<BTreeSet<String>> },
}

impl DerivedPath {
    /// Parses the legacy form `/nix/store/…drv!out,dev`; `^` is accepted
    /// as the separator too.
    pub fn parse(sd: &StoreDir, s: &str) -> Result<DerivedPath, String> {
        match s.rfind(['!', '^']) {
            Some(i) if s[..i].ends_with(".drv") => {
                let drv = sd.parse(&s[..i])?;
                let outs = &s[i + 1..];
                let outputs = if outs == "*" { None } else { Some(outs.split(',').map(String::from).collect()) };
                Ok(DerivedPath::Built { drv, outputs })
            }
            _ => Ok(DerivedPath::Opaque(sd.parse(s)?)),
        }
    }

    pub fn render(&self, sd: &StoreDir) -> String {
        match self {
            DerivedPath::Opaque(p) => sd.print(p),
            DerivedPath::Built { drv, outputs: None } => format!("{}!*", sd.print(drv)),
            DerivedPath::Built { drv, outputs: Some(o) } => {
                format!("{}!{}", sd.print(drv), o.iter().cloned().collect::<Vec<_>>().join(","))
            }
        }
    }
}

pub fn read_derived_paths(r: &mut (impl Read + ?Sized), sd: &StoreDir) -> io::Result<Vec<DerivedPath>> {
    r.read_strings()?.iter().map(|s| DerivedPath::parse(sd, s).map_err(bad)).collect()
}

pub fn write_derived_paths(w: &mut (impl Write + ?Sized), sd: &StoreDir, ps: &[DerivedPath]) -> io::Result<()> {
    let v: Vec<String> = ps.iter().map(|p| p.render(sd)).collect();
    w.write_strings(v.iter().map(String::as_str))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildStatus {
    Built = 0,
    Substituted = 1,
    AlreadyValid = 2,
    PermanentFailure = 3,
    InputRejected = 4,
    OutputRejected = 5,
    TransientFailure = 6,
    CachedFailure = 7,
    TimedOut = 8,
    MiscFailure = 9,
    DependencyFailed = 10,
    LogLimitExceeded = 11,
    NotDeterministic = 12,
    ResolvesToAlreadyValid = 13,
    NoSubstituters = 14,
}

impl BuildStatus {
    pub fn from_u64(n: u64) -> BuildStatus {
        use BuildStatus::*;
        [
            Built,
            Substituted,
            AlreadyValid,
            PermanentFailure,
            InputRejected,
            OutputRejected,
            TransientFailure,
            CachedFailure,
            TimedOut,
            MiscFailure,
            DependencyFailed,
            LogLimitExceeded,
            NotDeterministic,
            ResolvesToAlreadyValid,
            NoSubstituters,
        ]
        .get(n as usize)
        .copied()
        .unwrap_or(MiscFailure)
    }

    pub fn success(self) -> bool {
        matches!(self, BuildStatus::Built | BuildStatus::Substituted | BuildStatus::AlreadyValid | BuildStatus::ResolvesToAlreadyValid)
    }
}

/// A built output: its realisation id is `<drv hash modulo>!<output>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Realisation {
    pub id: String,
    pub out_path: StorePath,
}

impl Realisation {
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "id": self.id,
            "outPath": self.out_path.base_name(),
            "signatures": [],
            "dependentRealisations": {},
        })
        .to_string()
    }

    pub fn from_json(s: &str) -> io::Result<Realisation> {
        let v: serde_json::Value = serde_json::from_str(s).map_err(|e| bad(format!("invalid realisation: {e}")))?;
        let id = v["id"].as_str().ok_or_else(|| bad("realisation without id"))?.to_string();
        let out = v["outPath"].as_str().ok_or_else(|| bad("realisation without outPath"))?;
        let base = out.rsplit('/').next().unwrap_or(out);
        Ok(Realisation { id, out_path: StorePath::from_base_name(base).map_err(bad)? })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildResult {
    pub status: BuildStatus,
    pub error_msg: String,
    pub times_built: u64,
    pub is_non_deterministic: bool,
    pub start_time: u64,
    pub stop_time: u64,
    /// Output name to realisation.
    pub built_outputs: BTreeMap<String, Realisation>,
}

impl BuildResult {
    pub fn new(status: BuildStatus) -> BuildResult {
        BuildResult {
            status,
            error_msg: String::new(),
            times_built: 0,
            is_non_deterministic: false,
            start_time: 0,
            stop_time: 0,
            built_outputs: BTreeMap::new(),
        }
    }

    pub fn failure(msg: String) -> BuildResult {
        BuildResult { error_msg: msg, ..BuildResult::new(BuildStatus::MiscFailure) }
    }

    pub fn write(&self, w: &mut (impl Write + ?Sized), version: u64) -> io::Result<()> {
        w.write_u64(self.status as u64)?;
        w.write_str(&self.error_msg)?;
        if minor(version) >= 29 {
            w.write_u64(self.times_built)?;
            w.write_bool(self.is_non_deterministic)?;
            w.write_u64(self.start_time)?;
            w.write_u64(self.stop_time)?;
        }
        if minor(version) >= 37 {
            // cpuUser and cpuSystem, both absent.
            w.write_u64(0)?;
            w.write_u64(0)?;
        }
        if minor(version) >= 28 {
            w.write_u64(self.built_outputs.len() as u64)?;
            for r in self.built_outputs.values() {
                w.write_str(&r.id)?;
                w.write_str(&r.to_json())?;
            }
        }
        Ok(())
    }

    pub fn read(r: &mut (impl Read + ?Sized), version: u64) -> io::Result<BuildResult> {
        let mut res = BuildResult::new(BuildStatus::from_u64(r.read_u64()?));
        res.error_msg = r.read_string()?;
        if minor(version) >= 29 {
            res.times_built = r.read_u64()?;
            res.is_non_deterministic = r.read_bool()?;
            res.start_time = r.read_u64()?;
            res.stop_time = r.read_u64()?;
        }
        if minor(version) >= 37 {
            for _ in 0..2 {
                if r.read_bool()? {
                    r.read_u64()?;
                }
            }
        }
        if minor(version) >= 28 {
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
}

/// A derivation without its input derivations (`BasicDerivation`), as sent
/// with `BuildDerivation`; the sender lists all input paths in `inputSrcs`.
pub fn write_basic_derivation(w: &mut (impl Write + ?Sized), sd: &StoreDir, d: &Derivation) -> io::Result<()> {
    w.write_u64(d.outputs.len() as u64)?;
    for (name, o) in &d.outputs {
        w.write_str(name)?;
        write_opt_path(w, sd, o.path.as_ref())?;
        w.write_str(&o.hash_algo)?;
        w.write_str(&o.hash)?;
    }
    write_paths(w, sd, &d.input_srcs)?;
    w.write_str(&d.platform)?;
    w.write_str(&d.builder)?;
    w.write_strings(d.args.iter().map(String::as_str))?;
    w.write_u64(d.env.len() as u64)?;
    for (k, v) in &d.env {
        w.write_str(k)?;
        w.write_str(v)?;
    }
    Ok(())
}

pub fn read_basic_derivation(r: &mut (impl Read + ?Sized), sd: &StoreDir, name: &str) -> io::Result<Derivation> {
    let mut d = Derivation { name: name.to_string(), ..Default::default() };
    let n = r.read_u64()?;
    for _ in 0..n {
        let out = r.read_string()?;
        let path = read_opt_path(r, sd)?;
        let hash_algo = r.read_string()?;
        let hash = r.read_string()?;
        d.outputs.insert(out, Output { path, hash_algo, hash });
    }
    d.input_srcs = read_paths(r, sd)?;
    d.platform = r.read_string()?;
    d.builder = r.read_string()?;
    d.args = r.read_strings()?;
    let n = r.read_u64()?;
    for _ in 0..n {
        let k = r.read_string()?;
        let v = r.read_string()?;
        d.env.insert(k, v);
    }
    Ok(d)
}

/// `STDERR_ERROR` payload in the structured form of protocol 1.26 on.
pub fn write_error(w: &mut (impl Write + ?Sized), msg: &str, version: u64) -> io::Result<()> {
    w.write_u64(STDERR_ERROR)?;
    if minor(version) >= 26 {
        w.write_str("Error")?;
        w.write_u64(0)?; // lvlError
        w.write_str("Error")?;
        w.write_str(msg)?;
        w.write_u64(0)?; // no position
        w.write_u64(0)?; // no traces
    } else {
        w.write_str(msg)?;
        w.write_u64(1)?;
    }
    Ok(())
}

pub fn read_error(r: &mut (impl Read + ?Sized), version: u64) -> io::Result<String> {
    if minor(version) >= 26 {
        let _ty = r.read_string()?;
        let _level = r.read_u64()?;
        let _name = r.read_string()?;
        let mut msg = r.read_string()?;
        if r.read_bool()? {
            return Err(bad("error positions on the wire are not supported"));
        }
        let traces = r.read_u64()?;
        for _ in 0..traces {
            if r.read_bool()? {
                return Err(bad("error positions on the wire are not supported"));
            }
            msg.push_str("\n… ");
            msg.push_str(&r.read_string()?);
        }
        Ok(msg)
    } else {
        let msg = r.read_string()?;
        let _status = r.read_u64()?;
        Ok(msg)
    }
}

/// Typed activity fields: 0 is an integer, 1 a string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Field {
    Int(u64),
    Str(String),
}

pub fn read_fields(r: &mut (impl Read + ?Sized)) -> io::Result<Vec<Field>> {
    let n = r.read_u64()?;
    (0..n)
        .map(|_| match r.read_u64()? {
            0 => Ok(Field::Int(r.read_u64()?)),
            1 => Ok(Field::Str(r.read_string()?)),
            t => Err(bad(format!("unknown activity field type {t}"))),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cranix_core::StoreDir;

    fn sd() -> StoreDir {
        StoreDir::default()
    }

    fn sp(s: &str) -> StorePath {
        StorePath::from_base_name(s).unwrap()
    }

    #[test]
    fn path_info_roundtrip() {
        let info = PathInfo {
            path: sp("g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-foo"),
            nar_hash: Hash::sha256(b"x"),
            nar_size: 120,
            references: [sp("00000000000000000000000000000000-bar")].into(),
            deriver: Some(sp("11111111111111111111111111111111-foo.drv")),
            ca: Some("fixed:r:sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s".into()),
        };
        for v in [PROTOCOL_VERSION, 1 << 8 | 15] {
            let mut buf = Vec::new();
            write_path_info(&mut buf, &sd(), &info, v).unwrap();
            let got = read_path_info(&mut &buf[..], &sd(), v).unwrap();
            let want = if minor(v) >= 16 { info.clone() } else { PathInfo { ca: None, ..info.clone() } };
            assert_eq!(got, want);
        }
    }

    #[test]
    fn derived_paths() {
        let s = "/nix/store/11111111111111111111111111111111-foo.drv!dev,out";
        let p = DerivedPath::parse(&sd(), s).unwrap();
        assert_eq!(
            p,
            DerivedPath::Built {
                drv: sp("11111111111111111111111111111111-foo.drv"),
                outputs: Some(["out".to_string(), "dev".to_string()].into())
            }
        );
        assert_eq!(p.render(&sd()), s);
        let all = DerivedPath::parse(&sd(), "/nix/store/11111111111111111111111111111111-foo.drv^*").unwrap();
        assert_eq!(all.render(&sd()), "/nix/store/11111111111111111111111111111111-foo.drv!*");
        let o = "/nix/store/00000000000000000000000000000000-bar";
        assert_eq!(DerivedPath::parse(&sd(), o).unwrap(), DerivedPath::Opaque(sp("00000000000000000000000000000000-bar")));
    }

    #[test]
    fn build_result_roundtrip() {
        let mut res = BuildResult::new(BuildStatus::Built);
        res.times_built = 1;
        res.start_time = 5;
        res.stop_time = 7;
        res.built_outputs.insert(
            "out".into(),
            Realisation { id: format!("{}!out", Hash::sha256(b"d")), out_path: sp("00000000000000000000000000000000-bar") },
        );
        for v in [PROTOCOL_VERSION, 1 << 8 | 36, 1 << 8 | 28] {
            let mut buf = Vec::new();
            res.write(&mut buf, v).unwrap();
            let mut r = &buf[..];
            let got = BuildResult::read(&mut r, v).unwrap();
            assert!(r.is_empty());
            if minor(v) >= 29 {
                assert_eq!(got, res);
            } else {
                assert_eq!(got.built_outputs, res.built_outputs);
            }
        }
    }

    #[test]
    fn basic_derivation_roundtrip() {
        let mut d = Derivation { name: "foo".into(), platform: "x86_64-linux".into(), builder: "/bin/sh".into(), ..Default::default() };
        d.args = vec!["-c".into(), "echo > $out".into()];
        d.outputs.insert("out".into(), Output { path: Some(sp("00000000000000000000000000000000-foo")), ..Default::default() });
        d.input_srcs.insert(sp("11111111111111111111111111111111-src"));
        d.env.insert("out".into(), "/nix/store/00000000000000000000000000000000-foo".into());
        let mut buf = Vec::new();
        write_basic_derivation(&mut buf, &sd(), &d).unwrap();
        assert_eq!(read_basic_derivation(&mut &buf[..], &sd(), "foo").unwrap(), d);
    }

    #[test]
    fn error_roundtrip() {
        for v in [PROTOCOL_VERSION, 1 << 8 | 25] {
            let mut buf = Vec::new();
            write_error(&mut buf, "boom", v).unwrap();
            let mut r = &buf[..];
            assert_eq!(r.read_u64().unwrap(), STDERR_ERROR);
            assert_eq!(read_error(&mut r, v).unwrap(), "boom");
            assert!(r.is_empty());
        }
    }
}
