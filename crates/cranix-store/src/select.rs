//! Choosing what goes into a binary cache, shared by `copy --to` and
//! uploads while building.
//!
//! A [`Filter`] names the kinds of paths to take from the derivation graph
//! of the given roots ([`PathType`]) and the paths to leave out:
//!
//! - outputs of fixed-output derivations that fetch from given hosts;
//! - derivations whose name matches a pattern, or that belong to a
//!   [`Class`], together with every derivation built from them;
//! - derivations meant to be built locally (`preferLocalBuild = true` or
//!   `allowSubstitutes = false`), except downloads (fixed-output
//!   derivations), which nixpkgs' fetchers also mark;
//! - paths missing from the local store.
//!
//! Each chosen path goes up with its runtime closure, and a path whose
//! closure holds a left-out path is left out as well, so the cache only
//! ever holds complete closures.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::Mutex;

use cranix_core::{Derivation, StorePath};

use crate::{Result, Store};

/// The kinds of paths in a derivation graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathType {
    /// A path with no derivation, such as a source added by evaluation.
    Source,
    /// Any `.drv` file.
    Drv,
    /// Any output of a derivation.
    DrvOutPath,
    FixedOutputDrv,
    FixedOutputOutPath,
    /// A derivation that is not fixed-output.
    BuildDrv,
    BuildOutPath,
    /// A derivation given as a root, or the deriver of a root.
    ToplevelDrv,
}

impl PathType {
    pub const ALL: [PathType; 8] = [
        PathType::Source,
        PathType::Drv,
        PathType::DrvOutPath,
        PathType::FixedOutputDrv,
        PathType::FixedOutputOutPath,
        PathType::BuildDrv,
        PathType::BuildOutPath,
        PathType::ToplevelDrv,
    ];

    pub fn name(self) -> &'static str {
        match self {
            PathType::Source => "source",
            PathType::Drv => "drv",
            PathType::DrvOutPath => "drv-out-path",
            PathType::FixedOutputDrv => "fixed-output-drv",
            PathType::FixedOutputOutPath => "fixed-output-out-path",
            PathType::BuildDrv => "build-drv",
            PathType::BuildOutPath => "build-out-path",
            PathType::ToplevelDrv => "toplevel-drv",
        }
    }

    pub fn parse(s: &str) -> Result<PathType> {
        PathType::ALL.into_iter().find(|t| t.name() == s).ok_or_else(|| {
            let names: Vec<&str> = PathType::ALL.iter().map(|t| t.name()).collect();
            format!("unknown path type '{s}'; use one of {}", names.join(", "))
        })
    }
}

/// Groups of derivations recognised by name. A derivation of a class and
/// everything built from it are left out together.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// The parts of one machine's system: its toplevel, generated units
    /// and `/etc`, initrds and images.
    System,
    /// NixOS tests and test suites.
    Test,
}

const SYSTEM_PATTERNS: &[&str] = &[
    "nixos-system-*",
    "darwin-system-*",
    "system-path",
    "system-units",
    "user-units",
    "system-generators",
    "system-shutdown",
    "etc",
    "etc-*",
    "unit-*",
    "initrd*",
    "*-initrd",
    "*-image",
    "*-image-*",
    "*.img",
    "*.iso",
    "nixos-*.qcow2",
    "X-Restart-Triggers-*",
    "X-Reload-Triggers-*",
    "*.pam",
    "udev-rules",
    "extra-udev-rules",
    "extra-hwdb-file",
    "tmpfiles.d",
    "nixos-tmpfiles.d",
    "sysupdate.d",
    "security-wrapper-*",
];

const TEST_PATTERNS: &[&str] = &["vm-test-run-*", "nixos-test-driver*", "nixos-test-*", "*-test", "*-tests"];

impl Class {
    pub fn parse(s: &str) -> Result<Class> {
        match s {
            "system" => Ok(Class::System),
            "test" => Ok(Class::Test),
            _ => Err(format!("unknown closure class '{s}'; use 'system' or 'test'")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Class::System => "system",
            Class::Test => "test",
        }
    }

    pub fn patterns(self) -> &'static [&'static str] {
        match self {
            Class::System => SYSTEM_PATTERNS,
            Class::Test => TEST_PATTERNS,
        }
    }
}

/// What to take and what to leave out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    /// The kinds of paths to take from the derivation graph of the roots;
    /// empty takes the roots themselves.
    pub types: BTreeSet<PathType>,
    /// Host patterns of fixed-output downloads to leave out.
    pub hosts: Vec<String>,
    /// Name patterns of derivations to leave out with their dependents.
    pub names: Vec<String>,
    pub classes: BTreeSet<Class>,
    /// Leave out derivations meant to be built locally.
    pub local: bool,
}

impl Filter {
    pub fn is_empty(&self) -> bool {
        *self == Filter::default()
    }

    /// Adds the comma- or space-separated `types`.
    pub fn add_types(&mut self, types: &str) -> Result<()> {
        for t in types.split([',', ' ']).filter(|t| !t.is_empty()) {
            self.types.insert(PathType::parse(t)?);
        }
        Ok(())
    }

    pub fn add_classes(&mut self, classes: &str) -> Result<()> {
        for c in classes.split([',', ' ']).filter(|c| !c.is_empty()) {
            self.classes.insert(Class::parse(c)?);
        }
        Ok(())
    }
}

/// Why a path was left out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    Missing,
    Host { drv: String, host: String },
    Name { drv: String, pattern: String },
    Class { drv: String, class: Class },
    Local { drv: String },
    /// Built from a derivation left out for `why`.
    DependsOn { drv: String, why: Box<Reason> },
    /// Its closure holds a left-out path.
    Refers { path: String },
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Missing => write!(f, "not in the local store"),
            Reason::Host { drv, host } => write!(f, "'{drv}' downloads from '{host}'"),
            Reason::Name { drv, pattern } => write!(f, "'{drv}' matches '{pattern}'"),
            Reason::Class { drv, class } => write!(f, "'{drv}' is of class '{}'", class.name()),
            Reason::Local { drv } => write!(f, "'{drv}' is built locally (preferLocalBuild or allowSubstitutes)"),
            Reason::DependsOn { drv, why } => write!(f, "depends on '{drv}': {why}"),
            Reason::Refers { path } => write!(f, "refers to '{path}', which is left out"),
        }
    }
}

/// Whether `s` matches the glob `pat`, in which `*` stands for any text
/// and `?` for one character.
pub fn glob(pat: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// The host of `url`, without user information and port.
fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let auth = rest.split(['/', '?', '#']).next()?;
    let host = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    let host = if host.starts_with('[') { host.split_once(']').map_or(host, |(h, _)| &h[1..]) } else { host.split(':').next()? };
    (!host.is_empty()).then_some(host)
}

/// The URLs a fixed-output derivation downloads, from `url`, `urls` and
/// the same keys of structured attributes.
fn download_urls(drv: &Derivation) -> Vec<String> {
    let mut out: Vec<String> = ["url", "urls"].iter().filter_map(|k| drv.env.get(*k)).flat_map(|v| v.split_whitespace().map(str::to_string)).collect();
    if let Some(j) = drv.env.get("__json").and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok()) {
        for k in ["url", "urls"] {
            match &j[k] {
                serde_json::Value::String(s) => out.push(s.clone()),
                serde_json::Value::Array(a) => out.extend(a.iter().filter_map(|v| v.as_str().map(str::to_string))),
                _ => {}
            }
        }
    }
    out
}

/// A derivation attribute, also from structured attributes.
fn attr(drv: &Derivation, name: &str) -> Option<String> {
    if let Some(v) = drv.env.get(name) {
        return Some(v.clone());
    }
    let j: serde_json::Value = serde_json::from_str(drv.env.get("__json")?).ok()?;
    match &j[name] {
        serde_json::Value::Bool(true) => Some("1".into()),
        serde_json::Value::Bool(false) => Some(String::new()),
        serde_json::Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn is_local(drv: &Derivation) -> bool {
    attr(drv, "preferLocalBuild").as_deref() == Some("1") || attr(drv, "allowSubstitutes").as_deref() == Some("")
}

#[derive(Clone, Default)]
struct DrvVerdict {
    /// A reason that also leaves out what is built from the derivation.
    spreads: Option<Reason>,
    /// A reason for this derivation and its outputs only.
    own: Option<Reason>,
}

/// Classifies paths for a filter, remembering what it learnt.
pub struct Selector<'a> {
    store: &'a Store,
    pub filter: Filter,
    drvs: Mutex<HashMap<StorePath, DrvVerdict>>,
}

/// What a selection takes and leaves out.
#[derive(Debug, Default)]
pub struct Selection {
    /// The paths to upload, references before the paths that refer to
    /// them, with the type that chose each path (`None` for paths taken
    /// as references).
    pub take: Vec<(StorePath, Option<PathType>)>,
    pub left_out: BTreeMap<StorePath, Reason>,
}

impl<'a> Selector<'a> {
    pub fn new(store: &'a Store, filter: Filter) -> Selector<'a> {
        Selector { store, filter, drvs: Mutex::new(HashMap::new()) }
    }

    fn drv_verdict(&self, drv_path: &StorePath) -> Result<DrvVerdict> {
        if let Some(v) = self.drvs.lock().unwrap().get(drv_path) {
            return Ok(v.clone());
        }
        // Inputs first, iteratively, so deep graphs need no deep stack.
        let mut stack = vec![(drv_path.clone(), false)];
        while let Some((p, expanded)) = stack.pop() {
            if self.drvs.lock().unwrap().contains_key(&p) {
                continue;
            }
            let drv = match self.store.read_derivation(&p) {
                Ok(d) => d,
                Err(_) => {
                    self.drvs.lock().unwrap().insert(p, DrvVerdict::default());
                    continue;
                }
            };
            if !expanded {
                let todo: Vec<StorePath> = {
                    let m = self.drvs.lock().unwrap();
                    drv.input_drvs.keys().filter(|i| !m.contains_key(*i)).cloned().collect()
                };
                stack.push((p, true));
                stack.extend(todo.into_iter().map(|i| (i, false)));
                continue;
            }
            let v = self.judge(&drv);
            self.drvs.lock().unwrap().insert(p, v);
        }
        Ok(self.drvs.lock().unwrap().get(drv_path).cloned().unwrap_or_default())
    }

    /// The verdict on `drv`, whose inputs have verdicts already.
    fn judge(&self, drv: &Derivation) -> DrvVerdict {
        let name = drv.name.clone();
        let f = &self.filter;
        let mut spreads = f.names.iter().find(|pat| glob(pat, &name)).map(|pat| Reason::Name { drv: name.clone(), pattern: pat.clone() });
        if spreads.is_none() {
            spreads = f.classes.iter().find(|c| c.patterns().iter().any(|pat| glob(pat, &name))).map(|c| Reason::Class { drv: name.clone(), class: *c });
        }
        if spreads.is_none() {
            let m = self.drvs.lock().unwrap();
            spreads = drv.input_drvs.keys().find_map(|i| {
                let why = m.get(i)?.spreads.clone()?;
                // Name the derivation where the reason started.
                Some(match why {
                    Reason::DependsOn { .. } => why,
                    why => Reason::DependsOn { drv: self.store.dir.print(i), why: Box::new(why) },
                })
            });
        }
        let mut own = None;
        if drv.is_fixed_output() && !f.hosts.is_empty() {
            own = download_urls(drv).iter().filter_map(|u| url_host(u)).find_map(|h| {
                f.hosts.iter().any(|pat| glob(pat, h)).then(|| Reason::Host { drv: name.clone(), host: h.to_string() })
            });
        }
        if own.is_none() && f.local && !drv.is_fixed_output() && is_local(drv) {
            own = Some(Reason::Local { drv: name });
        }
        DrvVerdict { spreads, own }
    }

    /// The derivation that produced `p`, when this store has it.
    fn deriver_of(&self, p: &StorePath) -> Result<Option<(StorePath, Derivation)>> {
        let Some(info) = self.store.query_info(p)? else { return Ok(None) };
        let Some(d) = info.deriver else { return Ok(None) };
        let Ok(drv) = self.store.read_derivation(&d) else { return Ok(None) };
        let produced = drv.outputs.values().any(|o| o.path.as_ref() == Some(p)) || drv.outputs.values().any(|o| o.path.is_none());
        Ok(produced.then_some((d, drv)))
    }

    /// Why the path `p` itself is left out, if it is.
    pub fn reason(&self, p: &StorePath) -> Result<Option<Reason>> {
        if !self.store.is_valid(p) {
            return Ok(Some(Reason::Missing));
        }
        if self.filter.hosts.is_empty() && self.filter.names.is_empty() && self.filter.classes.is_empty() && !self.filter.local {
            return Ok(None);
        }
        // Downloads and local builds are left out as outputs; their `.drv`
        // files stay, so the derivations built from them keep complete
        // closures.
        if p.is_derivation() {
            return Ok(self.drv_verdict(p)?.spreads);
        }
        let Some((d, _)) = self.deriver_of(p)? else { return Ok(None) };
        let v = self.drv_verdict(&d)?;
        Ok(v.spreads.or(v.own))
    }

    /// The types of `p`; `toplevel` names the root derivations.
    pub fn types(&self, p: &StorePath, toplevel: &BTreeSet<StorePath>) -> Result<BTreeSet<PathType>> {
        let mut t = BTreeSet::new();
        if p.is_derivation() {
            let fixed = self.store.read_derivation(p).map(|d| d.is_fixed_output()).unwrap_or(false);
            t.insert(PathType::Drv);
            t.insert(if fixed { PathType::FixedOutputDrv } else { PathType::BuildDrv });
            if toplevel.contains(p) {
                t.insert(PathType::ToplevelDrv);
            }
        } else if let Some((_, drv)) = self.deriver_of(p)? {
            t.insert(PathType::DrvOutPath);
            t.insert(if drv.is_fixed_output() { PathType::FixedOutputOutPath } else { PathType::BuildOutPath });
        } else {
            t.insert(PathType::Source);
        }
        Ok(t)
    }

    /// Whether an output of a build is taken: always without types,
    /// else when one of its types is asked for.
    pub fn takes_output(&self, p: &StorePath) -> Result<bool> {
        if self.filter.types.is_empty() {
            return Ok(true);
        }
        Ok(self.types(p, &BTreeSet::new())?.iter().any(|t| self.filter.types.contains(t)))
    }

    /// The candidates for `roots`: the roots without types, else the paths
    /// of their derivation graph with a type asked for. Outputs of the
    /// graph missing from the store are candidates too, and left out later.
    pub fn candidates(&self, roots: &[StorePath]) -> Result<Vec<(StorePath, Option<PathType>)>> {
        if self.filter.types.is_empty() {
            return Ok(roots.iter().map(|r| (r.clone(), None)).collect());
        }
        let mut toplevel = BTreeSet::new();
        let mut graph: BTreeSet<StorePath> = BTreeSet::new();
        let mut todo = Vec::new();
        for r in roots {
            if r.is_derivation() {
                toplevel.insert(r.clone());
                todo.push(r.clone());
            } else if let Some((d, _)) = self.deriver_of(r)? {
                toplevel.insert(d.clone());
                todo.push(d);
                graph.insert(r.clone());
            } else {
                graph.insert(r.clone());
            }
        }
        let mut seen = BTreeSet::new();
        while let Some(d) = todo.pop() {
            if !seen.insert(d.clone()) {
                continue;
            }
            graph.insert(d.clone());
            let Ok(drv) = self.store.read_derivation(&d) else { continue };
            graph.extend(drv.outputs.values().filter_map(|o| o.path.clone()));
            graph.extend(drv.input_srcs.iter().cloned());
            todo.extend(drv.input_drvs.keys().filter(|i| !seen.contains(*i)).cloned());
        }
        let mut out = Vec::new();
        for p in graph {
            let types = if self.store.is_valid(&p) {
                self.types(&p, &toplevel)?
            } else {
                // A missing output: its type follows from the derivation
                // that names it, which the graph walk read.
                [PathType::DrvOutPath, PathType::BuildOutPath].into()
            };
            // The most specific matching type is shown.
            if let Some(t) = types.iter().rev().find(|t| self.filter.types.contains(t)) {
                out.push((p, Some(*t)));
            }
        }
        Ok(out)
    }

    /// Selects `roots` and their closures.
    pub fn select(&self, roots: &[StorePath]) -> Result<Selection> {
        let mut sel = Selection::default();
        let mut done: BTreeSet<StorePath> = BTreeSet::new();
        for (c, ty) in self.candidates(roots)? {
            self.visit(&c, ty, &mut done, &mut sel)?;
        }
        Ok(sel)
    }

    /// Adds `root` after its references unless it or one of them is left
    /// out; iterative post-order.
    fn visit(&self, root: &StorePath, ty: Option<PathType>, done: &mut BTreeSet<StorePath>, sel: &mut Selection) -> Result<()> {
        if done.contains(root) {
            if let Some(e) = sel.take.iter_mut().find(|(p, _)| p == root) {
                e.1 = e.1.or(ty);
            }
            return Ok(());
        }
        let mut stack: Vec<(StorePath, bool)> = vec![(root.clone(), false)];
        while let Some((p, expanded)) = stack.pop() {
            if done.contains(&p) {
                continue;
            }
            if let Some(r) = self.reason(&p)? {
                done.insert(p.clone());
                sel.left_out.insert(p, r);
                continue;
            }
            let info = self.store.query_info(&p)?.ok_or_else(|| format!("path '{}' is not valid", self.store.dir.print(&p)))?;
            let refs: Vec<StorePath> = info.references.into_iter().filter(|r| *r != p).collect();
            if !expanded {
                stack.push((p, true));
                stack.extend(refs.into_iter().filter(|r| !done.contains(r)).map(|r| (r, false)));
                continue;
            }
            done.insert(p.clone());
            match refs.iter().find(|r| sel.left_out.contains_key(*r)) {
                Some(r) => {
                    let path = self.store.dir.print(r);
                    sel.left_out.insert(p, Reason::Refers { path });
                }
                None => sel.take.push((p.clone(), if p == *root { ty } else { None })),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob("*.github.com", "codeload.github.com"));
        assert!(!glob("*.github.com", "github.com"));
        assert!(glob("unit-*", "unit-sshd.service"));
        assert!(glob("a?c", "abc") && !glob("a?c", "ac"));
        assert!(glob("*", "") && glob("**x", "x") && !glob("x*", "yx"));
        assert!(glob("*-image-*", "board-image-1.0"));
    }

    #[test]
    fn hosts() {
        assert_eq!(url_host("https://user:pw@example.org:8080/x?y"), Some("example.org"));
        assert_eq!(url_host("mirror://gnu/hello.tar.gz"), Some("gnu"));
        assert_eq!(url_host("http://[::1]:80/"), Some("::1"));
        assert_eq!(url_host("not a url"), None);
    }

    #[test]
    fn parses() {
        let mut f = Filter::default();
        f.add_types("source,build-out-path drv").unwrap();
        assert_eq!(f.types.len(), 3);
        assert!(f.add_types("nonsense").is_err());
        f.add_classes("system test").unwrap();
        assert!(f.add_classes("other").is_err());
    }
}
