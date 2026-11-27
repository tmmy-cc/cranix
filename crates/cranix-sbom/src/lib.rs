//! Software bills of materials for the closure of store paths.
//!
//! [`collect`] turns the runtime closure of some output paths into
//! components: the outputs of one derivation form one component, named
//! and versioned from the derivation, with every store path as a property.
//! Paths without a version (sources, generated files) are no components;
//! the dependencies of components pass through them. [`Meta`] from the
//! evaluated packages adds licences, descriptions, homepages and CPEs.
//! [`cyclonedx`] and [`spdx`] write the result; both are deterministic.

pub mod binaries;
pub mod cyclonedx;
pub mod lock;
pub mod spdx;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use cranix_core::{Derivation, StorePath};
use cranix_store::Store;

use binaries::Embedded;

pub type Result<T> = std::result::Result<T, String>;

/// A licence: an SPDX identifier, or a name when there is none.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum License {
    Id(String),
    Name(String),
}

/// What the evaluated package says about a derivation (`meta`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    pub licenses: Vec<License>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    /// `meta.identifiers.cpe`.
    pub cpe: Option<String>,
}

/// A download a component was built from.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Source {
    pub url: Option<String>,
    /// `(algorithm, hex digest)` of a flat download, such as `("SHA-256", …)`.
    pub hash: Option<(String, String)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Component {
    /// The derivation path, a stable reference within the document.
    pub key: String,
    pub name: String,
    pub version: String,
    pub purls: Vec<String>,
    pub cpe: String,
    pub meta: Meta,
    /// The store paths of its outputs.
    pub paths: Vec<String>,
    pub sources: Vec<Source>,
    /// Modules and crates linked into its binaries.
    pub embedded: Vec<Embedded>,
    /// Executables with statically linked code and no list of it,
    /// relative to their store path.
    pub unlisted: Vec<String>,
}

impl Component {
    pub fn purl(&self) -> &str {
        &self.purls[0]
    }
}

#[derive(Clone, Debug, Default)]
pub struct Sbom {
    /// The component described, or a document-level name for several roots.
    pub root: Component,
    pub components: BTreeMap<String, Component>,
    /// Dependencies by key.
    pub deps: BTreeMap<String, BTreeSet<String>>,
    /// Components of merged documents, by key, depended on by the root.
    pub merged: Vec<Component>,
}

/// Whether `id` is an SPDX licence identifier, by the list in the
/// CycloneDX schema.
pub fn known_license(id: &str) -> bool {
    static IDS: std::sync::OnceLock<BTreeSet<String>> = std::sync::OnceLock::new();
    IDS.get_or_init(|| {
        let v: serde_json::Value = serde_json::from_str(include_str!("../tests/schemas/spdx.schema.json")).unwrap_or_default();
        v["enum"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(str::to_string)).collect()
    })
    .contains(id)
}

/// Percent-encodes a purl name or version segment.
pub fn purl_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// [`purl_escape`] for each `/`-separated segment.
pub fn purl_escape_path(s: &str) -> String {
    s.split('/').map(purl_escape).collect::<Vec<_>>().join("/")
}

/// A CPE 2.3 formatted string for `product` and `version`, with an
/// unknown vendor.
pub fn cpe(product: &str, version: &str) -> String {
    let esc = |s: &str| {
        let mut o = String::new();
        for c in s.to_lowercase().chars() {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                o.push(c);
            } else if c == ' ' {
                o.push('_');
            } else {
                o.push('\\');
                o.push(c);
            }
        }
        o
    };
    format!("cpe:2.3:a:*:{}:{}:*:*:*:*:*:*:*", esc(product), esc(version))
}

/// The name and version of a derivation: `pname` and `version`, else the
/// name split before the first `-` followed by a digit.
pub fn name_version(drv: &Derivation) -> (String, Option<String>) {
    if let (Some(p), Some(v)) = (drv.env.get("pname"), drv.env.get("version")) {
        if !v.is_empty() {
            return (p.clone(), Some(v.clone()));
        }
    }
    let n = &drv.name;
    let b = n.as_bytes();
    match (0..b.len()).find(|&i| b[i] == b'-' && b.get(i + 1).is_some_and(u8::is_ascii_digit)) {
        Some(i) => (n[..i].to_string(), Some(n[i + 1..].to_string())),
        None => (n.clone(), None),
    }
}

/// The ecosystem purls of a package built from one: Python packages
/// (`python3.12-…`), npm packages (`npmDeps`) and Rust crates
/// (`cargoDeps`).
fn ecosystem_purls(drv: &Derivation, name: &str, version: &str) -> Vec<String> {
    let mut out = Vec::new();
    let py = drv.name.strip_prefix("python").is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()) && r.contains('-'));
    if py || drv.env.contains_key("pyproject") || drv.env.get("format").is_some_and(|f| matches!(f.as_str(), "setuptools" | "pyproject" | "wheel" | "flit")) {
        let n = name.to_lowercase().replace(['_', '.'], "-");
        out.push(format!("pkg:pypi/{}@{}", purl_escape(&n), purl_escape(version)));
    }
    if drv.env.contains_key("npmDeps") {
        let n = if let Some(scoped) = name.strip_prefix('@') { format!("%40{}", purl_escape_path(scoped)) } else { purl_escape(name) };
        out.push(format!("pkg:npm/{n}@{}", purl_escape(version)));
    }
    if drv.env.contains_key("cargoDeps") {
        out.push(format!("pkg:cargo/{}@{}", purl_escape(name), purl_escape(version)));
    }
    out
}

/// The downloads of `drv`: fixed-output inputs named by `src` or `srcs`.
fn sources(store: &Store, drv: &Derivation) -> Vec<Source> {
    let named: BTreeSet<&str> = ["src", "srcs"].iter().filter_map(|k| drv.env.get(*k)).flat_map(|v| v.split_whitespace()).collect();
    let mut out = BTreeSet::new();
    for d in drv.input_drvs.keys() {
        let Ok(i) = store.read_derivation(d) else { continue };
        if !i.is_fixed_output() {
            continue;
        }
        let o = &i.outputs["out"];
        let Some(p) = &o.path else { continue };
        if !named.contains(store.dir.print(p).as_str()) {
            continue;
        }
        let url = ["url", "urls"].iter().filter_map(|k| i.env.get(*k)).flat_map(|v| v.split_whitespace()).next().map(str::to_string);
        // A flat hash is the hash of the downloaded file.
        let algo = o.hash_algo.as_str();
        let hash = (!algo.starts_with("r:") && !o.hash.is_empty()).then(|| {
            let name = match algo {
                "sha256" => "SHA-256",
                "sha512" => "SHA-512",
                "sha1" => "SHA-1",
                "md5" => "MD5",
                a => a,
            };
            (name.to_string(), o.hash.clone())
        });
        out.insert(Source { url, hash });
    }
    out.into_iter().collect()
}

/// Options of [`collect`]. By default the linked crates and modules of a
/// package come from its derivations only.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Read binaries for the code linked into them, and name those that
    /// give no list of it.
    pub scan_binaries: bool,
    /// Read lock files in the unpacked sources of packages.
    pub scan_sources: bool,
}

/// The derivations of vendored dependencies (`cargoDeps`, `goModules`)
/// of the components whose outputs are missing from the store, with the
/// output each names.
pub fn missing_vendor_drvs(store: &Store, sbom: &Sbom) -> Vec<(StorePath, String)> {
    let mut out = BTreeSet::new();
    for key in sbom.components.keys() {
        let Ok(d) = store.dir.parse(key) else { continue };
        let Ok(drv) = store.read_derivation(&d) else { continue };
        for var in ["cargoDeps", "goModules"] {
            let Some(p) = drv.env.get(var) else { continue };
            if store.resolve(p).exists() {
                continue;
            }
            for i in drv.input_drvs.keys() {
                let Ok(id) = store.read_derivation(i) else { continue };
                if let Some((name, _)) = id.outputs.iter().find(|(_, o)| o.path.as_ref().map(|x| store.dir.print(x)).as_deref() == Some(p.as_str())) {
                    out.insert((i.clone(), name.clone()));
                }
            }
        }
    }
    out.into_iter().collect()
}

/// `crate-<name>-<version>.tar.gz`, the downloads `importCargoLock` makes.
fn crate_download(name: &str) -> Option<(String, String)> {
    let base = name.strip_prefix("crate-")?.strip_suffix(".tar.gz")?;
    let b = base.as_bytes();
    let i = (0..b.len()).rev().find(|&i| b[i] == b'-' && b.get(i + 1).is_some_and(u8::is_ascii_digit))?;
    Some((base[..i].to_string(), base[i + 1..].to_string()))
}

/// The crates and Go modules the derivations of a package name: crate
/// downloads in its build inputs (through helpers without a version, such
/// as the vendor directory), and the `modules.txt` of a Go vendor
/// directory that is in the store.
fn from_derivations(store: &Store, drv_path: &StorePath, drv: &Derivation) -> Vec<Embedded> {
    let mut out = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut todo: Vec<StorePath> = drv.input_drvs.keys().cloned().collect();
    seen.insert(drv_path.clone());
    while let Some(d) = todo.pop() {
        if !seen.insert(d.clone()) {
            continue;
        }
        let Ok(i) = store.read_derivation(&d) else { continue };
        if let Some((name, version)) = crate_download(&i.name) {
            let checksum = i.outputs.get("out").filter(|o| o.hash_algo == "sha256").map(|o| o.hash.clone());
            out.insert(Embedded { ecosystem: "cargo", name, version, checksum, found_in: "derivation" });
            continue;
        }
        if i.name.ends_with("-go-modules") {
            continue;
        }
        // Other packages are components of their own.
        if name_version(&i).1.is_none() || i.name.starts_with("cargo-vendor") {
            todo.extend(i.input_drvs.keys().cloned());
        }
    }
    // The vendored dependencies the package names, when they are in the
    // store: `cargoDeps` (a vendor tarball or directory with the
    // `Cargo.lock`) and `goModules` (with `modules.txt`).
    if let Some(p) = drv.env.get("cargoDeps") {
        let real = store.resolve(p);
        let text = if real.is_dir() { vendored_lock(&real) } else { tar_gz_member(&real, "Cargo.lock") };
        if let Some(s) = text.and_then(|t| lock::cargo(&t).ok()) {
            for c in s.components.values() {
                let checksum = c.sources.first().and_then(|s| s.hash.as_ref()).map(|h| h.1.clone());
                out.insert(Embedded { ecosystem: "cargo", name: c.name.clone(), version: c.version.clone(), checksum, found_in: "derivation" });
            }
        }
    }
    if let Some(p) = drv.env.get("goModules") {
        if let Ok(text) = std::fs::read_to_string(store.resolve(p).join("modules.txt")) {
            out.extend(go_modules_txt(&text));
        }
    }
    out.into_iter().collect()
}

/// The `Cargo.lock` of a vendor directory, at its top or one level down.
fn vendored_lock(dir: &Path) -> Option<String> {
    if let Ok(t) = std::fs::read_to_string(dir.join("Cargo.lock")) {
        return Some(t);
    }
    let mut subs: Vec<_> = std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path()).collect();
    subs.sort();
    subs.iter().find_map(|d| std::fs::read_to_string(d.join("Cargo.lock")).ok())
}

/// The contents of the first member of a `.tar.gz` file named `name` at
/// the top or one directory down.
pub fn tar_gz_member(path: &Path, name: &str) -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let mut r = flate2::read::GzDecoder::new(std::io::BufReader::new(f));
    let mut hdr = [0u8; 512];
    let mut long_name: Option<String> = None;
    loop {
        r.read_exact(&mut hdr).ok()?;
        if hdr.iter().all(|&b| b == 0) {
            return None;
        }
        let field = |a: usize, b: usize| {
            let raw = &hdr[a..b];
            String::from_utf8_lossy(&raw[..raw.iter().position(|&c| c == 0).unwrap_or(raw.len())]).into_owned()
        };
        let size = usize::from_str_radix(field(124, 136).trim(), 8).unwrap_or(0);
        let kind = hdr[156];
        let prefix = field(345, 500);
        let mut member = long_name.take().unwrap_or_else(|| if prefix.is_empty() { field(0, 100) } else { format!("{prefix}/{}", field(0, 100)) });
        let padded = size.div_ceil(512) * 512;
        let mut body = vec![0u8; padded];
        r.read_exact(&mut body).ok()?;
        body.truncate(size);
        match kind {
            // GNU long name for the next member.
            b'L' => long_name = Some(String::from_utf8_lossy(&body).trim_end_matches('\0').to_string()),
            b'0' | 0 => {
                member = member.trim_start_matches("./").to_string();
                let depth = member.matches('/').count();
                if member.rsplit('/').next() == Some(name) && depth <= 1 {
                    return String::from_utf8(body).ok();
                }
            }
            _ => {}
        }
    }
}

/// The modules of a Go `vendor/modules.txt`: `# path version` lines,
/// with `=> path version` replacements.
pub fn go_modules_txt(text: &str) -> Vec<Embedded> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("# ") else { continue };
        let f: Vec<&str> = rest.split_whitespace().collect();
        let (name, version) = match f.as_slice() {
            [_, _, "=>", p, v, ..] => (p, v),
            [p, v, ..] if v.starts_with('v') => (p, v),
            _ => continue,
        };
        out.push(Embedded { ecosystem: "golang", name: name.to_string(), version: version.to_string(), checksum: None, found_in: "derivation" });
    }
    out
}

/// The crates and npm packages in lock files of the unpacked source of a
/// package (`src` when it is a directory in the store).
fn from_sources(store: &Store, drv: &Derivation) -> Vec<Embedded> {
    let mut out = BTreeSet::new();
    for src in ["src", "srcs"].iter().filter_map(|k| drv.env.get(*k)).flat_map(|v| v.split_whitespace()) {
        let real = store.resolve(src);
        if !real.is_dir() {
            continue;
        }
        let mut locks = Vec::new();
        walk_files(&real, &mut |f| {
            if matches!(f.file_name().and_then(|n| n.to_str()), Some("Cargo.lock" | "package-lock.json")) && !f.components().any(|c| c.as_os_str() == "node_modules") {
                locks.push(f.to_path_buf());
            }
        });
        for l in locks {
            let Ok(s) = lock::from_file(&l) else { continue };
            for c in s.components.values() {
                let ecosystem = if c.purl().starts_with("pkg:npm/") { "npm" } else { "cargo" };
                let checksum = c.sources.first().and_then(|s| s.hash.as_ref()).map(|h| h.1.clone());
                out.insert(Embedded { ecosystem, name: c.name.clone(), version: c.version.clone(), checksum, found_in: "source" });
            }
        }
    }
    out.into_iter().collect()
}

/// The references of `p`: its registered ones, or for a path from the host
/// store a scan of its files for the hashes of `candidates`.
fn references(store: &Store, p: &StorePath, candidates: &BTreeSet<StorePath>) -> Result<BTreeSet<StorePath>> {
    if let Some(info) = store.query_info(p)? {
        return Ok(info.references);
    }
    let real = store.resolve(&store.dir.print(p));
    cranix_store::refs::scan_path(&real, candidates).map_err(|e| format!("scanning '{}': {e}", real.display()))
}

/// The deriver of `p`: the registered one, else the derivation among
/// `known` that names `p` as an output.
fn deriver(store: &Store, p: &StorePath, by_output: &HashMap<StorePath, StorePath>) -> Option<StorePath> {
    store.query_info(p).ok().flatten().and_then(|i| i.deriver).or_else(|| by_output.get(p).cloned())
}

/// The outputs and sources of the build graph of `drvs`, which reference
/// scans look for, and the derivation that makes each output.
fn build_graph(store: &Store, drvs: &[StorePath]) -> (BTreeSet<StorePath>, HashMap<StorePath, StorePath>) {
    let mut cands = BTreeSet::new();
    let mut by_output = HashMap::new();
    let mut seen = BTreeSet::new();
    let mut todo = drvs.to_vec();
    while let Some(d) = todo.pop() {
        if !seen.insert(d.clone()) {
            continue;
        }
        let Ok(drv) = store.read_derivation(&d) else { continue };
        for o in drv.outputs.values().filter_map(|o| o.path.clone()) {
            by_output.insert(o.clone(), d.clone());
            cands.insert(o);
        }
        cands.extend(drv.input_srcs.iter().cloned());
        todo.extend(drv.input_drvs.keys().cloned());
    }
    (cands, by_output)
}

/// Builds the SBOM of the runtime closure of `roots`, the outputs of
/// `drvs`. `meta` holds what evaluation found, by derivation.
pub fn collect(store: &Store, drvs: &[StorePath], roots: &[StorePath], meta: &HashMap<StorePath, Meta>, opts: &Options) -> Result<Sbom> {
    let (cands, by_output) = build_graph(store, drvs);
    // The runtime closure, with references.
    let mut refs: BTreeMap<StorePath, BTreeSet<StorePath>> = BTreeMap::new();
    let mut todo: Vec<StorePath> = roots.to_vec();
    while let Some(p) = todo.pop() {
        if refs.contains_key(&p) {
            continue;
        }
        let r: BTreeSet<StorePath> = references(store, &p, &cands)?.into_iter().filter(|r| *r != p).collect();
        todo.extend(r.iter().filter(|x| !refs.contains_key(*x)).cloned());
        refs.insert(p, r);
    }
    // Paths grouped by derivation; only versioned ones are components.
    let mut drv_of: BTreeMap<StorePath, StorePath> = BTreeMap::new();
    let mut comps: BTreeMap<String, Component> = BTreeMap::new();
    let mut drv_cache: HashMap<StorePath, Option<Derivation>> = HashMap::new();
    for p in refs.keys() {
        let Some(d) = deriver(store, p, &by_output) else { continue };
        let drv = drv_cache.entry(d.clone()).or_insert_with(|| store.read_derivation(&d).ok()).clone();
        let Some(drv) = drv else { continue };
        let (name, Some(version)) = name_version(&drv) else { continue };
        let key = store.dir.print(&d);
        let c = comps.entry(key.clone()).or_insert_with(|| {
            let m = meta.get(&d).cloned().unwrap_or_default();
            let mut purls = vec![format!("pkg:nix/{}@{}", purl_escape(&name), purl_escape(&version))];
            purls.extend(ecosystem_purls(&drv, &name, &version));
            Component {
                key: key.clone(),
                cpe: m.cpe.clone().unwrap_or_else(|| cpe(&name, &version)),
                name: name.clone(),
                version: version.clone(),
                purls,
                meta: m,
                sources: sources(store, &drv),
                embedded: {
                    let mut e = from_derivations(store, &d, &drv);
                    if opts.scan_sources {
                        e.extend(from_sources(store, &drv));
                    }
                    e
                },
                ..Default::default()
            }
        });
        c.paths.push(store.dir.print(p));
        drv_of.insert(p.clone(), d);
    }
    if opts.scan_binaries {
        for c in comps.values_mut() {
            scan_component(store, c);
        }
    }
    // Dependencies between components, passing through paths that are none.
    let comp_of = |p: &StorePath| drv_of.get(p).map(|d| store.dir.print(d));
    let mut deps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut reach_memo: HashMap<StorePath, BTreeSet<String>> = HashMap::new();
    fn reach(
        p: &StorePath,
        refs: &BTreeMap<StorePath, BTreeSet<StorePath>>,
        comp_of: &dyn Fn(&StorePath) -> Option<String>,
        memo: &mut HashMap<StorePath, BTreeSet<String>>,
        stack: &mut BTreeSet<StorePath>,
    ) -> BTreeSet<String> {
        if let Some(r) = memo.get(p) {
            return r.clone();
        }
        let mut out = BTreeSet::new();
        if !stack.insert(p.clone()) {
            return out;
        }
        for r in refs.get(p).into_iter().flatten() {
            match comp_of(r) {
                Some(k) => {
                    out.insert(k);
                }
                None => out.extend(reach(r, refs, comp_of, memo, stack)),
            }
        }
        stack.remove(p);
        memo.insert(p.clone(), out.clone());
        out
    }
    for p in refs.keys() {
        let Some(k) = comp_of(p) else { continue };
        let mut stack = BTreeSet::new();
        let r = reach(p, &refs, &comp_of, &mut reach_memo, &mut stack);
        deps.entry(k.clone()).or_default().extend(r.into_iter().filter(|d| *d != k));
    }
    for c in comps.values_mut() {
        c.paths.sort();
    }
    // The root: the one component of the roots, or a group of them.
    let root_keys: BTreeSet<String> = roots.iter().filter_map(comp_of).collect();
    let root = match root_keys.iter().next() {
        Some(k) if root_keys.len() == 1 => comps[k].clone(),
        _ => {
            let names: Vec<String> = roots.iter().map(|r| r.name().to_string()).collect();
            Component { key: "root".into(), name: names.join("+"), purls: Vec::new(), ..Default::default() }
        }
    };
    if root.key == "root" {
        let mut stack = BTreeSet::new();
        let mut d = BTreeSet::new();
        for r in roots {
            match comp_of(r) {
                Some(k) => {
                    d.insert(k);
                }
                None => d.extend(reach(r, &refs, &comp_of, &mut reach_memo, &mut stack)),
            }
        }
        deps.insert("root".into(), d);
    }
    Ok(Sbom { root, components: comps, deps, merged: Vec::new() })
}

/// Builds the SBOM of the build graph of `drvs`, for which no output
/// needs to exist: every derivation with a version is a component, apart
/// from downloads (fixed-output derivations), which are the sources of
/// the components that use them, and a derivation depends on the
/// components among its inputs.
pub fn collect_build_time(store: &Store, drvs: &[StorePath], meta: &HashMap<StorePath, Meta>, opts: &Options) -> Result<Sbom> {
    let mut loaded: BTreeMap<StorePath, Derivation> = BTreeMap::new();
    let mut todo = drvs.to_vec();
    while let Some(d) = todo.pop() {
        if loaded.contains_key(&d) {
            continue;
        }
        let drv = store.read_derivation(&d)?;
        todo.extend(drv.input_drvs.keys().filter(|i| !loaded.contains_key(*i)).cloned());
        loaded.insert(d, drv);
    }
    let is_comp = |d: &StorePath| loaded.get(d).is_some_and(|drv| !drv.is_fixed_output() && name_version(drv).1.is_some());
    let mut comps = BTreeMap::new();
    for (d, drv) in &loaded {
        if !is_comp(d) {
            continue;
        }
        let (name, version) = name_version(drv);
        let version = version.unwrap_or_default();
        let m = meta.get(d).cloned().unwrap_or_default();
        let mut purls = vec![format!("pkg:nix/{}@{}", purl_escape(&name), purl_escape(&version))];
        purls.extend(ecosystem_purls(drv, &name, &version));
        let key = store.dir.print(d);
        let mut c = Component {
            key: key.clone(),
            cpe: m.cpe.clone().unwrap_or_else(|| cpe(&name, &version)),
            name,
            version,
            purls,
            meta: m,
            paths: drv.outputs.values().filter_map(|o| o.path.as_ref().map(|p| store.dir.print(p))).collect(),
            sources: sources(store, drv),
            embedded: from_derivations(store, d, drv),
            ..Default::default()
        };
        if opts.scan_sources {
            c.embedded.extend(from_sources(store, drv));
            c.embedded.sort();
            c.embedded.dedup();
        }
        if opts.scan_binaries && c.paths.iter().all(|p| store.resolve(p).exists()) {
            scan_component(store, &mut c);
        }
        comps.insert(key, c);
    }
    // Dependencies pass through derivations that are no components.
    let mut memo: HashMap<StorePath, BTreeSet<String>> = HashMap::new();
    fn reach(d: &StorePath, loaded: &BTreeMap<StorePath, Derivation>, is_comp: &dyn Fn(&StorePath) -> bool, dir: &cranix_core::StoreDir, memo: &mut HashMap<StorePath, BTreeSet<String>>) -> BTreeSet<String> {
        if let Some(r) = memo.get(d) {
            return r.clone();
        }
        let mut out = BTreeSet::new();
        for i in loaded.get(d).map(|x| x.input_drvs.keys().cloned().collect::<Vec<_>>()).unwrap_or_default() {
            if is_comp(&i) {
                out.insert(dir.print(&i));
            } else {
                out.extend(reach(&i, loaded, is_comp, dir, memo));
            }
        }
        memo.insert(d.clone(), out.clone());
        out
    }
    let mut deps = BTreeMap::new();
    for d in loaded.keys().filter(|d| is_comp(d)) {
        deps.insert(store.dir.print(d), reach(d, &loaded, &is_comp, &store.dir, &mut memo));
    }
    let root = match drvs {
        [d] if is_comp(d) => comps[&store.dir.print(d)].clone(),
        _ => {
            let mut r = BTreeSet::new();
            for d in drvs {
                if is_comp(d) {
                    r.insert(store.dir.print(d));
                } else {
                    r.extend(reach(d, &loaded, &is_comp, &store.dir, &mut memo));
                }
            }
            deps.insert("root".into(), r);
            let names: Vec<String> = drvs.iter().map(|d| d.name().trim_end_matches(".drv").to_string()).collect();
            Component { key: "root".into(), name: names.join("+"), ..Default::default() }
        }
    };
    Ok(Sbom { root, components: comps, deps, merged: Vec::new() })
}

/// Reads the binaries of `c` for linked modules and crates.
fn scan_component(store: &Store, c: &mut Component) {
    let mut embedded = BTreeSet::new();
    let mut unlisted = BTreeSet::new();
    for p in &c.paths {
        let real = store.resolve(p);
        walk_files(&real, &mut |f| {
            let Some(info) = binaries::inspect(f) else { return };
            if info.unlisted {
                let rel = f.strip_prefix(&real).map(|r| r.display().to_string()).unwrap_or_default();
                unlisted.insert(format!("{p}/{rel}"));
            }
            if let Some(m) = &info.go_main {
                if !c.purls.iter().any(|u| u.starts_with("pkg:golang/")) {
                    c.purls.push(format!("pkg:golang/{}@{}", purl_escape_path(m), purl_escape(&c.version)));
                }
            }
            embedded.extend(info.embedded);
        });
    }
    // Entries the derivations name already stay as they are.
    let known: BTreeSet<(&str, String, String)> = c.embedded.iter().map(|e| (e.ecosystem, e.name.clone(), e.version.clone())).collect();
    let extra: Vec<Embedded> = embedded.into_iter().filter(|e| !known.contains(&(e.ecosystem, e.name.clone(), e.version.clone()))).collect();
    c.embedded.extend(extra);
    c.embedded.sort();
    c.unlisted = unlisted.into_iter().collect();
}

fn walk_files(dir: &Path, f: &mut dyn FnMut(&Path)) {
    let Ok(md) = dir.symlink_metadata() else { return };
    if md.is_file() {
        f(dir);
        return;
    }
    if !md.is_dir() {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for e in entries {
        walk_files(&e, f);
    }
}

/// A UUID formatted from the first 16 bytes of the SHA-256 of `data`,
/// with the version and variant bits of a name-based UUID.
pub fn content_uuid(data: &[u8]) -> String {
    let h = cranix_core::hash::Hash::sha256(data).to_base16();
    let mut b: Vec<u8> = (0..16).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect();
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    let x: String = b.iter().map(|v| format!("{v:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &x[..8], &x[8..12], &x[12..16], &x[16..20], &x[20..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_identifiers() {
        let mut d = Derivation { name: "openssl-3.0.13".into(), ..Default::default() };
        assert_eq!(name_version(&d), ("openssl".into(), Some("3.0.13".into())));
        assert_eq!(crate_download("crate-serde_json-1.0.120.tar.gz"), Some(("serde_json".into(), "1.0.120".into())));
        assert_eq!(crate_download("crate-x-y.tar.gz"), None);
        let m = go_modules_txt("# golang.org/x/sys v0.1.0\n## explicit\ngolang.org/x/sys/unix\n# github.com/a/b v1.0.0 => github.com/fork/b v1.0.1\n");
        assert_eq!(m.iter().map(|e| e.purl()).collect::<Vec<_>>(), ["pkg:golang/golang.org/x/sys@v0.1.0", "pkg:golang/github.com/fork/b@v1.0.1"]);
        d.name = "etc".into();
        assert_eq!(name_version(&d).1, None);
        d.env.insert("pname".into(), "requests".into());
        d.env.insert("version".into(), "2.31.0".into());
        d.name = "python3.12-requests-2.31.0".into();
        assert_eq!(ecosystem_purls(&d, "requests", "2.31.0"), ["pkg:pypi/requests@2.31.0"]);
        assert_eq!(cpe("Foo Bar", "1.0+x"), "cpe:2.3:a:*:foo_bar:1.0\\+x:*:*:*:*:*:*:*");
        assert_eq!(purl_escape("1.0+x"), "1.0%2Bx");
        assert!(known_license("MIT") && known_license("Apache-2.0") && !known_license("NOT-A-LICENCE"));
        let u = content_uuid(b"x");
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "5");
        assert_eq!(u, content_uuid(b"x"));
    }
}
