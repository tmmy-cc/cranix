//! Source bundles of a release: every source a build graph is made from
//! (downloads of fixed-output derivations and local source paths),
//! together with the derivations that name them, and an index of them
//! for a binary cache, so that the release rebuilds without network
//! access.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Write};
use std::path::Path;

use cranix_core::{Derivation, StorePath};
use cranix_store::binary_cache::BinaryCache;
use cranix_store::Store;
use serde_json::{json, Value};

use crate::{License, Meta};

/// The name of the index at the root of a bundle.
pub const INDEX: &str = "sources.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// The output of a fixed-output derivation (`fetchurl`, `fetchGit`, …).
    Fetched,
    /// A path copied into the store from the local file system.
    Local,
    /// A derivation of the build graph.
    Derivation,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Fetched => "fetched",
            Kind::Local => "local",
            Kind::Derivation => "derivation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: StorePath,
    pub kind: Kind,
    /// The derivation producing a fetched source.
    pub fetcher: Option<StorePath>,
    pub urls: Vec<String>,
    /// `(algorithm, digest)` as the fixed-output derivation states it,
    /// with `r:` for a hash of the NAR serialisation.
    pub hash: Option<(String, String)>,
    /// The licences of the packages that use the source.
    pub licenses: Vec<License>,
    /// The derivations that take the source as an input.
    pub used_by: BTreeSet<StorePath>,
    /// Whether the path is in the store.
    pub available: bool,
    /// Why the path is not in the bundle: it could not be fetched, or a
    /// filter left it out.
    pub reason: Option<String>,
}

/// Loads the build graph of `drvs`.
pub fn graph(store: &Store, drvs: &[StorePath]) -> Result<BTreeMap<StorePath, Derivation>, String> {
    let mut loaded = BTreeMap::new();
    let mut todo = drvs.to_vec();
    while let Some(d) = todo.pop() {
        if loaded.contains_key(&d) {
            continue;
        }
        let drv = store.read_derivation(&d)?;
        todo.extend(drv.input_drvs.keys().filter(|i| !loaded.contains_key(*i)).cloned());
        loaded.insert(d, drv);
    }
    Ok(loaded)
}

/// The fixed-output derivations of `graph` whose output is not in the
/// store.
pub fn missing_fetches(store: &Store, graph: &BTreeMap<StorePath, Derivation>) -> Vec<StorePath> {
    graph
        .iter()
        .filter(|(_, drv)| drv.is_fixed_output())
        .filter(|(_, drv)| drv.outputs["out"].path.as_ref().is_none_or(|p| !store.is_valid(p)))
        .map(|(d, _)| d.clone())
        .collect()
}

/// What stands in the way of building the fixed-output derivation `d`
/// without building anything else: `Ok(())` when all its inputs are in
/// the store, `Err(Some(input))` for a missing input that is a
/// fixed-output derivation itself (to be fetched first), and `Err(None)`
/// with a message when a missing input would have to be built.
pub fn blocker(store: &Store, graph: &BTreeMap<StorePath, Derivation>, d: &StorePath) -> Result<(), Result<StorePath, String>> {
    let drv = &graph[d];
    for (i, outs) in &drv.input_drvs {
        let Some(idrv) = graph.get(i) else { continue };
        let present = outs.iter().all(|o| idrv.outputs.get(o).and_then(|x| x.path.as_ref()).is_some_and(|p| store.is_valid(p)));
        if present {
            continue;
        }
        return Err(if idrv.is_fixed_output() {
            Ok(i.clone())
        } else {
            Err(format!("fetching it needs '{}', which is not fixed-output and is not built", store.dir.print(i)))
        });
    }
    Ok(())
}

/// Lists the sources and derivations of `graph`, sorted by path.
/// `meta` gives the licences of packages; a source carries those of the
/// derivations that use it.
pub fn collect(store: &Store, graph: &BTreeMap<StorePath, Derivation>, meta: &HashMap<StorePath, Meta>) -> Vec<Entry> {
    let mut entries: BTreeMap<StorePath, Entry> = BTreeMap::new();
    let licenses_of = |d: &StorePath| meta.get(d).map(|m| m.licenses.clone()).unwrap_or_default();
    for (d, drv) in graph {
        let entry = |p: &StorePath, kind| Entry {
            path: p.clone(),
            kind,
            fetcher: None,
            urls: Vec::new(),
            hash: None,
            licenses: Vec::new(),
            used_by: BTreeSet::new(),
            available: store.is_valid(p),
            reason: None,
        };
        entries.entry(d.clone()).or_insert_with(|| entry(d, Kind::Derivation)).licenses.extend(licenses_of(d));
        if drv.is_fixed_output() {
            let o = &drv.outputs["out"];
            if let Some(p) = &o.path {
                let e = entries.entry(p.clone()).or_insert_with(|| entry(p, Kind::Fetched));
                e.fetcher = Some(d.clone());
                e.urls = fetch_urls(drv);
                e.hash = (!o.hash.is_empty()).then(|| (o.hash_algo.clone(), o.hash.clone()));
            }
        }
        for s in &drv.input_srcs {
            let e = entries.entry(s.clone()).or_insert_with(|| entry(s, Kind::Local));
            e.used_by.insert(d.clone());
            e.licenses.extend(licenses_of(d));
        }
        for i in drv.input_drvs.keys() {
            let Some(p) = graph.get(i).filter(|x| x.is_fixed_output()).and_then(|x| x.outputs["out"].path.clone()) else { continue };
            let e = entries.entry(p.clone()).or_insert_with(|| entry(&p, Kind::Fetched));
            e.used_by.insert(d.clone());
            e.licenses.extend(licenses_of(d));
        }
    }
    entries
        .into_values()
        .map(|mut e| {
            e.licenses.sort();
            e.licenses.dedup();
            e
        })
        .collect()
}

/// The URLs a fixed-output derivation downloads from: `url`/`urls` of
/// `fetchurl`, the repository of `fetchGit` and friends.
fn fetch_urls(drv: &Derivation) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for k in ["url", "urls", "gitRepoUrl", "repository"] {
        for u in drv.env.get(k).map(|v| v.split_whitespace()).into_iter().flatten() {
            if !out.iter().any(|x| x == u) {
                out.push(u.to_string());
            }
        }
    }
    out
}

/// The index document of a bundle.
pub fn index(store: &Store, entries: &[Entry]) -> Value {
    let p = |x: &StorePath| store.dir.print(x);
    let sources: Vec<Value> = entries
        .iter()
        .map(|e| {
            let mut v = json!({
                "path": p(&e.path),
                "kind": e.kind.name(),
                "available": e.available,
            });
            let o = v.as_object_mut().unwrap();
            if let Some(f) = &e.fetcher {
                o.insert("fetcher".into(), json!(p(f)));
            }
            if !e.urls.is_empty() {
                o.insert("urls".into(), json!(e.urls));
            }
            if let Some((algo, hash)) = &e.hash {
                o.insert("hash".into(), json!({ "algorithm": algo, "value": hash }));
            }
            if !e.licenses.is_empty() {
                let l: Vec<Value> = e
                    .licenses
                    .iter()
                    .map(|l| match l {
                        License::Id(id) => json!({ "id": id }),
                        License::Name(n) => json!({ "name": n }),
                    })
                    .collect();
                o.insert("licenses".into(), Value::Array(l));
            }
            if let Some(r) = &e.reason {
                o.insert("reason".into(), json!(r));
            }
            if !e.used_by.is_empty() {
                o.insert("usedBy".into(), json!(e.used_by.iter().map(p).collect::<Vec<_>>()));
            }
            v
        })
        .collect();
    let missing = entries.iter().filter(|e| !e.available).count();
    let excluded = entries.iter().filter(|e| e.available && e.reason.is_some()).count();
    json!({
        "storeDir": store.dir.as_str(),
        "sources": sources,
        "missing": missing,
        "excluded": excluded,
    })
}

/// Writes the index of `entries` into `cache`.
pub fn write_index(store: &Store, entries: &[Entry], cache: &BinaryCache) -> Result<(), String> {
    let text = serde_json::to_string_pretty(&index(store, entries)).unwrap() + "\n";
    cache.put_bytes(INDEX, text.as_bytes(), "application/json")
}

/// Writes the files below `dir` as a gzip-compressed ustar archive,
/// in sorted order with zero times, so that equal trees give equal
/// archives.
pub fn write_tar_gz(dir: &Path, out: impl Write) -> io::Result<()> {
    let mut gz = flate2::write::GzEncoder::new(out, flate2::Compression::default());
    let mut files = Vec::new();
    list_files(dir, Path::new(""), &mut files)?;
    for (rel, is_dir) in files {
        let mut name = rel.to_string_lossy().into_owned();
        let data = if is_dir {
            name.push('/');
            Vec::new()
        } else {
            std::fs::read(dir.join(&rel))?
        };
        gz.write_all(&tar_header(&name, data.len() as u64, is_dir)?)?;
        gz.write_all(&data)?;
        gz.write_all(&vec![0; (512 - data.len() % 512) % 512])?;
    }
    gz.write_all(&[0; 1024])?;
    gz.finish()?.flush()
}

fn list_files(root: &Path, rel: &Path, out: &mut Vec<(std::path::PathBuf, bool)>) -> io::Result<()> {
    let mut names: Vec<_> = std::fs::read_dir(root.join(rel))?.map(|e| e.map(|e| e.file_name())).collect::<Result<_, _>>()?;
    names.sort();
    for n in names {
        let r = rel.join(n);
        if root.join(&r).is_dir() {
            out.push((r.clone(), true));
            list_files(root, &r, out)?;
        } else {
            out.push((r, false));
        }
    }
    Ok(())
}

fn tar_header(name: &str, size: u64, is_dir: bool) -> io::Result<[u8; 512]> {
    let mut h = [0u8; 512];
    let (prefix, base) = match name.len() {
        n if n <= 100 => ("", name),
        _ => name[..name.len() - 1]
            .rfind('/')
            .filter(|&i| i <= 155 && name.len() - i - 1 <= 100)
            .map(|i| (&name[..i], &name[i + 1..]))
            .ok_or_else(|| io::Error::other(format!("name too long for a tar archive: {name}")))?,
    };
    h[..base.len()].copy_from_slice(base.as_bytes());
    let mode = if is_dir { "0000755" } else { "0000644" };
    h[100..107].copy_from_slice(mode.as_bytes());
    h[108..115].copy_from_slice(b"0000000");
    h[116..123].copy_from_slice(b"0000000");
    h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
    h[136..147].copy_from_slice(b"00000000000");
    h[156] = if is_dir { b'5' } else { b'0' };
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cranix_core::derivation::Output;

    fn store() -> (std::path::PathBuf, Store) {
        let root = std::env::temp_dir().join(format!("cranix-release-{}-{}", std::process::id(), rand_suffix()));
        let s = Store::open_at(&root).unwrap();
        (root, s)
    }

    fn rand_suffix() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }

    #[test]
    fn collects_fetched_and_local_sources() {
        let (root, s) = store();
        let local = s.add_text("build.sh", b"echo hi", &BTreeSet::new()).unwrap();
        let mut fetch = Derivation { name: "src.tar.gz".into(), platform: "x".into(), builder: "builtin:fetchurl".into(), ..Default::default() };
        fetch.outputs.insert("out".into(), Output { path: None, hash_algo: "sha256".into(), hash: "ab".repeat(32) });
        fetch.env.insert("url".into(), "https://example.org/src.tar.gz".into());
        fetch.fill_output_paths(&s.dir, &mut |_| Err("no inputs".into())).unwrap();
        let fetch_path = s.add_text("src.tar.gz.drv", fetch.to_aterm(&s.dir).as_bytes(), &BTreeSet::new()).unwrap();
        let mut pkg = Derivation { name: "pkg-1.0".into(), platform: "x".into(), builder: "/bin/sh".into(), ..Default::default() };
        pkg.outputs.insert("out".into(), Output::default());
        pkg.input_srcs.insert(local.clone());
        pkg.input_drvs.insert(fetch_path.clone(), ["out".to_string()].into());
        let refs: BTreeSet<StorePath> = [local.clone(), fetch_path.clone()].into();
        let pkg_path = s.add_text("pkg-1.0.drv", pkg.to_aterm(&s.dir).as_bytes(), &refs).unwrap();
        let g = graph(&s, &[pkg_path.clone()]).unwrap();
        let meta = HashMap::from([(pkg_path.clone(), Meta { licenses: vec![License::Id("MIT".into())], ..Default::default() })]);
        let entries = collect(&s, &g, &meta);
        let fetched = entries.iter().find(|e| e.kind == Kind::Fetched).unwrap();
        assert_eq!(fetched.urls, ["https://example.org/src.tar.gz"]);
        assert_eq!(fetched.fetcher.as_ref(), Some(&fetch_path));
        assert!(!fetched.available);
        assert_eq!(fetched.licenses, [License::Id("MIT".into())]);
        assert_eq!(missing_fetches(&s, &g), [fetch_path.clone()]);
        assert_eq!(blocker(&s, &g, &fetch_path), Ok(()));
        let l = entries.iter().find(|e| e.path == local).unwrap();
        assert_eq!((l.kind, l.available), (Kind::Local, true));
        assert_eq!(entries.iter().filter(|e| e.kind == Kind::Derivation).count(), 2);
        let idx = index(&s, &entries);
        assert_eq!(idx["missing"], 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tarball_is_deterministic() {
        let (root, _) = store();
        let d = root.join("tree");
        std::fs::create_dir_all(d.join("nar")).unwrap();
        std::fs::write(d.join("nar/a.nar"), b"abc").unwrap();
        std::fs::write(d.join(INDEX), b"{}").unwrap();
        let mut a = Vec::new();
        write_tar_gz(&d, &mut a).unwrap();
        let mut b = Vec::new();
        write_tar_gz(&d, &mut b).unwrap();
        assert_eq!(a, b);
        let mut raw = Vec::new();
        io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&a[..]), &mut raw).unwrap();
        assert_eq!(&raw[..4], b"nar/");
        assert_eq!(&raw[257..262], b"ustar");
        assert_eq!(raw.len() % 512, 0);
        let _ = std::fs::remove_dir_all(root);
    }
}
