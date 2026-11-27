//! SBOM documents from lock files: `Cargo.lock` and npm's
//! `package-lock.json` (lockfile versions 2 and 3).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::{purl_escape, purl_escape_path, Component, Result, Sbom, Source};

/// Reads a lock file, telling the kind by its name.
pub fn from_file(path: &Path) -> Result<Sbom> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading '{}': {e}", path.display()))?;
    match path.file_name().and_then(|n| n.to_str()) {
        Some("Cargo.lock") => cargo(&text),
        Some("package-lock.json" | "npm-shrinkwrap.json") => npm(&text),
        _ => Err(format!("'{}' is not a Cargo.lock or package-lock.json", path.display())),
    }
}

/// The value of a `key = "value"` line.
fn toml_str<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?.trim_start().strip_prefix('=')?.trim();
    rest.strip_prefix('"')?.strip_suffix('"')
}

/// The packages of a `Cargo.lock`: crates from a registry or Git are
/// components; packages without a source are the workspace, the root.
pub fn cargo(text: &str) -> Result<Sbom> {
    #[derive(Default)]
    struct Pkg {
        name: String,
        version: String,
        source: Option<String>,
        checksum: Option<String>,
        deps: Vec<String>,
    }
    let mut pkgs: Vec<Pkg> = Vec::new();
    let mut in_deps = false;
    for line in text.lines() {
        let l = line.trim();
        if l == "[[package]]" {
            pkgs.push(Pkg::default());
            in_deps = false;
            continue;
        }
        if l.starts_with('[') && !l.starts_with("[[package]]") {
            in_deps = false;
        }
        let Some(p) = pkgs.last_mut() else { continue };
        if in_deps {
            if l.starts_with(']') {
                in_deps = false;
            } else if let Some(d) = l.trim_end_matches(',').strip_prefix('"').and_then(|d| d.strip_suffix('"')) {
                p.deps.push(d.to_string());
            }
            continue;
        }
        if let Some(v) = toml_str(l, "name") {
            p.name = v.into();
        } else if let Some(v) = toml_str(l, "version") {
            p.version = v.into();
        } else if let Some(v) = toml_str(l, "source") {
            p.source = Some(v.into());
        } else if let Some(v) = toml_str(l, "checksum") {
            p.checksum = Some(v.into());
        } else if l.starts_with("dependencies") {
            let inline = l.split_once('[').map(|(_, r)| r);
            match inline {
                Some(r) if r.contains(']') => {
                    p.deps.extend(r.trim_end_matches(']').split(',').filter_map(|d| d.trim().strip_prefix('"')?.strip_suffix('"').map(str::to_string)));
                }
                _ => in_deps = true,
            }
        }
    }
    if pkgs.is_empty() {
        return Err("no packages in Cargo.lock".into());
    }
    // A dependency is `name` or `name version` when names repeat.
    let key = |p: &Pkg| format!("pkg:cargo/{}@{}", purl_escape(&p.name), purl_escape(&p.version));
    let resolve = |d: &str| -> Option<String> {
        let mut it = d.split_whitespace();
        let (n, v) = (it.next()?, it.next());
        pkgs.iter().find(|p| p.name == n && v.is_none_or(|v| p.version == v)).map(key)
    };
    let mut sbom = Sbom::default();
    let roots: Vec<&Pkg> = pkgs.iter().filter(|p| p.source.is_none()).collect();
    sbom.root = match roots.as_slice() {
        [r] => Component { key: key(r), name: r.name.clone(), version: r.version.clone(), purls: vec![key(r)], ..Default::default() },
        _ => Component { key: "root".into(), name: "Cargo.lock".into(), ..Default::default() },
    };
    for p in &pkgs {
        let k = key(p);
        let deps: BTreeSet<String> = p.deps.iter().filter_map(|d| resolve(d)).collect();
        if p.source.is_none() {
            if sbom.root.key == "root" {
                sbom.deps.entry("root".into()).or_default().insert(k.clone());
            } else if k != sbom.root.key {
                // Further workspace members are components too.
            } else {
                sbom.deps.insert(k.clone(), deps);
                continue;
            }
        }
        let url = p.source.as_ref().filter(|s| s.starts_with("registry+")).map(|_| format!("https://crates.io/api/v1/crates/{}/{}/download", p.name, p.version));
        let git = p.source.as_ref().and_then(|s| s.strip_prefix("git+")).map(str::to_string);
        sbom.components.insert(
            k.clone(),
            Component {
                key: k.clone(),
                name: p.name.clone(),
                version: p.version.clone(),
                purls: vec![k.clone()],
                cpe: crate::cpe(&p.name, &p.version),
                sources: vec![Source { url: url.or(git), hash: p.checksum.clone().map(|c| ("SHA-256".to_string(), c)) }],
                ..Default::default()
            },
        );
        sbom.deps.insert(k, deps);
    }
    Ok(sbom)
}

/// The packages of an npm lock file (`packages`, lockfile version 2 or 3).
pub fn npm(text: &str) -> Result<Sbom> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("parsing package-lock.json: {e}"))?;
    let pkgs = v["packages"].as_object().ok_or("package-lock.json has no 'packages'; lockfile version 2 or 3 is needed")?;
    let name_of = |path: &str, p: &serde_json::Value| -> String {
        p["name"].as_str().map(str::to_string).unwrap_or_else(|| path.rsplit_once("node_modules/").map_or(path, |(_, n)| n).to_string())
    };
    let purl = |name: &str, version: &str| {
        let n = match name.strip_prefix('@') {
            Some(scoped) => format!("%40{}", purl_escape_path(scoped)),
            None => purl_escape(name),
        };
        format!("pkg:npm/{n}@{}", purl_escape(version))
    };
    let mut sbom = Sbom::default();
    let root = &pkgs.get("").cloned().unwrap_or_default();
    let root_name = v["name"].as_str().or(root["name"].as_str()).unwrap_or("package-lock.json").to_string();
    let root_version = v["version"].as_str().or(root["version"].as_str()).unwrap_or("").to_string();
    sbom.root = Component { key: "root".into(), name: root_name, version: root_version, ..Default::default() };
    // The installed copy a dependency name resolves to from `path`: the
    // nearest `node_modules` up the tree.
    let lookup = |from: &str, dep: &str| -> Option<String> {
        let mut base = from.to_string();
        loop {
            let cand = if base.is_empty() { format!("node_modules/{dep}") } else { format!("{base}/node_modules/{dep}") };
            if pkgs.contains_key(&cand) {
                return Some(cand);
            }
            match base.rfind("/node_modules/") {
                Some(i) => base.truncate(i),
                None if !base.is_empty() => base.clear(),
                None => return None,
            }
        }
    };
    let mut keys: BTreeMap<String, String> = BTreeMap::new();
    for (path, p) in pkgs {
        if path.is_empty() || p["link"].as_bool() == Some(true) {
            continue;
        }
        let name = name_of(path, p);
        let Some(version) = p["version"].as_str() else { continue };
        let k = purl(&name, version);
        keys.insert(path.clone(), k.clone());
        let hash = p["integrity"].as_str().and_then(|i| {
            let (algo, b64) = i.split_once('-')?;
            let raw = cranix_core::hash::base64_decode(b64)?;
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            Some((algo.to_uppercase().replace("SHA", "SHA-"), hex))
        });
        sbom.components.entry(k.clone()).or_insert(Component {
            key: k.clone(),
            name: name.clone(),
            version: version.into(),
            purls: vec![k],
            cpe: crate::cpe(&name, version),
            sources: vec![Source { url: p["resolved"].as_str().map(str::to_string), hash }],
            ..Default::default()
        });
    }
    let dep_names = |p: &serde_json::Value| -> Vec<String> {
        ["dependencies", "optionalDependencies", "peerDependencies"].iter().filter_map(|k| p[*k].as_object()).flat_map(|m| m.keys().cloned()).collect()
    };
    for (path, p) in pkgs {
        let from = if path.is_empty() { "root".to_string() } else { match keys.get(path) { Some(k) => k.clone(), None => continue } };
        let d: BTreeSet<String> = dep_names(p).iter().filter_map(|n| lookup(path, n)).filter_map(|q| keys.get(&q).cloned()).collect();
        sbom.deps.entry(from).or_default().extend(d);
    }
    Ok(sbom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_lock() {
        let s = cargo(
            r#"
version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "serde",
 "syn 2.0.1",
]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "syn"
version = "2.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["serde"]
"#,
        )
        .unwrap();
        assert_eq!(s.root.key, "pkg:cargo/app@0.1.0");
        assert_eq!(s.components.len(), 2);
        assert_eq!(s.deps["pkg:cargo/app@0.1.0"], ["pkg:cargo/serde@1.0.200".to_string(), "pkg:cargo/syn@2.0.1".to_string()].into());
        assert_eq!(s.deps["pkg:cargo/syn@2.0.1"].len(), 1);
        let serde = &s.components["pkg:cargo/serde@1.0.200"];
        assert_eq!(serde.sources[0].hash, Some(("SHA-256".into(), "abc123".into())));
    }

    #[test]
    fn npm_lock() {
        let s = npm(r#"{"name":"web","version":"1.0.0","lockfileVersion":3,"packages":{
            "":{"name":"web","version":"1.0.0","dependencies":{"@scope/a":"^1"}},
            "node_modules/@scope/a":{"version":"1.2.0","resolved":"https://registry.npmjs.org/@scope/a/-/a-1.2.0.tgz","integrity":"sha512-AAAA","dependencies":{"b":"*"}},
            "node_modules/b":{"version":"2.0.0"},
            "node_modules/@scope/a/node_modules/b":{"version":"1.0.0"}}}"#)
        .unwrap();
        assert_eq!(s.root.name, "web");
        assert_eq!(s.components.len(), 3);
        assert_eq!(s.deps["root"], ["pkg:npm/%40scope/a@1.2.0".to_string()].into());
        // The nested copy wins for the package that installs it.
        assert_eq!(s.deps["pkg:npm/%40scope/a@1.2.0"], ["pkg:npm/b@1.0.0".to_string()].into());
        assert_eq!(s.components["pkg:npm/%40scope/a@1.2.0"].sources[0].hash.as_ref().unwrap().0, "SHA-512");
    }
}
