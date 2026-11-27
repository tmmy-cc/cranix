//! CycloneDX 1.6 JSON. The document has no timestamp, and its serial
//! number is a UUID made from the rest of its content.

use serde_json::{json, Map, Value};

use crate::binaries::Embedded;
use crate::{content_uuid, Component, License, Sbom};

fn prop(name: &str, value: &str) -> Value {
    json!({ "name": name, "value": value })
}

/// The purl scanners should use: the ecosystem one when there is one,
/// else `pkg:nix`; the others become properties.
fn main_purl(c: &Component) -> Option<&str> {
    c.purls.iter().find(|p| !p.starts_with("pkg:nix/")).or(c.purls.first()).map(String::as_str)
}

fn licenses(ls: &[License]) -> Value {
    Value::Array(
        ls.iter()
            .map(|l| match l {
                License::Id(id) if crate::known_license(id) => json!({ "license": { "id": id } }),
                License::Id(n) => json!({ "license": { "name": n } }),
                License::Name(n) => json!({ "license": { "name": n } }),
            })
            .collect(),
    )
}

fn embedded(parent: &str, e: &Embedded) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), "library".into());
    m.insert("bom-ref".into(), format!("{parent}#{}", e.purl()).into());
    m.insert("name".into(), e.name.clone().into());
    m.insert("version".into(), e.version.clone().into());
    m.insert("purl".into(), e.purl().into());
    let mut props = vec![prop("cranix:found-in", e.found_in)];
    match &e.checksum {
        Some(c) if c.len() == 64 && c.bytes().all(|b| b.is_ascii_hexdigit()) => {
            m.insert("hashes".into(), json!([{ "alg": "SHA-256", "content": c.to_lowercase() }]));
        }
        Some(c) => props.push(prop("cranix:checksum", c)),
        None => {}
    }
    m.insert("properties".into(), props.into());
    Value::Object(m)
}

fn component(c: &Component, kind: &str) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), kind.into());
    m.insert("bom-ref".into(), c.key.clone().into());
    m.insert("name".into(), c.name.clone().into());
    if !c.version.is_empty() {
        m.insert("version".into(), c.version.clone().into());
    }
    if let Some(d) = &c.meta.description {
        m.insert("description".into(), d.clone().into());
    }
    if !c.meta.licenses.is_empty() {
        m.insert("licenses".into(), licenses(&c.meta.licenses));
    }
    if !c.cpe.is_empty() && !c.version.is_empty() {
        m.insert("cpe".into(), c.cpe.clone().into());
    }
    let main = main_purl(c);
    if let Some(p) = main {
        m.insert("purl".into(), p.into());
    }
    let mut refs = Vec::new();
    if let Some(h) = &c.meta.homepage {
        refs.push(json!({ "type": "website", "url": h }));
    }
    for s in &c.sources {
        let Some(url) = &s.url else { continue };
        let mut r = Map::new();
        r.insert("type".into(), "distribution".into());
        r.insert("url".into(), url.clone().into());
        if let Some((alg, hex)) = &s.hash {
            if matches!(alg.as_str(), "SHA-256" | "SHA-512" | "SHA-1" | "MD5") {
                r.insert("hashes".into(), json!([{ "alg": alg, "content": hex }]));
            }
        }
        refs.push(Value::Object(r));
    }
    if !refs.is_empty() {
        m.insert("externalReferences".into(), refs.into());
    }
    let mut props: Vec<Value> = c.paths.iter().map(|p| prop("nix:store_path", p)).collect();
    props.extend(c.purls.iter().filter(|p| Some(p.as_str()) != main).map(|p| prop("cranix:purl", p)));
    props.extend(c.unlisted.iter().map(|u| prop("cranix:unlisted-binary", u)));
    if !props.is_empty() {
        m.insert("properties".into(), props.into());
    }
    if !c.embedded.is_empty() {
        m.insert("components".into(), c.embedded.iter().map(|e| embedded(&c.key, e)).collect::<Vec<_>>().into());
    }
    Value::Object(m)
}

/// The document for `sbom`.
pub fn document(sbom: &Sbom) -> Value {
    let mut comps: Vec<Value> = sbom.components.values().filter(|c| c.key != sbom.root.key).map(|c| component(c, "library")).collect();
    comps.extend(sbom.merged.iter().map(|c| component(c, "library")));
    let mut deps: Vec<Value> = Vec::new();
    let mut keys: Vec<&String> = sbom.components.keys().collect();
    if !sbom.components.contains_key(&sbom.root.key) {
        keys.push(&sbom.root.key);
    }
    keys.extend(sbom.merged.iter().map(|c| &c.key));
    keys.sort();
    keys.dedup();
    for k in keys {
        let mut d: Vec<&String> = sbom.deps.get(k).into_iter().flatten().collect();
        if *k == sbom.root.key {
            d.extend(sbom.merged.iter().map(|c| &c.key));
        }
        d.sort();
        d.dedup();
        deps.push(json!({ "ref": k, "dependsOn": d }));
    }
    let mut doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": { "components": [{ "type": "application", "name": "cranix", "version": env!("CARGO_PKG_VERSION") }] },
            "component": component(&sbom.root, "application"),
        },
        "components": comps,
        "dependencies": deps,
    });
    let serial = format!("urn:uuid:{}", content_uuid(doc.to_string().as_bytes()));
    doc.as_object_mut().unwrap().insert("serialNumber".into(), serial.into());
    doc
}

/// Reads the components of a CycloneDX document, to merge it into another:
/// its root and components, with their dependencies.
pub fn read(doc: &Value) -> crate::Result<(Vec<Component>, Vec<(String, Vec<String>)>)> {
    if doc["bomFormat"].as_str() != Some("CycloneDX") {
        return Err("not a CycloneDX document".into());
    }
    let to_comp = |v: &Value| -> Option<Component> {
        Some(Component {
            key: v["bom-ref"].as_str().or(v["purl"].as_str()).or(v["name"].as_str())?.to_string(),
            name: v["name"].as_str()?.to_string(),
            version: v["version"].as_str().unwrap_or("").to_string(),
            purls: v["purl"].as_str().map(|p| vec![p.to_string()]).unwrap_or_default(),
            cpe: v["cpe"].as_str().unwrap_or("").to_string(),
            ..Default::default()
        })
    };
    let mut out: Vec<Component> = doc["metadata"]["component"].as_object().and_then(|_| to_comp(&doc["metadata"]["component"])).into_iter().collect();
    out.extend(doc["components"].as_array().into_iter().flatten().filter_map(to_comp));
    let deps = doc["dependencies"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| Some((d["ref"].as_str()?.to_string(), d["dependsOn"].as_array()?.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())))
        .collect();
    Ok((out, deps))
}
