//! SPDX 2.3 JSON. SPDX requires a creation time: it is
//! `SOURCE_DATE_EPOCH` when set, else the Unix epoch, so that the same
//! closure gives the same document. The namespace follows from the content.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::{content_uuid, Component, License, Sbom};

fn spdx_id(key: &str) -> String {
    let h = cranix_core::hash::Hash::sha256(key.as_bytes()).to_base16();
    format!("SPDXRef-Package-{}", &h[..16])
}

/// `YYYY-MM-DDThh:mm:ssZ` for seconds since the epoch.
pub fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn license_ref(name: &str) -> String {
    let s: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '-' }).collect();
    format!("LicenseRef-{s}")
}

fn package(c: &Component, extracted: &mut BTreeMap<String, String>) -> Value {
    let mut m = Map::new();
    m.insert("SPDXID".into(), spdx_id(&c.key).into());
    m.insert("name".into(), c.name.clone().into());
    if !c.version.is_empty() {
        m.insert("versionInfo".into(), c.version.clone().into());
    }
    let src = c.sources.iter().find(|s| s.url.is_some());
    m.insert("downloadLocation".into(), src.and_then(|s| s.url.clone()).unwrap_or_else(|| "NOASSERTION".into()).into());
    m.insert("filesAnalyzed".into(), false.into());
    let lic = if c.meta.licenses.is_empty() {
        "NOASSERTION".to_string()
    } else {
        let parts: Vec<String> = c
            .meta
            .licenses
            .iter()
            .map(|l| match l {
                License::Id(id) if crate::known_license(id) => id.clone(),
                License::Id(n) | License::Name(n) => {
                    let r = license_ref(n);
                    extracted.insert(r.clone(), n.clone());
                    r
                }
            })
            .collect();
        parts.join(" AND ")
    };
    m.insert("licenseConcluded".into(), "NOASSERTION".into());
    m.insert("licenseDeclared".into(), lic.into());
    m.insert("copyrightText".into(), "NOASSERTION".into());
    if let Some(d) = &c.meta.description {
        m.insert("description".into(), d.clone().into());
    }
    if let Some(h) = &c.meta.homepage {
        m.insert("homepage".into(), h.clone().into());
    }
    if let Some((alg, hex)) = src.and_then(|s| s.hash.as_ref()) {
        let alg = alg.replace('-', "");
        if matches!(alg.as_str(), "SHA256" | "SHA512" | "SHA1" | "MD5") {
            m.insert("checksums".into(), json!([{ "algorithm": alg, "checksumValue": hex }]));
        }
    }
    let mut refs: Vec<Value> = c.purls.iter().map(|p| json!({ "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": p })).collect();
    if !c.cpe.is_empty() && !c.version.is_empty() {
        refs.push(json!({ "referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": c.cpe }));
    }
    if !refs.is_empty() {
        m.insert("externalRefs".into(), refs.into());
    }
    let mut notes: Vec<String> = c.paths.iter().map(|p| format!("store path: {p}")).collect();
    notes.extend(c.unlisted.iter().map(|u| format!("binary without a list of its linked code: {u}")));
    if !notes.is_empty() {
        m.insert("comment".into(), notes.join("\n").into());
    }
    Value::Object(m)
}

fn embedded_package(parent: &Component, e: &crate::binaries::Embedded) -> (String, Value) {
    let key = format!("{}#{}", parent.key, e.purl());
    let mut m = Map::new();
    m.insert("SPDXID".into(), spdx_id(&key).into());
    m.insert("name".into(), e.name.clone().into());
    m.insert("versionInfo".into(), e.version.clone().into());
    m.insert("downloadLocation".into(), "NOASSERTION".into());
    m.insert("filesAnalyzed".into(), false.into());
    m.insert("licenseConcluded".into(), "NOASSERTION".into());
    m.insert("licenseDeclared".into(), "NOASSERTION".into());
    m.insert("copyrightText".into(), "NOASSERTION".into());
    m.insert("externalRefs".into(), json!([{ "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": e.purl() }]));
    m.insert("comment".into(), format!("found in: {}", e.found_in).into());
    (key, Value::Object(m))
}

/// The document for `sbom`, created at `epoch` seconds.
pub fn document(sbom: &Sbom, epoch: i64) -> Value {
    let mut extracted = BTreeMap::new();
    let mut packages = vec![package(&sbom.root, &mut extracted)];
    let mut rels = vec![json!({ "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": spdx_id(&sbom.root.key) })];
    let mut all: Vec<&Component> = sbom.components.values().filter(|c| c.key != sbom.root.key).collect();
    all.extend(sbom.merged.iter());
    for c in &all {
        packages.push(package(c, &mut extracted));
    }
    for c in std::iter::once(&sbom.root).chain(all.iter().copied()) {
        for e in &c.embedded {
            let (key, p) = embedded_package(c, e);
            packages.push(p);
            rels.push(json!({ "spdxElementId": spdx_id(&c.key), "relationshipType": "CONTAINS", "relatedSpdxElement": spdx_id(&key) }));
        }
    }
    for (k, ds) in &sbom.deps {
        for d in ds {
            rels.push(json!({ "spdxElementId": spdx_id(k), "relationshipType": "DEPENDS_ON", "relatedSpdxElement": spdx_id(d) }));
        }
    }
    for c in &sbom.merged {
        rels.push(json!({ "spdxElementId": spdx_id(&sbom.root.key), "relationshipType": "DEPENDS_ON", "relatedSpdxElement": spdx_id(&c.key) }));
    }
    packages.sort_by(|a, b| a["SPDXID"].as_str().cmp(&b["SPDXID"].as_str()));
    packages.dedup_by(|a, b| a["SPDXID"] == b["SPDXID"]);
    rels.sort_by_key(|r| r.to_string());
    rels.dedup();
    let mut doc = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": if sbom.root.version.is_empty() { sbom.root.name.clone() } else { format!("{}-{}", sbom.root.name, sbom.root.version) },
        "creationInfo": {
            "created": rfc3339(epoch),
            "creators": [format!("Tool: cranix-{}", env!("CARGO_PKG_VERSION"))],
        },
        "packages": packages,
        "relationships": rels,
    });
    if !extracted.is_empty() {
        let infos: Vec<Value> = extracted.iter().map(|(id, n)| json!({ "licenseId": id, "name": n, "extractedText": n })).collect();
        doc.as_object_mut().unwrap().insert("hasExtractedLicensingInfos".into(), infos.into());
    }
    let ns = format!("https://cranix.cc/spdx/{}", content_uuid(doc.to_string().as_bytes()));
    doc.as_object_mut().unwrap().insert("documentNamespace".into(), ns.into());
    doc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }
}
