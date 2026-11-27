//! The CycloneDX and SPDX documents of a small hand-made SBOM, compared
//! with the files in `tests/golden`. `UPDATE_GOLDEN=1` rewrites them.

use std::collections::BTreeSet;
use std::path::PathBuf;

use cranix_sbom::binaries::Embedded;
use cranix_sbom::{cpe, cyclonedx, spdx, Component, License, Meta, Sbom, Source};

fn component(key: &str, name: &str, version: &str) -> Component {
    Component {
        key: format!("/nix/store/{key}-{name}-{version}.drv"),
        name: name.into(),
        version: version.into(),
        purls: vec![format!("pkg:nix/{name}@{version}")],
        cpe: cpe(name, version),
        paths: vec![format!("/nix/store/{key}-{name}-{version}")],
        ..Default::default()
    }
}

fn sbom() -> Sbom {
    let mut app = component("0c6kzph7l0dcbfmjap64i0y8wd3fq1fz", "app", "2.0");
    app.purls.push("pkg:cargo/app@2.0".into());
    app.meta = Meta {
        licenses: vec![License::Id("MIT".into()), License::Name("Custom Licence".into())],
        description: Some("An application".into()),
        homepage: Some("https://example.org/app".into()),
        cpe: None,
    };
    app.sources = vec![Source { url: Some("https://example.org/app-2.0.tar.gz".into()), hash: Some(("SHA-256".into(), "ab".repeat(32))) }];
    app.embedded = vec![
        Embedded { ecosystem: "cargo", name: "serde".into(), version: "1.0.200".into(), checksum: Some("cd".repeat(32)), found_in: "derivation" },
        Embedded { ecosystem: "golang", name: "golang.org/x/sys".into(), version: "v0.1.0".into(), checksum: Some("h1:abc=".into()), found_in: "binary" },
    ];
    app.unlisted = vec!["/nix/store/0c6kzph7l0dcbfmjap64i0y8wd3fq1fz-app-2.0/bin/static-tool".into()];
    let mut lib = component("1b9p07z77phvv2hf6qhvhd9rcmmr9n1i", "libfoo", "1.2.3");
    lib.meta.licenses = vec![License::Id("BSD-3-Clause".into())];
    lib.paths.push("/nix/store/2whrxfwbq2c3s7x5tjm2cplxlr6p4c6d-libfoo-1.2.3-dev".into());
    let mut s = Sbom { root: app.clone(), ..Default::default() };
    s.deps.insert(app.key.clone(), BTreeSet::from([lib.key.clone()]));
    s.deps.insert(lib.key.clone(), BTreeSet::new());
    s.components.insert(app.key.clone(), app);
    s.components.insert(lib.key.clone(), lib);
    s
}

fn check(name: &str, doc: &serde_json::Value) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(name);
    let text = serde_json::to_string_pretty(doc).unwrap() + "\n";
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &text).unwrap();
    }
    let want = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(text, want, "{name} differs; rerun with UPDATE_GOLDEN=1 to accept");
}

#[test]
fn cyclonedx_golden() {
    let doc = cyclonedx::document(&sbom());
    assert_eq!(doc, cyclonedx::document(&sbom()));
    check("app.cdx.json", &doc);
}

#[test]
fn spdx_golden() {
    let doc = spdx::document(&sbom(), 0);
    assert_eq!(doc, spdx::document(&sbom(), 0));
    check("app.spdx.json", &doc);
}

#[test]
fn merged_documents_read_back() {
    let doc = cyclonedx::document(&sbom());
    let (comps, deps) = cyclonedx::read(&doc).unwrap();
    assert_eq!(comps.len(), 2);
    assert_eq!(deps.len(), 2);
}
