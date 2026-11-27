//! `vuln-db import` and `vuln-scan` with a small fixture database: matching
//! by ecosystem and by CPE product, one finding per product, OpenVEX
//! assessments, severity thresholds, reports and exit codes.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::json;

const CRANIX: &str = env!("CARGO_BIN_EXE_cranix");

struct Env {
    root: PathBuf,
}

impl Env {
    fn new(name: &str) -> Env {
        let root = std::env::temp_dir().join(format!("cranix-vuln-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("osv")).unwrap();
        let env = Env { root };
        env.fixtures();
        env
    }

    fn path(&self, p: &str) -> String {
        self.root.join(p).to_string_lossy().into_owned()
    }

    fn write(&self, p: &str, v: &serde_json::Value) {
        fs::write(self.root.join(p), v.to_string()).unwrap();
    }

    fn fixtures(&self) {
        self.write(
            "osv/GHSA-1.json",
            &json!({
                "id": "GHSA-aaaa", "aliases": ["CVE-2024-0001"], "summary": "requests leaks headers",
                "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" }],
                "affected": [{ "package": { "ecosystem": "PyPI", "name": "Requests" }, "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "0" }, { "fixed": "2.31.0" }] }] }]
            }),
        );
        self.write(
            "osv/RUSTSEC-1.json",
            &json!({
                "id": "RUSTSEC-2024-0002", "summary": "serde panic", "database_specific": { "severity": "LOW" },
                "affected": [{ "package": { "ecosystem": "crates.io", "name": "serde" }, "versions": ["1.0.200"] }]
            }),
        );
        let cve = |id: &str, score: f64, criteria: &str, extra: serde_json::Value| {
            let mut m = json!({ "vulnerable": true, "criteria": criteria });
            m.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            json!({ "cve": {
                "id": id,
                "descriptions": [{ "lang": "en", "value": format!("{id} description") }],
                "metrics": { "cvssMetricV31": [{ "cvssData": { "baseScore": score } }] },
                "configurations": [{ "nodes": [{ "cpeMatch": [m] }] }]
            }})
        };
        self.write(
            "nvd.json",
            &json!({ "vulnerabilities": [
                cve("CVE-2024-1000", 9.8, "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", json!({ "versionStartIncluding": "3.0.0", "versionEndExcluding": "3.0.14" })),
                cve("CVE-2024-2000", 5.3, "cpe:2.3:a:gnu:bash:5.2:*:*:*:*:*:*:*", json!({})),
                cve("CVE-2024-3000", 7.5, "cpe:2.3:a:other:zlib:1.3:*:*:*:*:*:*:*", json!({})),
            ]}),
        );
        let comp = |r: &str, name: &str, version: &str, purl: &str, cpe: Option<&str>| {
            let mut c = json!({ "type": "library", "bom-ref": r, "name": name, "version": version, "purl": purl });
            if let Some(cpe) = cpe {
                c["cpe"] = cpe.into();
            }
            c
        };
        self.write(
            "sbom.cdx.json",
            &json!({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "metadata": { "component": {
                    "type": "application", "bom-ref": "/nix/store/a-app-1.0.drv", "name": "app", "version": "1.0", "purl": "pkg:nix/app@1.0",
                    "components": [comp("/nix/store/a-app-1.0.drv#pkg:cargo/serde@1.0.200", "serde", "1.0.200", "pkg:cargo/serde@1.0.200", None)]
                }},
                "components": [
                    comp("/nix/store/b-openssl-3.0.13.drv", "openssl", "3.0.13", "pkg:nix/openssl@3.0.13", Some("cpe:2.3:a:*:openssl:3.0.13:*:*:*:*:*:*:*")),
                    comp("/nix/store/c-openssl-3.0.13.drv", "openssl", "3.0.13", "pkg:nix/openssl@3.0.13", Some("cpe:2.3:a:*:openssl:3.0.13:*:*:*:*:*:*:*")),
                    comp("/nix/store/d-bash-5.2p37.drv", "bash", "5.2p37", "pkg:nix/bash@5.2p37", None),
                    comp("/nix/store/e-zlib-1.3.drv", "zlib", "1.3", "pkg:nix/zlib@1.3", Some("cpe:2.3:a:zlib:zlib:1.3:*:*:*:*:*:*:*")),
                    comp("/nix/store/f-requests-2.30.0.drv", "requests", "2.30.0", "pkg:pypi/requests@2.30.0", None),
                    comp("/nix/store/g-openssh-9.0.drv", "openssh", "9.0", "pkg:nix/openssh@9.0", None),
                ],
                "dependencies": []
            }),
        );
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let o = Command::new(CRANIX).args(args).env("XDG_CACHE_HOME", self.root.join("cache")).output().unwrap();
        (o.status.code().unwrap_or(-1), String::from_utf8(o.stdout).unwrap(), String::from_utf8(o.stderr).unwrap())
    }

    fn import(&self) {
        let (code, _, err) = self.run(&["vuln-db", "import", "--db", &self.path("db"), "--osv", &self.path("osv"), "--nvd", &self.path("nvd.json")]);
        assert_eq!(code, 0, "{err}");
    }

    fn scan(&self, extra: &[&str]) -> (i32, String, String) {
        let sbom = self.path("sbom.cdx.json");
        let db = self.path("db");
        let mut a = vec!["vuln-scan", sbom.as_str(), "--db", db.as_str()];
        a.extend(extra);
        self.run(&a)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn ids(out: &str) -> Vec<String> {
    let mut v: Vec<String> = out.lines().map(|l| l.split_whitespace().next().unwrap().to_string()).collect();
    v.sort();
    v
}

#[test]
fn matching_and_exit_codes() {
    let env = Env::new("match");
    // Without a database, the scan cannot run.
    assert_eq!(env.scan(&[]).0, 3);
    env.import();

    let report = env.path("report.json");
    let (code, out, err) = env.scan(&["--report", &report]);
    assert_eq!(code, 2, "{err}");
    // openssl by product and version range, bash by the release part of
    // its version, requests and serde by their ecosystems; zlib has a
    // vendor in its CPE that the CVE does not name.
    assert_eq!(ids(&out), ["CVE-2024-1000", "CVE-2024-2000", "GHSA-aaaa", "RUSTSEC-2024-0002"]);
    let r: serde_json::Value = serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    let openssl = r["findings"].as_array().unwrap().iter().find(|f| f["id"] == "CVE-2024-1000").unwrap();
    // Two components of the same product are one finding.
    assert_eq!(openssl["components"].as_array().unwrap().len(), 2);
    assert_eq!((openssl["severity"].as_str(), openssl["status"].as_str()), (Some("critical"), Some("unassessed")));
    let ghsa = r["findings"].as_array().unwrap().iter().find(|f| f["id"] == "GHSA-aaaa").unwrap();
    assert_eq!((ghsa["severity"].as_str(), ghsa["score"].as_f64()), (Some("medium"), Some(6.1)));

    // Thresholds.
    assert_eq!(env.scan(&["--fail-on", "critical"]).0, 2);
    let (code, out, _) = env.scan(&["--fail-on", "high"]);
    assert_eq!(code, 2);
    assert_eq!(ids(&out).len(), 4);

    // The database age.
    let meta = env.root.join("db/meta.json");
    fs::write(&meta, json!({ "updated": 1_000_000_000, "sources": [] }).to_string()).unwrap();
    assert_eq!(env.scan(&["--max-db-age", "7d"]).0, 3);
    let (_, _, err) = env.scan(&[]);
    assert!(err.contains("days old"), "{err}");
    assert_eq!(env.scan(&["--max-db-age", "100000d"]).0, 2);

    // Wrong arguments.
    assert_eq!(env.scan(&["--fail-on", "severe"]).0, 64);
    assert_eq!(env.scan(&["--bogus"]).0, 64);
    assert_eq!(env.run(&["vuln-scan"]).0, 64);
}

#[test]
fn vex_assessments() {
    let env = Env::new("vex");
    env.import();
    let stmt = |vuln: &str, products: serde_json::Value, status: &str, extra: serde_json::Value| {
        let mut s = json!({ "vulnerability": { "name": vuln }, "products": products, "status": status });
        s.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        s
    };
    env.write(
        "vex.json",
        &json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://example.org/vex/1",
            "author": "Release team",
            "timestamp": "2026-01-01T00:00:00Z",
            "version": 1,
            "statements": [
                // A versionless purl names every version, and both openssl
                // components share it.
                stmt("CVE-2024-1000", json!([{ "@id": "pkg:nix/openssl" }]), "not_affected", json!({ "justification": "vulnerable_code_not_in_execute_path" })),
                // By alias.
                stmt("CVE-2024-0001", json!(["pkg:pypi/requests@2.30.0"]), "fixed", json!({})),
                stmt("RUSTSEC-2024-0002", json!([{ "@id": "/nix/store/a-app-1.0.drv#pkg:cargo/serde@1.0.200" }]), "under_investigation", json!({})),
            ]
        }),
    );
    let report = env.path("report.json");
    let (code, out, err) = env.scan(&["--vex", &env.path("vex.json"), "--report", &report]);
    assert_eq!(code, 2, "{err}");
    assert_eq!(ids(&out), ["CVE-2024-2000", "RUSTSEC-2024-0002"]);
    let r: serde_json::Value = serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(r["suppressed"], 2);
    let serde = r["findings"].as_array().unwrap().iter().find(|f| f["id"] == "RUSTSEC-2024-0002").unwrap();
    assert_eq!(serde["status"], "under_investigation");

    // Assessing the last unassessed finding lets the scan pass, also when
    // an assessed finding remains.
    env.write(
        "vex2.json",
        &json!({ "@context": "https://openvex.dev/ns/v0.2.0", "statements": [
            stmt("CVE-2024-2000", json!(["pkg:nix/bash@5.2p37"]), "affected", json!({ "action_statement": "update bash" })),
        ]}),
    );
    let (code, out, err) = env.scan(&["--vex", &env.path("vex.json"), "--vex", &env.path("vex2.json")]);
    assert_eq!(code, 0, "{out}{err}");

    // A not_affected statement needs a justification.
    env.write(
        "bad.json",
        &json!({ "@context": "https://openvex.dev/ns/v0.2.0", "statements": [stmt("CVE-2024-2000", json!(["pkg:nix/bash"]), "not_affected", json!({}))] }),
    );
    let (code, _, err) = env.scan(&["--vex", &env.path("bad.json")]);
    assert_eq!(code, 64);
    assert!(err.contains("justification"), "{err}");
}

#[test]
fn durations_and_osv_zip() {
    let env = Env::new("zip");
    let st = Command::new("zip").arg("-q").arg("-j").arg(env.root.join("osv.zip")).arg(env.root.join("osv/GHSA-1.json")).status();
    if !st.is_ok_and(|s| s.success()) {
        return;
    }
    let (code, _, err) = env.run(&["vuln-db", "import", "--db", &env.path("db"), "--osv", &env.path("osv.zip")]);
    assert_eq!(code, 0, "{err}");
    let (code, out, _) = env.scan(&["--max-db-age", "1h"]);
    assert_eq!(code, 2);
    assert_eq!(ids(&out), ["GHSA-aaaa"]);
}
