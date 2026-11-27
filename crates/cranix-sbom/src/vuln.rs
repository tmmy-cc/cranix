//! Vulnerability scanning of CycloneDX SBOMs against OSV and the NVD.
//!
//! The database is a directory with compact indexes built from the
//! published data ([`import_osv`], [`import_nvd`]):
//!
//! - `meta.json`: `{"updated": SECONDS, "sources": [...]}`;
//! - `osv.json`: OSV advisories by `<ecosystem>/<package>`;
//! - `nvd.json`: CVE configurations by CPE product.
//!
//! Ecosystem packages (`pkg:pypi`, `pkg:cargo`, `pkg:npm`, `pkg:golang`)
//! are matched against the advisories of their ecosystem. Other
//! components are matched against the NVD by CPE product (any vendor, or
//! the vendor of a CPE the SBOM gives) and the release part of their
//! version. Findings of one vulnerability for components that map to the
//! same product and version are one finding. OpenVEX statements assess
//! findings: `not_affected` and `fixed` remove them.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value};

use crate::Result;

/// Compares versions: runs of digits numerically, other runs as text, a
/// leading `v` ignored. A version that continues with letters after
/// another ends (`1.0rc1` after `1.0`) is a pre-release and sorts first.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    fn tokens(s: &str) -> Vec<(bool, String)> {
        let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
        let mut out: Vec<(bool, String)> = Vec::new();
        for c in s.chars() {
            if !c.is_ascii_alphanumeric() {
                out.push((false, String::new()));
                continue;
            }
            let digit = c.is_ascii_digit();
            match out.last_mut() {
                Some((d, t)) if !t.is_empty() && *d == digit => t.push(c),
                _ => out.push((digit, c.to_string())),
            }
        }
        out.retain(|(_, t)| !t.is_empty());
        out
    }
    let (ta, tb) = (tokens(a), tokens(b));
    for i in 0..ta.len().max(tb.len()) {
        match (ta.get(i), tb.get(i)) {
            (Some((true, x)), Some((true, y))) => {
                let (x, y) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
                match x.len().cmp(&y.len()).then_with(|| x.cmp(y)) {
                    Ordering::Equal => {}
                    o => return o,
                }
            }
            (Some((false, x)), Some((false, y))) => match x.to_lowercase().cmp(&y.to_lowercase()) {
                Ordering::Equal => {}
                o => return o,
            },
            (Some((true, _)), Some((false, _))) => return Ordering::Greater,
            (Some((false, _)), Some((true, _))) => return Ordering::Less,
            (Some((digit, _)), None) => return if *digit { Ordering::Greater } else { Ordering::Less },
            (None, Some((digit, _))) => return if *digit { Ordering::Less } else { Ordering::Greater },
            (None, None) => break,
        }
    }
    Ordering::Equal
}

/// The release part of a version: its leading digits and dots.
pub fn release_part(v: &str) -> &str {
    let v = v.strip_prefix(['v', 'V']).unwrap_or(v);
    let end = v.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(v.len());
    v[..end].trim_end_matches('.')
}

/// Severity levels, as `--fail-on` names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// No score is known.
    Unknown,
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(s: f64) -> Severity {
        match s {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s > 0.0 => Severity::Low,
            _ => Severity::None,
        }
    }

    pub fn from_name(s: &str) -> Severity {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            "low" => Severity::Low,
            "none" => Severity::None,
            _ => Severity::Unknown,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Severity::Unknown => "unknown",
            Severity::None => "none",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// The `--fail-on` threshold: findings at or above it fail the scan.
/// Findings without a score fail at every threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Threshold(Severity);

impl Threshold {
    pub fn parse(s: &str) -> Result<Threshold> {
        match s {
            "any" => Ok(Threshold(Severity::None)),
            "low" | "medium" | "high" | "critical" => Ok(Threshold(Severity::from_name(s))),
            _ => Err(format!("--fail-on takes any, low, medium, high or critical, not '{s}'")),
        }
    }

    pub fn fails(self, s: Severity) -> bool {
        s == Severity::Unknown || s >= self.0
    }
}

/// The base score of a CVSS 3.0 or 3.1 vector.
pub fn cvss3_score(vector: &str) -> Option<f64> {
    let m: BTreeMap<&str, &str> = vector.split('/').filter_map(|p| p.split_once(':')).collect();
    if !m.get("CVSS").is_some_and(|v| v.starts_with('3')) {
        return None;
    }
    let av = match *m.get("AV")? { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2, _ => return None };
    let ac = match *m.get("AC")? { "L" => 0.77, "H" => 0.44, _ => return None };
    let changed = match *m.get("S")? { "U" => false, "C" => true, _ => return None };
    let pr = match (*m.get("PR")?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *m.get("UI")? { "N" => 0.85, "R" => 0.62, _ => return None };
    let cia = |k: &str| -> Option<f64> { Some(match *m.get(k)? { "H" => 0.56, "L" => 0.22, "N" => 0.0, _ => return None }) };
    let iss = 1.0 - (1.0 - cia("C")?) * (1.0 - cia("I")?) * (1.0 - cia("A")?);
    let impact = if changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15) } else { 6.42 * iss };
    let expl = 8.22 * av * ac * pr * ui;
    if impact <= 0.0 {
        return Some(0.0);
    }
    let roundup = |x: f64| {
        let i = (x * 100_000.0).round() as i64;
        if i % 10_000 == 0 { i as f64 / 100_000.0 } else { ((i / 10_000) + 1) as f64 / 10.0 }
    };
    Some(if changed { roundup((1.08 * (impact + expl)).min(10.0)) } else { roundup((impact + expl).min(10.0)) })
}

/// The OSV ecosystem of a purl type.
fn osv_ecosystem(purl_type: &str) -> Option<&'static str> {
    Some(match purl_type {
        "pypi" => "PyPI",
        "cargo" => "crates.io",
        "npm" => "npm",
        "golang" => "Go",
        _ => return None,
    })
}

fn pypi_normalize(n: &str) -> String {
    n.to_lowercase().replace(['_', '.'], "-")
}

/// `(type, name, version)` of a purl, with percent-escapes decoded and
/// qualifiers and subpaths dropped.
pub fn parse_purl(p: &str) -> Option<(String, String, Option<String>)> {
    let rest = p.strip_prefix("pkg:")?;
    let rest = rest.split(['?', '#']).next()?;
    let (ty, rest) = rest.split_once('/')?;
    let (name, version) = match rest.rsplit_once('@') {
        Some((n, v)) if !n.is_empty() => (n, Some(v)),
        _ => (rest, None),
    };
    let dec = |s: &str| {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    Some((ty.to_lowercase(), dec(name), version.map(dec)))
}

// ---- The database ----

/// Writes the indexes and `meta.json` of a database.
fn write_json(dir: &Path, name: &str, v: &Value) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| format!("creating '{}': {e}", dir.display()))?;
    let tmp = dir.join(format!(".{name}.tmp"));
    std::fs::write(&tmp, v.to_string()).map_err(|e| format!("writing '{}': {e}", tmp.display()))?;
    std::fs::rename(&tmp, dir.join(name)).map_err(|e| format!("writing '{}': {e}", dir.join(name).display()))
}

/// The severity of an OSV record: the highest CVSS 3 base score among its
/// `severity` entries, else `database_specific.severity`.
fn osv_severity(r: &Value) -> (Severity, Option<f64>) {
    let score = r["severity"].as_array().into_iter().flatten().filter_map(|s| s["score"].as_str()).filter_map(cvss3_score).fold(None, |a: Option<f64>, s| Some(a.map_or(s, |a| a.max(s))));
    match score {
        Some(s) => (Severity::from_score(s), Some(s)),
        None => (r["database_specific"]["severity"].as_str().map_or(Severity::Unknown, Severity::from_name), None),
    }
}

/// Turns OSV records into index entries by `<ecosystem>/<package>`.
pub fn import_osv(records: impl IntoIterator<Item = Value>, index: &mut BTreeMap<String, Vec<Value>>) {
    for r in records {
        let (sev, score) = osv_severity(&r);
        for a in r["affected"].as_array().into_iter().flatten() {
            let (Some(eco), Some(name)) = (a["package"]["ecosystem"].as_str(), a["package"]["name"].as_str()) else { continue };
            // `Go`, `PyPI`, also `Debian:12`-like ecosystems with versions.
            let eco = eco.split(':').next().unwrap_or(eco);
            if !matches!(eco, "PyPI" | "crates.io" | "npm" | "Go") {
                continue;
            }
            let name = if eco == "PyPI" { pypi_normalize(name) } else { name.to_string() };
            let ranges: Vec<Value> = a["ranges"].as_array().into_iter().flatten().filter(|g| g["type"] != "GIT").map(|g| g["events"].clone()).collect();
            let entry = json!({
                "id": r["id"],
                "aliases": r["aliases"],
                "summary": r["summary"],
                "severity": sev.name(),
                "score": score,
                "ranges": ranges,
                "versions": a["versions"],
            });
            index.entry(format!("{eco}/{name}")).or_default().push(entry);
        }
    }
}

/// Turns NVD 2.0 feed records (`vulnerabilities[].cve`) into index
/// entries by CPE product.
pub fn import_nvd(feed: &Value, index: &mut BTreeMap<String, Vec<Value>>) {
    for v in feed["vulnerabilities"].as_array().into_iter().flatten() {
        let cve = &v["cve"];
        let Some(id) = cve["id"].as_str() else { continue };
        let metrics = &cve["metrics"];
        let score = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
            .iter()
            .find_map(|k| metrics[*k].as_array().and_then(|a| a.first()).and_then(|m| m["cvssData"]["baseScore"].as_f64()));
        let sev = score.map_or(Severity::Unknown, Severity::from_score);
        let summary = cve["descriptions"].as_array().into_iter().flatten().find(|d| d["lang"] == "en").and_then(|d| d["value"].as_str()).map(|s| s.chars().take(300).collect::<String>());
        for conf in cve["configurations"].as_array().into_iter().flatten() {
            for node in conf["nodes"].as_array().into_iter().flatten() {
                for m in node["cpeMatch"].as_array().into_iter().flatten() {
                    if m["vulnerable"].as_bool() != Some(true) {
                        continue;
                    }
                    let Some(crit) = m["criteria"].as_str() else { continue };
                    let f: Vec<&str> = crit.split(':').collect();
                    if f.len() < 6 || f[2] != "a" && f[2] != "o" {
                        continue;
                    }
                    let entry = json!({
                        "id": id,
                        "vendor": f[3],
                        "version": f[5],
                        "startIncluding": m["versionStartIncluding"],
                        "startExcluding": m["versionStartExcluding"],
                        "endIncluding": m["versionEndIncluding"],
                        "endExcluding": m["versionEndExcluding"],
                        "severity": sev.name(),
                        "score": score,
                        "summary": summary,
                    });
                    index.entry(f[4].to_lowercase()).or_default().push(entry);
                }
            }
        }
    }
}

/// Writes a database from the indexes, updated at `now`.
pub fn write_db(dir: &Path, osv: &BTreeMap<String, Vec<Value>>, nvd: &BTreeMap<String, Vec<Value>>, sources: &[String], now: i64) -> Result<()> {
    write_json(dir, "osv.json", &serde_json::to_value(osv).unwrap())?;
    write_json(dir, "nvd.json", &serde_json::to_value(nvd).unwrap())?;
    write_json(dir, "meta.json", &json!({ "updated": now, "sources": sources }))
}

pub struct Db {
    pub updated: i64,
    osv: BTreeMap<String, Vec<Value>>,
    nvd: BTreeMap<String, Vec<Value>>,
}

impl Db {
    pub fn open(dir: &Path) -> Result<Db> {
        let read = |n: &str| -> Result<Value> {
            let p = dir.join(n);
            let t = std::fs::read_to_string(&p).map_err(|e| format!("reading '{}': {e}; run 'cranix vuln-db update'", p.display()))?;
            serde_json::from_str(&t).map_err(|e| format!("parsing '{}': {e}", p.display()))
        };
        let meta = read("meta.json")?;
        let map = |v: Value| -> BTreeMap<String, Vec<Value>> { serde_json::from_value(v).unwrap_or_default() };
        let osv = if dir.join("osv.json").exists() { map(read("osv.json")?) } else { BTreeMap::new() };
        let nvd = if dir.join("nvd.json").exists() { map(read("nvd.json")?) } else { BTreeMap::new() };
        Ok(Db { updated: meta["updated"].as_i64().unwrap_or(0), osv, nvd })
    }
}

// ---- Matching ----

/// Whether `v` lies in one OSV range (`introduced`/`fixed`/`last_affected`
/// events in order).
fn in_osv_range(events: &Value, v: &str) -> bool {
    let mut affected = false;
    for e in events.as_array().into_iter().flatten() {
        if let Some(i) = e["introduced"].as_str() {
            if i == "0" || compare_versions(v, i) != Ordering::Less {
                affected = true;
            }
        } else if let Some(f) = e["fixed"].as_str() {
            if compare_versions(v, f) != Ordering::Less {
                affected = false;
            }
        } else if let Some(l) = e["last_affected"].as_str() {
            if compare_versions(v, l) == Ordering::Greater {
                affected = false;
            }
        }
    }
    affected
}

fn osv_matches(entry: &Value, version: &str) -> bool {
    if entry["versions"].as_array().into_iter().flatten().any(|x| x.as_str() == Some(version)) {
        return true;
    }
    entry["ranges"].as_array().into_iter().flatten().any(|r| in_osv_range(r, version))
}

fn nvd_matches(e: &Value, version: &str) -> bool {
    let rel = release_part(version);
    if rel.is_empty() {
        return false;
    }
    let cmp = |k: &str| e[k].as_str().filter(|s| !s.is_empty()).map(|b| compare_versions(rel, b));
    match e["version"].as_str() {
        Some("*") | Some("-") | None => {}
        Some(v) => {
            let v = v.replace('\\', "");
            return compare_versions(rel, &v) == Ordering::Equal || compare_versions(version, &v) == Ordering::Equal;
        }
    }
    let bounded = ["startIncluding", "startExcluding", "endIncluding", "endExcluding"].iter().any(|k| e[*k].is_string());
    bounded
        && cmp("startIncluding").is_none_or(|o| o != Ordering::Less)
        && cmp("startExcluding").is_none_or(|o| o == Ordering::Greater)
        && cmp("endIncluding").is_none_or(|o| o != Ordering::Greater)
        && cmp("endExcluding").is_none_or(|o| o == Ordering::Less)
}

/// A component of the SBOM, as scanning sees it.
#[derive(Clone, Debug)]
pub struct Target {
    pub bom_ref: String,
    pub name: String,
    pub version: String,
    pub purls: Vec<String>,
    pub cpe: Option<String>,
}

/// The components of a CycloneDX document, nested ones included, with the
/// purls of their `cranix:purl` properties.
pub fn targets(doc: &Value) -> Result<Vec<Target>> {
    if doc["bomFormat"] != "CycloneDX" {
        return Err("the SBOM is not a CycloneDX document".into());
    }
    let mut out = Vec::new();
    fn visit(c: &Value, out: &mut Vec<Target>) {
        if let (Some(name), Some(r)) = (c["name"].as_str(), c["bom-ref"].as_str().or(c["purl"].as_str()).or(c["name"].as_str())) {
            let mut purls: Vec<String> = c["purl"].as_str().map(str::to_string).into_iter().collect();
            purls.extend(c["properties"].as_array().into_iter().flatten().filter(|p| p["name"] == "cranix:purl").filter_map(|p| p["value"].as_str().map(str::to_string)));
            out.push(Target {
                bom_ref: r.to_string(),
                name: name.to_string(),
                version: c["version"].as_str().unwrap_or("").to_string(),
                purls,
                cpe: c["cpe"].as_str().map(str::to_string),
            });
        }
        for n in c["components"].as_array().into_iter().flatten() {
            visit(n, out);
        }
    }
    if doc["metadata"]["component"].is_object() {
        visit(&doc["metadata"]["component"], &mut out);
    }
    for c in doc["components"].as_array().into_iter().flatten() {
        visit(c, &mut out);
    }
    Ok(out)
}

/// One vulnerability of one product and version.
#[derive(Clone, Debug)]
pub struct Finding {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub severity: Severity,
    pub score: Option<f64>,
    /// `osv:<ecosystem>/<package>` or `nvd:<product>`.
    pub matched: String,
    pub version: String,
    /// The components, by `bom-ref`, with the purl a statement can name.
    pub components: Vec<(String, String, Option<String>)>,
    /// The VEX status, or `None` while nobody assessed it.
    pub status: Option<String>,
    pub justification: Option<String>,
}

/// Matches `targets` against `db`.
pub fn scan(db: &Db, targets: &[Target]) -> Vec<Finding> {
    let mut by_key: BTreeMap<(String, String, String), Finding> = BTreeMap::new();
    let mut add = |id: String, e: &Value, matched: String, version: &str, t: &Target, purl: Option<String>| {
        let key = (id.clone(), matched.clone(), version.to_string());
        let f = by_key.entry(key).or_insert_with(|| Finding {
            id,
            aliases: e["aliases"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect(),
            summary: e["summary"].as_str().map(str::to_string),
            severity: e["severity"].as_str().map_or(Severity::Unknown, Severity::from_name),
            score: e["score"].as_f64(),
            matched,
            version: version.to_string(),
            components: Vec::new(),
            status: None,
            justification: None,
        });
        if !f.components.iter().any(|(r, _, _)| *r == t.bom_ref) {
            f.components.push((t.bom_ref.clone(), t.name.clone(), purl));
        }
    };
    for t in targets {
        let mut ecosystem_matched = false;
        for p in &t.purls {
            let Some((ty, name, Some(version))) = parse_purl(p) else { continue };
            let Some(eco) = osv_ecosystem(&ty) else { continue };
            ecosystem_matched = true;
            let name = if eco == "PyPI" { pypi_normalize(&name) } else { name };
            let key = format!("{eco}/{name}");
            for e in db.osv.get(&key).into_iter().flatten() {
                if osv_matches(e, &version) {
                    add(e["id"].as_str().unwrap_or("?").to_string(), e, format!("osv:{key}"), &version, t, Some(p.clone()));
                }
            }
        }
        // Packages of an ecosystem have their advisories; the rest goes
        // by CPE product.
        if ecosystem_matched || t.version.is_empty() {
            continue;
        }
        let (vendor, product) = match t.cpe.as_deref().map(|c| c.split(':').collect::<Vec<_>>()) {
            Some(f) if f.len() > 4 => (Some(f[3].to_string()).filter(|v| v != "*"), f[4].replace('\\', "").to_lowercase()),
            _ => (None, t.name.to_lowercase()),
        };
        let purl = t.purls.iter().find(|p| p.starts_with("pkg:nix/")).or(t.purls.first()).cloned();
        let mut seen = BTreeSet::new();
        for prod in [product.clone(), product.replace('-', "_"), product.replace('_', "-")] {
            if !seen.insert(prod.clone()) {
                continue;
            }
            for e in db.nvd.get(&prod).into_iter().flatten() {
                if vendor.as_deref().is_some_and(|v| e["vendor"].as_str() != Some(v)) {
                    continue;
                }
                if nvd_matches(e, &t.version) {
                    add(e["id"].as_str().unwrap_or("?").to_string(), e, format!("nvd:{product}"), release_part(&t.version), t, purl.clone());
                }
            }
        }
    }
    let mut out: Vec<Finding> = by_key.into_values().collect();
    for f in &mut out {
        f.components.sort();
    }
    out
}

// ---- OpenVEX ----

/// One statement of an OpenVEX document.
#[derive(Clone, Debug)]
pub struct Statement {
    /// The vulnerability name and its aliases.
    pub vulnerability: Vec<String>,
    /// Product identifiers: purls, or `bom-ref`s of the SBOM.
    pub products: Vec<String>,
    pub status: String,
    pub justification: Option<String>,
    pub timestamp: Option<String>,
}

const STATUSES: &[&str] = &["not_affected", "affected", "fixed", "under_investigation"];

/// Reads the statements of an OpenVEX document (`@context` of
/// `openvex.dev`), versions 0.0.1 and 0.2.0.
pub fn read_vex(doc: &Value) -> Result<Vec<Statement>> {
    if !doc["@context"].as_str().is_some_and(|c| c.contains("openvex.dev")) {
        return Err("not an OpenVEX document".into());
    }
    let mut out = Vec::new();
    for (i, s) in doc["statements"].as_array().ok_or("OpenVEX document without statements")?.iter().enumerate() {
        let mut vulnerability = Vec::new();
        match &s["vulnerability"] {
            Value::String(v) => vulnerability.push(v.clone()),
            v => {
                vulnerability.extend(v["name"].as_str().or(v["@id"].as_str()).map(str::to_string));
                vulnerability.extend(v["aliases"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)));
            }
        }
        let products: Vec<String> = s["products"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| match p {
                Value::String(x) => Some(x.clone()),
                p => p["@id"].as_str().or(p["identifiers"]["purl"].as_str()).map(str::to_string),
            })
            .collect();
        let status = s["status"].as_str().unwrap_or("").to_string();
        if !STATUSES.contains(&status.as_str()) {
            return Err(format!("statement {} has status '{status}'; use {}", i + 1, STATUSES.join(", ")));
        }
        let justification = s["justification"].as_str().or(s["impact_statement"].as_str()).map(str::to_string);
        if status == "not_affected" && justification.is_none() {
            return Err(format!("statement {} is not_affected without a justification or impact_statement", i + 1));
        }
        if vulnerability.is_empty() || products.is_empty() {
            return Err(format!("statement {} names no vulnerability or no product", i + 1));
        }
        out.push(Statement { vulnerability, products, status, justification, timestamp: s["timestamp"].as_str().map(str::to_string) });
    }
    Ok(out)
}

/// Whether the product identifier `id` names the component `(bom_ref,
/// purl)`: the same `bom-ref`, or the same purl, where a purl without a
/// version names every version.
fn names(id: &str, bom_ref: &str, purl: Option<&str>) -> bool {
    if id == bom_ref {
        return true;
    }
    let (Some(a), Some(b)) = (parse_purl(id), purl.and_then(parse_purl)) else { return false };
    a.0 == b.0 && a.1.eq_ignore_ascii_case(&b.1) && a.2.as_ref().is_none_or(|v| Some(v) == b.2.as_ref())
}

/// Applies `statements` to `findings`; later statements win. Returns the
/// findings that remain: those not assessed `not_affected` or `fixed` for
/// every one of their components.
pub fn apply_vex(findings: Vec<Finding>, statements: &[Statement]) -> (Vec<Finding>, usize) {
    let mut remaining = Vec::new();
    let mut suppressed = 0;
    for mut f in findings {
        let ids: BTreeSet<&str> = std::iter::once(f.id.as_str()).chain(f.aliases.iter().map(String::as_str)).collect();
        let mut open = Vec::new();
        let mut status: Option<(String, Option<String>)> = None;
        for c in &f.components {
            let st = statements
                .iter()
                .filter(|s| s.vulnerability.iter().any(|v| ids.contains(v.as_str())))
                .filter(|s| s.products.iter().any(|p| names(p, &c.0, c.2.as_deref())))
                .last();
            match st {
                Some(s) if s.status == "not_affected" || s.status == "fixed" => {}
                Some(s) => {
                    status = Some((s.status.clone(), s.justification.clone()));
                    open.push(c.clone());
                }
                None => open.push(c.clone()),
            }
        }
        if open.is_empty() {
            suppressed += 1;
            continue;
        }
        if open.len() == f.components.len() || status.is_some() {
            if let Some((s, j)) = status {
                f.status = Some(s);
                f.justification = j;
            }
        }
        f.components = open;
        remaining.push(f);
    }
    (remaining, suppressed)
}

/// The report of the remaining findings.
pub fn report(db: &Db, findings: &[Finding], suppressed: usize) -> Value {
    json!({
        "database": { "updated": db.updated },
        "suppressed": suppressed,
        "findings": findings.iter().map(|f| json!({
            "id": f.id,
            "aliases": f.aliases,
            "summary": f.summary,
            "severity": f.severity.name(),
            "score": f.score,
            "matchedBy": f.matched,
            "version": f.version,
            "status": f.status.clone().unwrap_or_else(|| "unassessed".into()),
            "justification": f.justification,
            "components": f.components.iter().map(|(r, n, p)| json!({ "bom-ref": r, "name": n, "purl": p })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        use Ordering::*;
        assert_eq!(compare_versions("1.10", "1.9"), Greater);
        assert_eq!(compare_versions("v1.2.0", "1.2"), Greater);
        assert_eq!(compare_versions("1.0rc1", "1.0"), Less);
        assert_eq!(compare_versions("1.0.0-beta.2", "1.0.0-beta.10"), Less);
        assert_eq!(compare_versions("3.0.13", "3.0.13"), Equal);
        assert_eq!(compare_versions("2.0.1", "2.0.01"), Equal);
        assert_eq!(release_part("5.2p37"), "5.2");
        assert_eq!(release_part("1.2.3-unstable-2024"), "1.2.3");
        assert_eq!(release_part("unstable"), "");
    }

    #[test]
    fn cvss() {
        assert_eq!(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Some(9.8));
        assert_eq!(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), Some(6.1));
        assert_eq!(cvss3_score("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L"), Some(1.8));
        assert_eq!(cvss3_score("CVSS:2.0/AV:N"), None);
        assert!(Threshold::parse("high").unwrap().fails(Severity::Critical));
        assert!(!Threshold::parse("high").unwrap().fails(Severity::Medium));
        assert!(Threshold::parse("critical").unwrap().fails(Severity::Unknown));
        assert!(Threshold::parse("any").unwrap().fails(Severity::Low));
        assert!(Threshold::parse("nope").is_err());
    }

    #[test]
    fn purls_and_ranges() {
        assert_eq!(parse_purl("pkg:npm/%40scope/a@1.2.0?x=y"), Some(("npm".into(), "@scope/a".into(), Some("1.2.0".into()))));
        assert_eq!(parse_purl("pkg:golang/golang.org/x/sys@v0.1.0").unwrap().1, "golang.org/x/sys");
        assert_eq!(parse_purl("pkg:pypi/requests").unwrap().2, None);
        let ev = json!([{ "introduced": "0" }, { "fixed": "2.31.0" }]);
        assert!(in_osv_range(&ev, "2.30.9") && !in_osv_range(&ev, "2.31.0"));
        let ev = json!([{ "introduced": "1.0" }, { "last_affected": "1.4" }]);
        assert!(in_osv_range(&ev, "1.4") && !in_osv_range(&ev, "1.5") && !in_osv_range(&ev, "0.9"));
        let e = json!({ "version": "*", "startIncluding": "3.0.0", "endExcluding": "3.0.14" });
        assert!(nvd_matches(&e, "3.0.13") && !nvd_matches(&e, "3.0.14") && !nvd_matches(&e, "1.1.1"));
        assert!(nvd_matches(&json!({ "version": "5.2" }), "5.2p37"));
        assert!(!nvd_matches(&json!({ "version": "*" }), "5.2"));
    }
}
