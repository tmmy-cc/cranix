//! `vuln-db` keeps the vulnerability database up to date; `vuln-scan`
//! checks a CycloneDX SBOM against it, with OpenVEX assessments.
//!
//! `vuln-scan` exits with 0 when no unassessed finding of at least
//! `--fail-on` severity remains, 2 when one does, 3 when the database is
//! missing or older than `--max-db-age`, and 64 for wrong arguments.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use cranix_sbom::vuln::{self, Db, Threshold};
use cranix_store::http::HttpClient;
use serde_json::Value;

use crate::Cli;

const DB_USAGE: &str = "usage: cranix vuln-db update [--db DIR] [--ecosystems PyPI,crates.io,npm,Go] [--nvd-years FIRST-LAST | --no-nvd]
       cranix vuln-db import [--db DIR] [--osv FILE|DIR]... [--nvd FEED.json[.gz]]...";
const SCAN_USAGE: &str = "usage: cranix vuln-scan SBOM [--db DIR] [--vex FILE]... [--fail-on any|low|medium|high|critical]
                        [--max-db-age DURATION] [--report FILE]";

/// Ends the process with `code` after printing `msg`.
fn exit(code: i32, msg: &str) -> ! {
    if !msg.is_empty() {
        eprintln!("{msg}");
    }
    std::process::exit(code)
}

fn default_db() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cache")
    });
    base.join("cranix/vulndb")
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Seconds of `30d`, `12h`, `45m` or a plain number of seconds.
fn parse_duration(s: &str) -> Option<i64> {
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: i64 = n.parse().ok()?;
    Some(n * match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 7 * 86400,
        _ => return None,
    })
}

/// OSV records from a JSON file, a directory of them, or a zip archive.
fn osv_records(path: &Path) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    let mut files = Vec::new();
    let tmp;
    let dir = if path.extension().is_some_and(|e| e == "zip") {
        tmp = std::env::temp_dir().join(format!("cranix-osv-{}-{}", std::process::id(), now()));
        let st = std::process::Command::new("unzip").args(["-q", "-o"]).arg(path).arg("-d").arg(&tmp).status().map_err(|e| format!("running unzip: {e}"))?;
        if !st.success() {
            return Err(format!("unpacking '{}' failed", path.display()));
        }
        tmp.clone()
    } else {
        path.to_path_buf()
    };
    if dir.is_dir() {
        for e in std::fs::read_dir(&dir).map_err(|e| format!("reading '{}': {e}", dir.display()))?.flatten() {
            if e.path().extension().is_some_and(|x| x == "json") {
                files.push(e.path());
            }
        }
    } else {
        files.push(dir.clone());
    }
    files.sort();
    for f in files {
        let t = std::fs::read_to_string(&f).map_err(|e| format!("reading '{}': {e}", f.display()))?;
        match serde_json::from_str::<Value>(&t).map_err(|e| format!("parsing '{}': {e}", f.display()))? {
            Value::Array(a) => out.extend(a),
            v => out.push(v),
        }
    }
    if dir != path {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(out)
}

/// An NVD 2.0 feed, gzip-compressed or not.
fn nvd_feed(path: &Path) -> Result<Value, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("reading '{}': {e}", path.display()))?;
    let mut text = String::new();
    if path.extension().is_some_and(|e| e == "gz") {
        flate2::read::GzDecoder::new(f).read_to_string(&mut text)
    } else {
        std::io::BufReader::new(f).read_to_string(&mut text)
    }
    .map_err(|e| format!("reading '{}': {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parsing '{}': {e}", path.display()))
}

fn download(http: &HttpClient, url: &str, dest: &Path) -> Result<(), String> {
    eprintln!("downloading '{url}'...");
    let mut r = http.open(url)?;
    let mut f = std::fs::File::create(dest).map_err(|e| format!("creating '{}': {e}", dest.display()))?;
    std::io::copy(&mut r, &mut f).map_err(|e| format!("downloading '{url}': {e}"))?;
    Ok(())
}

pub fn cmd_vuln_db(cli: &Cli, args: &[String]) -> Result<(), String> {
    let Some((sub, rest)) = args.split_first() else { return Err(DB_USAGE.into()) };
    let mut db = default_db();
    let mut ecosystems: Vec<String> = ["PyPI", "crates.io", "npm", "Go"].map(String::from).to_vec();
    let this_year = 1970 + now() / 31_556_952;
    let mut years = Some((2002, this_year));
    let mut osv_in = Vec::new();
    let mut nvd_in = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        let mut value = |f: &str| it.next().cloned().ok_or_else(|| format!("{f} requires an argument\n{DB_USAGE}"));
        match a.as_str() {
            "--db" => db = value("--db")?.into(),
            "--ecosystems" => ecosystems = value("--ecosystems")?.split(',').map(str::to_string).collect(),
            "--nvd-years" => {
                let v = value("--nvd-years")?;
                let (a, b) = v.split_once('-').unwrap_or((&v, &v));
                years = Some((a.parse().map_err(|_| "invalid --nvd-years")?, b.parse().map_err(|_| "invalid --nvd-years")?));
            }
            "--no-nvd" => years = None,
            "--osv" => osv_in.push(PathBuf::from(value("--osv")?)),
            "--nvd" => nvd_in.push(PathBuf::from(value("--nvd")?)),
            f => return Err(format!("vuln-db: unknown argument '{f}'\n{DB_USAGE}")),
        }
    }
    let mut osv = BTreeMap::new();
    let mut nvd = BTreeMap::new();
    let mut sources = Vec::new();
    match sub.as_str() {
        "update" => {
            let http = cranix_store::substitute::http_client(&cli.settings);
            let tmp = std::env::temp_dir().join(format!("cranix-vulndb-{}", std::process::id()));
            std::fs::create_dir_all(&tmp).map_err(|e| format!("creating '{}': {e}", tmp.display()))?;
            let r = (|| {
                for eco in &ecosystems {
                    let url = format!("https://osv-vuln-data.storage.googleapis.com/{eco}/all.zip");
                    let f = tmp.join(format!("{eco}.zip"));
                    download(&http, &url, &f)?;
                    vuln::import_osv(osv_records(&f)?, &mut osv);
                    sources.push(format!("osv:{eco}"));
                }
                if let Some((a, b)) = years {
                    for y in a..=b {
                        let url = format!("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{y}.json.gz");
                        let f = tmp.join(format!("nvd-{y}.json.gz"));
                        download(&http, &url, &f)?;
                        vuln::import_nvd(&nvd_feed(&f)?, &mut nvd);
                        let _ = std::fs::remove_file(&f);
                    }
                    sources.push(format!("nvd:{a}-{b}"));
                }
                Ok::<(), String>(())
            })();
            let _ = std::fs::remove_dir_all(&tmp);
            r?;
        }
        "import" => {
            for p in &osv_in {
                vuln::import_osv(osv_records(p)?, &mut osv);
                sources.push(format!("osv:{}", p.display()));
            }
            for p in &nvd_in {
                vuln::import_nvd(&nvd_feed(p)?, &mut nvd);
                sources.push(format!("nvd:{}", p.display()));
            }
        }
        _ => return Err(DB_USAGE.into()),
    }
    vuln::write_db(&db, &osv, &nvd, &sources, now())?;
    eprintln!("wrote '{}': {} OSV packages, {} NVD products", db.display(), osv.len(), nvd.len());
    Ok(())
}

pub fn cmd_vuln_scan(args: &[String]) -> Result<(), String> {
    let usage = |m: String| -> ! { exit(64, &format!("{m}\n{SCAN_USAGE}")) };
    let mut db_dir = default_db();
    let mut vex = Vec::new();
    let mut fail_on = Threshold::parse("any").unwrap();
    let mut max_age: Option<i64> = None;
    let mut report_file: Option<PathBuf> = None;
    let mut sbom: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |f: &str| it.next().cloned().unwrap_or_else(|| usage(format!("{f} requires an argument")));
        match a.as_str() {
            "--db" => db_dir = value("--db").into(),
            "--vex" => vex.push(PathBuf::from(value("--vex"))),
            "--fail-on" => fail_on = Threshold::parse(&value("--fail-on")).unwrap_or_else(|e| usage(e)),
            "--max-db-age" => {
                let v = value("--max-db-age");
                max_age = Some(parse_duration(&v).unwrap_or_else(|| usage(format!("invalid --max-db-age '{v}'; use for example 7d or 12h"))));
            }
            "--report" => report_file = Some(value("--report").into()),
            f if f.starts_with('-') => usage(format!("vuln-scan: unknown flag '{f}'")),
            p if sbom.is_none() => sbom = Some(p.into()),
            _ => usage("vuln-scan takes one SBOM".into()),
        }
    }
    let Some(sbom) = sbom else { usage("vuln-scan needs an SBOM".into()) };
    let read_json = |p: &Path| -> Value {
        let t = std::fs::read_to_string(p).unwrap_or_else(|e| usage(format!("reading '{}': {e}", p.display())));
        serde_json::from_str(&t).unwrap_or_else(|e| usage(format!("parsing '{}': {e}", p.display())))
    };
    let doc = read_json(&sbom);
    let targets = vuln::targets(&doc).unwrap_or_else(|e| usage(format!("'{}': {e}", sbom.display())));
    let mut statements = Vec::new();
    for v in &vex {
        statements.extend(vuln::read_vex(&read_json(v)).unwrap_or_else(|e| usage(format!("'{}': {e}", v.display()))));
    }
    let db = Db::open(&db_dir).unwrap_or_else(|e| exit(3, &e));
    let age = now() - db.updated;
    if max_age.is_none() && age > 7 * 86400 {
        eprintln!("warning: the vulnerability database is {} days old; run 'cranix vuln-db update'", age / 86400);
    }
    if let Some(max) = max_age {
        if age > max {
            exit(3, &format!("the vulnerability database '{}' is {} hours old, more than --max-db-age allows; run 'cranix vuln-db update'", db_dir.display(), age / 3600));
        }
    }
    let (findings, suppressed) = vuln::apply_vex(vuln::scan(&db, &targets), &statements);
    if let Some(f) = &report_file {
        let text = serde_json::to_string_pretty(&vuln::report(&db, &findings, suppressed)).unwrap() + "\n";
        std::fs::write(f, text).map_err(|e| format!("writing '{}': {e}", f.display()))?;
    }
    let mut failing = 0;
    for f in &findings {
        let names: Vec<&str> = f.components.iter().map(|c| c.1.as_str()).collect();
        let status = f.status.as_deref().unwrap_or("unassessed");
        let score = f.score.map(|s| format!(" {s:.1}")).unwrap_or_default();
        println!("{} {}{score} {} {} ({status}, {})", f.id, f.severity.name(), names.join(", "), f.version, f.matched);
        if f.status.is_none() && fail_on.fails(f.severity) {
            failing += 1;
        }
    }
    eprintln!("{} components, {} findings, {} assessed as not affected or fixed, {failing} failing", targets.len(), findings.len(), suppressed);
    if failing > 0 {
        exit(2, "");
    }
    Ok(())
}
