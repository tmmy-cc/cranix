//! `sbom`: a CycloneDX or SPDX document for the runtime closure of a
//! package or a NixOS system, and documents for lock files.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use cranix_core::StorePath;
use cranix_eval::value::Sym;
use cranix_eval::{Eval, Value};
use cranix_sbom::{cyclonedx, lock, spdx, License, Meta, Options, Sbom};

use crate::{collect_drvs, eval_target, flake_cmd, new_eval, parse_target, render_error, Cli};

const USAGE: &str = "usage: cranix sbom [FILE | --expr E | INSTALLABLE] [-A ATTR] [--format cyclonedx|spdx] [-o FILE]
                   [--build-time] [--scan-binaries] [--scan-sources] [--no-fetch-deps] [--merge DOC]...
       cranix sbom lock Cargo.lock|package-lock.json [--format cyclonedx|spdx] [-o FILE]";

#[derive(Clone, Copy, PartialEq)]
enum Format {
    CycloneDx,
    Spdx,
}

struct Out {
    format: Format,
    file: Option<PathBuf>,
}

fn write(sbom: &Sbom, out: &Out) -> Result<(), String> {
    let doc = match out.format {
        Format::CycloneDx => cyclonedx::document(sbom),
        Format::Spdx => {
            let epoch = std::env::var("SOURCE_DATE_EPOCH").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
            spdx::document(sbom, epoch)
        }
    };
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    match &out.file {
        Some(f) => std::fs::write(f, text).map_err(|e| format!("writing '{}': {e}", f.display())),
        None => {
            print!("{text}");
            Ok(())
        }
    }
}

pub fn cmd_sbom(cli: &Cli, args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    let mut out = Out { format: Format::CycloneDx, file: None };
    let mut opts = Options::default();
    let mut merge = Vec::new();
    let mut fetch_deps = true;
    let mut build_time = false;
    let mut rest = Vec::new();
    let mut it = std::mem::take(&mut args).into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--format" => {
                out.format = match it.next().as_deref() {
                    Some("cyclonedx") => Format::CycloneDx,
                    Some("spdx") => Format::Spdx,
                    _ => return Err(format!("--format takes 'cyclonedx' or 'spdx'\n{USAGE}")),
                }
            }
            "-o" | "--output" => out.file = Some(it.next().ok_or("-o requires an argument")?.into()),
            "--scan-binaries" => opts.scan_binaries = true,
            "--scan-sources" => opts.scan_sources = true,
            "--no-fetch-deps" => fetch_deps = false,
            "--build-time" => build_time = true,
            "--merge" => merge.push(PathBuf::from(it.next().ok_or("--merge requires an argument")?)),
            _ => rest.push(a),
        }
    }
    if rest.first().map(String::as_str) == Some("lock") {
        let [_, file] = rest.as_slice() else { return Err(USAGE.into()) };
        return write(&lock::from_file(std::path::Path::new(file))?, &out);
    }
    let mut args = rest;
    let flags = flake_cmd::take_flake_flags(&mut args)?;
    let t = parse_target(&args, &[])?;
    if let Some(f) = t.flags.iter().next() {
        return Err(format!("sbom: unknown flag '{f}'\n{USAGE}"));
    }
    let installable = t.file.clone().filter(|f| t.expr.is_none() && flake_cmd::is_installable(f));
    let ev = match &installable {
        Some(_) => flake_cmd::new_eval(cli, flags.impure)?,
        None => new_eval(cli)?,
    };
    let value = match &installable {
        Some(spec) => flake_cmd::eval_installable(&ev, cli, &flags, spec, flake_cmd::Kind::Build).map(|s| s.value),
        None => eval_target(&ev, cli, &t),
    }
    .map_err(|e| render_error(&ev, cli, &e))?;
    // A NixOS configuration stands for its system, and its packages carry
    // the metadata.
    let (target, extra) = nixos_parts(&ev, &value).unwrap_or((value.clone(), Vec::new()));
    let mut drvs = Vec::new();
    collect_drvs(&ev, &target, &mut drvs).map_err(|e| render_error(&ev, cli, &e))?;
    if drvs.is_empty() {
        return Err("sbom: the expression names no derivation".into());
    }
    let mut meta = HashMap::new();
    let mut walker = Walker { ev: &ev, meta: &mut meta, seen: BTreeSet::new() };
    walker.walk(&target, 0);
    for v in &extra {
        walker.walk(v, 0);
    }
    let drv_paths: Vec<StorePath> = drvs.iter().map(|(d, _)| d.clone()).collect();
    let mut sbom = if build_time {
        cranix_sbom::collect_build_time(&ev.store, &drv_paths, &meta, &opts)?
    } else {
        let roots: Vec<StorePath> = flake_cmd::realise(&ev, cli, &drvs)?.iter().map(|p| ev.store.dir.parse(p)).collect::<Result<_, _>>()?;
        cranix_sbom::collect(&ev.store, &drv_paths, &roots, &meta, &opts)?
    };
    // Vendored dependencies name the crates and modules of a package;
    // fetch those that are missing and read them.
    if fetch_deps {
        let vendor = cranix_sbom::missing_vendor_drvs(&ev.store, &sbom);
        if !vendor.is_empty() {
            match flake_cmd::realise(&ev, cli, &vendor) {
                Ok(_) if build_time => sbom = cranix_sbom::collect_build_time(&ev.store, &drv_paths, &meta, &opts)?,
                Ok(_) => {
                    let roots: Vec<StorePath> = flake_cmd::realise(&ev, cli, &drvs)?.iter().map(|p| ev.store.dir.parse(p)).collect::<Result<_, _>>()?;
                    sbom = cranix_sbom::collect(&ev.store, &drv_paths, &roots, &meta, &opts)?
                }
                Err(e) => cranix_fetchers::warn(format!("cannot fetch the vendored dependencies: {e}")),
            }
        }
    }
    for m in &merge {
        let text = std::fs::read_to_string(m).map_err(|e| format!("reading '{}': {e}", m.display()))?;
        let doc: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("parsing '{}': {e}", m.display()))?;
        let (comps, deps) = cyclonedx::read(&doc).map_err(|e| format!("merging '{}': {e}", m.display()))?;
        for (k, d) in deps {
            sbom.deps.entry(k).or_default().extend(d);
        }
        for c in comps {
            if !sbom.components.contains_key(&c.key) && !sbom.merged.iter().any(|x| x.key == c.key) {
                sbom.merged.push(c);
            }
        }
    }
    sbom.merged.sort_by(|a, b| a.key.cmp(&b.key));
    write(&sbom, &out)
}

fn attr(ev: &Eval, v: &Value, path: &[&str]) -> Option<Value> {
    let mut v = v.clone();
    for k in path {
        let a = match ev.force(&v).ok()? {
            Value::Attrs(a) => a,
            _ => return None,
        };
        v = a.get(&Sym::new(k))?.clone();
    }
    ev.force(&v).ok()
}

/// For a NixOS configuration (`config.system.build.toplevel`): the
/// toplevel and the package lists whose metadata the toplevel lacks.
fn nixos_parts(ev: &Eval, v: &Value) -> Option<(Value, Vec<Value>)> {
    let top = attr(ev, v, &["config", "system", "build", "toplevel"])?;
    let mut extra = Vec::new();
    for p in [
        &["config", "environment", "systemPackages"][..],
        &["config", "systemd", "packages"],
        &["config", "services", "udev", "packages"],
        &["config", "boot", "kernelPackages", "kernel"],
        &["config", "hardware", "firmware"],
    ] {
        if let Some(x) = attr(ev, v, p) {
            extra.push(x);
        }
    }
    Some((top, extra))
}

/// Collects `meta` of the derivations reachable from a value through the
/// attributes that hold build inputs. Evaluation errors only end the walk
/// of the value that raised them.
struct Walker<'a> {
    ev: &'a Eval,
    meta: &'a mut HashMap<StorePath, Meta>,
    seen: BTreeSet<StorePath>,
}

const INPUT_ATTRS: &[&str] = &[
    "buildInputs",
    "nativeBuildInputs",
    "propagatedBuildInputs",
    "propagatedNativeBuildInputs",
    "depsBuildBuild",
    "depsBuildTarget",
    "depsHostHost",
    "depsTargetTarget",
    "dependencies",
    "build-system",
    "paths",
    "pkgs",
    "all",
];

impl Walker<'_> {
    fn walk(&mut self, v: &Value, depth: usize) {
        if depth > 48 {
            return;
        }
        let Ok(v) = self.ev.force(v) else { return };
        match &v {
            Value::List(l) => {
                for x in l.iter() {
                    self.walk(x, depth + 1);
                }
            }
            Value::Attrs(a) => {
                if !matches!(self.ev.is_derivation(a), Ok(true)) {
                    return;
                }
                let Some(drv) = a.get_str("drvPath").and_then(|d| self.ev.force_str(d).ok()) else { return };
                let Ok(drv) = self.ev.store.dir.parse(&drv.s) else { return };
                if !self.seen.insert(drv.clone()) {
                    return;
                }
                if let Some(m) = a.get_str("meta") {
                    let m = self.meta_of(m);
                    self.meta.insert(drv, m);
                }
                for k in INPUT_ATTRS {
                    if let Some(x) = a.get_str(k) {
                        self.walk(x, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }

    fn str_of(&self, v: &Value) -> Option<String> {
        match self.ev.force(v).ok()? {
            Value::Str(s) => Some(s.s.clone()),
            _ => None,
        }
    }

    fn license(&self, v: &Value) -> Option<License> {
        match self.ev.force(v).ok()? {
            Value::Str(s) => Some(License::Name(s.s.clone())),
            Value::Attrs(a) => match a.get_str("spdxId").and_then(|x| self.str_of(x)) {
                Some(id) => Some(License::Id(id)),
                None => a.get_str("fullName").or(a.get_str("shortName")).and_then(|x| self.str_of(x)).map(License::Name),
            },
            _ => None,
        }
    }

    fn meta_of(&self, m: &Value) -> Meta {
        let mut out = Meta::default();
        let Ok(Value::Attrs(m)) = self.ev.force(m) else { return out };
        if let Some(l) = m.get_str("license") {
            match self.ev.force(l) {
                Ok(Value::List(ls)) => out.licenses = ls.iter().filter_map(|x| self.license(x)).collect(),
                Ok(_) => out.licenses = self.license(l).into_iter().collect(),
                Err(_) => {}
            }
        }
        out.licenses.sort();
        out.licenses.dedup();
        out.description = m.get_str("description").and_then(|x| self.str_of(x));
        out.homepage = m.get_str("homepage").and_then(|x| match self.ev.force(x).ok()? {
            Value::List(l) => l.first().and_then(|y| self.str_of(y)),
            _ => self.str_of(x),
        });
        out.cpe = m.get_str("identifiers").and_then(|i| match self.ev.force(i).ok()? {
            Value::Attrs(a) => a.get_str("cpe").and_then(|x| self.str_of(x)),
            _ => None,
        });
        out
    }
}
