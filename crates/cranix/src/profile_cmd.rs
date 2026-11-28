//! `cranix profile`: the `nix profile` commands, on profiles whose
//! generations hold a version 3 `manifest.json`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use cranix_eval::Eval;
use serde_json::{json, Value as J};

use crate::flake_cmd::{self, FlakeFlags};
use crate::profiles::{self, DrvName};
use crate::{cwd, render_error, Cli};

const USAGE: &str = "\
usage: cranix profile COMMAND [--profile PATH] ...
commands:
  install INSTALLABLE... [--priority N]   flake references, store paths, or -f FILE ATTR / --expr E ATTR
  remove NAME|PATH... | --all | --regex RE
  upgrade NAME... | --all
  list [--json]
  rollback [--to N] [--dry-run]
  history
  wipe-history [--older-than Nd] [--dry-run]";

/// Where a flake element came from, so that it can be upgraded.
#[derive(Clone, Debug)]
pub struct Source {
    pub original_url: String,
    pub url: String,
    pub attr_path: String,
    pub outputs: J,
}

#[derive(Clone, Debug)]
pub struct Element {
    pub store_paths: BTreeSet<String>,
    pub active: bool,
    pub priority: i64,
    pub source: Option<Source>,
}

impl Element {
    /// Nix's identifier: the source, or the names of the store paths.
    fn identifier(&self) -> String {
        match &self.source {
            Some(s) => format!("{}#{}", s.original_url, s.attr_path),
            None => {
                let names: BTreeSet<String> = self.store_paths.iter().map(|p| DrvName::parse(&profiles::path_name(p)).name).collect();
                names.into_iter().collect::<Vec<_>>().join(", ")
            }
        }
    }

    /// The name an element gets in the manifest: the last component of
    /// its attribute path, else its identifier.
    fn default_name(&self) -> String {
        if let Some(s) = &self.source {
            let last = s.attr_path.rsplit('.').next().unwrap_or("");
            if !last.is_empty() && last != "default" {
                return last.to_string();
            }
            let base = s.original_url.split(['?', '#']).next().unwrap_or("");
            if let Some(n) = base.rsplit(['/', ':']).find(|c| !c.is_empty()) {
                return n.to_string();
            }
        }
        self.identifier()
    }

    fn versions(&self) -> BTreeSet<String> {
        self.store_paths.iter().map(|p| DrvName::parse(&profiles::path_name(p)).version).collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Manifest {
    pub elements: BTreeMap<String, Element>,
}

impl Manifest {
    fn add(&mut self, e: Element) -> String {
        let name = e.default_name();
        let mut final_name = name.clone();
        let mut i = 1;
        while self.elements.contains_key(&final_name) {
            final_name = format!("{name}-{i}");
            i += 1;
        }
        self.elements.insert(final_name.clone(), e);
        final_name
    }

    fn parse_element(v: &J, version: u64) -> Result<Element, String> {
        let paths = v.get("storePaths").and_then(J::as_array).ok_or("manifest element without 'storePaths'")?;
        let (orig_key, url_key) = if version == 1 { ("originalUri", "uri") } else { ("originalUrl", "url") };
        let source = match (v.get(orig_key).and_then(J::as_str), v.get(url_key).and_then(J::as_str), v.get("attrPath").and_then(J::as_str)) {
            (Some(o), Some(u), Some(a)) => Some(Source {
                original_url: o.to_string(),
                url: u.to_string(),
                attr_path: a.to_string(),
                outputs: v.get("outputs").cloned().unwrap_or(J::Null),
            }),
            _ => None,
        };
        Ok(Element {
            store_paths: paths.iter().filter_map(J::as_str).map(String::from).collect(),
            active: v.get("active").and_then(J::as_bool).unwrap_or(true),
            priority: v.get("priority").and_then(J::as_i64).unwrap_or(5),
            source,
        })
    }

    /// Reads the manifest of a profile or user environment; a `nix-env`
    /// environment's packages become elements without a source.
    pub fn read(ev: &Eval, profile: &Path) -> Result<Manifest, String> {
        let mut m = Manifest::default();
        let json_path = profile.join("manifest.json");
        if json_path.exists() {
            let text = std::fs::read_to_string(&json_path).map_err(|e| format!("reading '{}': {e}", json_path.display()))?;
            let j: J = serde_json::from_str(&text).map_err(|e| format!("parsing '{}': {e}", json_path.display()))?;
            let version = j.get("version").and_then(J::as_u64).unwrap_or(0);
            match (version, j.get("elements")) {
                (3, Some(J::Object(es))) => {
                    for (name, v) in es {
                        m.elements.insert(name.clone(), Self::parse_element(v, 3)?);
                    }
                }
                (1 | 2, Some(J::Array(es))) => {
                    for v in es {
                        m.add(Self::parse_element(v, version)?);
                    }
                }
                _ => return Err(format!("profile manifest '{}' has unsupported version {version}", json_path.display())),
            }
        } else if profile.join("manifest.nix").exists() {
            for e in crate::nix_env_cmd::installed(ev, profile)? {
                m.add(Element { store_paths: e.outputs.into_iter().map(|(_, p)| p).collect(), active: true, priority: 5, source: None });
            }
        }
        Ok(m)
    }

    pub fn to_json(&self) -> J {
        let mut es = serde_json::Map::new();
        for (name, e) in &self.elements {
            let mut o = serde_json::Map::new();
            o.insert("active".into(), J::Bool(e.active));
            if let Some(s) = &e.source {
                o.insert("attrPath".into(), J::String(s.attr_path.clone()));
                o.insert("originalUrl".into(), J::String(s.original_url.clone()));
                o.insert("outputs".into(), s.outputs.clone());
            }
            o.insert("priority".into(), J::from(e.priority));
            o.insert("storePaths".into(), J::Array(e.store_paths.iter().cloned().map(J::String).collect()));
            if let Some(s) = &e.source {
                o.insert("url".into(), J::String(s.url.clone()));
            }
            es.insert(name.clone(), J::Object(o));
        }
        json!({ "elements": es, "version": 3 })
    }

    /// Builds the user environment and makes it the profile's next
    /// generation.
    fn write(&self, cli: &Cli, ev: &Eval, profile: &Path) -> Result<(), String> {
        let store = &ev.store;
        let mut refs = BTreeSet::new();
        let mut packages = Vec::new();
        for e in self.elements.values() {
            refs.extend(e.store_paths.iter().filter_map(|p| store.dir.to_store_path(p)).map(|(p, _)| p));
            packages.push((e.store_paths.iter().cloned().collect(), e.active, e.priority));
        }
        let manifest = store.add_text("manifest.json", self.to_json().to_string().as_bytes(), &refs)?;
        profiles::build_user_env(cli, ev, profile, "profile", &packages, manifest, Some("manifest.json"))?;
        Ok(())
    }
}

/// The store paths to install from an evaluated installable: the outputs
/// in `meta.outputsToInstall`, else `out` or the selected output.
fn install_paths(cli: &Cli, ev: &Eval, v: &cranix_eval::Value) -> Result<(Vec<String>, Option<i64>), String> {
    let mut wanted = Vec::new();
    let mut priority = None;
    let r = (|| -> cranix_eval::R<()> {
        let v = ev.force(v)?;
        let items: Vec<cranix_eval::Value> = match &v {
            cranix_eval::Value::List(l) => l.iter().cloned().collect(),
            _ => vec![v.clone()],
        };
        for item in items {
            let e = crate::nix_env_cmd::elem_of(ev, &item, "")?;
            if let Some(p) = e.meta.get("priority").and_then(J::as_i64) {
                priority = Some(p);
            }
            let drv = e.drv_path.as_deref().and_then(|d| ev.store.dir.to_store_path(d)).map(|(p, _)| p);
            for (o, p) in &e.outputs {
                wanted.push((drv.clone(), o.clone(), p.clone()));
            }
        }
        Ok(())
    })();
    r.map_err(|e| render_error(ev, cli, &e))?;
    let drvs: Vec<_> = wanted.iter().filter_map(|(d, o, _)| Some((d.clone()?, o.clone()))).collect();
    if !drvs.is_empty() {
        flake_cmd::realise(ev, cli, &drvs)?;
    }
    Ok((wanted.into_iter().map(|(_, _, p)| p).collect(), priority))
}

/// Evaluates `-f FILE ATTR` or `--expr E ATTR`.
fn eval_file(cli: &Cli, ev: &Eval, file: Option<&str>, expr: Option<&str>, attr: &str) -> Result<cranix_eval::Value, String> {
    let r = (|| {
        let mut v = match (expr, file) {
            (Some(e), _) => ev.eval_string(e, &cwd())?,
            (None, Some(f)) => ev.import(&if f.starts_with('/') { f.to_string() } else { format!("{}/{f}", cwd()) })?,
            (None, None) => unreachable!(),
        };
        v = crate::auto_call(ev, cli, v)?;
        for k in flake_cmd::parse_attr_path(attr) {
            v = match ev.force_attrs(&v)?.get(&cranix_eval::value::Sym::new(&k)) {
                Some(x) => crate::auto_call(ev, cli, x.clone())?,
                None => return cranix_eval::eval::err(format!("attribute '{k}' in selection path '{attr}' not found")),
            };
        }
        Ok(v)
    })();
    r.map_err(|e| render_error(ev, cli, &e))
}

/// A store path given on the command line, following symlinks such as
/// `./result` into the store.
fn store_path_arg(ev: &Eval, a: &str) -> Option<String> {
    let p = if a.starts_with('/') { PathBuf::from(a) } else { Path::new(&cwd()).join(a) };
    let s = p.to_string_lossy();
    if let Some((sp, _)) = ev.store.dir.to_store_path(&s) {
        return Some(ev.store.dir.print(&sp));
    }
    let target = std::fs::canonicalize(&p).ok()?;
    ev.store.dir.to_store_path(&target.to_string_lossy()).map(|(sp, _)| ev.store.dir.print(&sp))
}

/// Locks and evaluates a flake installable, returning its source and
/// store paths.
fn flake_element(cli: &Cli, ev: &Eval, flags: &FlakeFlags, spec: &str) -> Result<Element, String> {
    let r = (|| -> cranix_eval::R<_> {
        let inst = flake_cmd::lock_installable(ev, flags, spec)?;
        let sel = flake_cmd::eval_locked(ev, cli, &inst, flake_cmd::Kind::Build)?;
        let original_url = inst.flake_ref.to_string();
        let url = inst.locked.flake.locked_ref.to_string();
        Ok((sel, original_url, url))
    })();
    let (sel, original_url, url) = r.map_err(|e| render_error(ev, cli, &e))?;
    let (paths, priority) = install_paths(cli, ev, &sel.value)?;
    Ok(Element {
        store_paths: paths.into_iter().collect(),
        active: true,
        priority: priority.unwrap_or(5),
        source: Some(Source { original_url, url, attr_path: sel.attr_path, outputs: J::Null }),
    })
}

struct Common {
    profile: PathBuf,
    dry_run: bool,
    all: bool,
    json: bool,
    priority: Option<i64>,
    file: Option<String>,
    expr: Option<String>,
    regex: Vec<String>,
    to: Option<u64>,
    older_than: Option<String>,
    rest: Vec<String>,
}

pub fn cmd_profile(cli: &Cli, args: &[String]) -> Result<(), String> {
    let Some((sub, args)) = args.split_first() else { return Err(USAGE.into()) };
    let mut args = args.to_vec();
    let flags = flake_cmd::take_flake_flags(&mut args)?;
    let ev = flake_cmd::new_eval(cli, flags.impure)?;
    let mut c = Common {
        profile: profiles::default_profile(&ev.store),
        dry_run: false,
        all: false,
        json: false,
        priority: None,
        file: None,
        expr: None,
        regex: Vec::new(),
        to: None,
        older_than: None,
        rest: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| format!("{a} requires an argument"));
        match a.as_str() {
            "--profile" => c.profile = PathBuf::from(val()?),
            "--dry-run" => c.dry_run = true,
            "--all" => c.all = true,
            "--json" => c.json = true,
            "--priority" => c.priority = Some(val()?.parse().map_err(|_| "invalid --priority value")?),
            "-f" | "--file" => c.file = Some(val()?),
            "--expr" => c.expr = Some(val()?),
            "--regex" => c.regex.push(val()?),
            "--to" => c.to = Some(val()?.parse().map_err(|_| "invalid --to value")?),
            "--older-than" => c.older_than = Some(val()?),
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            _ => c.rest.push(a.clone()),
        }
    }
    c.profile = profiles::absolute(&c.profile)?;
    let profile = c.profile.clone();
    match sub.as_str() {
        "install" | "add" => {
            let mut m = Manifest::read(&ev, &profile)?;
            let mut added = Vec::new();
            for a in &c.rest {
                let mut e = if c.file.is_some() || c.expr.is_some() {
                    let v = eval_file(cli, &ev, c.file.as_deref(), c.expr.as_deref(), a)?;
                    let (paths, priority) = install_paths(cli, &ev, &v)?;
                    Element { store_paths: paths.into_iter().collect(), active: true, priority: priority.unwrap_or(5), source: None }
                } else if let Some(p) = store_path_arg(&ev, a).filter(|_| !flake_cmd::is_installable(a) || a.starts_with('/')) {
                    let paths = if p.ends_with(".drv") {
                        let sp = ev.store.dir.parse(&p)?;
                        let drv = ev.store.read_derivation(&sp)?;
                        let outs: Vec<_> = drv.outputs.keys().map(|o| (sp.clone(), o.clone())).collect();
                        flake_cmd::realise(&ev, cli, &outs)?
                    } else {
                        vec![p]
                    };
                    Element { store_paths: paths.into_iter().collect(), active: true, priority: 5, source: None }
                } else {
                    flake_element(cli, &ev, &flags, a)?
                };
                if let Some(p) = c.priority {
                    e.priority = p;
                }
                added.push(m.add(e));
            }
            if c.rest.is_empty() {
                return Err("'profile install' requires at least one installable".into());
            }
            if c.dry_run {
                return Ok(());
            }
            m.write(cli, &ev, &profile)
        }
        "remove" => {
            let mut m = Manifest::read(&ev, &profile)?;
            let res: Vec<regex::Regex> = c.regex.iter().map(|r| regex::Regex::new(&format!("^(?:{r})$")).map_err(|e| e.to_string())).collect::<Result<_, _>>()?;
            let mut matched = BTreeSet::new();
            let before = m.elements.len();
            m.elements.retain(|name, e| {
                let hit = c.all
                    || c.rest.iter().any(|a| {
                        let hit = a == name || store_path_arg(&ev, a).is_some_and(|p| e.store_paths.contains(&p));
                        if hit {
                            matched.insert(a.clone());
                        }
                        hit
                    })
                    || res.iter().any(|r| r.is_match(name));
                if hit {
                    eprintln!("removing '{}'", e.identifier());
                }
                !hit
            });
            let removed = before - m.elements.len();
            for a in c.rest.iter().filter(|a| !matched.contains(*a)) {
                cranix_fetchers::warn(format!("'{a}' does not match any packages in '{}'", profile.display()));
            }
            if removed == 0 {
                cranix_fetchers::warn("Use 'cranix profile list' to see the current profile.");
                return Ok(());
            }
            if c.dry_run {
                return Ok(());
            }
            m.write(cli, &ev, &profile)
        }
        "upgrade" => {
            let mut m = Manifest::read(&ev, &profile)?;
            let mut changed = false;
            let names: Vec<String> = m.elements.keys().cloned().collect();
            for name in names {
                if !c.all && !c.rest.is_empty() && !c.rest.contains(&name) {
                    continue;
                }
                let e = m.elements[&name].clone();
                let Some(s) = &e.source else {
                    if c.rest.contains(&name) {
                        cranix_fetchers::warn(format!("'{name}' was not installed from a flake and cannot be upgraded"));
                    }
                    continue;
                };
                let spec = format!("{}#.{}", s.original_url, s.attr_path);
                let new = flake_element(cli, &ev, &flags, &spec)?;
                let new_src = new.source.clone().unwrap();
                if new.store_paths == e.store_paths && new_src.url == s.url {
                    continue;
                }
                eprintln!("upgrading '{name}' from flake '{}' to '{}'", s.url, new_src.url);
                let mut up = e.clone();
                up.store_paths = new.store_paths;
                up.source = Some(Source { url: new_src.url, ..s.clone() });
                m.elements.insert(name, up);
                changed = true;
            }
            if !changed || c.dry_run {
                return Ok(());
            }
            m.write(cli, &ev, &profile)
        }
        "list" => {
            let m = Manifest::read(&ev, &profile)?;
            if c.json {
                println!("{}", m.to_json());
                return Ok(());
            }
            let mut first = true;
            for (name, e) in &m.elements {
                if !first {
                    println!();
                }
                first = false;
                println!("Name:               {name}{}", if e.active { "" } else { " (inactive)" });
                if let Some(s) = &e.source {
                    let outs = match &s.outputs {
                        J::Array(a) => format!("^{}", a.iter().filter_map(J::as_str).collect::<Vec<_>>().join(",")),
                        J::String(s) if s == "*" => "^*".into(),
                        _ => String::new(),
                    };
                    println!("Flake attribute:    {}{outs}", s.attr_path);
                    println!("Original flake URL: {}", s.original_url);
                    println!("Locked flake URL:   {}", s.url);
                }
                println!("Store paths:        {}", e.store_paths.iter().cloned().collect::<Vec<_>>().join(" "));
            }
            Ok(())
        }
        "rollback" => profiles::switch_generation(&profile, c.to, c.dry_run),
        "history" => {
            let mut prev: Option<(u64, Manifest)> = None;
            for (i, g) in profiles::generations(&profile)?.into_iter().enumerate() {
                let m = Manifest::read(&ev, &g.path)?;
                if i > 0 {
                    println!();
                }
                let date = &profiles::format_time(g.created, false)[..10];
                let from = prev.as_ref().map_or(String::new(), |(n, _)| format!(" <- {n}"));
                println!("Version {} ({date}){from}:", g.number);
                print_diff(prev.as_ref().map(|(_, m)| m).unwrap_or(&Manifest::default()), &m, "  ");
                prev = Some((g.number, m));
            }
            Ok(())
        }
        "wipe-history" => match &c.older_than {
            Some(t) => profiles::delete_generations_older_than(&profile, profiles::parse_older_than(t)?, c.dry_run),
            None => profiles::delete_old_generations(&profile, c.dry_run),
        },
        s => Err(format!("unknown profile command '{s}'\n{USAGE}")),
    }
}

fn show_versions(v: &BTreeSet<String>) -> String {
    if v.is_empty() {
        return "∅".into();
    }
    let v: BTreeSet<&str> = v.iter().map(|s| if s.is_empty() { "ε" } else { s.as_str() }).collect();
    v.into_iter().collect::<Vec<_>>().join(", ")
}

fn print_diff(prev: &Manifest, cur: &Manifest, indent: &str) {
    let names: BTreeSet<&String> = prev.elements.keys().chain(cur.elements.keys()).collect();
    let mut changes = false;
    for n in names {
        let a = prev.elements.get(n).map(Element::versions).unwrap_or_default();
        let b = cur.elements.get(n).map(Element::versions).unwrap_or_default();
        let (pa, pb) = (prev.elements.contains_key(n), cur.elements.contains_key(n));
        if pa != pb || a != b {
            println!("{indent}{n}: {} -> {}", if pa { show_versions(&a) } else { "∅".into() }, if pb { show_versions(&b) } else { "∅".into() });
            changes = true;
        }
    }
    if !changes {
        println!("{indent}No changes.");
    }
}
