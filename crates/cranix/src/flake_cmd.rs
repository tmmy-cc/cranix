//! Flake commands (`cranix flake …`) and flake installables (`.#attr`,
//! `nixpkgs#hello`) for `eval`, `build`, `run`, `develop` and `shell`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::rc::Rc;

use cranix_core::StorePath;
use cranix_eval::eval::err;
use cranix_eval::flake::lockfile::{parse_input_path, print_input_path, Edge, Node};
use cranix_eval::flake::{self, flakeref, FlakeRef, LockFlags, LockedFlake};
use cranix_eval::value::Sym;
use cranix_eval::{print, Eval, Options, Value, R};
use cranix_fetchers::Attr;

use crate::Cli;

/// Options shared by commands that lock flakes.
pub struct FlakeFlags {
    pub lock: LockFlags,
    pub impure: bool,
}

/// Removes the flake-related options from `args`.
pub fn take_flake_flags(args: &mut Vec<String>) -> Result<FlakeFlags, String> {
    let mut f = FlakeFlags { lock: LockFlags::cli(), impure: false };
    let mut rest = Vec::new();
    let mut it = std::mem::take(args).into_iter();
    while let Some(a) = it.next() {
        let mut val = |n: &str| it.next().ok_or_else(|| format!("{n} requires an argument"));
        match a.as_str() {
            "--impure" => f.impure = true,
            "--no-write-lock-file" => f.lock.write_lock_file = false,
            "--no-update-lock-file" => f.lock.update_lock_file = false,
            "--recreate-lock-file" => f.lock.recreate_lock_file = true,
            "--commit-lock-file" => f.lock.commit_lock_file = true,
            "--no-registries" => f.lock.use_registries = Some(false),
            "--refresh" => cranix_fetchers::set_settings(|s| s.tarball_ttl = 0),
            "--reference-lock-file" => f.lock.reference_lock_file = Some(val(&a)?),
            "--output-lock-file" => f.lock.output_lock_file = Some(val(&a)?),
            "--update-input" => {
                let p = parse_input_path(&val(&a)?)?;
                f.lock.input_updates.insert(p);
            }
            "--override-input" => {
                let p = parse_input_path(&val(&a)?)?;
                let r = flakeref::parse(&val(&a)?, Some(&crate::cwd()), true, true)?;
                f.lock.input_overrides.push((p, r));
            }
            "--override-flake" => {
                let from = flakeref::parse(&val(&a)?, Some(&crate::cwd()), true, true)?;
                let to = flakeref::parse(&val(&a)?, Some(&crate::cwd()), true, true)?;
                let mut extra = cranix_fetchers::Attrs::new();
                if !to.subdir.is_empty() {
                    extra.insert("dir".into(), Attr::Str(to.subdir.clone()));
                }
                cranix_fetchers::registry::override_registry(from.input, to.input, extra);
            }
            _ => rest.push(a),
        }
    }
    *args = rest;
    Ok(f)
}

/// Whether a command line argument names a flake installable.
pub fn is_installable(s: &str) -> bool {
    s.contains('#')
        || ["github:", "gitlab:", "sourcehut:", "git+", "path:", "flake:", "tarball+", "file+"].iter().any(|p| s.starts_with(p))
}

pub fn new_eval(cli: &Cli, impure: bool) -> Result<Rc<Eval>, String> {
    let store = crate::open_store(cli)?;
    let pure = cli.pure || !impure;
    let search_path = if pure { Vec::new() } else { cli.search.clone() };
    let ev = Eval::new(store, Options { search_path, system: cli.system().to_string(), pure, trace_verbose: false, experimental_features: cli.settings.experimental_features.clone(), resolve_search: None });
    Ok(ev)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Eval,
    Build,
    Run,
    Develop,
}

fn defaults(kind: Kind, sys: &str) -> (Vec<String>, Vec<String>) {
    let pkgs = vec![format!("packages.{sys}."), format!("legacyPackages.{sys}.")];
    let pkg_default = vec![format!("packages.{sys}.default"), format!("defaultPackage.{sys}")];
    match kind {
        Kind::Eval | Kind::Build => (pkg_default, pkgs),
        Kind::Run => {
            let mut d = vec![format!("apps.{sys}.default"), format!("defaultApp.{sys}")];
            d.extend(pkg_default);
            let mut p = vec![format!("apps.{sys}.")];
            p.extend(pkgs);
            (d, p)
        }
        Kind::Develop => {
            let mut d = vec![format!("devShells.{sys}.default"), format!("devShell.{sys}")];
            d.extend(pkg_default);
            let mut p = vec![format!("devShells.{sys}.")];
            p.extend(pkgs);
            (d, p)
        }
    }
}

/// Splits an attribute path, honouring double quotes.
pub fn parse_attr_path(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            '.' if !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    if !cur.is_empty() || !out.is_empty() {
        out.push(cur);
    }
    out
}

fn select(ev: &Eval, v: &Value, path: &[String]) -> R<Option<Value>> {
    let mut v = v.clone();
    for k in path {
        let a = match ev.force(&v)? {
            Value::Attrs(a) => a,
            _ => return Ok(None),
        };
        match a.get(&Sym::new(k)) {
            Some(x) => v = x.clone(),
            None => return Ok(None),
        }
    }
    Ok(Some(ev.force(&v)?))
}

pub struct Selected {
    pub value: Value,
}

/// Locks and evaluates `spec` (`flakeref#attrpath`), trying Nix's
/// default attribute paths and prefixes for `kind`.
pub fn eval_installable(ev: &Eval, cli: &Cli, flags: &FlakeFlags, spec: &str, kind: Kind) -> R<Selected> {
    let (r, frag) = flakeref::parse_with_fragment(spec, Some(&crate::cwd()), false, true).or_else(err)?;
    let mut lock = flags.lock.clone();
    if ev.opts.pure {
        lock.allow_unlocked = true;
    }
    let locked = flake::lock_flake(ev, &r, &lock)?;
    let outputs = flake::call_flake(ev, &locked)?;
    let (defs, prefixes) = defaults(kind, cli.system());
    let candidates: Vec<String> = if frag.is_empty() {
        defs
    } else if let Some(f) = frag.strip_prefix('.') {
        vec![f.to_string()]
    } else {
        prefixes.iter().map(|p| format!("{p}{frag}")).chain([frag.clone()]).collect()
    };
    for c in &candidates {
        if let Some(v) = select(ev, &outputs, &parse_attr_path(c))? {
            return Ok(Selected { value: v });
        }
    }
    let quoted: Vec<String> = candidates.iter().map(|c| format!("'{c}'")).collect();
    let list = match quoted.split_last() {
        Some((last, init)) if !init.is_empty() => format!("{} or {last}", init.join(", ")),
        _ => quoted.join(""),
    };
    err(format!("flake '{}' does not provide attribute {list}", r.to_string()))
}

/// Derivations named by a value, with the output each one selects.
pub fn drvs_of(ev: &Eval, v: &Value) -> R<Vec<(StorePath, String)>> {
    let mut out = Vec::new();
    crate::collect_drvs(ev, v, &mut out)?;
    Ok(out)
}

/// The outputs of `drvs` when every one of them is already present in
/// this store or the host store.
pub fn present_outputs(ev: &Eval, drvs: &[StorePath]) -> Option<BTreeMap<StorePath, BTreeMap<String, StorePath>>> {
    let mut res = BTreeMap::new();
    for d in drvs {
        let drv = ev.store.read_derivation(d).ok()?;
        let mut outs = BTreeMap::new();
        for (name, o) in &drv.outputs {
            let p = o.path.clone()?;
            if !ev.store.is_valid(&p) && !ev.store.resolve(&ev.store.dir.print(&p)).exists() {
                return None;
            }
            outs.insert(name.clone(), p);
        }
        res.insert(d.clone(), outs);
    }
    Some(res)
}

/// Makes sure the outputs exist, building only what is missing from this
/// store and the host store: through a daemon given with `--store`,
/// locally, or on the configured remote builders.
pub fn realise(ev: &Eval, cli: &Cli, drvs: &[(StorePath, String)]) -> Result<Vec<String>, String> {
    realise_opt(ev, cli, drvs, false)
}

fn realise_opt(ev: &Eval, cli: &Cli, drvs: &[(StorePath, String)], best_effort: bool) -> Result<Vec<String>, String> {
    let mut paths = Vec::new();
    let mut missing = Vec::new();
    for (d, o) in drvs {
        let drv = ev.store.read_derivation(d)?;
        let out = drv.outputs.get(o).and_then(|x| x.path.clone()).ok_or_else(|| format!("derivation has no output '{o}'"))?;
        let s = ev.store.dir.print(&out);
        if !ev.store.is_valid(&out) && !ev.store.resolve(&s).exists() {
            missing.push(d.clone());
        }
        paths.push(s);
    }
    if !missing.is_empty() {
        match build_missing(ev, cli, &missing) {
            Err(BuildError::Impossible(e)) if best_effort => cranix_fetchers::warn(e),
            Err(BuildError::Impossible(e) | BuildError::Failed(e)) => return Err(e),
            Ok(()) => {}
        }
    }
    Ok(paths)
}

enum BuildError {
    /// Nothing is configured that could build here.
    Impossible(String),
    Failed(String),
}

/// Builds `missing`: through the store `--store` names when it is a
/// daemon, else in this store, which substitutes what it can and hands
/// builds to the configured remote builders.
fn build_missing(ev: &Eval, cli: &Cli, missing: &[StorePath]) -> Result<(), BuildError> {
    let mut opts = crate::build_options(cli);
    if let Some(u) = &cli.remote {
        let mut session = crate::remote::Session::open(u).map_err(BuildError::Failed)?;
        session.realise(&ev.store, missing, &opts).map_err(BuildError::Failed)?;
        return Ok(());
    }
    crate::remote::configure_builders(&mut opts, &cli.settings.builders).map_err(BuildError::Failed)?;
    let res = ev.store.realise(missing, &opts);
    if res.is_err() && !ev.store.can_build() && opts.hook.is_none() {
        let names: Vec<String> = missing.iter().map(|d| format!("'{}'", ev.store.dir.print(d))).collect();
        return Err(BuildError::Impossible(format!(
            "cannot build {}: this store keeps '{}' paths elsewhere, so it cannot run builders, and no remote builders are configured; \
             build through the Nix daemon with --store daemon, set 'builders', or use a store that can build with --store DIR",
            names.join(", "),
            ev.store.dir.as_str()
        )));
    }
    res.map_err(BuildError::Failed)?;
    Ok(())
}

/// `%F %T` of a timestamp in UTC, or in local time like `localtime(3)`.
fn date(t: u64, local: bool) -> String {
    let secs = if local {
        let tt = t as libc::time_t;
        // SAFETY: localtime_r only writes the zero-initialised `tm` we pass.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
            t as i64
        } else {
            t as i64 + tm.tm_gmtoff
        }
    } else {
        t as i64
    };
    let d = cranix_fetchers::format_date_signed(secs);
    format!("{}-{}-{} {}:{}:{}", &d[0..4], &d[4..6], &d[6..8], &d[8..10], &d[10..12], &d[12..14])
}

fn flake_ref_arg(args: &[String]) -> Result<FlakeRef, String> {
    let s = args.iter().find(|a| !a.starts_with('-')).cloned().unwrap_or_else(|| ".".into());
    flakeref::parse(&s, Some(&crate::cwd()), false, true)
}

fn input_tree(node: &Rc<Node>, prefix: &str, out: &mut String, visited: &mut Vec<*const Node>) {
    let inputs = node.inputs.borrow().clone();
    let n = inputs.len();
    for (i, (k, e)) in inputs.iter().enumerate() {
        let last = i + 1 == n;
        let branch = if last { "└───" } else { "├───" };
        match e {
            Edge::Node(c) => {
                let l = c.locked.as_ref().unwrap();
                let lm = match l.locked.input.get_last_modified() {
                    Ok(Some(t)) => format!(" ({})", date(t, false)),
                    _ => String::new(),
                };
                out.push_str(&format!("{prefix}{branch}\x1b[1m{k}\x1b[0m: {}{lm}\n", l.locked.to_string()));
                if !visited.contains(&Rc::as_ptr(c)) {
                    visited.push(Rc::as_ptr(c));
                    let p = format!("{prefix}{}", if last { "    " } else { "│   " });
                    input_tree(c, &p, out, visited);
                }
            }
            Edge::Follows(f) => out.push_str(&format!("{prefix}{branch}\x1b[1m{k}\x1b[0m follows input '{}'\n", print_input_path(f))),
        }
    }
}

fn metadata(ev: &Eval, lf: &LockedFlake, json: bool) -> R<String> {
    let f = &lf.flake;
    let path = ev.store.dir.print(&f.store_path);
    let input = &f.locked_ref.input;
    if json {
        let mut j = serde_json::Map::new();
        if let Some(d) = &f.description {
            j.insert("description".into(), d.clone().into());
        }
        j.insert("original".into(), cranix_fetchers::attrs::to_json(&f.original_ref.to_attrs()));
        j.insert("originalUrl".into(), f.original_ref.to_string().into());
        j.insert("resolved".into(), cranix_fetchers::attrs::to_json(&f.resolved_ref.to_attrs()));
        j.insert("resolvedUrl".into(), f.resolved_ref.to_string().into());
        if let Some(fp) = lf.fingerprint(&ev.store) {
            j.insert("fingerprint".into(), fp.into());
        }
        j.insert("locked".into(), cranix_fetchers::attrs::to_json(&f.locked_ref.to_attrs()));
        j.insert("url".into(), f.locked_ref.to_string().into());
        if let Ok(Some(r)) = input.get_rev() {
            j.insert("revision".into(), r.into());
        }
        if let Ok(Some(d)) = cranix_fetchers::attrs::get_str(&input.attrs, "dirtyRev") {
            j.insert("dirtyRevision".into(), d.into());
        }
        if let Ok(Some(n)) = input.get_rev_count() {
            j.insert("revCount".into(), n.into());
        }
        if let Ok(Some(n)) = input.get_last_modified() {
            j.insert("lastModified".into(), n.into());
        }
        j.insert("path".into(), path.into());
        j.insert("locks".into(), lf.lock_file.to_json().0);
        return Ok(serde_json::Value::Object(j).to_string());
    }
    let mut s = String::new();
    let mut field = |label: &str, v: String| {
        s.push_str(&format!("\x1b[1m{label}:\x1b[0m{}{v}\n", " ".repeat(15 - label.len() - 1)));
    };
    field("Resolved URL", f.resolved_ref.to_string());
    if input.is_locked() {
        field("Locked URL", f.locked_ref.to_string());
    }
    if let Some(d) = &f.description {
        field("Description", d.clone());
    }
    field("Path", path);
    if let Ok(Some(r)) = input.get_rev() {
        field("Revision", r);
    }
    if let Ok(Some(d)) = cranix_fetchers::attrs::get_str(&input.attrs, "dirtyRev") {
        field("Revision", d);
    }
    if let Ok(Some(n)) = input.get_rev_count() {
        field("Revisions", n.to_string());
    }
    if let Ok(Some(n)) = input.get_last_modified() {
        field("Last modified", date(n, true));
    }
    if let Some(fp) = lf.fingerprint(&ev.store) {
        field("Fingerprint", fp);
    }
    let root = &lf.lock_file.root;
    if !root.inputs.borrow().is_empty() {
        s.push_str("\x1b[1mInputs:\x1b[0m\n");
    }
    input_tree(root, "", &mut s, &mut vec![Rc::as_ptr(root)]);
    Ok(s.trim_end().to_string())
}

struct Show<'a> {
    ev: &'a Eval,
    system: &'a str,
    all_systems: bool,
    legacy: bool,
    json: bool,
    color: bool,
}

const TREE_CONN: &str = "├───";
const TREE_LAST: &str = "└───";
const TREE_LINE: &str = "│   ";
const TREE_NULL: &str = "    ";

impl Show<'_> {
    fn c(&self, code: &str) -> &'static str {
        if !self.color {
            return "";
        }
        match code {
            "green" => "\x1b[32;1m",
            "bold" => "\x1b[1m",
            "warn" => "\x1b[35;1m",
            _ => "\x1b[0m",
        }
    }

    /// Lines are written as they are produced, so an evaluation error
    /// leaves the tree printed so far, as in Nix.
    fn line(&mut self, s: String) {
        if !self.json {
            let mut o = std::io::stdout().lock();
            let _ = writeln!(o, "{s}");
            let _ = o.flush();
        }
    }

    fn omitted(&mut self, header: &str, path: &[String], flag: &str) {
        if self.json {
            cranix_fetchers::warn(format!("{} omitted (use '{flag}' to show)", path.join(".")));
        } else {
            let s = format!("{header} {}omitted{} (use '{flag}' to show)", self.c("warn"), self.c("normal"));
            self.line(s);
        }
    }

    fn attrs(&self, v: &Value) -> R<Rc<cranix_eval::value::Attrs>> {
        self.ev.force_attrs(v)
    }

    fn is_drv(&self, v: &Value) -> R<bool> {
        match self.ev.force(v)? {
            Value::Attrs(a) => self.ev.is_derivation(&a),
            _ => Ok(false),
        }
    }

    fn get_str(&self, v: &Value, k: &str) -> R<String> {
        let a = self.attrs(v)?;
        match a.get_str(k) {
            Some(x) => self.ev.force_plain_str(x),
            None => err(format!("attribute '{k}' missing")),
        }
    }

    fn has_content(&self, v: &Value, path: &[String]) -> bool {
        let r: R<bool> = (|| {
            let p0 = path[0].as_str();
            let deep = matches!(p0, "apps" | "checks" | "devShells" | "legacyPackages" | "packages") && (path.len() == 1 || path.len() == 2);
            let shallow = path.len() == 1 && matches!(p0, "formatter" | "nixosConfigurations" | "nixosModules" | "overlays");
            if deep || shallow {
                for (k, x) in self.attrs(v)?.iter() {
                    let mut p2 = path.to_vec();
                    p2.push(k.as_str().to_string());
                    if self.has_content(x, &p2) {
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
            Ok(true)
        })();
        r.unwrap_or(true)
    }

    fn show_drv(&mut self, v: &Value, path: &[String], header: &str, j: &mut serde_json::Map<String, serde_json::Value>) -> R<()> {
        let name = self.get_str(v, "name")?;
        if self.json {
            let a = self.attrs(v)?;
            let mut desc = None;
            if let Some(m) = a.get_str("meta") {
                if let Value::Attrs(m) = self.ev.force(m)? {
                    if let Some(d) = m.get_str("description") {
                        desc = Some(self.ev.force_plain_str(d)?);
                    }
                }
            }
            j.insert("type".into(), "derivation".into());
            j.insert("name".into(), name.into());
            if let Some(d) = desc {
                j.insert("description".into(), d.into());
            }
        } else {
            let p0 = path.first().map_or("", |s| s.as_str());
            let what = if (path.len() == 2 && p0 == "devShell") || (path.len() >= 2 && p0 == "devShells") {
                "development environment"
            } else if (path.len() == 3 && p0 == "checks") || (!path.is_empty() && p0 == "hydraJobs") {
                "derivation"
            } else {
                "package"
            };
            self.line(format!("{header}: {what} '{name}'"));
        }
        Ok(())
    }

    fn recurse(&mut self, v: &Value, path: &[String], header: &str, next: &str, j: &mut serde_json::Map<String, serde_json::Value>) -> R<()> {
        self.line(header.to_string());
        let a = self.attrs(v)?;
        let kids: Vec<(String, Value)> = a
            .iter()
            .filter(|(k, x)| {
                let mut p2 = path.to_vec();
                p2.push(k.as_str().to_string());
                self.has_content(x, &p2)
            })
            .map(|(k, x)| (k.as_str().to_string(), x.clone()))
            .collect();
        let n = kids.len();
        for (i, (k, x)) in kids.into_iter().enumerate() {
            let last = i + 1 == n;
            let mut p2 = path.to_vec();
            p2.push(k.clone());
            let h = format!("{}{next}{}{}{}{k}{}", self.c("green"), if last { TREE_LAST } else { TREE_CONN }, self.c("normal"), self.c("bold"), self.c("normal"));
            let nx = format!("{next}{}", if last { TREE_NULL } else { TREE_LINE });
            let j2 = self.visit(&x, &p2, &h, &nx)?;
            if self.json {
                j.insert(k, j2);
            }
        }
        Ok(())
    }

    fn visit(&mut self, v: &Value, path: &[String], header: &str, next: &str) -> R<serde_json::Value> {
        let mut j = serde_json::Map::new();
        let r = self.visit_inner(v, path, header, next, &mut j);
        if let Err(e) = r {
            if !(path.first().is_some_and(|p| p == "legacyPackages")) {
                return Err(e);
            }
        }
        Ok(serde_json::Value::Object(j))
    }

    fn visit_inner(&mut self, v: &Value, path: &[String], header: &str, next: &str, j: &mut serde_json::Map<String, serde_json::Value>) -> R<()> {
        let p0 = path.first().map_or("", |s| s.as_str());
        let len = path.len();
        let other_system = len >= 2 && !self.all_systems && path[1] != self.system;
        if len == 0
            || (len == 1
                && matches!(p0, "defaultPackage" | "devShell" | "formatter" | "nixosConfigurations" | "nixosModules" | "defaultApp" | "templates" | "overlays"))
            || ((len == 1 || len == 2) && matches!(p0, "checks" | "packages" | "devShells" | "apps"))
        {
            self.recurse(v, path, header, next, j)
        } else if (len == 2 && matches!(p0, "defaultPackage" | "devShell" | "formatter")) || (len == 3 && matches!(p0, "checks" | "packages" | "devShells")) {
            if other_system {
                self.omitted(header, path, "--all-systems");
                Ok(())
            } else if self.is_drv(v)? {
                self.show_drv(v, path, header, j)
            } else {
                err("expected a derivation")
            }
        } else if len > 0 && p0 == "hydraJobs" {
            if self.is_drv(v)? {
                self.show_drv(v, path, header, j)
            } else {
                self.recurse(v, path, header, next, j)
            }
        } else if len > 0 && p0 == "legacyPackages" {
            if len == 1 {
                self.recurse(v, path, header, next, j)
            } else if !self.legacy {
                self.omitted(header, path, "--legacy");
                Ok(())
            } else if other_system {
                self.omitted(header, path, "--all-systems");
                Ok(())
            } else if self.is_drv(v)? {
                self.show_drv(v, path, header, j)
            } else if len <= 2 {
                self.recurse(v, path, header, next, j)
            } else {
                Ok(())
            }
        } else if (len == 2 && p0 == "defaultApp") || (len == 3 && p0 == "apps") {
            let a = self.attrs(v)?;
            let is_app = match a.get_str("type") {
                Some(t) => self.ev.force_plain_str(t)? == "app",
                None => false,
            };
            if !is_app {
                return err("not an app definition");
            }
            if self.json {
                j.insert("type".into(), "app".into());
            } else {
                self.line(format!("{header}: app"));
            }
            Ok(())
        } else if (len == 1 && p0 == "defaultTemplate") || (len == 2 && p0 == "templates") {
            let d = self.get_str(v, "description")?;
            if self.json {
                j.insert("type".into(), "template".into());
                j.insert("description".into(), d.into());
            } else {
                let s = format!("{header}: template: {}{d}{}", self.c("bold"), self.c("normal"));
                self.line(s);
            }
            Ok(())
        } else {
            let (ty, desc) = if (len == 1 && p0 == "overlay") || (len == 2 && p0 == "overlays") {
                ("nixpkgs-overlay", "Nixpkgs overlay")
            } else if len == 2 && p0 == "nixosConfigurations" {
                ("nixos-configuration", "NixOS configuration")
            } else if (len == 1 && p0 == "nixosModule") || (len == 2 && p0 == "nixosModules") {
                ("nixos-module", "NixOS module")
            } else {
                ("unknown", "unknown")
            };
            if self.json {
                j.insert("type".into(), ty.into());
            } else {
                let s = format!("{header}: {}{desc}{}", self.c("warn"), self.c("normal"));
                self.line(s);
            }
            Ok(())
        }
    }
}

/// `flake show`: the tree (or JSON) of a flake's outputs, as Nix prints it.
fn show(ev: &Eval, cli: &Cli, lf: &LockedFlake, outputs: &Value, all_systems: bool, legacy: bool, json: bool) -> R<String> {
    // Nix writes the colours regardless of where stdout goes.
    let color = !json;
    let mut s = Show { ev, system: cli.system(), all_systems, legacy, json, color };
    let outs = match ev.force_attrs(outputs)?.get_str("outputs") {
        Some(o) => o.clone(),
        None => outputs.clone(),
    };
    let header = format!("{}{}{}", s.c("bold"), lf.flake.locked_ref.to_string(), s.c("normal"));
    let j = s.visit(&outs, &[], &header, "")?;
    Ok(if json { format!("{j}\n") } else { String::new() })
}

fn check(ev: &Eval, cli: &Cli, outputs: &Value, build: bool) -> R<()> {
    let top = ev.force_attrs(outputs)?;
    let outs = match top.get_str("outputs") {
        Some(o) => ev.force_attrs(o)?,
        None => top,
    };
    let mut to_build = Vec::new();
    for (k, v) in outs.iter() {
        let name = k.as_str();
        let per_system_drvs = matches!(name, "packages" | "checks" | "devShells");
        if per_system_drvs || matches!(name, "apps" | "formatter" | "legacyPackages") {
            for (sys, sv) in ev.force_attrs(v)?.iter() {
                if sys.as_str() != cli.system() || name == "legacyPackages" {
                    continue;
                }
                if name == "formatter" {
                    let d = ev.force(sv)?;
                    drvs_of(ev, &d)?;
                    continue;
                }
                for (an, av) in ev.force_attrs(sv)?.iter() {
                    let what = format!("{name}.{}.{}", sys.as_str(), an.as_str());
                    let av = ev.force(av)?;
                    if name == "apps" {
                        let a = ev.force_attrs(&av)?;
                        if !matches!(a.get_str("type").map(|t| ev.force(t)), Some(Ok(Value::Str(ref s))) if s.s == "app") {
                            return err(format!("app '{what}' is not an app definition"));
                        }
                        continue;
                    }
                    let is_drv = matches!(&av, Value::Attrs(a) if ev.is_derivation(a)?);
                    if !is_drv {
                        return err(format!("flake attribute '{what}' is not a derivation"));
                    }
                    if name == "checks" {
                        to_build.extend(drvs_of(ev, &av)?);
                    }
                }
            }
        } else if matches!(name, "overlays" | "nixosModules" | "templates" | "lib" | "nixosConfigurations" | "darwinConfigurations" | "homeConfigurations") {
            ev.force(v)?;
        } else if matches!(name, "overlay" | "nixosModule" | "defaultTemplate" | "defaultPackage" | "devShell" | "defaultApp") {
            ev.force(v)?;
        } else {
            cranix_fetchers::warn(format!("unknown flake output '{name}'"));
        }
    }
    if build && !to_build.is_empty() {
        realise(ev, cli, &to_build).or_else(err)?;
    }
    Ok(())
}

fn copy_template(src: &Path, dst: &Path, created: &mut Vec<String>) -> Result<(), String> {
    for e in std::fs::read_dir(src).map_err(|e| e.to_string())? {
        let e = e.map_err(|e| e.to_string())?;
        let from = e.path();
        let to = dst.join(e.file_name());
        let md = std::fs::symlink_metadata(&from).map_err(|e| e.to_string())?;
        if md.is_dir() {
            std::fs::create_dir_all(&to).map_err(|e| e.to_string())?;
            copy_template(&from, &to, created)?;
        } else if to.symlink_metadata().is_ok() {
            if std::fs::read(&from).ok() != std::fs::read(&to).ok() {
                return Err(format!("refusing to overwrite existing file '{}'\n please merge it manually with '{}'", to.display(), from.display()));
            }
        } else {
            if md.is_symlink() {
                std::os::unix::fs::symlink(std::fs::read_link(&from).map_err(|e| e.to_string())?, &to).map_err(|e| e.to_string())?;
            } else {
                std::fs::copy(&from, &to).map_err(|e| e.to_string())?;
                use std::os::unix::fs::PermissionsExt;
                let exec = md.permissions().mode() & 0o100 != 0;
                std::fs::set_permissions(&to, std::fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 })).map_err(|e| e.to_string())?;
            }
            created.push(to.display().to_string());
        }
    }
    Ok(())
}

pub fn cmd_flake(cli: &Cli, args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    let flags = take_flake_flags(&mut args)?;
    let sub = if args.is_empty() { String::new() } else { args.remove(0) };
    let has = |f: &str| args.iter().any(|a| a == f);
    let positional: Vec<String> = args.iter().filter(|a| !a.starts_with('-')).cloned().collect();
    let ev = new_eval(cli, flags.impure)?;
    let r: R<()> = (|| {
        match sub.as_str() {
            "metadata" | "info" => {
                let r = flake_ref_arg(&positional).or_else(err)?;
                let lf = flake::lock_flake(&ev, &r, &flags.lock)?;
                println!("{}", metadata(&ev, &lf, has("--json"))?);
            }
            "lock" => {
                let r = flake_ref_arg(&positional).or_else(err)?;
                let mut l = flags.lock.clone();
                l.write_lock_file = true;
                flake::lock_flake(&ev, &r, &l)?;
            }
            "update" => {
                // `flake update [INPUTS...] [--flake REF]`
                let mut l = flags.lock.clone();
                let mut fref = ".".to_string();
                let mut inputs = Vec::new();
                let mut it = args.iter();
                while let Some(a) = it.next() {
                    if a == "--flake" {
                        fref = it.next().cloned().unwrap_or(fref);
                    } else if !a.starts_with('-') {
                        inputs.push(a.clone());
                    }
                }
                if inputs.is_empty() {
                    l.recreate_lock_file = true;
                } else {
                    for i in inputs {
                        l.input_updates.insert(parse_input_path(&i).or_else(err)?);
                    }
                }
                let r = flakeref::parse(&fref, Some(&crate::cwd()), false, true).or_else(err)?;
                flake::lock_flake(&ev, &r, &l)?;
            }
            "show" => {
                let r = flake_ref_arg(&positional).or_else(err)?;
                let lf = flake::lock_flake(&ev, &r, &flags.lock)?;
                let out = flake::call_flake(&ev, &lf)?;
                print!("{}", show(&ev, cli, &lf, &out, has("--all-systems"), has("--legacy"), has("--json"))?);
            }
            "check" => {
                let r = flake_ref_arg(&positional).or_else(err)?;
                let lf = flake::lock_flake(&ev, &r, &flags.lock)?;
                let out = flake::call_flake(&ev, &lf)?;
                check(&ev, cli, &out, !has("--no-build"))?;
            }
            "init" | "new" => {
                let mut tmpl = "templates".to_string();
                let mut it = args.iter();
                let mut dest = crate::cwd();
                while let Some(a) = it.next() {
                    if a == "-t" || a == "--template" {
                        tmpl = it.next().cloned().unwrap_or(tmpl);
                    } else if sub == "new" && !a.starts_with('-') {
                        dest = if a.starts_with('/') { a.clone() } else { format!("{}/{a}", crate::cwd()) };
                    }
                }
                let (r, frag) = flakeref::parse_with_fragment(&tmpl, Some(&crate::cwd()), false, true).or_else(err)?;
                let lf = flake::lock_flake(&ev, &r, &flags.lock)?;
                let out = flake::call_flake(&ev, &lf)?;
                let cands: Vec<String> = if frag.is_empty() {
                    vec!["templates.default".into(), "defaultTemplate".into()]
                } else {
                    vec![format!("templates.{frag}"), frag.clone()]
                };
                let mut found = None;
                for c in &cands {
                    if let Some(v) = select(&ev, &out, &parse_attr_path(c))? {
                        found = Some(v);
                        break;
                    }
                }
                let t = found.ok_or(()).or_else(|_| err(format!("flake '{}' does not provide a template", r.to_string())))?;
                let ta = ev.force_attrs(&t)?;
                let p = ta.get_str("path").ok_or(()).or_else(|_| err("template has no 'path' attribute"))?;
                let src = ev.coerce_to_path(p, &mut Default::default())?;
                std::fs::create_dir_all(&dest).or_else(|e| err(e.to_string()))?;
                let mut created = Vec::new();
                copy_template(&ev.store.resolve(&src), Path::new(&dest), &mut created).or_else(err)?;
                for c in &created {
                    eprintln!("wrote: {c}");
                }
                if let Some(m) = ta.get_str("welcomeText") {
                    eprintln!("{}", ev.force_plain_str(m)?);
                }
                if std::path::Path::new(&dest).join(".git").exists() && !created.is_empty() {
                    let _ = std::process::Command::new("git").arg("-C").arg(&dest).args(["add", "--intent-to-add", "--force", "--"]).args(&created).status();
                }
            }
            "" => return err("usage: cranix flake metadata|show|lock|update|check|init|new [FLAKE]"),
            s => return err(format!("unknown flake subcommand '{s}'")),
        }
        Ok(())
    })();
    r.map_err(|e| e.to_string())
}

/// `cranix eval INSTALLABLE`.
pub fn cmd_eval(cli: &Cli, spec: &str, flags: &FlakeFlags, json: bool, raw: bool) -> Result<(), String> {
    let ev = new_eval(cli, flags.impure)?;
    let r = (|| {
        let sel = eval_installable(&ev, cli, flags, spec, Kind::Eval)?;
        if json {
            let mut s = String::new();
            print::to_json(&ev, &sel.value, &mut s, &mut Default::default())?;
            Ok(s)
        } else if raw {
            Ok(ev.force_str(&sel.value)?.s.clone())
        } else {
            ev.deep_force(&sel.value)?;
            print::print_value(&ev, &sel.value, true)
        }
    })();
    match r {
        Ok(s) => {
            if raw {
                print!("{s}");
            } else {
                println!("{s}");
            }
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

fn main_program(ev: &Eval, v: &Value) -> R<String> {
    let a = ev.force_attrs(v)?;
    if let Some(m) = a.get_str("meta") {
        if let Value::Attrs(m) = ev.force(m)? {
            if let Some(p) = m.get_str("mainProgram") {
                return ev.force_plain_str(p);
            }
        }
    }
    if let Some(p) = a.get_str("pname") {
        return ev.force_plain_str(p);
    }
    let name = ev.force_plain_str(a.get_str("name").ok_or(()).or_else(|_| err("derivation has no name"))?)?;
    let parsed = ev.call(&ev.global("__parseDrvName").unwrap(), Value::str(name))?;
    ev.force_plain_str(ev.force_attrs(&parsed)?.get_str("name").unwrap())
}

fn exec(prog: &str, args: &[String], env: &BTreeMap<String, String>) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let mut c = std::process::Command::new(prog);
    c.args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    let e = c.exec();
    Err(format!("unable to execute '{prog}': {e}"))
}

/// `run`, `shell` and `develop`.
pub fn cmd_run_like(cli: &Cli, cmd: &str, args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    let flags = take_flake_flags(&mut args)?;
    let (mine, passthru): (Vec<String>, Vec<String>) = match args.iter().position(|a| a == "--") {
        Some(i) => (args[..i].to_vec(), args[i + 1..].to_vec()),
        None if cmd == "run" && !args.is_empty() => {
            let first = args.iter().position(|a| !a.starts_with('-')).unwrap_or(0);
            (args[..=first.min(args.len() - 1)].to_vec(), args[first + 1..].to_vec())
        }
        None => (args.clone(), Vec::new()),
    };
    let mut command: Option<Vec<String>> = None;
    let mut specs = Vec::new();
    let mut it = mine.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-c" | "--command" => {
                let mut c: Vec<String> = it.by_ref().cloned().collect();
                c.extend(passthru.iter().cloned());
                command = Some(c);
                break;
            }
            a if a.starts_with('-') => {}
            a => specs.push(a.to_string()),
        }
    }
    if specs.is_empty() {
        specs.push(".".into());
    }
    let ev = new_eval(cli, flags.impure)?;
    let kind = match cmd {
        "run" => Kind::Run,
        "develop" => Kind::Develop,
        _ => Kind::Build,
    };
    let r: Result<(), String> = (|| {
        match cmd {
            "run" => {
                let sel = eval_installable(&ev, cli, &flags, &specs[0], kind).map_err(|e| e.to_string())?;
                let a = ev.force_attrs(&sel.value).map_err(|e| e.to_string())?;
                let is_app = matches!(a.get_str("type").map(|t| ev.force(t)), Some(Ok(Value::Str(ref s))) if s.s == "app");
                let prog = if is_app {
                    let p = a.get_str("program").ok_or("app has no 'program' attribute")?;
                    let mut ctx = Default::default();
                    let s = ev.coerce_to_string(p, &cranix_eval::eval::CoerceOpts { more: false, copy: true }, &mut ctx).map_err(|e| e.to_string())?;
                    let drvs: Vec<(StorePath, String)> = ctx
                        .iter()
                        .filter_map(|c| match c {
                            cranix_eval::value::CtxElem::Built { drv, output } => Some((ev.store.dir.parse(drv).ok()?, output.clone())),
                            _ => None,
                        })
                        .collect();
                    realise(&ev, cli, &drvs)?;
                    s
                } else {
                    let drvs = drvs_of(&ev, &sel.value).map_err(|e| e.to_string())?;
                    let outs = realise(&ev, cli, &drvs)?;
                    let mp = main_program(&ev, &sel.value).map_err(|e| e.to_string())?;
                    format!("{}/bin/{mp}", outs[0])
                };
                let real = ev.store.resolve(&prog);
                exec(&real.to_string_lossy(), &passthru, &BTreeMap::new())
            }
            "shell" => {
                let mut bins = Vec::new();
                for s in &specs {
                    let sel = eval_installable(&ev, cli, &flags, s, kind).map_err(|e| e.to_string())?;
                    let drvs = drvs_of(&ev, &sel.value).map_err(|e| e.to_string())?;
                    for o in realise(&ev, cli, &drvs)? {
                        bins.push(format!("{}/bin", ev.store.resolve(&o).display()));
                    }
                }
                let path = std::env::var("PATH").unwrap_or_default();
                let mut env = BTreeMap::new();
                env.insert("PATH".to_string(), format!("{}:{path}", bins.join(":")));
                match command {
                    Some(c) if !c.is_empty() => exec(&c[0], &c[1..], &env),
                    _ => exec(&std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()), &[], &env),
                }
            }
            _ => develop(&ev, cli, &flags, &specs[0], command),
        }
    })();
    r
}

/// A minimal `nix develop`: the derivation's environment with its inputs
/// built, `stdenv/setup` sourced, then an interactive bash or `--command`.
fn develop(ev: &Eval, cli: &Cli, flags: &FlakeFlags, spec: &str, command: Option<Vec<String>>) -> Result<(), String> {
    let sel = eval_installable(ev, cli, flags, spec, Kind::Develop).map_err(|e| e.to_string())?;
    let drvs = drvs_of(ev, &sel.value).map_err(|e| e.to_string())?;
    let (drv_path, _) = drvs.first().ok_or("installable is not a derivation")?;
    let drv = ev.store.read_derivation(drv_path)?;
    let mut inputs = Vec::new();
    for (d, outs) in &drv.input_drvs {
        for o in outs {
            inputs.push((d.clone(), o.clone()));
        }
    }
    realise_opt(ev, cli, &inputs, true)?;
    let tmp = std::env::temp_dir().join(format!("cranix-develop-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let mut rc = String::new();
    let cwd = crate::cwd();
    for (k, v) in &drv.env {
        let v = if drv.outputs.contains_key(k) { format!("{cwd}/outputs/{k}") } else { v.clone() };
        rc.push_str(&format!("export {k}={}\n", shell_quote(&v)));
    }
    rc.push_str(&format!(
        "export NIX_BUILD_TOP={t} TMPDIR={t} TEMPDIR={t} TMP={t} TEMP={t}\nexport IN_NIX_SHELL=impure\nunset NIX_ENFORCE_PURITY\n",
        t = shell_quote(&tmp.to_string_lossy())
    ));
    rc.push_str("if [ -n \"$stdenv\" ] && [ -e \"$stdenv/setup\" ]; then source \"$stdenv/setup\"; fi\n");
    rc.push_str("export PATH=\"$PATH:$ORIG_PATH\"\nPS1='\\n\\[\\033[1;32m\\][cranix develop:\\w]\\$\\[\\033[0m\\] '\n");
    let rcfile = tmp.join("rc");
    std::fs::File::create(&rcfile).and_then(|mut f| f.write_all(rc.as_bytes())).map_err(|e| e.to_string())?;
    let bash = drv
        .env
        .get("SHELL")
        .filter(|s| ev.store.resolve(s).exists())
        .map(|s| ev.store.resolve(s).to_string_lossy().into_owned())
        .unwrap_or_else(|| "bash".into());
    let mut env = BTreeMap::new();
    env.insert("ORIG_PATH".into(), std::env::var("PATH").unwrap_or_default());
    match command {
        Some(c) if !c.is_empty() => {
            let script = format!("source {}\n{}", shell_quote(&rcfile.to_string_lossy()), c.iter().map(|x| shell_quote(x)).collect::<Vec<_>>().join(" "));
            exec(&bash, &["-c".into(), script], &env)
        }
        _ => {
            use std::io::IsTerminal;
            if std::io::stdin().is_terminal() {
                exec(&bash, &["--rcfile".into(), rcfile.to_string_lossy().into_owned()], &env)
            } else {
                // Commands piped in run in a non-interactive bash, which
                // reads `$BASH_ENV` instead of an rc file.
                env.insert("BASH_ENV".into(), rcfile.to_string_lossy().into_owned());
                exec(&bash, &[], &env)
            }
        }
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Resolves a `flake:` search path entry (`nixpkgs=flake:nixpkgs`) to the
/// store path of the fetched flake, as Nix does on the first lookup.
pub fn resolve_search_entry(store: &cranix_store::Store, entry: &str) -> Result<String, String> {
    let r = entry.strip_prefix("flake:").ok_or_else(|| format!("unsupported search path entry '{entry}'"))?;
    let fr = flakeref::parse(r, None, true, true)?;
    let fr = if fr.input.is_direct() { fr } else { fr.resolve(store)? };
    let (sp, _) = fr.fetch_tree(store)?;
    let p = store.dir.print(&sp);
    Ok(if fr.subdir.is_empty() { p } else { format!("{p}/{}", fr.subdir) })
}
