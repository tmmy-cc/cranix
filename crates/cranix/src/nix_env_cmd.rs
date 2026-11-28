//! `cranix nix-env`: installs, upgrades, removes and queries packages in a
//! profile whose generations hold `manifest.nix`, as `nix-env` does.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cranix_eval::value::Sym;
use cranix_eval::{Eval, Value};
use serde_json::{json, Map, Value as J};

use crate::profiles::{self, compare_versions, DrvName};
use crate::{auto_call, cwd, render_error, Cli};

const USAGE: &str = "\
usage: cranix nix-env [-p PROFILE] [-f FILE] OPERATION [ARGS]
operations:
  -i, --install [-A] [-r] [--preserve-installed] NAME|ATTR|PATH...
  -e, --uninstall NAME...
  -u, --upgrade [NAME...]
  -q, --query [-a] [-P] [--out-path] [NAME...]
  --set-flag NAME VALUE NAME...
  --rollback | --switch-generation N | -G N
  --list-generations | --delete-generations old|Nd|+N|N...";

/// An element of a user environment, as `manifest.nix` stores it.
#[derive(Clone, Debug)]
pub struct Elem {
    pub name: String,
    pub system: Option<String>,
    pub out_path: String,
    pub drv_path: Option<String>,
    pub outputs: Vec<(String, String)>,
    pub meta: Map<String, J>,
    /// Where the element was found in the `-f` expression.
    pub attr_path: String,
}

impl Elem {
    pub fn drv_name(&self) -> DrvName {
        DrvName::parse(&self.name)
    }

    fn priority(&self) -> i64 {
        match self.meta.get("priority") {
            Some(J::Number(n)) => n.as_i64().unwrap_or(5),
            Some(J::String(s)) => s.parse().unwrap_or(5),
            _ => 5,
        }
    }

    fn active(&self) -> bool {
        !matches!(self.meta.get("active"), Some(J::Bool(false))) && self.meta.get("active") != Some(&J::String("false".into()))
    }

    /// The element in the form `manifest.nix` lists it.
    fn to_manifest(&self) -> J {
        let mut o = Map::new();
        o.insert("meta".into(), J::Object(self.meta.clone()));
        o.insert("name".into(), J::String(self.name.clone()));
        o.insert("outPath".into(), J::String(self.out_path.clone()));
        if let Some(d) = &self.drv_path {
            o.insert("drvPath".into(), J::String(d.clone()));
        }
        if let Some(s) = &self.system {
            o.insert("system".into(), J::String(s.clone()));
        }
        o.insert("type".into(), J::String("derivation".into()));
        o.insert("outputs".into(), J::Array(self.outputs.iter().map(|(n, _)| J::String(n.clone())).collect()));
        for (n, p) in &self.outputs {
            o.insert(n.clone(), json!({ "outPath": p }));
        }
        J::Object(o)
    }
}

fn get_str(ev: &Eval, a: &cranix_eval::value::Attrs, k: &str) -> cranix_eval::R<Option<String>> {
    match a.get_str(k) {
        Some(v) => Ok(Some(ev.force_str(v)?.s.clone())),
        None => Ok(None),
    }
}

/// Reads an element from a derivation or a `manifest.nix` entry.
pub fn elem_of(ev: &Eval, v: &Value, attr_path: &str) -> cranix_eval::R<Elem> {
    let a = ev.force_attrs(v)?;
    let name = get_str(ev, &a, "name")?.unwrap_or_default();
    let out_path = get_str(ev, &a, "outPath")?.unwrap_or_default();
    let mut meta = Map::new();
    if let Some(m) = a.get_str("meta") {
        if let Ok(m) = ev.force_attrs(m) {
            for (k, x) in m.iter() {
                // Meta attributes that fail to evaluate are left out.
                if let Ok(Some(j)) = profiles::value_to_json(ev, x, 0) {
                    meta.insert(k.as_str().to_string(), j);
                }
            }
        }
    }
    let mut names: Vec<String> = match a.get_str("outputs") {
        Some(o) => ev.force_list(o)?.iter().map(|x| ev.force_plain_str(x)).collect::<Result<_, _>>()?,
        None => vec!["out".into()],
    };
    if let Some(J::Array(want)) = meta.get("outputsToInstall") {
        let want: BTreeSet<&str> = want.iter().filter_map(J::as_str).collect();
        names.retain(|n| want.contains(n.as_str()));
    }
    let mut outputs = Vec::new();
    for n in names {
        let p = match a.get(&Sym::new(&n)) {
            Some(o) => match get_str(ev, &*ev.force_attrs(o)?, "outPath")? {
                Some(p) => p,
                None => continue,
            },
            None if n == "out" => out_path.clone(),
            None => continue,
        };
        outputs.push((n, p));
    }
    if outputs.is_empty() {
        outputs.push(("out".into(), out_path.clone()));
    }
    Ok(Elem {
        name,
        system: get_str(ev, &a, "system")?.filter(|s| !s.is_empty()),
        out_path,
        drv_path: get_str(ev, &a, "drvPath")?,
        outputs,
        meta,
        attr_path: attr_path.to_string(),
    })
}

/// The elements of the profile's current generation.
pub fn installed(ev: &Eval, profile: &Path) -> Result<Vec<Elem>, String> {
    if profile.join("manifest.json").exists() {
        return Err(format!("profile '{}' is incompatible with 'nix-env'; please use 'nix profile' instead", profile.display()));
    }
    let manifest = profile.join("manifest.nix");
    if !manifest.exists() {
        return Ok(Vec::new());
    }
    let target = std::fs::canonicalize(&manifest).map_err(|e| format!("resolving '{}': {e}", manifest.display()))?;
    let r = (|| -> cranix_eval::R<Vec<Elem>> {
        let v = ev.import(&target.to_string_lossy())?;
        let mut out = Vec::new();
        for x in ev.force_list(&v)?.iter() {
            out.push(elem_of(ev, x, "")?);
        }
        Ok(out)
    })();
    r.map_err(|e| format!("reading '{}': {e}", manifest.display()))
}

/// Writes a user environment holding `elems` as the profile's next
/// generation.
pub fn create_user_env(cli: &Cli, ev: &Eval, profile: &Path, elems: &[Elem]) -> Result<(), String> {
    let store = &ev.store;
    let mut refs = BTreeSet::new();
    let mut packages = Vec::new();
    for e in elems {
        for (_, p) in &e.outputs {
            refs.extend(store.dir.to_store_path(p).map(|(sp, _)| sp));
        }
        if let Some(d) = &e.drv_path {
            refs.extend(store.dir.to_store_path(d).map(|(sp, _)| sp).filter(|sp| store.is_valid(sp)));
        }
        packages.push((e.outputs.iter().map(|(_, p)| p.clone()).collect(), e.active(), e.priority()));
    }
    let mut text = String::new();
    profiles::json_to_nix(&J::Array(elems.iter().map(Elem::to_manifest).collect()), &mut text);
    let manifest = store.add_text("env-manifest.nix", text.as_bytes(), &refs)?;
    profiles::build_user_env(cli, ev, profile, "user-environment", &packages, manifest, None)?;
    Ok(())
}

/// Makes sure the outputs of `elems` exist, building them if needed.
fn realise(cli: &Cli, ev: &Eval, elems: &[Elem]) -> Result<(), String> {
    let mut drvs = Vec::new();
    for e in elems {
        let Some(d) = e.drv_path.as_deref().and_then(|d| ev.store.dir.to_store_path(d)).map(|(p, _)| p) else { continue };
        for (o, _) in &e.outputs {
            drvs.push((d.clone(), o.clone()));
        }
    }
    if !drvs.is_empty() {
        crate::flake_cmd::realise(ev, cli, &drvs)?;
    }
    Ok(())
}

struct Opts {
    profile: PathBuf,
    file: Option<String>,
    attr: bool,
    available: bool,
    attr_path_col: bool,
    out_path_col: bool,
    remove_all: bool,
    preserve: bool,
    dry_run: bool,
}

/// Splits clustered short options (`-iA`, `-qaP`) into separate ones.
fn expand(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for a in args {
        let b = a.as_bytes();
        if b.len() > 2 && b[0] == b'-' && b[1] != b'-' && b[1].is_ascii_alphabetic() {
            out.extend(a[1..].chars().map(|c| format!("-{c}")));
        } else {
            out.push(a.clone());
        }
    }
    out
}

pub fn cmd_nix_env(cli: &Cli, args: &[String]) -> Result<(), String> {
    let args = expand(args);
    let ev = crate::new_eval(cli)?;
    let mut o = Opts {
        profile: profiles::default_profile(&ev.store),
        file: None,
        attr: false,
        available: false,
        attr_path_col: false,
        out_path_col: false,
        remove_all: false,
        preserve: false,
        dry_run: false,
    };
    let mut op: Option<String> = None;
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| format!("{a} requires an argument"));
        match a.as_str() {
            "-p" | "--profile" => o.profile = PathBuf::from(val()?),
            "-f" | "--file" => o.file = Some(val()?),
            "-A" | "--attr" => o.attr = true,
            "-a" | "--available" => o.available = true,
            "--installed" => o.available = false,
            "-P" | "--attr-path" => o.attr_path_col = true,
            "--out-path" => o.out_path_col = true,
            "-r" | "--remove-all" => o.remove_all = true,
            "--preserve-installed" => o.preserve = true,
            "--dry-run" => o.dry_run = true,
            "-i" | "--install" => op = Some("install".into()),
            "-e" | "--uninstall" => op = Some("uninstall".into()),
            "-u" | "--upgrade" => op = Some("upgrade".into()),
            "-q" | "--query" => op = Some("query".into()),
            "--set-flag" => op = Some("set-flag".into()),
            "--rollback" => op = Some("rollback".into()),
            "--list-generations" => op = Some("list-generations".into()),
            "--delete-generations" => op = Some("delete-generations".into()),
            "-G" | "--switch-generation" => {
                op = Some("switch-generation".into());
                rest.push(val()?);
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            _ => rest.push(a.clone()),
        }
    }
    o.profile = profiles::absolute(&o.profile)?;
    let op = op.ok_or_else(|| format!("no operation specified\n{USAGE}"))?;
    let profile = o.profile.clone();
    match op.as_str() {
        "install" => install(cli, &ev, &o, &rest),
        "uninstall" => {
            let sel: Vec<DrvName> = rest.iter().map(|s| DrvName::parse(s)).collect();
            let mut kept = Vec::new();
            for e in installed(&ev, &profile)? {
                let by_path = rest.iter().any(|r| r == &e.out_path);
                if by_path || sel.iter().any(|s| s.matches(&e.drv_name())) {
                    eprintln!("uninstalling '{}'", e.name);
                } else {
                    kept.push(e);
                }
            }
            if o.dry_run {
                return Ok(());
            }
            create_user_env(cli, &ev, &profile, &kept)
        }
        "upgrade" => upgrade(cli, &ev, &o, &rest),
        "query" => query(cli, &ev, &o, &rest),
        "set-flag" => {
            let [flag, value, names @ ..] = rest.as_slice() else { return Err("--set-flag requires a flag name, a value and package names".into()) };
            let sel: Vec<DrvName> = names.iter().map(|s| DrvName::parse(s)).collect();
            let mut elems = installed(&ev, &profile)?;
            for e in elems.iter_mut().filter(|e| sel.iter().any(|s| s.matches(&e.drv_name()))) {
                let v = match flag.as_str() {
                    "priority" => value.parse::<i64>().map(J::from).unwrap_or(J::String(value.clone())),
                    "active" => J::Bool(value == "true"),
                    _ => J::String(value.clone()),
                };
                e.meta.insert(flag.clone(), v);
            }
            create_user_env(cli, &ev, &profile, &elems)
        }
        "rollback" => profiles::switch_generation(&profile, None, o.dry_run),
        "switch-generation" => {
            let n = rest.first().and_then(|n| n.parse().ok()).ok_or("--switch-generation requires a generation number")?;
            profiles::switch_generation(&profile, Some(n), o.dry_run)
        }
        "list-generations" => {
            let cur = profiles::current(&profile);
            for g in profiles::generations(&profile)? {
                println!(
                    "{:>4}   {}   {}",
                    g.number,
                    profiles::format_time(g.created, true),
                    if Some(g.number) == cur { "(current)" } else { "" }
                );
            }
            Ok(())
        }
        "delete-generations" => delete_generations(&profile, &rest, o.dry_run),
        _ => unreachable!(),
    }
}

fn delete_generations(profile: &Path, args: &[String], dry_run: bool) -> Result<(), String> {
    match args {
        [a] if a == "old" => profiles::delete_old_generations(profile, dry_run),
        [a] if a.ends_with('d') => profiles::delete_generations_older_than(profile, profiles::parse_older_than(a)?, dry_run),
        [a] if a.starts_with('+') => {
            let keep: usize = a[1..].parse().map_err(|_| format!("invalid number of generations to keep '{a}'"))?;
            let cur = profiles::current(profile);
            let gens = profiles::generations(profile)?;
            let old: BTreeSet<u64> = gens.iter().rev().skip(keep).map(|g| g.number).filter(|n| Some(*n) != cur).collect();
            profiles::delete_generations(profile, &old, dry_run)
        }
        _ => {
            let numbers = args.iter().map(|a| a.parse().map_err(|_| format!("invalid generation number '{a}'"))).collect::<Result<_, String>>()?;
            profiles::delete_generations(profile, &numbers, dry_run)
        }
    }
}

/// The value of the `-f` expression, auto-called with `--arg`s.
fn top_value(cli: &Cli, ev: &Eval, o: &Opts) -> cranix_eval::R<Value> {
    let v = match &o.file {
        Some(f) => {
            let p = if f.starts_with('/') { f.clone() } else { format!("{}/{f}", cwd()) };
            ev.import(&p)?
        }
        None => ev.eval_string("<nixpkgs>", &cwd()).and_then(|p| match p {
            Value::Path(p) => ev.import(&p),
            v => Ok(v),
        })?,
    };
    auto_call(ev, cli, v)
}

/// The derivations in `v`: `v` itself, the elements of a list, or the
/// attributes of a set, descending into sets with `recurseForDerivations`.
fn derivations(ev: &Eval, v: &Value, prefix: &str, top: bool, out: &mut Vec<Elem>) -> cranix_eval::R<()> {
    let v = ev.force(v)?;
    let join = |k: &str| if prefix.is_empty() { k.to_string() } else { format!("{prefix}.{k}") };
    match &v {
        Value::Attrs(a) if ev.is_derivation(a)? => out.push(elem_of(ev, &v, prefix)?),
        Value::Attrs(a) => {
            let recurse = top || matches!(a.get_str("recurseForDerivations").map(|r| ev.force(r)), Some(Ok(Value::Bool(true))));
            if !recurse {
                return Ok(());
            }
            let mut entries: Vec<_> = a.iter().map(|(k, x)| (k.as_str().to_string(), x.clone())).collect();
            entries.sort_by(|x, y| x.0.cmp(&y.0));
            for (k, x) in entries {
                // Attributes that fail to evaluate are not derivations.
                let Ok(x) = ev.force(&x) else { continue };
                if let Value::Attrs(b) = &x {
                    if ev.is_derivation(b)? {
                        if let Ok(e) = elem_of(ev, &x, &join(&k)) {
                            out.push(e);
                        }
                    } else {
                        derivations(ev, &x, &join(&k), false, out)?;
                    }
                }
            }
        }
        Value::List(l) if top => {
            for (i, x) in l.iter().enumerate() {
                derivations(ev, x, &join(&i.to_string()), false, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn available(cli: &Cli, ev: &Eval, o: &Opts) -> Result<Vec<Elem>, String> {
    let r = top_value(cli, ev, o).and_then(|v| {
        let mut out = Vec::new();
        derivations(ev, &v, "", true, &mut out)?;
        Ok(out)
    });
    r.map_err(|e| render_error(ev, cli, &e))
}

/// The derivations at attribute path `path` of the `-f` expression.
fn by_attr(cli: &Cli, ev: &Eval, o: &Opts, path: &str) -> Result<Vec<Elem>, String> {
    let r = top_value(cli, ev, o).and_then(|mut v| {
        for k in path.split('.').filter(|k| !k.is_empty()) {
            v = match ev.force_attrs(&v)?.get(&Sym::new(k)) {
                Some(x) => auto_call(ev, cli, x.clone())?,
                None => return cranix_eval::eval::err(format!("attribute '{k}' in selection path '{path}' not found")),
            };
        }
        let mut out = Vec::new();
        derivations(ev, &v, path, true, &mut out)?;
        Ok(out)
    });
    r.map_err(|e| render_error(ev, cli, &e))
}

/// An element for a store path given on the command line.
fn elem_of_path(ev: &Eval, arg: &str) -> Result<Elem, String> {
    let (p, _) = ev.store.dir.to_store_path(arg).ok_or_else(|| format!("'{arg}' is not in the Nix store"))?;
    let s = ev.store.dir.print(&p);
    if s.ends_with(".drv") {
        let drv = ev.store.read_derivation(&p)?;
        let outputs: Vec<(String, String)> =
            drv.outputs.iter().filter_map(|(n, o)| Some((n.clone(), ev.store.dir.print(o.path.as_ref()?)))).collect();
        let out_path = outputs.iter().find(|(n, _)| n == "out").or(outputs.first()).map(|(_, p)| p.clone()).unwrap_or_default();
        return Ok(Elem {
            name: drv.name.clone(),
            system: Some(drv.platform.clone()),
            out_path,
            drv_path: Some(s),
            outputs,
            meta: Map::new(),
            attr_path: String::new(),
        });
    }
    Ok(Elem { name: profiles::path_name(&s), system: None, out_path: s.clone(), drv_path: None, outputs: vec![("out".into(), s)], meta: Map::new(), attr_path: String::new() })
}

/// Of the derivations matching each selector, the best one per name: the
/// highest priority, then the newest version.
fn select(avail: &[Elem], selectors: &[String]) -> Result<Vec<Elem>, String> {
    let mut out: Vec<Elem> = Vec::new();
    for s in selectors {
        let sel = DrvName::parse(s);
        let mut best: Vec<Elem> = Vec::new();
        for e in avail.iter().filter(|e| sel.matches(&e.drv_name())) {
            let n = e.drv_name();
            match best.iter_mut().find(|b| b.drv_name().name == n.name) {
                Some(b) => {
                    let better = e.priority() < b.priority()
                        || (e.priority() == b.priority() && compare_versions(&n.version, &b.drv_name().version).is_gt());
                    if better {
                        *b = e.clone();
                    }
                }
                None => best.push(e.clone()),
            }
        }
        if best.is_empty() {
            return Err(format!("selector '{s}' matches no derivations"));
        }
        out.extend(best);
    }
    Ok(out)
}

fn install(cli: &Cli, ev: &Eval, o: &Opts, args: &[String]) -> Result<(), String> {
    let mut new = Vec::new();
    let mut names = Vec::new();
    for a in args {
        if a.starts_with('/') && !o.attr {
            new.push(elem_of_path(ev, a)?);
        } else if o.attr {
            new.extend(by_attr(cli, ev, o, a)?);
        } else {
            names.push(a.clone());
        }
    }
    if !names.is_empty() {
        new.extend(select(&available(cli, ev, o)?, &names)?);
    }
    let new_names: BTreeSet<String> = new.iter().map(|e| e.drv_name().name).collect();
    let mut elems = Vec::new();
    if !o.remove_all {
        for e in installed(ev, &o.profile)? {
            if !o.preserve && new_names.contains(&e.drv_name().name) {
                eprintln!("replacing old '{}'", e.name);
            } else {
                elems.push(e);
            }
        }
    }
    for e in &new {
        eprintln!("installing '{}'", e.name);
    }
    if o.dry_run {
        return Ok(());
    }
    realise(cli, ev, &new)?;
    elems.extend(new);
    create_user_env(cli, ev, &o.profile, &elems)
}

fn upgrade(cli: &Cli, ev: &Eval, o: &Opts, args: &[String]) -> Result<(), String> {
    let sel: Vec<DrvName> = args.iter().map(|s| DrvName::parse(s)).collect();
    let avail = available(cli, ev, o)?;
    let mut elems = installed(ev, &o.profile)?;
    let mut changed = Vec::new();
    for e in elems.iter_mut() {
        let n = e.drv_name();
        if !sel.is_empty() && !sel.iter().any(|s| s.matches(&n)) {
            continue;
        }
        let mut best: Option<&Elem> = None;
        for c in avail.iter().filter(|c| c.drv_name().name == n.name) {
            let cv = c.drv_name().version;
            if !compare_versions(&cv, &n.version).is_gt() {
                continue;
            }
            let better = match best {
                None => true,
                Some(b) => c.priority() < b.priority() || (c.priority() == b.priority() && compare_versions(&cv, &b.drv_name().version).is_gt()),
            };
            if better {
                best = Some(c);
            }
        }
        if let Some(b) = best.filter(|b| b.out_path != e.out_path) {
            eprintln!("upgrading '{}' to '{}'", e.name, b.name);
            *e = b.clone();
            changed.push(b.clone());
        }
    }
    if o.dry_run || changed.is_empty() {
        return Ok(());
    }
    realise(cli, ev, &changed)?;
    create_user_env(cli, ev, &o.profile, &elems)
}

fn query(cli: &Cli, ev: &Eval, o: &Opts, args: &[String]) -> Result<(), String> {
    let mut elems = if o.available { available(cli, ev, o)? } else { installed(ev, &o.profile)? };
    if !args.is_empty() {
        let sel: Vec<DrvName> = args.iter().map(|s| DrvName::parse(s)).collect();
        elems.retain(|e| sel.iter().any(|s| s.matches(&e.drv_name())));
    }
    elems.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.attr_path.cmp(&b.attr_path)));
    let rows: Vec<Vec<String>> = elems
        .iter()
        .map(|e| {
            let mut row = Vec::new();
            if o.attr_path_col {
                row.push(e.attr_path.clone());
            }
            row.push(e.name.clone());
            if o.out_path_col {
                if e.outputs.len() == 1 && e.outputs[0].0 == "out" {
                    row.push(e.outputs[0].1.clone());
                } else {
                    row.push(e.outputs.iter().map(|(n, p)| format!("{n}={p}")).collect::<Vec<_>>().join(";"));
                }
            }
            row
        })
        .collect();
    let ncols = rows.first().map_or(0, Vec::len);
    let widths: Vec<usize> = (0..ncols).map(|c| rows.iter().map(|r| r[c].len()).max().unwrap_or(0)).collect();
    for r in rows {
        let mut line = String::new();
        for (c, cell) in r.iter().enumerate() {
            line.push_str(cell);
            if c + 1 < ncols {
                line.push_str(&" ".repeat(widths[c] - cell.len() + 2));
            }
        }
        println!("{line}");
    }
    Ok(())
}
