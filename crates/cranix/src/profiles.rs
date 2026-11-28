//! Profiles: generations of user environments behind a symlink, with
//! Nix's `profile-N-link` layout, and the user environments themselves,
//! built by `builtin:buildenv`.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use cranix_core::derivation::{Derivation, Output};
use cranix_core::StorePath;
use cranix_eval::Eval;
use cranix_store::Store;

use crate::{build_options, remote, Cli};

/// One `profile-N-link`.
#[derive(Clone, Debug)]
pub struct Generation {
    pub number: u64,
    pub path: PathBuf,
    /// Seconds since the epoch at which the link was made.
    pub created: i64,
}

/// The profile used when none is given: `profiles/profile` in the store's
/// state directory, so that cranix leaves Nix's own profiles alone.
pub fn default_profile(store: &Store) -> PathBuf {
    store.state_dir().join("profiles/profile")
}

/// Makes `p` absolute, keeping its last component a link name.
pub fn absolute(p: &Path) -> Result<PathBuf, String> {
    std::path::absolute(p).map_err(|e| format!("resolving '{}': {e}", p.display()))
}

fn link_name(profile: &Path, n: u64) -> PathBuf {
    let base = profile.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    profile.with_file_name(format!("{base}-{n}-link"))
}

fn parse_number(profile_base: &str, link: &str) -> Option<u64> {
    let n = link.strip_prefix(profile_base)?.strip_prefix('-')?.strip_suffix("-link")?;
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}

/// The generations of `profile`, oldest first.
pub fn generations(profile: &Path) -> Result<Vec<Generation>, String> {
    let dir = profile.parent().unwrap_or(Path::new("/"));
    let base = profile.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(format!("reading '{}': {e}", dir.display())),
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(number) = parse_number(&base, &name) else { continue };
        let path = dir.join(&name);
        let created = fs::symlink_metadata(&path).map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.mtime()
        });
        out.push(Generation { number, path, created: created.unwrap_or(0) });
    }
    out.sort_by_key(|g| g.number);
    Ok(out)
}

/// The number of the generation `profile` points at.
pub fn current(profile: &Path) -> Option<u64> {
    let target = fs::read_link(profile).ok()?;
    let base = profile.file_name()?.to_string_lossy().into_owned();
    parse_number(&base, &target.file_name()?.to_string_lossy())
}

/// Replaces the symlink `link` with one to `target` atomically; targets
/// in the same directory are written relative to it, as Nix does.
fn replace_link(target: &Path, link: &Path) -> Result<(), String> {
    let target = if target.parent() == link.parent() { PathBuf::from(target.file_name().unwrap()) } else { target.to_path_buf() };
    let tmp = link.with_file_name(format!(".{}-tmp-{}", link.file_name().unwrap().to_string_lossy(), std::process::id()));
    let _ = fs::remove_file(&tmp);
    std::os::unix::fs::symlink(&target, &tmp).map_err(|e| format!("creating '{}': {e}", tmp.display()))?;
    fs::rename(&tmp, link).map_err(|e| format!("replacing '{}': {e}", link.display()))
}

/// Makes `out` the newest generation of `profile` (reusing the newest one
/// when it already points there) and switches the profile to it.
pub fn add_generation(roots: &mut Roots<'_>, profile: &Path, out: &str) -> Result<u64, String> {
    if let Some(dir) = profile.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("creating '{}': {e}", dir.display()))?;
    }
    let gens = generations(profile)?;
    let reuse = gens.last().filter(|g| fs::read_link(&g.path).is_ok_and(|t| t == Path::new(out)));
    let number = match reuse {
        Some(g) => g.number,
        None => {
            let n = gens.last().map_or(1, |g| g.number + 1);
            let link = link_name(profile, n);
            std::os::unix::fs::symlink(out, &link).map_err(|e| format!("creating '{}': {e}", link.display()))?;
            roots.add(&link)?;
            n
        }
    };
    replace_link(&link_name(profile, number), profile)?;
    Ok(number)
}

/// Switches `profile` to generation `to`, or to the one before the current
/// one, printing what it does as Nix does.
pub fn switch_generation(profile: &Path, to: Option<u64>, dry_run: bool) -> Result<(), String> {
    let gens = generations(profile)?;
    let cur = current(profile);
    let dst = match to {
        Some(n) => gens.iter().find(|g| g.number == n).ok_or_else(|| format!("generation {n} does not exist"))?,
        None => {
            let cur = cur.ok_or("no generation older than the current one exists")?;
            gens.iter()
                .rev()
                .find(|g| g.number < cur)
                .ok_or_else(|| format!("no generation older than the current ({cur}) exists"))?
        }
    };
    eprintln!("switching profile from version {} to {}", cur.map_or("?".into(), |c| c.to_string()), dst.number);
    if dry_run {
        return Ok(());
    }
    replace_link(&dst.path, profile)
}

fn delete_generation(profile: &Path, g: &Generation, dry_run: bool) -> Result<(), String> {
    if current(profile) == Some(g.number) {
        return Err(format!("cannot delete current version of profile {}'", profile.display()));
    }
    eprintln!("{} profile version {}", if dry_run { "would remove" } else { "removing" }, g.number);
    if !dry_run {
        fs::remove_file(&g.path).map_err(|e| format!("removing '{}': {e}", g.path.display()))?;
    }
    Ok(())
}

/// Deletes the given generations.
pub fn delete_generations(profile: &Path, numbers: &BTreeSet<u64>, dry_run: bool) -> Result<(), String> {
    for g in generations(profile)?.iter().filter(|g| numbers.contains(&g.number)) {
        delete_generation(profile, g, dry_run)?;
    }
    Ok(())
}

/// Deletes every generation but the current one.
pub fn delete_old_generations(profile: &Path, dry_run: bool) -> Result<(), String> {
    let cur = current(profile);
    for g in generations(profile)?.iter().filter(|g| Some(g.number) != cur) {
        delete_generation(profile, g, dry_run)?;
    }
    Ok(())
}

/// Deletes the generations older than `cutoff` (seconds since the epoch),
/// keeping the newest of them, which was active at the cutoff.
pub fn delete_generations_older_than(profile: &Path, cutoff: i64, dry_run: bool) -> Result<(), String> {
    let cur = current(profile);
    let gens = generations(profile)?;
    let mut kept_one = false;
    for g in gens.iter().rev() {
        if g.created >= cutoff {
            continue;
        }
        if !kept_one {
            kept_one = true;
            continue;
        }
        if Some(g.number) != cur {
            delete_generation(profile, g, dry_run)?;
        }
    }
    Ok(())
}

/// Parses `Nd`, the `--older-than` argument, into a cutoff time.
pub fn parse_older_than(s: &str) -> Result<i64, String> {
    let days: i64 = s.strip_suffix('d').and_then(|d| d.parse().ok()).ok_or_else(|| format!("invalid number of days specifier '{s}', expected something like '14d'"))?;
    Ok(now() - days * 24 * 3600)
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// `t` as `YYYY-MM-DD HH:MM:SS`, in local time or UTC.
pub fn format_time(t: i64, local: bool) -> String {
    // SAFETY: localtime_r and gmtime_r only write into `tm`.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let tt = t as libc::time_t;
    unsafe {
        if local {
            libc::localtime_r(&tt, &mut tm);
        } else {
            libc::gmtime_r(&tt, &mut tm);
        }
    }
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)
}

/// Where generation links are registered as GC roots: the local store, or
/// the daemon that `--store` names.
pub struct Roots<'a> {
    store: &'a Store,
    session: Option<remote::Session>,
}

impl<'a> Roots<'a> {
    pub fn add(&mut self, link: &Path) -> Result<(), String> {
        match &mut self.session {
            Some(s) => s.add_indirect_root(link),
            None => self.store.add_indirect_root(link),
        }
    }
}

/// A derivation name split into name and version at the first dash that
/// is not followed by a letter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrvName {
    pub name: String,
    pub version: String,
}

impl DrvName {
    pub fn parse(s: &str) -> DrvName {
        let b = s.as_bytes();
        for i in 0..b.len() {
            if b[i] == b'-' && b.get(i + 1).is_some_and(|c| !c.is_ascii_alphabetic()) {
                return DrvName { name: s[..i].to_string(), version: s[i + 1..].to_string() };
            }
        }
        DrvName { name: s.to_string(), version: String::new() }
    }

    /// Whether `self`, a selector, matches `other`: the name as a regular
    /// expression (or `*`) and the version, when the selector has one.
    pub fn matches(&self, other: &DrvName) -> bool {
        if self.name != "*" {
            let ok = regex::Regex::new(&format!("^(?:{})$", self.name)).map_or(self.name == other.name, |r| r.is_match(&other.name));
            if !ok {
                return false;
            }
        }
        self.version.is_empty() || self.version == other.version
    }
}

fn next_component(s: &str) -> (&str, &str) {
    let s = s.trim_start_matches(|c: char| c == '.' || c == '-');
    let Some(first) = s.chars().next() else { return ("", "") };
    let end = if first.is_ascii_digit() {
        s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len())
    } else {
        s.find(|c: char| c.is_ascii_digit() || c == '.' || c == '-').unwrap_or(s.len())
    };
    (&s[..end], &s[end..])
}

fn component_lt(a: &str, b: &str) -> bool {
    let an = (!a.is_empty() && a.bytes().all(|c| c.is_ascii_digit())).then(|| a.parse::<u128>().unwrap_or(u128::MAX));
    let bn = (!b.is_empty() && b.bytes().all(|c| c.is_ascii_digit())).then(|| b.parse::<u128>().unwrap_or(u128::MAX));
    match (an, bn) {
        (Some(x), Some(y)) => x < y,
        _ if a.is_empty() && bn.is_some() => true,
        _ if a == "pre" && b != "pre" => true,
        _ if b == "pre" => false,
        (_, Some(_)) => true,
        (Some(_), _) => false,
        _ => a < b,
    }
}

/// `builtins.compareVersions`.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a, b);
    while !a.is_empty() || !b.is_empty() {
        let (ca, ra) = next_component(a);
        let (cb, rb) = next_component(b);
        if component_lt(ca, cb) {
            return Ordering::Less;
        }
        if component_lt(cb, ca) {
            return Ordering::Greater;
        }
        a = ra;
        b = rb;
    }
    Ordering::Equal
}

/// The name of a store path without its hash part.
pub fn path_name(p: &str) -> String {
    let base = Path::new(p).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    base.split_once('-').map(|(_, n)| n.to_string()).unwrap_or(base)
}

/// Builds a user environment holding `packages` (store paths with their
/// priorities) and `manifest`, linked under `manifest_name`, and makes it
/// the new generation of `profile`. Returns the environment's path.
pub fn build_user_env(
    cli: &Cli,
    ev: &Eval,
    profile: &Path,
    name: &str,
    packages: &[(Vec<String>, bool, i64)],
    manifest: StorePath,
    manifest_name: Option<&str>,
) -> Result<String, String> {
    let store = &ev.store;
    let mut drv = Derivation { name: name.into(), platform: "builtin".into(), builder: "builtin:buildenv".into(), ..Default::default() };
    let mut groups = Vec::new();
    for (paths, active, priority) in packages {
        groups.push(format!("{active} {priority} {}", paths.len()));
        for p in paths {
            groups.push(p.clone());
            if let Some((sp, _)) = store.dir.to_store_path(p) {
                drv.input_srcs.insert(sp);
            }
        }
    }
    drv.input_srcs.insert(manifest.clone());
    drv.env.insert("allowSubstitutes".into(), String::new());
    drv.env.insert("builder".into(), drv.builder.clone());
    drv.env.insert("derivations".into(), groups.join(" "));
    drv.env.insert("manifest".into(), store.dir.print(&manifest));
    if let Some(m) = manifest_name {
        drv.env.insert("manifestName".into(), m.into());
    }
    drv.env.insert("name".into(), name.into());
    drv.env.insert("preferLocalBuild".into(), "1".into());
    drv.env.insert("system".into(), drv.platform.clone());
    drv.outputs.insert("out".into(), Output::default());
    drv.fill_output_paths(&store.dir, &mut |p| Err(format!("unexpected input derivation '{p}'")))?;
    let drv_path = store.add_text(&format!("{name}.drv"), drv.to_aterm(&store.dir).as_bytes(), &drv.references())?;
    let opts = build_options(cli);
    let (built, session) = match &cli.remote {
        Some(u) => {
            let mut s = remote::Session::open(u)?;
            (s.realise(store, std::slice::from_ref(&drv_path), &opts)?, Some(s))
        }
        None => {
            let mut opts = opts;
            remote::configure_builders(&mut opts, &cli.settings.builders)?;
            (store.realise(std::slice::from_ref(&drv_path), &opts)?, None)
        }
    };
    let out = built.get(&drv_path).and_then(|o| o.get("out")).ok_or("the user environment has no output")?;
    let out = store.dir.print(out);
    let mut roots = Roots { store, session };
    add_generation(&mut roots, profile, &out)?;
    Ok(out)
}

/// Escapes `s` as a Nix string literal.
pub fn nix_string(s: &str) -> String {
    let mut out = String::from("\"");
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '$' if chars.peek() == Some(&'{') => out.push_str("\\$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn is_ident(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|f| f.is_ascii_alphabetic() || f == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '\'' || c == '-')
        && !matches!(s, "if" | "then" | "else" | "assert" | "with" | "let" | "in" | "rec" | "inherit" | "or")
}

/// Prints a JSON value as a Nix expression, in the layout of
/// `printAmbiguous`.
pub fn json_to_nix(v: &serde_json::Value, out: &mut String) {
    use serde_json::Value as J;
    match v {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Number(n) => out.push_str(&n.to_string()),
        J::String(s) => out.push_str(&nix_string(s)),
        J::Array(a) => {
            out.push_str("[ ");
            for x in a {
                json_to_nix(x, out);
                out.push(' ');
            }
            out.push(']');
        }
        J::Object(o) => {
            out.push_str("{ ");
            let sorted: BTreeMap<&String, &J> = o.iter().collect();
            for (k, x) in sorted {
                if is_ident(k) {
                    out.push_str(k);
                } else {
                    out.push_str(&nix_string(k));
                }
                out.push_str(" = ");
                json_to_nix(x, out);
                out.push_str("; ");
            }
            out.push('}');
        }
    }
}

/// A value converted to JSON for storing in a manifest; functions and
/// other values without a JSON form are left out.
pub fn value_to_json(ev: &Eval, v: &cranix_eval::Value, depth: usize) -> cranix_eval::R<Option<serde_json::Value>> {
    use cranix_eval::Value as V;
    use serde_json::Value as J;
    if depth > 16 {
        return Ok(None);
    }
    Ok(Some(match ev.force(v)? {
        V::Null => J::Null,
        V::Bool(b) => J::Bool(b),
        V::Int(i) => J::from(i),
        V::Float(f) => serde_json::Number::from_f64(f).map_or(J::Null, J::Number),
        V::Str(s) => J::String(s.s.clone()),
        V::Path(p) => J::String(p.to_string()),
        V::List(l) => J::Array(l.iter().map(|x| value_to_json(ev, x, depth + 1)).collect::<Result<Vec<_>, _>>()?.into_iter().flatten().collect()),
        V::Attrs(a) => {
            if ev.is_derivation(&a)? {
                return Ok(None);
            }
            let mut m = serde_json::Map::new();
            for (k, x) in a.iter() {
                if let Some(j) = value_to_json(ev, x, depth + 1)? {
                    m.insert(k.as_str().to_string(), j);
                }
            }
            J::Object(m)
        }
        _ => return Ok(None),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drv_names() {
        assert_eq!(DrvName::parse("hello-2.12.1"), DrvName { name: "hello".into(), version: "2.12.1".into() });
        assert_eq!(DrvName::parse("xorg-server-21.1"), DrvName { name: "xorg-server".into(), version: "21.1".into() });
        assert_eq!(DrvName::parse("profile"), DrvName { name: "profile".into(), version: String::new() });
        assert!(DrvName::parse("hello").matches(&DrvName::parse("hello-1.0")));
        assert!(DrvName::parse("hel.*").matches(&DrvName::parse("hello-1.0")));
        assert!(!DrvName::parse("hello-2.0").matches(&DrvName::parse("hello-1.0")));
    }

    #[test]
    fn versions() {
        assert_eq!(compare_versions("1.0", "2.3"), Ordering::Less);
        assert_eq!(compare_versions("2.1", "2.3"), Ordering::Less);
        assert_eq!(compare_versions("2.3", "2.3"), Ordering::Equal);
        assert_eq!(compare_versions("2.5", "2.3"), Ordering::Greater);
        assert_eq!(compare_versions("3.1", "2.3"), Ordering::Greater);
        assert_eq!(compare_versions("2.3.1", "2.3"), Ordering::Greater);
        assert_eq!(compare_versions("2.3.1", "2.3a"), Ordering::Greater);
        assert_eq!(compare_versions("2.3pre1", "2.3"), Ordering::Less);
        assert_eq!(compare_versions("2.3", "2.3pre1"), Ordering::Greater);
        assert_eq!(compare_versions("2.3pre3", "2.3pre12"), Ordering::Less);
        assert_eq!(compare_versions("2.3a", "2.3c"), Ordering::Less);
        assert_eq!(compare_versions("2.3pre1", "2.3c"), Ordering::Less);
    }

    #[test]
    fn generation_links() {
        let d = std::env::temp_dir().join(format!("cranix-gens-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let profile = d.join("p");
        let store = Store::open_at(&d.join("root")).unwrap();
        let mut roots = Roots { store: &store, session: None };
        assert_eq!(add_generation(&mut roots, &profile, "/x/a").unwrap(), 1);
        assert_eq!(add_generation(&mut roots, &profile, "/x/a").unwrap(), 1);
        assert_eq!(add_generation(&mut roots, &profile, "/x/b").unwrap(), 2);
        assert_eq!(fs::read_link(&profile).unwrap(), Path::new("p-2-link"));
        assert_eq!(fs::read_link(d.join("p-1-link")).unwrap(), Path::new("/x/a"));
        switch_generation(&profile, None, false).unwrap();
        assert_eq!(current(&profile), Some(1));
        assert!(switch_generation(&profile, None, false).is_err());
        assert!(delete_generations(&profile, &[1].into(), false).is_err());
        delete_old_generations(&profile, false).unwrap();
        assert_eq!(generations(&profile).unwrap().iter().map(|g| g.number).collect::<Vec<_>>(), [1]);
        assert_eq!(add_generation(&mut roots, &profile, "/x/c").unwrap(), 2);
        fs::remove_dir_all(&d).unwrap();
    }
}
