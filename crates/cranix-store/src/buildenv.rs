//! `builtin:buildenv`: the user environment builder behind `nix-env` and
//! `nix profile`, with Nix's link layout and collision rules.
//!
//! The derivation passes `derivations` as a flat list of
//! `active priority n path1 .. pathn` groups and `manifest` as a store
//! path that is linked into the output as `manifest.nix`, or under the
//! name in `manifestName` when that is set.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use cranix_core::derivation::Derivation;

/// A package directory and its priority; lower numbers win collisions.
#[derive(Clone)]
pub struct Package {
    pub path: String,
    pub active: bool,
    pub priority: i64,
}

/// Parses the `derivations` attribute of a `builtin:buildenv` derivation.
pub fn parse_packages(s: &str) -> Result<Vec<Package>, String> {
    let bad = || format!("malformed 'derivations' attribute of builtin:buildenv: '{s}'");
    let mut it = s.split_whitespace();
    let mut pkgs = Vec::new();
    while let Some(active) = it.next() {
        let priority: i64 = it.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
        let n: usize = it.next().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
        for _ in 0..n {
            let path = it.next().ok_or_else(bad)?;
            pkgs.push(Package { path: path.to_string(), active: active != "false", priority });
        }
    }
    Ok(pkgs)
}

/// Files that stay out of user environments.
fn is_ignored(path: &Path) -> bool {
    let s = path.to_string_lossy();
    ["/propagated-build-inputs", "/nix-support", "/perllocal.pod", "/info/dir", "/log", "/manifest.nix", "/manifest.json"]
        .iter()
        .any(|suffix| s.ends_with(suffix))
}

struct Env {
    priorities: BTreeMap<PathBuf, i64>,
}

impl Env {
    fn link_tree(&mut self, src: &Path, dst: &Path, priority: i64) -> Result<(), String> {
        let mut entries: Vec<_> = fs::read_dir(src)
            .map_err(|e| format!("reading '{}': {e}", src.display()))?
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();
        entries.sort();
        for name in entries {
            if name.as_encoded_bytes().first() == Some(&b'.') {
                continue;
            }
            let src_file = src.join(&name);
            let dst_file = dst.join(&name);
            // Dangling symlinks in packages are skipped.
            let Ok(st) = fs::metadata(&src_file) else { continue };
            if is_ignored(&src_file) {
                continue;
            }
            if st.is_dir() {
                if let Ok(dst_st) = fs::symlink_metadata(&dst_file) {
                    if dst_st.is_dir() {
                        self.link_tree(&src_file, &dst_file, priority)?;
                        continue;
                    }
                    if dst_st.is_symlink() {
                        // Two packages provide this directory: replace the
                        // link by a directory holding links to both.
                        let target = fs::read_link(&dst_file).map_err(|e| format!("reading '{}': {e}", dst_file.display()))?;
                        let target = dst.join(target);
                        if !target.is_dir() {
                            return Err(format!("collision between '{}' and non-directory '{}'", src_file.display(), target.display()));
                        }
                        let prev = self.priorities.get(&dst_file).copied().unwrap_or(priority);
                        fs::remove_file(&dst_file).map_err(|e| format!("removing '{}': {e}", dst_file.display()))?;
                        fs::create_dir(&dst_file).map_err(|e| format!("creating '{}': {e}", dst_file.display()))?;
                        self.link_tree(&target, &dst_file, prev)?;
                        self.link_tree(&src_file, &dst_file, priority)?;
                        continue;
                    }
                }
            } else if let Ok(dst_st) = fs::symlink_metadata(&dst_file) {
                if dst_st.is_symlink() {
                    let prev = self.priorities.get(&dst_file).copied().unwrap_or(priority);
                    if prev == priority {
                        let existing = fs::read_link(&dst_file).unwrap_or_default();
                        return Err(format!(
                            "two packages provide the file '{}' with the same priority {priority}:\n  {}\n  {}\n\
                             give one of them a different priority (e.g. with 'nix-env --set-flag priority N NAME')",
                            dst_file.display(),
                            existing.display(),
                            src_file.display()
                        ));
                    }
                    if prev < priority {
                        continue;
                    }
                    fs::remove_file(&dst_file).map_err(|e| format!("removing '{}': {e}", dst_file.display()))?;
                } else if dst_st.is_dir() {
                    return Err(format!("collision between non-directories '{}' and '{}'", src_file.display(), dst_file.display()));
                }
            }
            symlink(&src_file, &dst_file).map_err(|e| format!("creating '{}': {e}", dst_file.display()))?;
            self.priorities.insert(dst_file, priority);
        }
        Ok(())
    }
}

/// Links the active packages, and the packages they list in
/// `nix-support/propagated-user-env-packages`, into `out`.
pub fn build_env(out: &Path, packages: &[Package]) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| format!("creating '{}': {e}", out.display()))?;
    let mut pkgs: Vec<&Package> = packages.iter().filter(|p| p.active).collect();
    // Higher priorities (lower numbers) first; the sort is stable, so
    // packages of equal priority keep their order.
    pkgs.sort_by_key(|p| p.priority);
    let mut env = Env { priorities: BTreeMap::new() };
    let mut done = BTreeSet::new();
    let mut postponed: Vec<(String, i64)> = Vec::new();
    let mut add = |env: &mut Env, path: &str, priority: i64, postponed: &mut Vec<(String, i64)>| -> Result<(), String> {
        if !done.insert(path.to_string()) {
            return Ok(());
        }
        let dir = Path::new(path);
        if dir.is_dir() {
            env.link_tree(dir, out, priority)?;
        } else {
            // A package that is a single file is linked under its name.
            let name = dir.file_name().ok_or_else(|| format!("bad package path '{path}'"))?;
            let dst = out.join(name);
            if fs::symlink_metadata(&dst).is_err() {
                symlink(dir, &dst).map_err(|e| format!("creating '{}': {e}", dst.display()))?;
            }
        }
        if let Ok(s) = fs::read_to_string(dir.join("nix-support/propagated-user-env-packages")) {
            postponed.extend(s.split_whitespace().map(|p| (p.to_string(), priority + 1)));
        }
        Ok(())
    };
    for p in pkgs {
        add(&mut env, &p.path, p.priority, &mut postponed)?;
    }
    while !postponed.is_empty() {
        for (p, prio) in std::mem::take(&mut postponed) {
            add(&mut env, &p, prio, &mut postponed)?;
        }
    }
    Ok(())
}

/// Runs a `builtin:buildenv` derivation into `out`.
pub fn run(drv: &Derivation, out: &Path) -> Result<(), String> {
    let packages = parse_packages(drv.env.get("derivations").map(String::as_str).unwrap_or(""))?;
    build_env(out, &packages)?;
    if let Some(manifest) = drv.env.get("manifest").filter(|m| !m.is_empty()) {
        let name = drv.env.get("manifestName").map(String::as_str).unwrap_or("manifest.nix");
        let dst = out.join(name);
        symlink(manifest, &dst).map_err(|e| format!("creating '{}': {e}", dst.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cranix-buildenv-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn pkg(root: &Path, name: &str, files: &[&str]) -> String {
        let p = root.join(name);
        for f in files {
            let f = p.join(f);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(&f, name).unwrap();
        }
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn parses_groups() {
        let p = parse_packages("true 5 1 /s/a false 3 2 /s/b /s/c").unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!((p[1].path.as_str(), p[1].active, p[1].priority), ("/s/b", false, 3));
        assert!(parse_packages("true 5 2 /s/a").is_err());
    }

    #[test]
    fn merges_directories_and_resolves_priorities() {
        let d = tmp("merge");
        let a = pkg(&d, "a", &["bin/a", "bin/same", "share/x/a"]);
        let b = pkg(&d, "b", &["bin/b", "bin/same", "nix-support/propagated-build-inputs"]);
        let out = d.join("out");
        build_env(&out, &[
            Package { path: a.clone(), active: true, priority: 5 },
            Package { path: b.clone(), active: true, priority: 4 },
        ])
        .unwrap();
        assert!(fs::symlink_metadata(out.join("bin")).unwrap().is_dir());
        assert_eq!(fs::read_link(out.join("bin/same")).unwrap(), Path::new(&b).join("bin/same"));
        assert_eq!(fs::read_link(out.join("bin/a")).unwrap(), Path::new(&a).join("bin/a"));
        assert_eq!(fs::read_link(out.join("share")).unwrap(), Path::new(&a).join("share"));
        assert!(fs::symlink_metadata(out.join("nix-support")).is_err());

        let out2 = d.join("out2");
        let err = build_env(&out2, &[
            Package { path: a, active: true, priority: 5 },
            Package { path: b, active: true, priority: 5 },
        ]);
        assert!(err.unwrap_err().contains("same priority"));
        fs::remove_dir_all(&d).unwrap();
    }
}
