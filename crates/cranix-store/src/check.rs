//! Reproducibility checks: rebuilding a derivation whose outputs are
//! present and comparing the result with the registered outputs, as
//! `nix build --rebuild` does.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cranix_core::StorePath;

use crate::build::{Activity, BuildLog, BuildOptions};
use crate::nar_import::PathLock;
use crate::{canonicalise, fsutil, Result, Store};

/// An output whose rebuild differs from the registered one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputDiff {
    pub output: String,
    pub path: StorePath,
    /// One line per differing file, relative to the output.
    pub differences: Vec<String>,
    /// Where the rebuilt output was kept (`<path>.check`) with
    /// `keep-failed`.
    pub kept: Option<PathBuf>,
}

impl Store {
    /// Rebuilds `drv_path`, whose outputs must all be valid, and compares
    /// each rebuilt output with the registered one. The registered outputs
    /// stay in place and are returned to their paths whatever the outcome.
    /// Returns the outputs that differ.
    pub fn check_derivation(&self, drv_path: &StorePath, opts: &BuildOptions) -> Result<Vec<OutputDiff>> {
        let drv = self.read_derivation(drv_path)?;
        let drv_s = self.dir.print(drv_path);
        if drv.has_unknown_outputs() {
            return Err(format!("cannot check '{drv_s}': the paths of its outputs depend on their contents"));
        }
        let mut outputs: Vec<(&String, StorePath)> = Vec::new();
        for (n, o) in &drv.outputs {
            let p = o.path.clone().ok_or_else(|| format!("output '{n}' of '{drv_s}' has no path"))?;
            if !self.is_valid(&p) {
                return Err(format!("cannot check '{drv_s}': its output '{n}' is not valid; build it first"));
            }
            outputs.push((n, p));
        }
        if !self.can_build() {
            return Err(format!("cannot check '{drv_s}': this store cannot build"));
        }
        let mut keys: Vec<String> = outputs.iter().map(|(_, p)| format!("build:{}", self.real_path(p).display())).collect();
        keys.sort();
        let _locks: Vec<PathLock> = keys.into_iter().map(PathLock::take).collect();

        let inputs = self.input_closure(&drv, &HashMap::new())?;
        let mut opts = opts.clone();
        opts.upload = None;
        opts.hook = None;
        let log = BuildLog::start(&opts, &drv_s, &drv.name, &format!("checking outputs of '{drv_s}'"));
        let _activity = Activity(&log);

        // The registered outputs wait beside their paths during the rebuild.
        let aside: Vec<(PathBuf, PathBuf)> = outputs
            .iter()
            .map(|(_, p)| {
                let real = self.real_path(p);
                let orig = suffixed(&real, ".check-orig");
                (real, orig)
            })
            .collect();
        for (real, orig) in &aside {
            fsutil::remove_all(orig)?;
            move_object(real, orig).map_err(|e| format!("moving '{}' aside: {e}", real.display()))?;
        }
        let restore = || -> Result<()> {
            for (real, orig) in &aside {
                fsutil::remove_all(real)?;
                move_object(orig, real).map_err(|e| format!("restoring '{}': {e}", real.display()))?;
            }
            Ok(())
        };

        let rewrites: BTreeMap<String, String> = outputs
            .iter()
            .map(|(n, p)| (cranix_core::derivation::hash_placeholder(n), self.dir.print(p)))
            .collect();
        let built = if drv.builder.starts_with("builtin:") {
            match drv.builder.as_str() {
                "builtin:fetchurl" => self.builtin_fetchurl(&drv, &outputs[0].1, &log),
                "builtin:buildenv" => crate::buildenv::run(&drv, &self.real_path(&outputs[0].1)),
                b => Err(format!("unsupported builtin builder '{b}'")),
            }
        } else {
            let outs: Vec<&StorePath> = outputs.iter().map(|(_, p)| p).collect();
            self.run_builder(drv_path, &drv, &inputs, &outs, &opts, &log, &rewrites)
        };
        let compared = built.and_then(|()| {
            let mut diffs = Vec::new();
            for ((name, p), (real, orig)) in outputs.iter().zip(&aside) {
                if real.symlink_metadata().is_err() {
                    return Err(format!("the rebuild of '{drv_s}' did not produce output '{name}'"));
                }
                canonicalise(real)?;
                let want = self.query_info(p)?.map(|i| i.nar_hash);
                let (got, _) = Store::nar_hash(real)?;
                if want.as_ref() == Some(&got) {
                    continue;
                }
                let mut differences = Vec::new();
                compare_trees(orig, real, Path::new(""), &mut differences)?;
                if differences.is_empty() {
                    differences.push("the NAR hashes differ".into());
                }
                let kept = if opts.keep_failed {
                    let dest = suffixed(real, ".check");
                    fsutil::remove_all(&dest)?;
                    move_object(real, &dest).map_err(|e| format!("keeping '{}': {e}", dest.display()))?;
                    Some(dest)
                } else {
                    None
                };
                diffs.push(OutputDiff { output: (*name).clone(), path: p.clone(), differences, kept });
            }
            Ok(diffs)
        });
        let restored = restore();
        let diffs = compared?;
        restored?;
        Ok(diffs)
    }
}

/// Renames a canonical store object. A directory is writable while it
/// moves, since renaming one updates its `..` entry.
fn move_object(from: &Path, to: &Path) -> Result<()> {
    let md = fs::symlink_metadata(from).map_err(|e| e.to_string())?;
    if md.is_dir() {
        fs::set_permissions(from, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    let moved = fs::rename(from, to).map_err(|e| e.to_string());
    canonicalise(if moved.is_ok() { to } else { from })?;
    moved
}

fn suffixed(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn show(rel: &Path) -> String {
    if rel.as_os_str().is_empty() {
        "(the output itself)".into()
    } else {
        rel.display().to_string()
    }
}

/// Appends a line to `out` for each path under `a` and `b` that differs,
/// in sorted order; text files also show their first differing line.
fn err(p: &Path) -> impl Fn(std::io::Error) -> String + '_ {
    move |e| format!("reading '{}': {e}", p.display())
}

fn compare_trees(a: &Path, b: &Path, rel: &Path, out: &mut Vec<String>) -> Result<()> {
    let ma = fs::symlink_metadata(a).map_err(err(a))?;
    let mb = fs::symlink_metadata(b).map_err(err(b))?;
    let kind = |m: &fs::Metadata| {
        if m.is_dir() {
            "directory"
        } else if m.file_type().is_symlink() {
            "symlink"
        } else {
            "file"
        }
    };
    if kind(&ma) != kind(&mb) {
        out.push(format!("{}: a {} in the existing output, a {} in the rebuild", show(rel), kind(&ma), kind(&mb)));
        return Ok(());
    }
    if ma.is_dir() {
        let names = |p: &Path| -> Result<BTreeSet<std::ffi::OsString>> {
            fs::read_dir(p).map_err(err(p))?.map(|e| e.map(|e| e.file_name()).map_err(err(p))).collect()
        };
        let (na, nb) = (names(a)?, names(b)?);
        for n in na.union(&nb) {
            let r = rel.join(n);
            match (na.contains(n), nb.contains(n)) {
                (true, false) => out.push(format!("{}: only in the existing output", show(&r))),
                (false, true) => out.push(format!("{}: only in the rebuild", show(&r))),
                _ => compare_trees(&a.join(n), &b.join(n), &r, out)?,
            }
        }
    } else if ma.file_type().is_symlink() {
        let (ta, tb) = (fs::read_link(a).map_err(err(a))?, fs::read_link(b).map_err(err(b))?);
        if ta != tb {
            out.push(format!("{}: symlink target '{}' became '{}'", show(rel), ta.display(), tb.display()));
        }
    } else {
        let exec = |m: &fs::Metadata| m.permissions().mode() & 0o100 != 0;
        if exec(&ma) != exec(&mb) {
            out.push(format!("{}: the executable bit differs", show(rel)));
        }
        let (da, db) = (fs::read(a).map_err(err(a))?, fs::read(b).map_err(err(b))?);
        if da != db {
            out.push(format!("{}: contents differ{}", show(rel), first_line_diff(&da, &db)));
        }
    }
    Ok(())
}

/// For two texts: the first line where they differ, as `-`/`+` lines.
fn first_line_diff(a: &[u8], b: &[u8]) -> String {
    let (Ok(a), Ok(b)) = (std::str::from_utf8(a), std::str::from_utf8(b)) else {
        return format!(" ({} and {} bytes)", a.len(), b.len());
    };
    let (mut la, mut lb) = (a.lines(), b.lines());
    for n in 1.. {
        match (la.next(), lb.next()) {
            (Some(x), Some(y)) if x == y => continue,
            (None, None) => return String::new(),
            (x, y) => {
                let mut s = format!(" at line {n}");
                if let Some(x) = x {
                    s.push_str(&format!("\n    - {}", clip(x)));
                }
                if let Some(y) = y {
                    s.push_str(&format!("\n    + {}", clip(y)));
                }
                return s;
            }
        }
    }
    unreachable!()
}

fn clip(s: &str) -> String {
    if s.chars().count() > 200 {
        s.chars().take(200).collect::<String>() + "..."
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_differing_files() {
        let t = std::env::temp_dir().join(format!("cranix-check-test-{}", std::process::id()));
        let _ = fsutil::remove_all(&t);
        let (a, b) = (t.join("a"), t.join("b"));
        for d in [&a, &b] {
            fs::create_dir_all(d.join("share")).unwrap();
            fs::write(d.join("share/same"), "x\n").unwrap();
        }
        fs::write(a.join("share/stamp"), "built\nMon\n").unwrap();
        fs::write(b.join("share/stamp"), "built\nTue\n").unwrap();
        fs::write(a.join("old"), "").unwrap();
        fs::write(b.join("new"), "").unwrap();
        let mut out = Vec::new();
        compare_trees(&a, &b, Path::new(""), &mut out).unwrap();
        assert_eq!(
            out,
            [
                "new: only in the rebuild",
                "old: only in the existing output",
                "share/stamp: contents differ at line 2\n    - Mon\n    + Tue",
            ]
        );
        let mut out = Vec::new();
        compare_trees(&a.join("share/same"), &b.join("share/same"), Path::new(""), &mut out).unwrap();
        assert!(out.is_empty());
        fsutil::remove_all(&t).unwrap();
    }
}
