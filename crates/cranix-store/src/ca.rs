//! Building content-addressed floating, impure and deferred derivations:
//! resolving their inputs, moving outputs from scratch paths to their
//! content-addressed paths, and recording realisations.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use cranix_core::hash::{Hash, HashAlgo, HashSink};
use cranix_core::store_path::output_path_name;
use cranix_core::{nar, Derivation, FileIngestion, StorePath};

use crate::build::{BuildOptions, Built};
use crate::realisation::{DrvOutput, Realisation};
use crate::{canonicalise, fsutil, refs, PathInfo, Result, Store};

impl Store {
    /// The path an output with an unknown final path is built at, the same
    /// as Nix's so that builds see identical strings.
    pub(crate) fn scratch_path(&self, drv_path: &StorePath, drv: &Derivation, output: &str) -> Result<StorePath> {
        let ty = format!("rewrite:{}:name:{output}", drv_path.base_name());
        self.dir.make_store_path(&ty, &Hash::from_bytes(HashAlgo::Sha256, &[0; 32]), &output_path_name(&drv.name, output))
    }

    /// The output paths of `drv`: static ones, or those of its realisations.
    pub(crate) fn output_paths(&self, drv_path: &StorePath, drv: &Derivation) -> Result<BTreeMap<String, StorePath>> {
        let mut out = BTreeMap::new();
        for (name, o) in &drv.outputs {
            let p = match &o.path {
                Some(p) => p.clone(),
                None => match self.query_output_realisation(drv, name)? {
                    Some(r) => r.out_path,
                    None => return Err(format!("output '{name}' of '{}' is not realised", self.dir.print(drv_path))),
                },
            };
            out.insert(name.clone(), p);
        }
        Ok(out)
    }

    /// Builds the resolved form of `drv` (unless its outputs are already
    /// known) and records realisations of `drv`'s own outputs. Reports the
    /// resolution like Nix, and the build only if a builder runs.
    pub(crate) fn build_resolved(
        &self,
        drv_path: &StorePath,
        drv: &Derivation,
        all: &HashMap<StorePath, Derivation>,
        opts: &BuildOptions,
        built: &Built,
        progress: &str,
    ) -> Result<BTreeMap<String, StorePath>> {
        let mut input_paths = BTreeMap::new();
        let mut input_realisations = Vec::new();
        for (d, outs) in &drv.input_drvs {
            let dd = match all.get(d) {
                Some(dd) => dd.clone(),
                None => self.read_derivation(d)?,
            };
            if dd.is_impure() && !drv.is_impure() {
                return Err(format!(
                    "pure derivation '{}' depends on impure derivation '{}'",
                    self.dir.print(drv_path),
                    self.dir.print(d)
                ));
            }
            let done = built.lock().unwrap().get(d).cloned();
            for o in outs {
                let realisation = if dd.is_impure() { None } else { self.query_output_realisation(&dd, o)? };
                let p = match (done.as_ref().and_then(|m| m.get(o)), &dd.outputs.get(o).and_then(|x| x.path.clone()), &realisation) {
                    (Some(p), _, _) | (None, Some(p), _) => p.clone(),
                    (None, None, Some(r)) => r.out_path.clone(),
                    (None, None, None) => {
                        return Err(format!("output '{o}' of input '{}' is not realised", self.dir.print(d)));
                    }
                };
                input_realisations.extend(realisation);
                input_paths.insert((d.clone(), o.clone()), p);
            }
        }

        let resolved = drv.resolve(&self.dir, &input_paths)?;
        let text = resolved.to_aterm(&self.dir);
        let resolved_path = self.add_text(&format!("{}.drv", drv.name), text.as_bytes(), &resolved.references())?;
        eprintln!("resolved derivation: '{}' -> '{}'", self.dir.print(drv_path), self.dir.print(&resolved_path));
        let outputs = if self.missing_outputs(&resolved)? {
            self.build_derivation(&resolved_path, &resolved, all, opts, progress)?
        } else {
            self.output_paths(&resolved_path, &resolved)?
        };

        if !drv.is_impure() {
            let h = self.static_output_hash(drv)?;
            let inputs = self.realisation_closure(input_realisations)?;
            for (name, p) in &outputs {
                let mut r = Realisation::new(DrvOutput { drv_hash: h.clone(), output: name.clone() }, p.clone());
                let refs = self.query_info(p)?.map(|i| i.references).unwrap_or_default();
                r.dependent_realisations = inputs.iter().filter(|(_, q)| refs.contains(q)).map(|(k, q)| (k.clone(), q.clone())).collect();
                self.register_realisation(&r)?;
            }
        }
        Ok(outputs)
    }

    /// Registers outputs built at scratch paths under their
    /// content-addressed paths. References to the scratch paths of this
    /// derivation's outputs are rewritten to the final paths, in dependency
    /// order so each output's hash already covers the final paths of the
    /// outputs it refers to; self-references are hashed as zeros.
    pub(crate) fn register_floating(
        &self,
        drv_path: &StorePath,
        drv: &Derivation,
        outputs: &[(&String, StorePath)],
        candidates: &BTreeSet<StorePath>,
    ) -> Result<BTreeMap<String, StorePath>> {
        let mut refs_of: BTreeMap<String, BTreeSet<StorePath>> = BTreeMap::new();
        for (name, scratch) in outputs {
            let real = self.real_path(scratch);
            if real.symlink_metadata().is_err() {
                return Err(format!(
                    "builder for '{}' failed to produce output '{name}' at '{}'",
                    self.dir.print(drv_path),
                    self.dir.print(scratch)
                ));
            }
            canonicalise(&real)?;
            let found = refs::scan_path(&real, candidates).map_err(|e| format!("scanning references: {e}"))?;
            refs_of.insert((*name).clone(), found);
        }
        let scratch_of: BTreeMap<&str, &StorePath> = outputs.iter().map(|(n, p)| (n.as_str(), p)).collect();
        let order = topo_order(&refs_of, &scratch_of).map_err(|cycle| {
            format!("cycle detected in the references of '{}' from output '{cycle}'", self.dir.print(drv_path))
        })?;

        let mut rewrites: BTreeMap<String, String> = BTreeMap::new();
        let mut result = BTreeMap::new();
        for name in order {
            let scratch = scratch_of[name.as_str()];
            let real = self.real_path(scratch);
            let (method, algo) = drv.outputs[&name].method_algo().ok_or_else(|| format!("output '{name}' has an invalid hash algorithm"))?;
            if method.ingestion() == FileIngestion::Flat {
                let md = fs::symlink_metadata(&real).map_err(|e| e.to_string())?;
                if !md.is_file() || md.permissions().mode() & 0o100 != 0 {
                    return Err(format!(
                        "output path '{}' should be a non-executable regular file since recursive hashing is not enabled (one of outputHashMode or the method is 'flat')",
                        self.dir.print(scratch)
                    ));
                }
            }
            if !rewrites.is_empty() {
                self.rewrite_path(&real, &rewrites)?;
            }
            let old = scratch.hash_part().to_string();
            let hash = hash_modulo(&real, method.ingestion(), algo, &old)?;
            let mut self_ref = false;
            let mut others = BTreeSet::new();
            for r in &refs_of[&name] {
                if r == scratch {
                    self_ref = true;
                } else if let Some(h) = rewrites.get(r.hash_part()) {
                    others.insert(StorePath::from_base_name(&format!("{h}-{}", r.name()))?);
                } else {
                    others.insert(r.clone());
                }
            }
            let path_name = output_path_name(&drv.name, &name);
            let fin = method
                .make_path(&self.dir, &hash, &path_name, &others, self_ref)
                .map_err(|e| format!("output '{name}' of '{}': {e}", self.dir.print(drv_path)))?;
            if &fin != scratch {
                if self_ref {
                    self.rewrite_path(&real, &[(old.clone(), fin.hash_part().to_string())].into())?;
                }
                let dest = self.real_path(&fin);
                if self.is_valid(&fin) {
                    fsutil::remove_all(&real)?;
                } else {
                    fsutil::remove_all(&dest)?;
                    // macOS only renames directories whose `..` entry it may update.
                    if real.is_dir() && !real.is_symlink() {
                        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
                    }
                    fs::rename(&real, &dest).map_err(|e| format!("moving output to '{}': {e}", dest.display()))?;
                }
            }
            rewrites.insert(old, fin.hash_part().to_string());
            if !self.is_valid(&fin) {
                let dest = self.real_path(&fin);
                canonicalise(&dest)?;
                let (nar_hash, nar_size) = Store::nar_hash(&dest)?;
                let mut references = others;
                if self_ref {
                    references.insert(fin.clone());
                }
                let ca = Some(method.content_address(&hash));
                self.register(&PathInfo { path: fin.clone(), nar_hash, nar_size, references, deriver: Some(drv_path.clone()), ca })?;
            }
            result.insert(name, fin);
        }
        Ok(result)
    }

    /// Replaces the given equal-length strings throughout the file system
    /// object at `real` (contents, names and symlink targets).
    fn rewrite_path(&self, real: &Path, rewrites: &BTreeMap<String, String>) -> Result<()> {
        let tmp = real.with_extension(format!("rewrite-{}", std::process::id()));
        {
            let f = fs::File::create(&tmp).map_err(|e| format!("creating '{}': {e}", tmp.display()))?;
            let mut w = RewritingWriter::new(rewrites, io::BufWriter::new(f));
            nar::dump(real, &mut w).and_then(|_| w.finish()).map_err(|e| format!("rewriting '{}': {e}", real.display()))?;
        }
        fsutil::remove_all(real)?;
        let r = fs::File::open(&tmp)
            .and_then(|f| nar::restore(io::BufReader::new(f), real))
            .map_err(|e| format!("rewriting '{}': {e}", real.display()));
        let _ = fs::remove_file(&tmp);
        r?;
        canonicalise(real)
    }
}

/// Orders outputs so every output comes after the outputs it refers to.
/// Fails with an output on a reference cycle.
fn topo_order(refs: &BTreeMap<String, BTreeSet<StorePath>>, scratch: &BTreeMap<&str, &StorePath>) -> std::result::Result<Vec<String>, String> {
    fn visit(
        n: &str,
        refs: &BTreeMap<String, BTreeSet<StorePath>>,
        scratch: &BTreeMap<&str, &StorePath>,
        state: &mut BTreeMap<String, bool>,
        out: &mut Vec<String>,
    ) -> std::result::Result<(), String> {
        match state.get(n) {
            Some(true) => return Ok(()),
            Some(false) => return Err(n.to_string()),
            None => {}
        }
        state.insert(n.to_string(), false);
        for (m, p) in scratch {
            if *m != n && refs[n].contains(*p) {
                visit(m, refs, scratch, state, out)?;
            }
        }
        state.insert(n.to_string(), true);
        out.push(n.to_string());
        Ok(())
    }
    let mut state = BTreeMap::new();
    let mut out = Vec::new();
    for n in refs.keys() {
        visit(n, refs, scratch, &mut state, &mut out)?;
    }
    Ok(out)
}

/// The content hash of `real` with occurrences of `modulus` (the scratch
/// hash part) replaced by NUL bytes, so that it does not depend on where
/// the output was built.
fn hash_modulo(real: &Path, method: FileIngestion, algo: HashAlgo, modulus: &str) -> Result<Hash> {
    let zeros = "\0".repeat(modulus.len());
    let rewrites = [(modulus.to_string(), zeros)].into();
    let mut w = RewritingWriter::new(&rewrites, HashSink::new(algo));
    let r = match method {
        FileIngestion::Recursive => nar::dump(real, &mut w),
        FileIngestion::Flat => fs::read(real).and_then(|d| w.write_all(&d)),
    };
    r.and_then(|_| w.flush_carry()).map_err(|e| format!("hashing '{}': {e}", real.display()))?;
    Ok(w.inner.finish().0)
}

/// A writer that replaces equal-length strings in the stream, keeping back
/// enough bytes to catch matches split across writes.
struct RewritingWriter<'a, W: Write> {
    rewrites: &'a BTreeMap<String, String>,
    keep: usize,
    carry: Vec<u8>,
    inner: W,
}

impl<'a, W: Write> RewritingWriter<'a, W> {
    fn new(rewrites: &'a BTreeMap<String, String>, inner: W) -> Self {
        let keep = rewrites.keys().map(String::len).max().unwrap_or(1).saturating_sub(1);
        RewritingWriter { rewrites, keep, carry: Vec::new(), inner }
    }

    fn flush_carry(&mut self) -> io::Result<()> {
        let c = std::mem::take(&mut self.carry);
        self.inner.write_all(&c)
    }

    fn finish(mut self) -> io::Result<()> {
        self.flush_carry()?;
        self.inner.flush()
    }
}

fn replace_all(buf: &mut [u8], from: &[u8], to: &[u8]) {
    let mut i = 0;
    while i + from.len() <= buf.len() {
        if &buf[i..i + from.len()] == from {
            buf[i..i + from.len()].copy_from_slice(to);
            i += from.len();
        } else {
            i += 1;
        }
    }
}

impl<W: Write> Write for RewritingWriter<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(data);
        for (from, to) in self.rewrites {
            replace_all(&mut buf, from.as_bytes(), to.as_bytes());
        }
        let emit = buf.len().saturating_sub(self.keep);
        self.inner.write_all(&buf[..emit])?;
        self.carry = buf[emit..].to_vec();
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_across_writes() {
        let rewrites = [("abcd".to_string(), "wxyz".to_string())].into();
        let mut out = Vec::new();
        let mut w = RewritingWriter::new(&rewrites, &mut out);
        w.write_all(b"xxab").unwrap();
        w.write_all(b"cdyyabcd").unwrap();
        w.finish().unwrap();
        assert_eq!(out, b"xxwxyzyywxyz");
    }
}
