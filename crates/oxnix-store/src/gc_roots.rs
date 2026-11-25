//! Garbage collection as the daemon requests it: honouring temporary roots
//! held by clients and offering the `GCAction` modes of Nix.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use oxnix_core::StorePath;

use crate::{flock, fsutil, Result, Store};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcAction {
    ReturnLive,
    ReturnDead,
    DeleteDead,
    /// Deletes only the requested paths, which must be dead.
    DeleteSpecific,
}

impl Store {
    /// Every GC root symlink and the store path it keeps alive.
    pub fn list_roots(&self) -> Result<Vec<(PathBuf, StorePath)>> {
        let mut out = Vec::new();
        for e in fs::read_dir(self.state.join("gcroots")).map_err(|e| format!("listing GC roots: {e}"))? {
            let e = e.map_err(|e| format!("listing GC roots: {e}"))?;
            let mut link = e.path();
            let mut target = link.clone();
            // Indirect roots point at a symlink that points into the store.
            for _ in 0..2 {
                match fs::read_link(&target) {
                    Ok(t) => {
                        link = target;
                        target = t;
                    }
                    Err(_) => break,
                }
            }
            if let Some((p, _)) = self.dir.to_store_path(&target.to_string_lossy()) {
                out.push((link, p));
            }
        }
        Ok(out)
    }

    /// Runs the collector with `extra_roots` (e.g. temporary roots of
    /// daemon clients) counted as live. Returns the affected paths and the
    /// bytes freed. Deletion stops once `max_freed` bytes are freed.
    pub fn collect_garbage_with(
        &self,
        action: GcAction,
        specific: &BTreeSet<StorePath>,
        extra_roots: &BTreeSet<StorePath>,
        max_freed: u64,
    ) -> Result<(Vec<StorePath>, u64)> {
        let deleting = matches!(action, GcAction::DeleteDead | GcAction::DeleteSpecific);
        if deleting {
            flock(&self.lock, libc::LOCK_EX | libc::LOCK_NB)
                .map_err(|_| "another oxnix process is using the store; run garbage collection when it has finished".to_string())?;
        }
        let r = self.gc_locked(action, specific, extra_roots, max_freed);
        if deleting {
            flock(&self.lock, libc::LOCK_SH).map_err(|e| format!("locking the store: {e}"))?;
        }
        r
    }

    fn gc_locked(
        &self,
        action: GcAction,
        specific: &BTreeSet<StorePath>,
        extra_roots: &BTreeSet<StorePath>,
        max_freed: u64,
    ) -> Result<(Vec<StorePath>, u64)> {
        let mut roots = self.roots()?;
        roots.extend(extra_roots.iter().cloned());
        let live = self.closure(roots)?;
        let valid = self.valid_paths()?;
        if action == GcAction::ReturnLive {
            return Ok((valid.into_iter().filter(|p| live.contains(p)).collect(), 0));
        }
        let candidates: Vec<StorePath> = match action {
            GcAction::DeleteSpecific => {
                for p in specific {
                    if live.contains(p) {
                        return Err(format!("cannot delete path '{}' since it is still alive", self.dir.print(p)));
                    }
                }
                // A path stays alive while a valid path outside the request
                // still refers to it.
                for q in &valid {
                    if specific.contains(q) {
                        continue;
                    }
                    if let Some(info) = self.query_info(q)? {
                        if let Some(p) = info.references.iter().find(|r| specific.contains(*r)) {
                            return Err(format!(
                                "cannot delete path '{}' since it is still referenced by '{}'",
                                self.dir.print(p),
                                self.dir.print(q)
                            ));
                        }
                    }
                }
                valid.into_iter().filter(|p| specific.contains(p)).collect()
            }
            _ => valid.into_iter().filter(|p| !live.contains(p)).collect(),
        };
        let limit = if max_freed == 0 { u64::MAX } else { max_freed };
        let mut out = Vec::new();
        let mut freed = 0;
        for p in candidates {
            if action != GcAction::ReturnDead && freed >= limit {
                break;
            }
            if let Some(info) = self.query_info(&p)? {
                freed += info.nar_size;
            }
            if action != GcAction::ReturnDead {
                fs::remove_file(self.info_file(&p)).map_err(|e| format!("unregistering path: {e}"))?;
                fsutil::remove_all(&self.real_path(&p))?;
            }
            out.push(p);
        }
        if action == GcAction::ReturnDead {
            freed = 0;
        }
        Ok((out, freed))
    }
}
