//! Adding store objects received as NAR streams (from a daemon client, a
//! remote builder or another store), with their metadata supplied by the
//! sender.

use std::collections::BTreeSet;
use std::io::{self, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

use cranix_core::hash::{Hash, HashAlgo, Hasher};
use cranix_core::{nar, FileIngestion, StorePath};

use crate::{canonicalise, fsutil, PathInfo, Result, Store};

/// Keys (paths being imported or built) held by some thread of this
/// process; a second holder of the same key waits for the first one.
static BUSY: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
static BUSY_CV: Condvar = Condvar::new();

pub(crate) struct PathLock(String);

impl PathLock {
    pub(crate) fn take(key: String) -> PathLock {
        let mut g = BUSY.lock().unwrap();
        while g.contains(&key) {
            g = BUSY_CV.wait(g).unwrap();
        }
        g.insert(key.clone());
        PathLock(key)
    }
}

impl Drop for PathLock {
    fn drop(&mut self) {
        BUSY.lock().unwrap().remove(&self.0);
        BUSY_CV.notify_all();
    }
}

struct Hashing<R> {
    inner: R,
    hasher: Hasher,
    size: u64,
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.size += n as u64;
        Ok(n)
    }
}

impl Store {
    /// Unpacks `nar` as `info.path` and registers it with `info`, failing
    /// when the stream's hash or size differ from the declared ones. The
    /// stream is read to its end even when the path is already valid.
    pub fn import_nar(&self, info: &PathInfo, nar: impl Read) -> Result<()> {
        let _lock = PathLock::take(self.real_path(&info.path).to_string_lossy().into_owned());
        let mut src = Hashing { inner: nar, hasher: Hasher::new(HashAlgo::Sha256), size: 0 };
        if self.is_valid(&info.path) {
            io::copy(&mut src, &mut io::sink()).map_err(|e| format!("receiving '{}': {e}", info.path))?;
            return Ok(());
        }
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let real = self.real_path(&info.path);
        let tmp = self.real.join(format!(
            ".tmp-import-{}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            info.path.hash_part()
        ));
        fsutil::remove_all(&tmp)?;
        let unpacked = nar::restore(&mut src, &tmp).and_then(|()| io::copy(&mut src, &mut io::sink()).map(|_| ()));
        if let Err(e) = unpacked {
            let _ = fsutil::remove_all(&tmp);
            return Err(format!("unpacking NAR of '{}': {e}", self.dir.print(&info.path)));
        }
        let got = src.hasher.finish();
        if got != info.nar_hash || src.size != info.nar_size {
            fsutil::remove_all(&tmp)?;
            return Err(format!(
                "hash mismatch importing path '{}';\n  specified: {} ({} bytes)\n  got:       {} ({} bytes)",
                self.dir.print(&info.path),
                info.nar_hash.to_sri(),
                info.nar_size,
                got.to_sri(),
                src.size
            ));
        }
        fsutil::remove_all(&real)?;
        std::fs::rename(&tmp, &real).map_err(|e| format!("moving into store: {e}"))?;
        canonicalise(&real)?;
        self.register(info)
    }

    /// Checks that a content-addressed path's name follows from its `CA`
    /// field and contents; paths without one are reported as unverifiable.
    pub fn check_content_address(&self, info: &PathInfo) -> Result<()> {
        let ca = info.ca.as_deref().ok_or_else(|| format!("path '{}' is not content-addressed", self.dir.print(&info.path)))?;
        let real = self.real_path(&info.path);
        let parse = |s: &str| Hash::parse(s, None);
        let expected = if let Some(h) = ca.strip_prefix("text:") {
            let h = parse(h)?;
            let data = std::fs::read(&real).map_err(|e| format!("reading '{}': {e}", real.display()))?;
            if Hash::digest(h.algo, &data) != h {
                return Err(format!("content of '{}' does not match its content address", self.dir.print(&info.path)));
            }
            self.dir.make_text_path(info.path.name(), &h, &info.references)?
        } else if let Some(rest) = ca.strip_prefix("fixed:") {
            let (method, h) = match rest.strip_prefix("r:") {
                Some(h) => (FileIngestion::Recursive, parse(h)?),
                None => (FileIngestion::Flat, parse(rest)?),
            };
            let got = match method {
                FileIngestion::Flat => Hash::digest(h.algo, &std::fs::read(&real).map_err(|e| format!("reading '{}': {e}", real.display()))?),
                FileIngestion::Recursive => {
                    let mut sink = cranix_core::hash::HashSink::new(h.algo);
                    nar::dump(&real, &mut sink).map_err(|e| e.to_string())?;
                    sink.finish().0
                }
            };
            if got != h {
                return Err(format!("content of '{}' does not match its content address", self.dir.print(&info.path)));
            }
            let mut refs = info.references.clone();
            let self_ref = refs.remove(&info.path);
            self.dir.make_fixed_output_path(method, &h, info.path.name(), &refs, self_ref)?
        } else {
            return Err(format!("unsupported content address '{ca}'"));
        };
        if expected != info.path {
            return Err(format!(
                "content-addressed path '{}' does not match its content address (expected '{}')",
                self.dir.print(&info.path),
                self.dir.print(&expected)
            ));
        }
        Ok(())
    }

    /// The paths of `closure` in an order where every path comes after the
    /// paths it references.
    pub fn topo_sort(&self, closure: &BTreeSet<StorePath>) -> Result<Vec<StorePath>> {
        fn visit(s: &Store, p: &StorePath, set: &BTreeSet<StorePath>, done: &mut BTreeSet<StorePath>, out: &mut Vec<StorePath>) -> Result<()> {
            if !done.insert(p.clone()) {
                return Ok(());
            }
            if let Some(info) = s.query_info(p)? {
                for r in &info.references {
                    if r != p && set.contains(r) {
                        visit(s, r, set, done, out)?;
                    }
                }
            }
            out.push(p.clone());
            Ok(())
        }
        let mut done = BTreeSet::new();
        let mut out = Vec::new();
        for p in closure {
            visit(self, p, closure, &mut done, &mut out)?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_checks_hash() {
        let root = std::env::temp_dir().join(format!("cranix-import-test-{}", std::process::id()));
        let _ = fsutil::remove_all(&root);
        let store = Store::open_at(&root).unwrap();
        let mut nar_bytes = Vec::new();
        nar::dump_bytes(b"hi\n", false, &mut nar_bytes).unwrap();
        let h = Hash::sha256(b"hi\n");
        let path = store.dir.make_fixed_output_path(FileIngestion::Flat, &h, "hi", &BTreeSet::new(), false).unwrap();
        let mut info = PathInfo {
            path,
            nar_hash: Hash::sha256(b"wrong"),
            nar_size: nar_bytes.len() as u64,
            references: BTreeSet::new(),
            deriver: None,
            ca: Some(format!("fixed:sha256:{}", h.to_nix32())),
        };
        assert!(store.import_nar(&info, &nar_bytes[..]).is_err());
        assert!(!store.is_valid(&info.path));
        info.nar_hash = Hash::sha256(&nar_bytes);
        store.import_nar(&info, &nar_bytes[..]).unwrap();
        assert!(store.verify(&info.path).unwrap());
        store.check_content_address(&info).unwrap();
        drop(store);
        fsutil::remove_all(&root).unwrap();
    }
}
