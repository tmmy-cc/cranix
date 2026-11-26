//! An on-disk record of what binary caches answered, so that repeated
//! lookups do not go over the network again.
//!
//! Each cache gets a directory under `<state>/narinfo-cache`, named by a
//! hash of its URL. In it, `<hash>.narinfo` holds a line with the time of
//! the lookup and whether the path was found, followed by the narinfo as
//! the cache sent it. `nix-cache-info` is kept the same way. Answers older
//! than `narinfo-cache-positive-ttl` (found) or
//! `narinfo-cache-negative-ttl` (not found) are asked again.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use oxnix_core::hash::Hash;

pub const DEFAULT_POSITIVE_TTL: u64 = 30 * 24 * 3600;
pub const DEFAULT_NEGATIVE_TTL: u64 = 3600;
/// How long a cache's `nix-cache-info` is kept, as in Nix.
const CACHE_INFO_TTL: u64 = 7 * 24 * 3600;

#[derive(Clone, Debug)]
pub struct NarinfoCache {
    dir: PathBuf,
    positive_ttl: u64,
    negative_ttl: u64,
}

/// A remembered answer: the file's contents, or `None` when the cache
/// did not have it.
pub type Entry = Option<Vec<u8>>;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

impl NarinfoCache {
    /// The record for the cache at `url`, kept under `root`.
    pub fn new(root: &Path, url: &str, positive_ttl: u64, negative_ttl: u64) -> NarinfoCache {
        let id = Hash::sha256(url.as_bytes()).to_nix32();
        NarinfoCache { dir: root.join(&id[..32]), positive_ttl, negative_ttl }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn read(&self, name: &str, positive_ttl: u64, negative_ttl: u64) -> Option<Entry> {
        let data = fs::read(self.file(name)).ok()?;
        let nl = data.iter().position(|&b| b == b'\n')?;
        let head = std::str::from_utf8(&data[..nl]).ok()?;
        let (time, present) = head.split_once(' ')?;
        let age = now().saturating_sub(time.parse().ok()?);
        match present {
            "1" if age < positive_ttl => Some(Some(data[nl + 1..].to_vec())),
            "0" if age < negative_ttl => Some(None),
            _ => None,
        }
    }

    /// Records `entry` for `name`. Failing to write the record only means
    /// the next lookup asks the cache again, so errors are ignored.
    fn write(&self, name: &str, entry: &Entry) {
        let mut data = format!("{} {}\n", now(), u8::from(entry.is_some())).into_bytes();
        if let Some(d) = entry {
            data.extend_from_slice(d);
        }
        let tmp = self.dir.join(format!(".tmp-{}-{}", std::process::id(), TMP_COUNTER.fetch_add(1, Ordering::Relaxed)));
        let ok = fs::create_dir_all(&self.dir).is_ok() && fs::write(&tmp, &data).is_ok();
        if !ok || fs::rename(&tmp, self.file(name)).is_err() {
            let _ = fs::remove_file(&tmp);
        }
    }

    /// The remembered narinfo for `hash_part`, if it is fresh enough.
    pub fn narinfo(&self, hash_part: &str) -> Option<Entry> {
        self.read(&format!("{hash_part}.narinfo"), self.positive_ttl, self.negative_ttl)
    }

    pub fn put_narinfo(&self, hash_part: &str, entry: &Entry) {
        self.write(&format!("{hash_part}.narinfo"), entry)
    }

    pub fn cache_info(&self) -> Option<Entry> {
        self.read("nix-cache-info", CACHE_INFO_TTL, CACHE_INFO_TTL)
    }

    pub fn put_cache_info(&self, entry: &Entry) {
        self.write("nix-cache-info", entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_answers_within_their_ttl() {
        let root = std::env::temp_dir().join(format!("oxnix-nic-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let c = NarinfoCache::new(&root, "https://cache.example", 100, 100);
        assert_eq!(c.narinfo("a"), None);
        c.put_narinfo("a", &Some(b"StorePath: x\n".to_vec()));
        c.put_narinfo("b", &None);
        assert_eq!(c.narinfo("a"), Some(Some(b"StorePath: x\n".to_vec())));
        assert_eq!(c.narinfo("b"), Some(None));

        // Another URL has its own record.
        assert_eq!(NarinfoCache::new(&root, "https://other.example", 100, 100).narinfo("a"), None);

        // A TTL of 0 turns that kind of answer off; old ones expire.
        let c0 = NarinfoCache::new(&root, "https://cache.example", 100, 0);
        assert_eq!(c0.narinfo("b"), None);
        assert!(c0.narinfo("a").is_some());
        let path = c.file("a.narinfo");
        let old = fs::read(&path).unwrap();
        let rest = &old[old.iter().position(|&b| b == b'\n').unwrap()..];
        fs::write(&path, [format!("{}", now() - 200).as_bytes(), b" 1", rest].concat()).unwrap();
        assert_eq!(c.narinfo("a"), None);
        fs::remove_dir_all(&root).unwrap();
    }
}
