//! Reference scanning: finds which candidate store paths' hash parts occur
//! in the bytes of a build output.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Read;
use std::path::Path;

use oxnix_core::base32;
use oxnix_core::store_path::HASH_PART_LEN;
use oxnix_core::StorePath;

pub struct Scanner<'a> {
    candidates: HashMap<&'a [u8], &'a StorePath>,
    found: BTreeSet<StorePath>,
    /// Tail of the previous chunk so hashes split across reads are seen.
    carry: Vec<u8>,
}

impl<'a> Scanner<'a> {
    pub fn new(candidates: &'a BTreeSet<StorePath>) -> Scanner<'a> {
        Scanner {
            candidates: candidates.iter().map(|p| (p.hash_part().as_bytes(), p)).collect(),
            found: BTreeSet::new(),
            carry: Vec::new(),
        }
    }

    fn scan(&mut self, data: &[u8]) {
        let n = data.len();
        let mut i = 0;
        while i + HASH_PART_LEN <= n {
            // Scan the window right to left: an invalid byte at offset j
            // means no hash can start at or before i + j.
            let mut j = HASH_PART_LEN;
            while j > 0 && base32::is_valid_char(data[i + j - 1]) {
                j -= 1;
            }
            if j > 0 {
                i += j;
                continue;
            }
            if let Some(p) = self.candidates.remove(&data[i..i + HASH_PART_LEN]) {
                self.found.insert(p.clone());
            }
            i += 1;
        }
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        if self.candidates.is_empty() {
            return;
        }
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        self.scan(&buf);
        let keep = buf.len().min(HASH_PART_LEN - 1);
        self.carry = buf[buf.len() - keep..].to_vec();
    }

    /// Resets the carry between independent files.
    fn boundary(&mut self) {
        self.carry.clear();
    }

    pub fn finish(self) -> BTreeSet<StorePath> {
        self.found
    }
}

/// Scans every file name, symlink target and file content below `path`.
pub fn scan_path(path: &Path, candidates: &BTreeSet<StorePath>) -> std::io::Result<BTreeSet<StorePath>> {
    let mut s = Scanner::new(candidates);
    walk(path, &mut s)?;
    Ok(s.finish())
}

fn walk(path: &Path, s: &mut Scanner<'_>) -> std::io::Result<()> {
    let md = fs::symlink_metadata(path)?;
    if md.is_symlink() {
        s.boundary();
        s.feed(fs::read_link(path)?.as_os_str().as_encoded_bytes());
    } else if md.is_dir() {
        for e in fs::read_dir(path)? {
            let e = e?;
            s.boundary();
            s.feed(e.file_name().as_encoded_bytes());
            walk(&e.path(), s)?;
        }
    } else {
        s.boundary();
        let mut f = fs::File::open(path)?;
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            s.feed(&buf[..n]);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_split_hashes() {
        let a = StorePath::from_base_name("q790zdjk75hm2cn42nh77pqw4gbv1b88-a").unwrap();
        let b = StorePath::from_base_name("6clbak7fmwwqzh1qpdwlpbs1d5sijkq8-b").unwrap();
        let cands: BTreeSet<_> = [a.clone(), b].into();
        let mut s = Scanner::new(&cands);
        s.feed(b"xx /nix/store/q790zdjk75hm2cn4");
        s.feed(b"2nh77pqw4gbv1b88-a yy");
        assert_eq!(s.finish(), [a].into());
    }
}
