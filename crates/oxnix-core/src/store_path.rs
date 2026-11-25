//! Store paths and the fingerprints from which their digests are derived.

use std::collections::BTreeSet;
use std::fmt;

use crate::base32;
use crate::hash::{compress, Hash, HashAlgo};

pub const HASH_PART_LEN: usize = 32;
const DIGEST_LEN: usize = 20;

/// A store path relative to its store directory: `<digest>-<name>`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StorePath {
    // Ordering by the encoded text keeps sets sorted the way Nix prints them.
    base: Box<str>,
}

impl StorePath {
    pub fn from_digest(digest: &[u8], name: &str) -> Result<StorePath, String> {
        validate_name(name)?;
        Ok(StorePath { base: format!("{}-{}", base32::encode(digest), name).into() })
    }

    /// Parses a base name `<hash>-<name>`.
    pub fn from_base_name(s: &str) -> Result<StorePath, String> {
        let b = s.as_bytes();
        if b.len() < HASH_PART_LEN + 2 || b[HASH_PART_LEN] != b'-' {
            return Err(format!("'{s}' is not a valid store path name"));
        }
        if !b[..HASH_PART_LEN].iter().all(|&c| base32::is_valid_char(c)) {
            return Err(format!("'{s}' has an invalid hash part"));
        }
        validate_name(&s[HASH_PART_LEN + 1..])?;
        Ok(StorePath { base: s.into() })
    }

    pub fn hash_part(&self) -> &str {
        &self.base[..HASH_PART_LEN]
    }

    pub fn name(&self) -> &str {
        &self.base[HASH_PART_LEN + 1..]
    }

    pub fn base_name(&self) -> &str {
        &self.base
    }

    pub fn is_derivation(&self) -> bool {
        self.name().ends_with(".drv")
    }
}

impl fmt::Debug for StorePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base)
    }
}

impl fmt::Display for StorePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base)
    }
}

pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("store path name is empty".into());
    }
    if name.len() > 211 {
        return Err(format!("store path name '{name}' is longer than 211 characters"));
    }
    if name.starts_with('.') {
        return Err(format!("store path name '{name}' starts with a period"));
    }
    if let Some(c) = name.chars().find(|c| !(c.is_ascii_alphanumeric() || "+-._?=".contains(*c))) {
        return Err(format!("store path name '{name}' contains illegal character '{c}'"));
    }
    Ok(())
}

/// How the contents of a content-addressed path are fed to the hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FileIngestion {
    /// The file's bytes.
    Flat,
    /// The NAR serialisation of the file system object.
    Recursive,
}

/// A store directory such as `/nix/store`. All path arithmetic that needs
/// the directory lives here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreDir {
    dir: String,
}

impl Default for StoreDir {
    fn default() -> Self {
        StoreDir::new("/nix/store")
    }
}

impl StoreDir {
    pub fn new(dir: impl Into<String>) -> StoreDir {
        let mut dir = dir.into();
        while dir.len() > 1 && dir.ends_with('/') {
            dir.pop();
        }
        StoreDir { dir }
    }

    pub fn as_str(&self) -> &str {
        &self.dir
    }

    pub fn print(&self, p: &StorePath) -> String {
        format!("{}/{}", self.dir, p.base)
    }

    /// Parses an absolute path that names a store object exactly.
    pub fn parse(&self, s: &str) -> Result<StorePath, String> {
        match s.strip_prefix(self.dir.as_str()).and_then(|r| r.strip_prefix('/')) {
            Some(base) if !base.contains('/') => StorePath::from_base_name(base),
            _ => Err(format!("path '{s}' is not a store path in {}", self.dir)),
        }
    }

    /// Splits an absolute path inside the store into its store path and the
    /// remaining sub path (possibly empty).
    pub fn to_store_path<'a>(&self, s: &'a str) -> Option<(StorePath, &'a str)> {
        let rest = s.strip_prefix(self.dir.as_str())?.strip_prefix('/')?;
        let (base, sub) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        Some((StorePath::from_base_name(base).ok()?, sub))
    }

    pub fn is_in_store(&self, s: &str) -> bool {
        self.to_store_path(s).is_some()
    }

    /// `makeStorePath`: digest = compress(sha256("<type>:<hash>:<dir>:<name>")).
    pub fn make_store_path(&self, ty: &str, hash: &Hash, name: &str) -> Result<StorePath, String> {
        let fingerprint = format!("{ty}:{}:{}:{}:{name}", hash.algo, hash.to_base16(), self.dir);
        let digest = compress(Hash::sha256(fingerprint.as_bytes()).as_bytes(), DIGEST_LEN);
        StorePath::from_digest(&digest, name)
    }

    fn make_type(&self, ty: &str, refs: &BTreeSet<StorePath>, self_ref: bool) -> String {
        let mut s = ty.to_string();
        for r in refs {
            s.push(':');
            s.push_str(&self.print(r));
        }
        if self_ref {
            s.push_str(":self");
        }
        s
    }

    /// Path of a text file such as a `.drv` or `builtins.toFile` result.
    pub fn make_text_path(&self, name: &str, content_hash: &Hash, refs: &BTreeSet<StorePath>) -> Result<StorePath, String> {
        self.make_store_path(&self.make_type("text", refs, false), content_hash, name)
    }

    pub fn make_fixed_output_path(
        &self,
        method: FileIngestion,
        hash: &Hash,
        name: &str,
        refs: &BTreeSet<StorePath>,
        self_ref: bool,
    ) -> Result<StorePath, String> {
        if method == FileIngestion::Recursive && hash.algo == HashAlgo::Sha256 {
            self.make_store_path(&self.make_type("source", refs, self_ref), hash, name)
        } else {
            let prefix = if method == FileIngestion::Recursive { "r:" } else { "" };
            let inner = format!("fixed:out:{prefix}{}:{}:", hash.algo, hash.to_base16());
            self.make_store_path("output:out", &Hash::sha256(inner.as_bytes()), name)
        }
    }

    /// Output path of an input-addressed derivation output.
    pub fn make_output_path(&self, output: &str, drv_hash: &Hash, drv_name: &str) -> Result<StorePath, String> {
        let name = output_path_name(drv_name, output);
        self.make_store_path(&format!("output:{output}"), drv_hash, &name)
    }
}

pub fn output_path_name(drv_name: &str, output: &str) -> String {
    if output == "out" {
        drv_name.to_string()
    } else {
        format!("{drv_name}-{output}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_path_matches_nix() {
        // nix-instantiate --eval -E 'builtins.toFile "hello.txt" "hello"'
        let sd = StoreDir::default();
        let p = sd.make_text_path("hello.txt", &Hash::sha256(b"hello"), &BTreeSet::new()).unwrap();
        assert_eq!(sd.print(&p), "/nix/store/q790zdjk75hm2cn42nh77pqw4gbv1b88-hello.txt");
    }
}
