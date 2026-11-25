//! `.narinfo` files: the per-path metadata of a binary cache, naming the
//! compressed NAR that holds the path's contents.

use std::collections::BTreeSet;

use crate::hash::{Hash, HashAlgo};
use crate::signing::{fingerprint, verify_any, PublicKey};
use crate::{FileIngestion, StoreDir, StorePath};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NarInfo {
    pub path: StorePath,
    /// Location of the NAR, relative to the cache root.
    pub url: String,
    pub compression: String,
    /// Hash and size of the file at `url`.
    pub file_hash: Option<Hash>,
    pub file_size: Option<u64>,
    pub nar_hash: Hash,
    pub nar_size: u64,
    pub references: BTreeSet<StorePath>,
    pub deriver: Option<StorePath>,
    pub sigs: Vec<String>,
    pub ca: Option<String>,
}

impl NarInfo {
    pub fn parse(dir: &StoreDir, text: &str, whence: &str) -> Result<NarInfo, String> {
        let corrupt = |why: &str| format!("NAR info file '{whence}' is corrupt: {why}");
        let mut path = None;
        let mut url = None;
        let mut compression = None;
        let mut file_hash = None;
        let mut file_size = None;
        let mut nar_hash = None;
        let mut nar_size = None;
        let mut references = BTreeSet::new();
        let mut deriver = None;
        let mut sigs = Vec::new();
        let mut ca = None;
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let (k, v) = line.split_once(':').ok_or_else(|| corrupt("line without a colon"))?;
            let v = v.strip_prefix(' ').unwrap_or(v);
            let size = |v: &str| v.parse::<u64>().map_err(|_| corrupt(&format!("invalid {k}")));
            match k {
                "StorePath" => path = Some(dir.parse(v).map_err(|e| corrupt(&e))?),
                "URL" => url = Some(v.to_string()),
                "Compression" => compression = Some(v.to_string()),
                "FileHash" => file_hash = Some(Hash::parse(v, None).map_err(|e| corrupt(&e))?),
                "FileSize" => file_size = Some(size(v)?),
                "NarHash" => nar_hash = Some(Hash::parse(v, None).map_err(|e| corrupt(&e))?),
                "NarSize" => nar_size = Some(size(v)?),
                "References" => {
                    for r in v.split_whitespace() {
                        references.insert(StorePath::from_base_name(r).map_err(|e| corrupt(&e))?);
                    }
                }
                "Deriver" if v != "unknown-deriver" => deriver = Some(StorePath::from_base_name(v).map_err(|e| corrupt(&e))?),
                "Sig" => sigs.push(v.to_string()),
                "CA" => ca = Some(v.to_string()),
                _ => {}
            }
        }
        Ok(NarInfo {
            path: path.ok_or_else(|| corrupt("missing StorePath"))?,
            url: url.ok_or_else(|| corrupt("missing URL"))?,
            // Old caches omitted the field and always used bzip2.
            compression: compression.filter(|c| !c.is_empty()).unwrap_or_else(|| "bzip2".into()),
            file_hash,
            file_size,
            nar_hash: nar_hash.ok_or_else(|| corrupt("missing NarHash"))?,
            nar_size: nar_size.filter(|&n| n > 0).ok_or_else(|| corrupt("missing NarSize"))?,
            references,
            deriver,
            sigs,
            ca,
        })
    }

    /// Renders the file in the field order Nix writes.
    pub fn to_text(&self, dir: &StoreDir) -> String {
        let mut s = format!("StorePath: {}\nURL: {}\nCompression: {}\n", dir.print(&self.path), self.url, self.compression);
        if let Some(h) = &self.file_hash {
            s.push_str(&format!("FileHash: {h}\n"));
        }
        if let Some(n) = self.file_size {
            s.push_str(&format!("FileSize: {n}\n"));
        }
        let refs: Vec<&str> = self.references.iter().map(StorePath::base_name).collect();
        s.push_str(&format!("NarHash: {}\nNarSize: {}\nReferences: {}\n", self.nar_hash, self.nar_size, refs.join(" ")));
        if let Some(d) = &self.deriver {
            s.push_str(&format!("Deriver: {d}\n"));
        }
        for sig in &self.sigs {
            s.push_str(&format!("Sig: {sig}\n"));
        }
        if let Some(ca) = &self.ca {
            s.push_str(&format!("CA: {ca}\n"));
        }
        s
    }

    pub fn fingerprint(&self, dir: &StoreDir) -> Result<String, String> {
        fingerprint(dir, &self.path, &self.nar_hash, self.nar_size, &self.references)
    }

    /// Whether the path can be trusted: it carries a signature by one of
    /// `keys`, or its name is derived from its content address.
    pub fn is_trusted(&self, dir: &StoreDir, keys: &[PublicKey]) -> bool {
        if self.ca.as_deref().is_some_and(|ca| ca_matches_path(dir, &self.path, ca, &self.references)) {
            return true;
        }
        match self.fingerprint(dir) {
            Ok(fp) => verify_any(keys, fp.as_bytes(), &self.sigs),
            Err(_) => false,
        }
    }
}

/// Whether `path` is the store path that content address `ca` (`text:…`
/// or `fixed:[r:]algo:hash`) with `refs` produces.
pub fn ca_matches_path(dir: &StoreDir, path: &StorePath, ca: &str, refs: &BTreeSet<StorePath>) -> bool {
    let computed = if let Some(h) = ca.strip_prefix("text:") {
        match Hash::parse(h, None) {
            Ok(h) if !refs.contains(path) => dir.make_text_path(path.name(), &h, refs),
            _ => return false,
        }
    } else if let Some(rest) = ca.strip_prefix("fixed:") {
        let (method, h) = match rest.strip_prefix("r:") {
            Some(h) => (FileIngestion::Recursive, h),
            None => (FileIngestion::Flat, rest),
        };
        let Ok(h) = Hash::parse(h, None) else { return false };
        let self_ref = refs.contains(path);
        let others: BTreeSet<StorePath> = refs.iter().filter(|r| *r != path).cloned().collect();
        // Only recursive SHA-256 addresses can carry references.
        if !(method == FileIngestion::Recursive && h.algo == HashAlgo::Sha256) && !refs.is_empty() {
            return false;
        }
        dir.make_fixed_output_path(method, &h, path.name(), &others, self_ref)
    } else {
        return false;
    };
    computed.as_ref() == Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &str = "\
StorePath: /nix/store/9l3rahv16sipckaksiw988lxyfcihql9-hello-2.12.1
URL: nar/1qlznvv0jjaw3xia8fmcdk8km3i5yk62p3ihy8v5cr6hizwd2w80.nar.xz
Compression: xz
FileHash: sha256:1qlznvv0jjaw3xia8fmcdk8km3i5yk62p3ihy8v5cr6hizwd2w80
FileSize: 26644
NarHash: sha256:10y15sjp6ql0a5011sgm6pwfk3shaqiawwq4z2ks63amyphwk59n
NarSize: 121208
References: dka6i6yj8sgws93wc6m0lmqzhk21kq87-libiconv-107
Deriver: 8y3lhf43nkr6qgggy1jjnkvxv112nczk-hello-2.12.1.drv
Sig: cache.nixos.org-1:AqRLWawyss+37tITYnqHt6kmUZDqZjDVV3yiRoMpv6h+HCNE6c2rPzxyiGF2wVuliIJw+QB3mK93UPF4WGimBg==
";

    fn key() -> PublicKey {
        PublicKey::parse("cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=").unwrap()
    }

    #[test]
    fn parse_and_render() {
        let dir = StoreDir::default();
        let ni = NarInfo::parse(&dir, HELLO, "hello").unwrap();
        assert_eq!(ni.path.name(), "hello-2.12.1");
        assert_eq!(ni.compression, "xz");
        assert_eq!(ni.file_size, Some(26644));
        assert_eq!(ni.nar_size, 121208);
        assert_eq!(ni.references.len(), 1);
        assert_eq!(ni.deriver.as_ref().unwrap().base_name(), "8y3lhf43nkr6qgggy1jjnkvxv112nczk-hello-2.12.1.drv");
        assert_eq!(ni.sigs.len(), 1);
        assert_eq!(ni.to_text(&dir), HELLO);
        assert!(ni.is_trusted(&dir, &[key()]));
        assert!(!ni.is_trusted(&dir, &[]));
    }

    #[test]
    fn tampered_info_is_untrusted() {
        let dir = StoreDir::default();
        let ni = NarInfo::parse(&dir, &HELLO.replace("NarSize: 121208", "NarSize: 121209"), "x").unwrap();
        assert!(!ni.is_trusted(&dir, &[key()]));
        let ni = NarInfo::parse(&dir, &HELLO.replace("References: dka6i6yj8sgws93wc6m0lmqzhk21kq87-libiconv-107", "References: "), "x").unwrap();
        assert!(ni.references.is_empty());
        assert!(!ni.is_trusted(&dir, &[key()]));
    }

    #[test]
    fn defaults_and_errors() {
        let dir = StoreDir::default();
        let minimal = "StorePath: /nix/store/9l3rahv16sipckaksiw988lxyfcihql9-hello-2.12.1\nURL: nar/x.nar.bz2\n\
                       NarHash: sha256:10y15sjp6ql0a5011sgm6pwfk3shaqiawwq4z2ks63amyphwk59n\nNarSize: 5\nReferences: \n\
                       Deriver: unknown-deriver\nSystem: x86_64-linux\n";
        let ni = NarInfo::parse(&dir, minimal, "m").unwrap();
        assert_eq!(ni.compression, "bzip2");
        assert!(ni.deriver.is_none() && ni.file_hash.is_none() && ni.references.is_empty());
        assert!(NarInfo::parse(&dir, "URL: x\n", "m").unwrap_err().contains("missing StorePath"));
        assert!(NarInfo::parse(&StoreDir::new("/other"), HELLO, "m").is_err());
        assert!(NarInfo::parse(&dir, &HELLO.replace("NarSize: 121208", "NarSize: big"), "m").is_err());
    }

    #[test]
    fn content_addressed_paths_need_no_signature() {
        let dir = StoreDir::default();
        let content = b"hello";
        let h = Hash::sha256(content);
        let p = dir.make_text_path("greeting", &h, &BTreeSet::new()).unwrap();
        let ca = format!("text:sha256:{}", h.to_nix32());
        assert!(ca_matches_path(&dir, &p, &ca, &BTreeSet::new()));
        assert!(!ca_matches_path(&dir, &p, &ca, &[p.clone()].into()));
        let q = dir.make_fixed_output_path(FileIngestion::Recursive, &h, "src", &BTreeSet::new(), false).unwrap();
        assert!(ca_matches_path(&dir, &q, &format!("fixed:r:sha256:{}", h.to_nix32()), &BTreeSet::new()));
        assert!(!ca_matches_path(&dir, &q, &format!("fixed:sha256:{}", h.to_nix32()), &BTreeSet::new()));
        let f = dir.make_fixed_output_path(FileIngestion::Flat, &h, "f", &BTreeSet::new(), false).unwrap();
        assert!(ca_matches_path(&dir, &f, &format!("fixed:sha256:{}", h.to_nix32()), &BTreeSet::new()));
        assert!(!ca_matches_path(&dir, &f, &format!("fixed:sha256:{}", h.to_nix32()), &[q].into()));
        assert!(!ca_matches_path(&dir, &f, "nonsense", &BTreeSet::new()));
    }
}
