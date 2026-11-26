//! Ed25519 store path signatures in Nix's `name:base64` text format.
//!
//! A signature covers a path's fingerprint, which binds its store path,
//! NAR hash, NAR size and references. Secret keys hold libsodium's 64-byte
//! layout (seed followed by the public key); public keys hold 32 bytes.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::hash::{base64_decode, base64_encode, Hash, HashAlgo};
use crate::{StoreDir, StorePath};

/// The text that signatures sign:
/// `1;<path>;<narHash>;<narSize>;<ref>,<ref>,...` with full store paths.
pub fn fingerprint(
    dir: &StoreDir,
    path: &StorePath,
    nar_hash: &Hash,
    nar_size: u64,
    references: &BTreeSet<StorePath>,
) -> Result<String, String> {
    if nar_hash.algo != HashAlgo::Sha256 || nar_size == 0 {
        return Err(format!("cannot calculate fingerprint of path '{}' because its hash or size is not known", dir.print(path)));
    }
    let refs: Vec<String> = references.iter().map(|r| dir.print(r)).collect();
    Ok(format!("1;{};{};{};{}", dir.print(path), nar_hash, nar_size, refs.join(",")))
}

fn split_key(s: &str, what: &str) -> Result<(String, Vec<u8>), String> {
    let (name, data) = s.trim().split_once(':').ok_or_else(|| format!("{what} is corrupt"))?;
    if name.is_empty() {
        return Err(format!("{what} is corrupt"));
    }
    let bytes = base64_decode(data).ok_or_else(|| format!("{what} '{name}' is not valid base64"))?;
    Ok((name.to_string(), bytes))
}

#[derive(Clone)]
pub struct SecretKey {
    pub name: String,
    key: SigningKey,
}

impl SecretKey {
    pub fn parse(s: &str) -> Result<SecretKey, String> {
        let (name, bytes) = split_key(s, "secret key")?;
        let bytes: [u8; 64] = bytes.try_into().map_err(|_| format!("secret key '{name}' has the wrong length"))?;
        let key = SigningKey::from_keypair_bytes(&bytes).map_err(|_| format!("secret key '{name}' is inconsistent"))?;
        Ok(SecretKey { name, key })
    }

    pub fn from_seed(name: &str, seed: &[u8; 32]) -> SecretKey {
        SecretKey { name: name.to_string(), key: SigningKey::from_bytes(seed) }
    }

    /// Creates a key from 32 bytes of `/dev/urandom`.
    pub fn generate(name: &str) -> Result<SecretKey, String> {
        use std::io::Read;
        let mut seed = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut seed))
            .map_err(|e| format!("reading /dev/urandom: {e}"))?;
        Ok(SecretKey::from_seed(name, &seed))
    }

    pub fn to_public(&self) -> PublicKey {
        PublicKey { name: self.name.clone(), key: self.key.verifying_key() }
    }

    /// Signs `data`, returning `name:base64(signature)`.
    pub fn sign(&self, data: &[u8]) -> String {
        format!("{}:{}", self.name, base64_encode(&self.key.sign(data).to_bytes()))
    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.name, base64_encode(&self.key.to_keypair_bytes()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub name: String,
    key: VerifyingKey,
}

impl PublicKey {
    pub fn parse(s: &str) -> Result<PublicKey, String> {
        let (name, bytes) = split_key(s, "public key")?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| format!("public key '{name}' has the wrong length"))?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| format!("public key '{name}' is not a valid point"))?;
        Ok(PublicKey { name, key })
    }

    /// Checks `sig` (`name:base64`) over `data`; a signature by a key of
    /// another name does not verify.
    pub fn verify(&self, data: &[u8], sig: &str) -> bool {
        let Some((name, b64)) = sig.split_once(':') else { return false };
        if name != self.name {
            return false;
        }
        let Some(bytes) = base64_decode(b64).and_then(|b| <[u8; 64]>::try_from(b).ok()) else { return false };
        self.key.verify_strict(data, &Signature::from_bytes(&bytes)).is_ok()
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.name, base64_encode(self.key.as_bytes()))
    }
}

/// Whether any of `sigs` is a valid signature of `data` by one of `keys`.
pub fn verify_any<'a>(keys: &[PublicKey], data: &[u8], sigs: impl IntoIterator<Item = &'a String>) -> bool {
    sigs.into_iter().any(|s| keys.iter().any(|k| k.verify(data, s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CACHE_KEY: &str = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";

    fn hello() -> (StoreDir, StorePath, Hash, u64, BTreeSet<StorePath>) {
        let dir = StoreDir::default();
        let p = StorePath::from_base_name("9l3rahv16sipckaksiw988lxyfcihql9-hello-2.12.1").unwrap();
        let h = Hash::parse("sha256:10y15sjp6ql0a5011sgm6pwfk3shaqiawwq4z2ks63amyphwk59n", None).unwrap();
        let refs = [StorePath::from_base_name("dka6i6yj8sgws93wc6m0lmqzhk21kq87-libiconv-107").unwrap()].into();
        (dir, p, h, 121208, refs)
    }

    #[test]
    fn fingerprint_format() {
        let (dir, p, h, n, refs) = hello();
        assert_eq!(
            fingerprint(&dir, &p, &h, n, &refs).unwrap(),
            "1;/nix/store/9l3rahv16sipckaksiw988lxyfcihql9-hello-2.12.1;\
             sha256:10y15sjp6ql0a5011sgm6pwfk3shaqiawwq4z2ks63amyphwk59n;121208;\
             /nix/store/dka6i6yj8sgws93wc6m0lmqzhk21kq87-libiconv-107"
        );
        assert!(fingerprint(&dir, &p, &h, 0, &refs).is_err());
    }

    #[test]
    fn verifies_cache_nixos_org_signature() {
        let (dir, p, h, n, refs) = hello();
        let fp = fingerprint(&dir, &p, &h, n, &refs).unwrap();
        let key = PublicKey::parse(CACHE_KEY).unwrap();
        let sig = "cache.nixos.org-1:AqRLWawyss+37tITYnqHt6kmUZDqZjDVV3yiRoMpv6h+HCNE6c2rPzxyiGF2wVuliIJw+QB3mK93UPF4WGimBg==";
        assert!(key.verify(fp.as_bytes(), sig));
        // Any change to the fingerprint invalidates it.
        let other = fingerprint(&dir, &p, &h, n + 1, &refs).unwrap();
        assert!(!key.verify(other.as_bytes(), sig));
        // So does a different key name.
        assert!(!key.verify(fp.as_bytes(), &sig.replace("cache.nixos.org-1", "other")));
        assert_eq!(key.to_string(), CACHE_KEY);
    }

    #[test]
    fn sign_round_trip() {
        let sk = SecretKey::from_seed("test-1", &[7; 32]);
        let text = sk.to_string();
        let sk2 = SecretKey::parse(&text).unwrap();
        let pk = PublicKey::parse(&sk2.to_public().to_string()).unwrap();
        let sig = sk2.sign(b"data");
        assert!(sig.starts_with("test-1:"));
        assert!(pk.verify(b"data", &sig));
        assert!(!pk.verify(b"datb", &sig));
        assert!(verify_any(&[PublicKey::parse(CACHE_KEY).unwrap(), pk], b"data", &[String::from("x:y"), sig]));
        assert!(SecretKey::parse("test-1:AAAA").is_err());
        assert!(PublicKey::parse("nocolon").is_err());
    }
}
