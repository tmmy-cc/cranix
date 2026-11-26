//! Hash algorithms and the textual hash encodings Nix uses: base16,
//! nix-base32, base64 and SRI.

use std::fmt;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::base32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HashAlgo {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl HashAlgo {
    pub fn parse(s: &str) -> Option<HashAlgo> {
        Some(match s {
            "md5" => HashAlgo::Md5,
            "sha1" => HashAlgo::Sha1,
            "sha256" => HashAlgo::Sha256,
            "sha512" => HashAlgo::Sha512,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            HashAlgo::Md5 => "md5",
            HashAlgo::Sha1 => "sha1",
            HashAlgo::Sha256 => "sha256",
            HashAlgo::Sha512 => "sha512",
        }
    }

    pub fn size(self) -> usize {
        match self {
            HashAlgo::Md5 => 16,
            HashAlgo::Sha1 => 20,
            HashAlgo::Sha256 => 32,
            HashAlgo::Sha512 => 64,
        }
    }
}

impl fmt::Display for HashAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A digest together with the algorithm that produced it.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash {
    pub algo: HashAlgo,
    bytes: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Base16,
    Nix32,
    Base64,
    Sri,
}

impl Hash {
    pub fn from_bytes(algo: HashAlgo, b: &[u8]) -> Hash {
        assert_eq!(b.len(), algo.size());
        let mut bytes = [0u8; 64];
        bytes[..b.len()].copy_from_slice(b);
        Hash { algo, bytes }
    }

    pub fn digest(algo: HashAlgo, data: &[u8]) -> Hash {
        let mut h = Hasher::new(algo);
        h.update(data);
        h.finish()
    }

    pub fn sha256(data: &[u8]) -> Hash {
        Hash::digest(HashAlgo::Sha256, data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.algo.size()]
    }

    pub fn to_base16(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(self.algo.size() * 2);
        for b in self.as_bytes() {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }

    pub fn to_nix32(&self) -> String {
        base32::encode(self.as_bytes())
    }

    pub fn to_base64(&self) -> String {
        base64_encode(self.as_bytes())
    }

    pub fn to_sri(&self) -> String {
        format!("{}-{}", self.algo, self.to_base64())
    }

    /// Encodes the digest; `with_algo` prefixes `algo:` for the non-SRI forms.
    pub fn encode(&self, enc: Encoding, with_algo: bool) -> String {
        let body = match enc {
            Encoding::Base16 => self.to_base16(),
            Encoding::Nix32 => self.to_nix32(),
            Encoding::Base64 => self.to_base64(),
            Encoding::Sri => return self.to_sri(),
        };
        if with_algo {
            format!("{}:{}", self.algo, body)
        } else {
            body
        }
    }

    /// Parses `algo:digest`, `algo-base64` (SRI) or a bare digest when
    /// `algo` is given. The digest encoding is inferred from its length.
    pub fn parse(s: &str, algo: Option<HashAlgo>) -> Result<Hash, String> {
        if let Some((a, rest)) = s.split_once(':') {
            let a2 = HashAlgo::parse(a).ok_or_else(|| format!("unknown hash algorithm '{a}'"))?;
            if algo.is_some_and(|x| x != a2) {
                return Err(format!("hash '{s}' should have type '{}'", algo.unwrap()));
            }
            return Hash::parse_bare(rest, a2);
        }
        if let Some((a, rest)) = s.split_once('-') {
            if let Some(a2) = HashAlgo::parse(a) {
                if algo.is_some_and(|x| x != a2) {
                    return Err(format!("hash '{s}' should have type '{}'", algo.unwrap()));
                }
                let bytes = base64_decode(rest).ok_or_else(|| format!("invalid SRI hash '{s}'"))?;
                if bytes.len() != a2.size() {
                    return Err(format!("invalid SRI hash '{s}': wrong length"));
                }
                return Ok(Hash::from_bytes(a2, &bytes));
            }
        }
        match algo {
            Some(a) => Hash::parse_bare(s, a),
            None => Err(format!("hash '{s}' does not include a type")),
        }
    }

    pub fn parse_bare(s: &str, algo: HashAlgo) -> Result<Hash, String> {
        let size = algo.size();
        let bytes = if s.len() == size * 2 {
            hex_decode(s)
        } else if s.len() == base32::encoded_len(size) {
            base32::decode(s)
        } else {
            base64_decode(s).filter(|b| b.len() == size)
        };
        match bytes {
            Some(b) if b.len() == size => Ok(Hash::from_bytes(algo, &b)),
            _ => Err(format!("invalid {algo} hash '{s}'")),
        }
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algo, self.to_nix32())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algo, self.to_nix32())
    }
}

/// Incremental hasher over any supported algorithm.
pub enum Hasher {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Sha512),
}

impl Hasher {
    pub fn new(algo: HashAlgo) -> Hasher {
        match algo {
            HashAlgo::Md5 => Hasher::Md5(Md5::new()),
            HashAlgo::Sha1 => Hasher::Sha1(Sha1::new()),
            HashAlgo::Sha256 => Hasher::Sha256(Sha256::new()),
            HashAlgo::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Md5(h) => h.update(data),
            Hasher::Sha1(h) => h.update(data),
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }

    pub fn finish(self) -> Hash {
        match self {
            Hasher::Md5(h) => Hash::from_bytes(HashAlgo::Md5, &h.finalize()),
            Hasher::Sha1(h) => Hash::from_bytes(HashAlgo::Sha1, &h.finalize()),
            Hasher::Sha256(h) => Hash::from_bytes(HashAlgo::Sha256, &h.finalize()),
            Hasher::Sha512(h) => Hash::from_bytes(HashAlgo::Sha512, &h.finalize()),
        }
    }
}

/// Hashing sink that also counts bytes, used for NAR hash + size.
pub struct HashSink {
    pub hasher: Hasher,
    pub len: u64,
}

impl HashSink {
    pub fn new(algo: HashAlgo) -> HashSink {
        HashSink { hasher: Hasher::new(algo), len: 0 }
    }
    pub fn finish(self) -> (Hash, u64) {
        (self.hasher.finish(), self.len)
    }
}

impl std::io::Write for HashSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.len += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// XOR-folds a hash down to `size` bytes, as used for store path digests.
pub fn compress(hash: &[u8], size: usize) -> Vec<u8> {
    let mut out = vec![0u8; size];
    for (i, b) in hash.iter().enumerate() {
        out[i % size] ^= b;
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    b.chunks(2).map(|p| Some(nib(p[0])? << 4 | nib(p[1])?)).collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = match chunk.len() {
            3 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32,
            2 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8,
            _ => (chunk[0] as u32) << 16,
        };
        out.push(B64[(n >> 18 & 63) as usize] as char);
        out.push(B64[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = B64.iter().position(|&x| x == c)? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_encodings() {
        let h = Hash::sha256(b"hello");
        assert_eq!(h.to_base16(), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(h.to_nix32(), "094qif9n4cq4fdg459qzbhg1c6wywawwaaivx0k0x8xhbyx4vwic");
        assert_eq!(h.to_sri(), "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
        for s in [h.to_sri(), format!("sha256:{}", h.to_nix32()), format!("sha256:{}", h.to_base16())] {
            assert_eq!(Hash::parse(&s, None).unwrap(), h);
        }
    }
}
