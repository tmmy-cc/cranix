//! nix-base32: a 32-character alphabet without `e o u t`, emitted
//! least-significant digit last.

pub const ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

const fn reverse_table() -> [u8; 256] {
    let mut t = [0xffu8; 256];
    let mut i = 0;
    while i < 32 {
        t[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    t
}

static REVERSE: [u8; 256] = reverse_table();

pub fn encoded_len(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        (n * 8 - 1) / 5 + 1
    }
}

pub fn is_valid_char(c: u8) -> bool {
    REVERSE[c as usize] != 0xff
}

pub fn encode(bytes: &[u8]) -> String {
    let len = encoded_len(bytes.len());
    let mut out = String::with_capacity(len);
    for n in (0..len).rev() {
        let b = n * 5;
        let i = b / 8;
        let j = b % 8;
        let lo = (bytes[i] as u16) >> j;
        let hi = if i + 1 < bytes.len() { (bytes[i + 1] as u16) << (8 - j) } else { 0 };
        out.push(ALPHABET[((lo | hi) & 0x1f) as usize] as char);
    }
    out
}

pub fn decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    let size = s.len() * 5 / 8;
    let mut out = vec![0u8; size];
    for n in 0..s.len() {
        let digit = REVERSE[s[s.len() - n - 1] as usize];
        if digit == 0xff {
            return None;
        }
        let b = n * 5;
        let i = b / 8;
        let j = b % 8;
        if i < size {
            out[i] |= digit << j;
        }
        let carry = (digit as u16) >> (8 - j);
        if i + 1 < size {
            out[i + 1] |= carry as u8;
        } else if carry != 0 {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        for len in [0usize, 1, 5, 20, 32, 64] {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(super::decode(&super::encode(&data)).unwrap(), data);
        }
    }
}
