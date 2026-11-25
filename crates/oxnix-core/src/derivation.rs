//! Derivations: the build recipes stored as `.drv` files in ATerm syntax,
//! plus the "hash modulo" scheme that makes output paths independent of
//! how fixed-output inputs were fetched.

use std::collections::{BTreeMap, BTreeSet};

use crate::hash::{Hash, HashAlgo};
use crate::store_path::{FileIngestion, StoreDir, StorePath};

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Output {
    /// Empty while the output paths are still being computed.
    pub path: Option<StorePath>,
    /// `""` for input-addressed outputs, else e.g. `r:sha256` or `sha1`.
    pub hash_algo: String,
    /// Base16 digest for fixed-output derivations.
    pub hash: String,
}

impl Output {
    /// The expected content hash of a fixed-output derivation.
    pub fn fixed(&self) -> Option<(FileIngestion, Hash)> {
        if self.hash.is_empty() {
            return None;
        }
        let (method, algo) = match self.hash_algo.strip_prefix("r:") {
            Some(a) => (FileIngestion::Recursive, a),
            None => (FileIngestion::Flat, self.hash_algo.as_str()),
        };
        let algo = HashAlgo::parse(algo)?;
        Some((method, Hash::parse_bare(&self.hash, algo).ok()?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Derivation {
    pub name: String,
    pub outputs: BTreeMap<String, Output>,
    pub input_drvs: BTreeMap<StorePath, BTreeSet<String>>,
    pub input_srcs: BTreeSet<StorePath>,
    pub platform: String,
    pub builder: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
}

fn quote(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn list<I, T>(out: &mut String, items: I, mut f: impl FnMut(&mut String, T))
where
    I: IntoIterator<Item = T>,
{
    out.push('[');
    for (i, it) in items.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        f(out, it);
    }
    out.push(']');
}

impl Derivation {
    pub fn is_fixed_output(&self) -> bool {
        self.outputs.len() == 1 && self.outputs.get("out").is_some_and(|o| !o.hash.is_empty())
    }

    /// The ATerm text of the `.drv` file.
    pub fn to_aterm(&self, sd: &StoreDir) -> String {
        let inputs: Vec<(String, &BTreeSet<String>)> = self.input_drvs.iter().map(|(p, o)| (sd.print(p), o)).collect();
        self.unparse(sd, false, &inputs)
    }

    fn unparse(&self, sd: &StoreDir, mask_outputs: bool, input_drvs: &[(String, &BTreeSet<String>)]) -> String {
        let mut s = String::with_capacity(4096);
        s.push_str("Derive(");
        list(&mut s, &self.outputs, |s, (name, o)| {
            s.push('(');
            quote(s, name);
            s.push(',');
            let p = match (&o.path, mask_outputs) {
                (Some(p), false) => sd.print(p),
                _ => String::new(),
            };
            quote(s, &p);
            s.push(',');
            quote(s, &o.hash_algo);
            s.push(',');
            quote(s, &o.hash);
            s.push(')');
        });
        s.push(',');
        list(&mut s, input_drvs, |s, (p, outs)| {
            s.push('(');
            quote(s, p);
            s.push(',');
            list(s, outs.iter(), |s, o| quote(s, o));
            s.push(')');
        });
        s.push(',');
        list(&mut s, &self.input_srcs, |s, p| quote(s, &sd.print(p)));
        s.push(',');
        quote(&mut s, &self.platform);
        s.push(',');
        quote(&mut s, &self.builder);
        s.push(',');
        list(&mut s, &self.args, |s, a| quote(s, a));
        s.push(',');
        list(&mut s, &self.env, |s, (k, v)| {
            s.push('(');
            quote(s, k);
            s.push(',');
            let masked = mask_outputs && self.outputs.contains_key(k);
            quote(s, if masked { "" } else { v });
            s.push(')');
        });
        s.push(')');
        s
    }

    /// `hashDerivationModulo`: fixed-output derivations hash to their
    /// declared content; all others hash their ATerm with input derivations
    /// replaced by their own modulo hashes. `input_hash` resolves those.
    pub fn hash_modulo(
        &self,
        sd: &StoreDir,
        mask_outputs: bool,
        input_hash: &mut dyn FnMut(&StorePath) -> Result<Hash, String>,
    ) -> Result<Hash, String> {
        if self.is_fixed_output() {
            let o = &self.outputs["out"];
            let path = o.path.as_ref().map(|p| sd.print(p)).unwrap_or_default();
            let s = format!("fixed:out:{}:{}:{}", o.hash_algo, o.hash, path);
            return Ok(Hash::sha256(s.as_bytes()));
        }
        let mut by_hash: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (p, outs) in &self.input_drvs {
            by_hash.entry(input_hash(p)?.to_base16()).or_default().extend(outs.iter().cloned());
        }
        let inputs: Vec<(String, &BTreeSet<String>)> = by_hash.iter().map(|(h, o)| (h.clone(), o)).collect();
        Ok(Hash::sha256(self.unparse(sd, mask_outputs, &inputs).as_bytes()))
    }

    /// References of the `.drv` file itself.
    pub fn references(&self) -> BTreeSet<StorePath> {
        let mut r = self.input_srcs.clone();
        r.extend(self.input_drvs.keys().cloned());
        r
    }

    /// Writes the output paths (and their `env` entries) into a derivation
    /// whose outputs are still empty.
    pub fn fill_output_paths(
        &mut self,
        sd: &StoreDir,
        input_hash: &mut dyn FnMut(&StorePath) -> Result<Hash, String>,
    ) -> Result<(), String> {
        if self.is_fixed_output() {
            let (method, hash) = self.outputs["out"].fixed().ok_or("invalid fixed-output hash")?;
            let p = sd.make_fixed_output_path(method, &hash, &self.name, &BTreeSet::new(), false)?;
            self.env.insert("out".into(), sd.print(&p));
            self.outputs.get_mut("out").unwrap().path = Some(p);
            return Ok(());
        }
        for o in self.outputs.values_mut() {
            o.path = None;
        }
        for k in self.outputs.keys() {
            self.env.insert(k.clone(), String::new());
        }
        let h = self.hash_modulo(sd, true, input_hash)?;
        let names: Vec<String> = self.outputs.keys().cloned().collect();
        for name in names {
            let p = sd.make_output_path(&name, &h, &self.name)?;
            self.env.insert(name.clone(), sd.print(&p));
            self.outputs.get_mut(&name).unwrap().path = Some(p);
        }
        Ok(())
    }

    pub fn parse(sd: &StoreDir, name: &str, text: &str) -> Result<Derivation, String> {
        let mut p = AtermParser { s: text.as_bytes(), i: 0 };
        let mut d = Derivation { name: name.to_string(), ..Default::default() };
        p.lit("Derive(")?;
        p.list(|p| {
            p.lit("(")?;
            let name = p.string()?;
            p.lit(",")?;
            let path = p.string()?;
            p.lit(",")?;
            let hash_algo = p.string()?;
            p.lit(",")?;
            let hash = p.string()?;
            p.lit(")")?;
            let path = if path.is_empty() { None } else { Some(sd.parse(&path)?) };
            d.outputs.insert(name, Output { path, hash_algo, hash });
            Ok(())
        })?;
        p.lit(",")?;
        p.list(|p| {
            p.lit("(")?;
            let drv = sd.parse(&p.string()?)?;
            p.lit(",")?;
            let mut outs = BTreeSet::new();
            p.list(|p| {
                outs.insert(p.string()?);
                Ok(())
            })?;
            p.lit(")")?;
            d.input_drvs.insert(drv, outs);
            Ok(())
        })?;
        p.lit(",")?;
        p.list(|p| {
            d.input_srcs.insert(sd.parse(&p.string()?)?);
            Ok(())
        })?;
        p.lit(",")?;
        d.platform = p.string()?;
        p.lit(",")?;
        d.builder = p.string()?;
        p.lit(",")?;
        p.list(|p| {
            d.args.push(p.string()?);
            Ok(())
        })?;
        p.lit(",")?;
        p.list(|p| {
            p.lit("(")?;
            let k = p.string()?;
            p.lit(",")?;
            let v = p.string()?;
            p.lit(")")?;
            d.env.insert(k, v);
            Ok(())
        })?;
        p.lit(")")?;
        if p.i != p.s.len() {
            return Err("trailing data after derivation".into());
        }
        Ok(d)
    }
}

struct AtermParser<'a> {
    s: &'a [u8],
    i: usize,
}

impl AtermParser<'_> {
    fn lit(&mut self, l: &str) -> Result<(), String> {
        if self.s[self.i..].starts_with(l.as_bytes()) {
            self.i += l.len();
            Ok(())
        } else {
            Err(format!("expected '{l}' at offset {} of derivation", self.i))
        }
    }

    fn list(&mut self, mut item: impl FnMut(&mut Self) -> Result<(), String>) -> Result<(), String> {
        self.lit("[")?;
        if self.s.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(());
        }
        loop {
            item(self)?;
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(format!("expected ',' or ']' at offset {}", self.i)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.lit("\"")?;
        let mut out = Vec::new();
        loop {
            match self.s.get(self.i) {
                None => return Err("unterminated string in derivation".into()),
                Some(b'"') => {
                    self.i += 1;
                    break;
                }
                Some(b'\\') => {
                    let c = *self.s.get(self.i + 1).ok_or("unterminated escape")?;
                    out.push(match c {
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        c => c,
                    });
                    self.i += 2;
                }
                Some(&c) => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
        String::from_utf8(out).map_err(|_| "derivation contains invalid UTF-8".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_derivation_matches_nix() {
        // derivation { name = "t"; system = "x"; builder = "/bin/sh"; }
        let sd = StoreDir::default();
        let mut d = Derivation {
            name: "t".into(),
            platform: "x".into(),
            builder: "/bin/sh".into(),
            ..Default::default()
        };
        d.outputs.insert("out".into(), Output::default());
        for (k, v) in [("builder", "/bin/sh"), ("name", "t"), ("system", "x")] {
            d.env.insert(k.into(), v.into());
        }
        d.fill_output_paths(&sd, &mut |_| unreachable!()).unwrap();
        assert_eq!(sd.print(d.outputs["out"].path.as_ref().unwrap()), "/nix/store/6clbak7fmwwqzh1qpdwlpbs1d5sijkq8-t");
        let text = d.to_aterm(&sd);
        let drv = sd.make_text_path("t.drv", &Hash::sha256(text.as_bytes()), &d.references()).unwrap();
        assert_eq!(sd.print(&drv), "/nix/store/pjqkd6csp29mdqlkk9lvhjlqfvjyz2x5-t.drv");
        assert_eq!(Derivation::parse(&sd, "t", &text).unwrap(), d);
    }
}
