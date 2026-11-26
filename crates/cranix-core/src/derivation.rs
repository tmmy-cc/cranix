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

/// The kinds of derivation outputs, as told apart by their ATerm fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputKind {
    /// A path computed from the derivation's hash.
    InputAddressed,
    /// A path computed from the declared content hash.
    Fixed,
    /// Content-addressed with a path known only after the build.
    Floating,
    /// Input-addressed, but the path depends on content-addressed inputs and
    /// is computed once they are built.
    Deferred,
    /// Content-addressed, rebuilt every time and never cached.
    Impure,
}

/// The string standing in for output `name` of the derivation being
/// defined: `builtins.placeholder name`.
pub fn hash_placeholder(name: &str) -> String {
    format!("/{}", Hash::sha256(format!("nix-output:{name}").as_bytes()).to_nix32())
}

/// The string standing in for output `output` of `drv` while that output's
/// path is unknown (a content-addressed or deferred input).
pub fn downstream_placeholder(drv: &StorePath, output: &str) -> String {
    let name = drv.name().strip_suffix(".drv").unwrap_or(drv.name());
    let clear = format!("nix-upstream-output:{}:{}", drv.hash_part(), crate::store_path::output_path_name(name, output));
    format!("/{}", Hash::sha256(clear.as_bytes()).to_nix32())
}

/// Replaces every occurrence of each key of `rewrites` in `s`.
pub fn rewrite_strings(s: &str, rewrites: &BTreeMap<String, String>) -> String {
    let mut s = s.to_string();
    for (from, to) in rewrites {
        if s.contains(from.as_str()) {
            s = s.replace(from.as_str(), to);
        }
    }
    s
}

/// The result of `hashDerivationModulo`. All outputs of a derivation share
/// one hash, except that impure derivations hash to a constant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrvHash {
    pub hash: Hash,
    /// Set when the derivation or one of its inputs is content-addressed
    /// floating or impure, so its outputs are not known statically.
    pub deferred: bool,
}

impl Output {
    pub fn kind(&self) -> OutputKind {
        match (self.hash_algo.is_empty(), self.hash.as_str(), &self.path) {
            (true, _, Some(_)) => OutputKind::InputAddressed,
            (true, _, None) => OutputKind::Deferred,
            (false, "impure", _) => OutputKind::Impure,
            (false, "", _) => OutputKind::Floating,
            (false, _, _) => OutputKind::Fixed,
        }
    }

    /// The method and hash algorithm of a content-addressed output, from
    /// its `hashAlgo` field (`r:sha256`, `text:sha256`, `sha1`, ...).
    pub fn method_algo(&self) -> Option<(CaMethod, HashAlgo)> {
        let (method, algo) = if let Some(a) = self.hash_algo.strip_prefix("r:") {
            (CaMethod::Nar, a)
        } else if let Some(a) = self.hash_algo.strip_prefix("text:") {
            (CaMethod::Text, a)
        } else {
            (CaMethod::Flat, self.hash_algo.as_str())
        };
        Some((method, HashAlgo::parse(algo)?))
    }

    /// The expected content hash of a fixed-output derivation.
    pub fn fixed(&self) -> Option<(CaMethod, Hash)> {
        if self.kind() != OutputKind::Fixed {
            return None;
        }
        let (method, algo) = self.method_algo()?;
        Some((method, Hash::parse_bare(&self.hash, algo).ok()?))
    }
}

/// How the content of a content-addressed derivation output is hashed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaMethod {
    /// The bytes of a single file.
    Flat,
    /// The NAR serialisation.
    Nar,
    /// The bytes of a single file, addressed like `builtins.toFile` text.
    Text,
}

impl CaMethod {
    /// The prefix of the `hashAlgo` field and of content addresses.
    pub fn prefix(self) -> &'static str {
        match self {
            CaMethod::Flat => "",
            CaMethod::Nar => "r:",
            CaMethod::Text => "text:",
        }
    }

    /// The name `nix derivation show` prints as `method`.
    pub fn name(self) -> &'static str {
        match self {
            CaMethod::Flat => "flat",
            CaMethod::Nar => "nar",
            CaMethod::Text => "text",
        }
    }

    /// How the content is serialised before hashing.
    pub fn ingestion(self) -> FileIngestion {
        match self {
            CaMethod::Nar => FileIngestion::Recursive,
            CaMethod::Flat | CaMethod::Text => FileIngestion::Flat,
        }
    }

    /// The content address recorded for a path, e.g. `fixed:r:sha256:<nix32>`.
    pub fn content_address(self, hash: &Hash) -> String {
        match self {
            CaMethod::Text => format!("text:{}:{}", hash.algo, hash.to_nix32()),
            m => format!("fixed:{}{}:{}", m.prefix(), hash.algo, hash.to_nix32()),
        }
    }

    /// The store path of content with `hash` and the given references.
    pub fn make_path(self, sd: &StoreDir, hash: &Hash, name: &str, refs: &BTreeSet<StorePath>, self_ref: bool) -> Result<StorePath, String> {
        match self {
            CaMethod::Text => {
                if self_ref {
                    return Err("reference to self not allowed with text hashing".into());
                }
                if hash.algo != HashAlgo::Sha256 {
                    return Err(format!("text hashing requires SHA-256, but '{name}' uses {}", hash.algo));
                }
                sd.make_text_path(name, hash, refs)
            }
            m => {
                let sha256_nar = m == CaMethod::Nar && hash.algo == HashAlgo::Sha256;
                if !sha256_nar && (self_ref || !refs.is_empty()) {
                    return Err(format!(
                        "'{name}' refers to store paths, which only content hashed as a SHA-256 NAR or as text may do"
                    ));
                }
                sd.make_fixed_output_path(m.ingestion(), hash, name, refs, self_ref)
            }
        }
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
        self.outputs.len() == 1 && self.outputs.get("out").is_some_and(|o| o.kind() == OutputKind::Fixed)
    }

    pub fn is_impure(&self) -> bool {
        self.outputs.values().any(|o| o.kind() == OutputKind::Impure)
    }

    /// Whether some output's path is only known after building (or after
    /// building the inputs).
    pub fn has_unknown_outputs(&self) -> bool {
        self.outputs.values().any(|o| o.path.is_none())
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
        input_hash: &mut dyn FnMut(&StorePath) -> Result<DrvHash, String>,
    ) -> Result<DrvHash, String> {
        if self.is_fixed_output() {
            let o = &self.outputs["out"];
            let path = o.path.as_ref().map(|p| sd.print(p)).unwrap_or_default();
            let s = format!("fixed:out:{}:{}:{}", o.hash_algo, o.hash, path);
            return Ok(DrvHash { hash: Hash::sha256(s.as_bytes()), deferred: false });
        }
        if self.is_impure() {
            return Ok(DrvHash { hash: Hash::sha256(b"impure"), deferred: true });
        }
        let mut deferred = self.outputs.values().any(|o| o.kind() == OutputKind::Floating);
        let mut by_hash: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (p, outs) in &self.input_drvs {
            let h = input_hash(p)?;
            deferred |= h.deferred;
            by_hash.entry(h.hash.to_base16()).or_default().extend(outs.iter().cloned());
        }
        let inputs: Vec<(String, &BTreeSet<String>)> = by_hash.iter().map(|(h, o)| (h.clone(), o)).collect();
        Ok(DrvHash { hash: Hash::sha256(self.unparse(sd, mask_outputs, &inputs).as_bytes()), deferred })
    }

    /// References of the `.drv` file itself.
    pub fn references(&self) -> BTreeSet<StorePath> {
        let mut r = self.input_srcs.clone();
        r.extend(self.input_drvs.keys().cloned());
        r
    }

    /// Writes the output paths (and their `env` entries) into a derivation
    /// whose outputs are still empty. Content-addressed floating and impure
    /// outputs get placeholders; input-addressed outputs that depend on such
    /// derivations stay deferred with empty `env` entries.
    pub fn fill_output_paths(
        &mut self,
        sd: &StoreDir,
        input_hash: &mut dyn FnMut(&StorePath) -> Result<DrvHash, String>,
    ) -> Result<(), String> {
        if self.is_fixed_output() {
            let (method, hash) = self.outputs["out"].fixed().ok_or("invalid fixed-output hash")?;
            let p = method.make_path(sd, &hash, &self.name, &BTreeSet::new(), false)?;
            self.env.insert("out".into(), sd.print(&p));
            self.outputs.get_mut("out").unwrap().path = Some(p);
            return Ok(());
        }
        if self.outputs.values().any(|o| matches!(o.kind(), OutputKind::Floating | OutputKind::Impure)) {
            for (k, o) in self.outputs.iter_mut() {
                o.path = None;
                self.env.insert(k.clone(), hash_placeholder(k));
            }
            return Ok(());
        }
        for o in self.outputs.values_mut() {
            o.path = None;
        }
        for k in self.outputs.keys() {
            self.env.insert(k.clone(), String::new());
        }
        let h = self.hash_modulo(sd, true, input_hash)?;
        if h.deferred {
            return Ok(());
        }
        self.set_input_addressed_paths(sd, &h.hash)
    }

    fn set_input_addressed_paths(&mut self, sd: &StoreDir, h: &Hash) -> Result<(), String> {
        let names: Vec<String> = self.outputs.keys().cloned().collect();
        for name in names {
            let p = sd.make_output_path(&name, h, &self.name)?;
            self.env.insert(name.clone(), sd.print(&p));
            self.outputs.get_mut(&name).unwrap().path = Some(p);
        }
        Ok(())
    }

    /// Nix's "resolved derivation": `inputs` gives the realised path of
    /// every input derivation output; those paths become input sources, the
    /// placeholders standing for them are rewritten, and deferred outputs
    /// get their input-addressed paths.
    pub fn resolve(&self, sd: &StoreDir, inputs: &BTreeMap<(StorePath, String), StorePath>) -> Result<Derivation, String> {
        let mut r = self.clone();
        let mut rewrites = BTreeMap::new();
        for (d, outs) in &self.input_drvs {
            for o in outs {
                let p = inputs.get(&(d.clone(), o.clone())).ok_or_else(|| format!("output '{o}' of '{}' is not realised", sd.print(d)))?;
                rewrites.insert(downstream_placeholder(d, o), sd.print(p));
                r.input_srcs.insert(p.clone());
            }
        }
        r.input_drvs.clear();
        r.builder = rewrite_strings(&r.builder, &rewrites);
        for a in &mut r.args {
            *a = rewrite_strings(a, &rewrites);
        }
        r.env = r.env.iter().map(|(k, v)| (rewrite_strings(k, &rewrites), rewrite_strings(v, &rewrites))).collect();
        if r.outputs.values().any(|o| o.kind() == OutputKind::Deferred) {
            let h = r.hash_modulo(sd, true, &mut |_| unreachable!("resolved derivations have no input derivations"))?;
            r.set_input_addressed_paths(sd, &h.hash)?;
        }
        Ok(r)
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

    fn ca_drv(name: &str, script: &str) -> Derivation {
        let mut d = Derivation {
            name: name.into(),
            platform: "aarch64-darwin".into(),
            builder: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            ..Default::default()
        };
        d.outputs.insert("out".into(), Output { path: None, hash_algo: "r:sha256".into(), hash: String::new() });
        for (k, v) in [
            ("builder", "/bin/sh"),
            ("name", name),
            ("outputHashAlgo", "sha256"),
            ("outputHashMode", "recursive"),
            ("system", "aarch64-darwin"),
        ] {
            d.env.insert(k.into(), v.into());
        }
        d
    }

    #[test]
    fn floating_derivations_match_nix() {
        // A content-addressed derivation and one that depends on it, as
        // instantiated by Nix 2.24 with `ca-derivations` enabled.
        let sd = StoreDir::default();
        let mut a = ca_drv("a", "echo hello > $out");
        a.fill_output_paths(&sd, &mut |_| unreachable!()).unwrap();
        assert_eq!(a.env["out"], "/1rz4g4znpzjwh1xymhjpm42vipw92pr73vdgl6xs1hycac8kf2n9");
        let text = a.to_aterm(&sd);
        assert_eq!(Derivation::parse(&sd, "a", &text).unwrap(), a);
        let a_path = sd.make_text_path("a.drv", &Hash::sha256(text.as_bytes()), &a.references()).unwrap();
        assert_eq!(a_path.base_name(), "vyqpa8j3gqrl0bycrl93n6x14h8bmgxf-a.drv");
        let a_ph = downstream_placeholder(&a_path, "out");
        assert_eq!(a_ph, "/0bjlhr1gzaw07ajxj6m1bjdv5kxj2wn17ip38l2qqd83gxkyyli2");
        let a_hash = a.hash_modulo(&sd, false, &mut |_| unreachable!()).unwrap();
        assert!(a_hash.deferred);

        let mut b = ca_drv("b", &format!("/bin/mkdir $out; echo {a_ph} > $out/a; echo $out > $out/self"));
        b.input_drvs.insert(a_path.clone(), ["out".to_string()].into());
        b.fill_output_paths(&sd, &mut |_| Ok(a_hash.clone())).unwrap();
        let text = b.to_aterm(&sd);
        let b_path = sd.make_text_path("b.drv", &Hash::sha256(text.as_bytes()), &b.references()).unwrap();
        assert_eq!(b_path.base_name(), "glgnfq21bblhyqzfhj14apdwd2jxiw5v-b.drv");
        let b_hash = b.hash_modulo(&sd, false, &mut |_| Ok(a_hash.clone())).unwrap();

        // An input-addressed derivation depending on `b` is deferred.
        let mut c = Derivation {
            name: "c".into(),
            platform: "aarch64-darwin".into(),
            builder: "/bin/sh".into(),
            args: vec!["-c".into(), format!("echo {} > $out", downstream_placeholder(&b_path, "out"))],
            ..Default::default()
        };
        c.outputs.insert("out".into(), Output::default());
        for (k, v) in [("builder", "/bin/sh"), ("name", "c"), ("system", "aarch64-darwin")] {
            c.env.insert(k.into(), v.into());
        }
        c.input_drvs.insert(b_path.clone(), ["out".to_string()].into());
        c.fill_output_paths(&sd, &mut |_| Ok(b_hash.clone())).unwrap();
        assert_eq!(c.outputs["out"].kind(), OutputKind::Deferred);
        assert_eq!(c.env["out"], "");
        let text = c.to_aterm(&sd);
        let c_path = sd.make_text_path("c.drv", &Hash::sha256(text.as_bytes()), &c.references()).unwrap();
        assert_eq!(c_path.base_name(), "ksvrzivrldgb4s8rdsa9qzhpmfylnn6v-c.drv");

        // Resolving `c` against a realised `b` makes it input-addressed.
        let b_out = StorePath::from_base_name("i8kmnqh12ywrs4h8hh66lq954klihyqn-b").unwrap();
        let r = c.resolve(&sd, &[((b_path, "out".to_string()), b_out.clone())].into()).unwrap();
        assert!(r.input_drvs.is_empty() && r.input_srcs.contains(&b_out));
        assert_eq!(r.args[1], format!("echo {} > $out", sd.print(&b_out)));
        assert_eq!(r.outputs["out"].kind(), OutputKind::InputAddressed);
    }

    #[test]
    fn text_fixed_output_matches_nix() {
        // outputHashMode = "text" with the sha256 of "hello", as
        // instantiated by Nix 2.24 with `dynamic-derivations` enabled.
        let sd = StoreDir::default();
        let o = Output {
            path: None,
            hash_algo: "text:sha256".into(),
            hash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".into(),
        };
        let (method, hash) = o.fixed().unwrap();
        assert_eq!(method, CaMethod::Text);
        let p = method.make_path(&sd, &hash, "fod", &BTreeSet::new(), false).unwrap();
        assert_eq!(p.base_name(), "g3am45jb0f8005kyvmyzz9a1kwq1knhj-fod");
        assert!(method.make_path(&sd, &hash, "fod", &BTreeSet::new(), true).is_err());
    }

    #[test]
    fn impure_outputs_are_recognised() {
        let o = Output { path: None, hash_algo: "r:sha256".into(), hash: "impure".into() };
        assert_eq!(o.kind(), OutputKind::Impure);
        assert_eq!(o.fixed(), None);
    }
}
