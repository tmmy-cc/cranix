//! Realisations: the recorded mapping from a derivation output, named by
//! the derivation's hash modulo its outputs, to the store path a build
//! produced for it. Content-addressed derivations need them to find their
//! outputs; each is kept as a JSON file in `state/realisations` in the
//! format of Nix's `.doi` files.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::PathBuf;

use cranix_core::{Derivation, DrvHash, Hash, StorePath};
use serde_json::{json, Map, Value};

use crate::{fsutil, Result, Store};

/// One output of a derivation, keyed by the derivation's static output
/// hash: printed as `sha256:<base16>!<output>`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DrvOutput {
    pub drv_hash: Hash,
    pub output: String,
}

impl DrvOutput {
    pub fn parse(s: &str) -> Result<DrvOutput> {
        let (h, output) = s.rsplit_once('!').ok_or_else(|| format!("invalid derivation output id '{s}'"))?;
        let (algo, hex) = h.split_once(':').ok_or_else(|| format!("invalid derivation output id '{s}'"))?;
        let algo = cranix_core::HashAlgo::parse(algo).ok_or_else(|| format!("unknown hash algorithm in '{s}'"))?;
        Ok(DrvOutput { drv_hash: Hash::parse_bare(hex, algo)?, output: output.to_string() })
    }
}

impl std::fmt::Display for DrvOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}!{}", self.drv_hash.algo, self.drv_hash.to_base16(), self.output)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Realisation {
    pub id: DrvOutput,
    pub out_path: StorePath,
    pub signatures: BTreeSet<String>,
    /// Realisations of inputs whose output paths `out_path` references.
    pub dependent_realisations: BTreeMap<DrvOutput, StorePath>,
}

impl Realisation {
    pub fn new(id: DrvOutput, out_path: StorePath) -> Realisation {
        Realisation { id, out_path, signatures: BTreeSet::new(), dependent_realisations: BTreeMap::new() }
    }

    /// The JSON object Nix prints, with keys in its order.
    pub fn to_json(&self) -> Value {
        let deps: Map<String, Value> =
            self.dependent_realisations.iter().map(|(k, v)| (k.to_string(), json!(v.base_name()))).collect();
        json!({
            "dependentRealisations": deps,
            "id": self.id.to_string(),
            "outPath": self.out_path.base_name(),
            "signatures": self.signatures.iter().collect::<Vec<_>>(),
        })
    }

    pub fn from_json(v: &Value) -> Result<Realisation> {
        let field = |k: &str| v.get(k).and_then(Value::as_str).ok_or_else(|| format!("realisation lacks '{k}'"));
        let mut r = Realisation::new(DrvOutput::parse(field("id")?)?, StorePath::from_base_name(field("outPath")?)?);
        for s in v.get("signatures").and_then(Value::as_array).into_iter().flatten() {
            r.signatures.extend(s.as_str().map(String::from));
        }
        for (k, p) in v.get("dependentRealisations").and_then(Value::as_object).into_iter().flatten() {
            let p = p.as_str().ok_or("invalid dependent realisation")?;
            r.dependent_realisations.insert(DrvOutput::parse(k)?, StorePath::from_base_name(p)?);
        }
        Ok(r)
    }
}

impl Store {
    fn realisation_file(&self, id: &DrvOutput) -> PathBuf {
        self.state.join("realisations").join(format!("{id}.doi"))
    }

    pub fn register_realisation(&self, r: &Realisation) -> Result<()> {
        fsutil::write_atomic(&self.realisation_file(&r.id), r.to_json().to_string().as_bytes())
    }

    /// The realisation of `id`, if one is recorded and its path is valid.
    pub fn query_realisation(&self, id: &DrvOutput) -> Result<Option<Realisation>> {
        let text = match fs::read_to_string(self.realisation_file(id)) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("reading realisation '{id}': {e}")),
        };
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("parsing realisation '{id}': {e}"))?;
        let r = Realisation::from_json(&v)?;
        Ok(self.is_valid(&r.out_path).then_some(r))
    }

    /// Forgets the realisations that point at any of `paths`.
    pub(crate) fn drop_realisations_of(&self, paths: &BTreeSet<StorePath>) -> Result<()> {
        let dir = self.state.join("realisations");
        for e in fs::read_dir(&dir).map_err(|e| format!("listing realisations: {e}"))? {
            let e = e.map_err(|e| format!("listing realisations: {e}"))?;
            let gone = fs::read_to_string(e.path())
                .ok()
                .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                .and_then(|v| Realisation::from_json(&v).ok())
                .map_or(true, |r| paths.contains(&r.out_path));
            if gone {
                fs::remove_file(e.path()).map_err(|e| format!("removing realisation: {e}"))?;
            }
        }
        Ok(())
    }

    /// `hashDerivationModulo(drv, maskOutputs = false)` of the `.drv` file
    /// at `p`, the hash by which derivations refer to their inputs.
    pub fn drv_hash(&self, p: &StorePath) -> Result<DrvHash> {
        if let Some(h) = self.drv_hashes.lock().unwrap().get(p) {
            return Ok(h.clone());
        }
        let d = self.read_derivation(p)?;
        let h = d.hash_modulo(&self.dir, false, &mut |q| self.drv_hash(q))?;
        self.drv_hashes.lock().unwrap().insert(p.clone(), h.clone());
        Ok(h)
    }

    /// The hash that names the realisations of `drv`'s outputs: its hash
    /// modulo with output paths masked.
    pub fn static_output_hash(&self, drv: &Derivation) -> Result<Hash> {
        Ok(drv.hash_modulo(&self.dir, true, &mut |q| self.drv_hash(q))?.hash)
    }

    /// The realisation of output `output` of the derivation at `drv_path`.
    pub fn query_output_realisation(&self, drv: &Derivation, output: &str) -> Result<Option<Realisation>> {
        let id = DrvOutput { drv_hash: self.static_output_hash(drv)?, output: output.to_string() };
        self.query_realisation(&id)
    }

    /// The realisations of `roots` and, transitively, of their dependent
    /// realisations.
    pub fn realisation_closure(&self, roots: Vec<Realisation>) -> Result<BTreeMap<DrvOutput, StorePath>> {
        let mut seen = BTreeMap::new();
        let mut todo = roots;
        while let Some(r) = todo.pop() {
            if seen.insert(r.id.clone(), r.out_path.clone()).is_some() {
                continue;
            }
            for id in r.dependent_realisations.keys() {
                if !seen.contains_key(id) {
                    if let Some(d) = self.query_realisation(id)? {
                        todo.push(d);
                    }
                }
            }
        }
        Ok(seen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_matches_nix() {
        // As printed by `nix realisation info --json` for a CA derivation.
        let text = r#"{"dependentRealisations":{"sha256:3599f5ed4204c38c7ed1172c8bdc0469fa1a968be65bd320c928aaae6dfcfcba!out":"z8nj2n09pc9qy4nyhnznxvwjfmacbhsd-a"},"id":"sha256:06eafaed3d2c93f934e8008bc8f1fa6c7da31ce47a134f34950de6cc2c69dcf8!out","outPath":"i8kmnqh12ywrs4h8hh66lq954klihyqn-b","signatures":[]}"#;
        let r = Realisation::from_json(&serde_json::from_str(text).unwrap()).unwrap();
        assert_eq!(r.id.output, "out");
        assert_eq!(r.to_json().to_string(), text);
    }
}
