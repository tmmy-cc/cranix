//! Build provenance: an in-toto Statement v1 with a SLSA Provenance v1
//! predicate for each output of a derivation.
//!
//! The subject is the output path with the SHA-256 of its NAR
//! serialisation (its `NarHash`). The build definition names the
//! derivation, and lists the derivation file, its input sources and the
//! outputs of its input derivations with their NAR hashes. The internal
//! parameters record the platform, the sandbox settings and the time
//! limits. Statements hold no wall-clock time, so they are the same on
//! every run; keys are sorted.

use std::collections::BTreeMap;

use cranix_core::{Derivation, StorePath};
use cranix_store::build::BuildOptions;
use cranix_store::Store;
use serde_json::{json, Map, Value};

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
/// Where the build type of these statements is described.
pub const BUILD_TYPE: &str = "https://github.com/tmmy-cc/cranix/blob/main/docs/provenance.md#build-type";
pub const BUILDER_ID: &str = "https://github.com/tmmy-cc/cranix";

fn digest(store: &Store, p: &StorePath) -> Result<Option<Value>, String> {
    Ok(store.query_info(p)?.map(|i| json!({ "sha256": i.nar_hash.to_base16() })))
}

/// A resource descriptor for a store path, with its digest when the path
/// is valid in `store`.
fn resource(store: &Store, p: &StorePath, annotations: Option<Value>) -> Result<Value, String> {
    let mut m = Map::new();
    m.insert("uri".into(), json!(store.dir.print(p)));
    if let Some(d) = digest(store, p)? {
        m.insert("digest".into(), d);
    }
    if let Some(a) = annotations {
        m.insert("annotations".into(), a);
    }
    Ok(Value::Object(m))
}

/// The settings of `opts` that decide how a derivation is built.
fn internal_parameters(drv: &Derivation, opts: &BuildOptions) -> Value {
    let mut features = opts.system_features.clone();
    features.sort();
    features.dedup();
    let mut paths = opts.sandbox_paths.clone();
    paths.sort();
    let mut impure = opts.allowed_impure_host_deps.clone();
    impure.sort();
    json!({
        "system": opts.system,
        "platform": drv.platform,
        "systemFeatures": features,
        "sandbox": {
            "mode": opts.sandbox.name(),
            "paths": paths,
            "fallback": opts.sandbox_fallback,
            "allowedImpureHostDeps": impure,
        },
        "timeout": opts.timeout,
        "maxSilentTime": opts.max_silent_time,
    })
}

/// One statement per output of `drv_path`, in output name order. Outputs
/// must be valid in `store`.
pub fn statements(store: &Store, drv_path: &StorePath, opts: &BuildOptions) -> Result<Vec<(String, StorePath, Value)>, String> {
    let drv = store.read_derivation(drv_path)?;
    let drv_s = store.dir.print(drv_path);

    let mut deps: BTreeMap<String, Value> = BTreeMap::new();
    deps.insert(drv_s.clone(), resource(store, drv_path, Some(json!({ "role": "derivation" })))?);
    for s in &drv.input_srcs {
        deps.insert(store.dir.print(s), resource(store, s, Some(json!({ "role": "source" })))?);
    }
    for (d, outs) in &drv.input_drvs {
        let dd = store.read_derivation(d)?;
        for o in outs {
            let Some(p) = dd.outputs.get(o).and_then(|x| x.path.clone()) else { continue };
            let a = json!({ "role": "input", "derivation": store.dir.print(d), "output": o });
            deps.insert(store.dir.print(&p), resource(store, &p, Some(a))?);
        }
    }
    let deps: Vec<Value> = deps.into_values().collect();

    let paths = store.output_paths(drv_path, &drv)?;
    let mut out = Vec::new();
    for (name, p) in paths {
        let d = digest(store, &p)?.ok_or_else(|| format!("output '{}' of '{drv_s}' is not valid; build it first", store.dir.print(&p)))?;
        let st = json!({
            "_type": STATEMENT_TYPE,
            "subject": [{ "name": store.dir.print(&p), "digest": d }],
            "predicateType": PREDICATE_TYPE,
            "predicate": {
                "buildDefinition": {
                    "buildType": BUILD_TYPE,
                    "externalParameters": { "derivation": drv_s, "output": name },
                    "internalParameters": internal_parameters(&drv, opts),
                    "resolvedDependencies": deps,
                },
                "runDetails": {
                    "builder": { "id": BUILDER_ID, "version": { "cranix": env!("CARGO_PKG_VERSION") } },
                },
            },
        });
        out.push((name, p, st));
    }
    Ok(out)
}

/// The name of the file a statement for `p` has in a binary cache, beside
/// `<hash>.narinfo`.
pub fn cache_file(p: &StorePath) -> String {
    format!("{}.provenance.json", p.hash_part())
}
