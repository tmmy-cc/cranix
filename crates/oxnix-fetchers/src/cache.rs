//! The fetcher cache: `(domain, key) -> (value, timestamp)` entries in the
//! store's state directory, with `tarball-ttl` expiry, mirroring Nix's
//! `fetcher-cache` database.

use std::path::PathBuf;

use oxnix_core::hash::Hash;
use oxnix_core::StorePath;
use oxnix_store::Store;
use serde_json::json;

use crate::attrs::{self, Attr, Attrs};

fn entry_file(store: &Store, domain: &str, key: &Attrs) -> PathBuf {
    let k = format!("{domain}\0{}", attrs::to_json_string(key));
    store.state_dir().join("fetcher-cache").join(Hash::sha256(k.as_bytes()).to_nix32())
}

pub fn upsert(store: &Store, domain: &str, key: &Attrs, value: &Attrs) {
    let f = entry_file(store, domain, key);
    let body = json!({
        "domain": domain,
        "key": attrs::to_json(key),
        "value": attrs::to_json(value),
        "timestamp": crate::now(),
    });
    let _ = std::fs::create_dir_all(f.parent().unwrap());
    let tmp = f.with_extension(format!("tmp{}", std::process::id()));
    if std::fs::write(&tmp, body.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, &f);
    }
}

/// The cached value and whether it is older than `tarball-ttl`.
pub fn lookup(store: &Store, domain: &str, key: &Attrs) -> Option<(Attrs, bool)> {
    let text = std::fs::read_to_string(entry_file(store, domain, key)).ok()?;
    let j: serde_json::Value = serde_json::from_str(&text).ok()?;
    let value = attrs::from_json(j.get("value")?).ok()?;
    let ts = j.get("timestamp")?.as_u64()?;
    let ttl = crate::settings().tarball_ttl;
    Some((value, ttl == 0 || ts + ttl < crate::now()))
}

pub fn lookup_fresh(store: &Store, domain: &str, key: &Attrs) -> Option<Attrs> {
    lookup(store, domain, key).filter(|(_, expired)| !expired).map(|(v, _)| v)
}

fn with_store(store: &Store, key: &Attrs) -> Attrs {
    let mut k = key.clone();
    k.insert("store".into(), Attr::Str(store.dir.as_str().into()));
    k
}

pub fn upsert_path(store: &Store, domain: &str, key: &Attrs, value: &Attrs, p: &StorePath) {
    let mut v = value.clone();
    v.insert("storePath".into(), Attr::Str(p.base_name().into()));
    upsert(store, domain, &with_store(store, key), &v);
}

/// A cached value with its store path, if the path is still available.
pub fn lookup_path(store: &Store, domain: &str, key: &Attrs) -> Option<(Attrs, StorePath, bool)> {
    let (mut v, expired) = lookup(store, domain, &with_store(store, key))?;
    let sp = match v.remove("storePath") {
        Some(Attr::Str(s)) => StorePath::from_base_name(&s).ok()?,
        _ => return None,
    };
    crate::storeutil::is_available(store, &sp).then_some((v, sp, expired))
}
