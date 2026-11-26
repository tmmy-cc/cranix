//! Store helpers shared by the fetchers.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cranix_core::hash::Hash;
use cranix_core::{FileIngestion, StorePath};
use cranix_store::Store;

use crate::Result;

/// Removes a tree, making directories writable first.
pub fn remove_tree(p: &Path) {
    fn make_writable(p: &Path) {
        if let Ok(md) = fs::symlink_metadata(p) {
            if md.is_dir() {
                let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
                if let Ok(rd) = fs::read_dir(p) {
                    for e in rd.flatten() {
                        make_writable(&e.path());
                    }
                }
            }
        }
    }
    make_writable(p);
    match fs::symlink_metadata(p) {
        Ok(md) if md.is_dir() => {
            let _ = fs::remove_dir_all(p);
        }
        Ok(_) => {
            let _ = fs::remove_file(p);
        }
        Err(_) => {}
    }
}

/// Where the host's `/nix/store` holds `p`, when this store's objects
/// live elsewhere but share its logical directory.
pub fn host_path(store: &Store, p: &StorePath) -> Option<PathBuf> {
    if store.dir.as_str() != "/nix/store" {
        return None;
    }
    let host = Path::new("/nix/store").join(p.base_name());
    (host != store.real_path(p) && host.symlink_metadata().is_ok()).then_some(host)
}

/// Whether `p` can be read: valid in this store, or present in the
/// host store at the same logical location.
pub fn is_available(store: &Store, p: &StorePath) -> bool {
    store.is_valid(p) || host_path(store, p).is_some()
}

/// The real location of an available path.
pub fn real_path(store: &Store, p: &StorePath) -> PathBuf {
    if store.is_valid(p) {
        return store.real_path(p);
    }
    host_path(store, p).unwrap_or_else(|| store.real_path(p))
}

/// NAR hash of an available path; host-store paths are hashed once and
/// remembered in the fetcher cache.
pub fn nar_hash(store: &Store, p: &StorePath) -> Result<Hash> {
    if let Some(info) = store.query_info(p)? {
        return Ok(info.nar_hash);
    }
    let key: crate::Attrs = [("path".to_string(), crate::Attr::Str(store.dir.print(p)))].into();
    if let Some((v, _)) = crate::cache::lookup(store, "hostNarHash", &key) {
        if let Ok(Some(h)) = crate::attrs::get_str(&v, "narHash") {
            if let Ok(h) = Hash::parse(&h, None) {
                return Ok(h);
            }
        }
    }
    let real = host_path(store, p).ok_or_else(|| format!("path '{}' is not valid", store.dir.print(p)))?;
    let (h, _) = Store::nar_hash(&real)?;
    crate::cache::upsert(store, "hostNarHash", &key, &[("narHash".to_string(), crate::Attr::Str(h.to_sri()))].into());
    Ok(h)
}

/// Adds `src` recursively under `name`, reusing an existing copy in this
/// store or the host store. Returns the path and its NAR hash.
pub fn add_to_store(store: &Store, src: &Path, name: &str) -> Result<(StorePath, Hash)> {
    let (p, h, _) = store.compute_path(src, name, None)?;
    if is_available(store, &p) {
        return Ok((p, h));
    }
    let p2 = store.add_path(src, name, FileIngestion::Recursive, None)?;
    Ok((p2, h))
}

/// Like `add_to_store`, keeping only entries accepted by `keep`, which
/// receives paths relative to `src`.
pub fn add_filtered(store: &Store, src: &Path, name: &str, keep: &dyn Fn(&str) -> bool) -> Result<(StorePath, Hash)> {
    let prefix = src.to_string_lossy().len() + 1;
    let mut f = |p: &Path, _: &fs::Metadata| -> std::io::Result<bool> { Ok(keep(&p.to_string_lossy()[prefix..])) };
    let (p, h, _) = store.compute_path(src, name, Some(&mut f))?;
    if is_available(store, &p) {
        return Ok((p, h));
    }
    let mut f = |p: &Path, _: &fs::Metadata| -> std::io::Result<bool> { Ok(keep(&p.to_string_lossy()[prefix..])) };
    let p2 = store.add_path(src, name, FileIngestion::Recursive, Some(&mut f))?;
    Ok((p2, h))
}

/// The newest modification time of any entry below `p`, including `p`.
pub fn max_mtime(p: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let Ok(md) = fs::symlink_metadata(p) else { return 0 };
    let mut t = md.mtime().max(0) as u64;
    if md.is_dir() {
        if let Ok(rd) = fs::read_dir(p) {
            for e in rd.flatten() {
                t = t.max(max_mtime(&e.path()));
            }
        }
    }
    t
}

/// The path a fixed-output recursive (`narHash`-locked) object gets.
pub fn fixed_path(store: &Store, name: &str, nar_hash: &Hash) -> Result<StorePath> {
    store.dir.make_fixed_output_path(FileIngestion::Recursive, nar_hash, name, &Default::default(), false)
}
