use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use oxnix_core::nar;

use crate::Result;

pub fn write_atomic(dest: &Path, data: &[u8]) -> Result<()> {
    let tmp = dest.with_extension(format!("tmp-{}", std::process::id()));
    let mut f = fs::File::create(&tmp).map_err(|e| format!("creating '{}': {e}", tmp.display()))?;
    f.write_all(data).map_err(|e| format!("writing '{}': {e}", tmp.display()))?;
    drop(f);
    fs::rename(&tmp, dest).map_err(|e| format!("renaming to '{}': {e}", dest.display()))
}

/// Removes a file or tree, making directories writable first since store
/// objects are read-only.
pub fn remove_all(p: &Path) -> Result<()> {
    let md = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("removing '{}': {e}", p.display())),
    };
    if md.is_dir() {
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
        for e in fs::read_dir(p).map_err(|e| format!("reading '{}': {e}", p.display()))? {
            remove_all(&e.map_err(|e| e.to_string())?.path())?;
        }
        fs::remove_dir(p).map_err(|e| format!("removing '{}': {e}", p.display()))
    } else {
        fs::remove_file(p).map_err(|e| format!("removing '{}': {e}", p.display()))
    }
}

pub fn copy_tree(src: &Path, dst: &Path, filter: &mut Option<nar::Filter<'_>>) -> Result<()> {
    let err = |e: io::Error| format!("copying '{}': {e}", src.display());
    let md = fs::symlink_metadata(src).map_err(err)?;
    let ft = md.file_type();
    if ft.is_symlink() {
        symlink(fs::read_link(src).map_err(err)?, dst).map_err(err)?;
    } else if ft.is_dir() {
        fs::create_dir(dst).map_err(err)?;
        for e in fs::read_dir(src).map_err(err)? {
            let e = e.map_err(err)?;
            let child = e.path();
            if let Some(f) = filter.as_mut() {
                let cmd = fs::symlink_metadata(&child).map_err(err)?;
                if !f(&child, &cmd).map_err(err)? {
                    continue;
                }
            }
            copy_tree(&child, &dst.join(e.file_name()), filter)?;
        }
    } else {
        fs::copy(src, dst).map_err(err)?;
        let exec = md.permissions().mode() & 0o100 != 0;
        fs::set_permissions(dst, fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 })).map_err(err)?;
    }
    Ok(())
}

/// Puts a freshly created store object into canonical form: read-only,
/// executable bit preserved for owner/group/other, mtime 1.
pub fn canonicalise(p: &Path) -> Result<()> {
    let err = |e: io::Error| format!("canonicalising '{}': {e}", p.display());
    let md = fs::symlink_metadata(p).map_err(err)?;
    let ft = md.file_type();
    if ft.is_symlink() {
        return Ok(());
    }
    if ft.is_dir() {
        for e in fs::read_dir(p).map_err(err)? {
            canonicalise(&e.map_err(err)?.path())?;
        }
    }
    let mtime = UNIX_EPOCH + Duration::from_secs(1);
    if ft.is_file() {
        let f = fs::OpenOptions::new().read(true).open(p).map_err(err)?;
        f.set_modified(mtime).map_err(err)?;
        let exec = md.permissions().mode() & 0o100 != 0;
        fs::set_permissions(p, fs::Permissions::from_mode(if exec { 0o555 } else { 0o444 })).map_err(err)?;
    } else {
        if let Ok(f) = fs::File::open(p) {
            let _ = f.set_modified(mtime);
        }
        fs::set_permissions(p, fs::Permissions::from_mode(0o555)).map_err(err)?;
    }
    Ok(())
}
