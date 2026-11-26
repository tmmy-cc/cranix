//! Fetching source trees and files into the store, compatible with Nix's
//! fetchers: the same input attributes, store paths, locking rules and
//! URL syntax.
//!
//! Network access goes through `curl`, archives are decompressed with the
//! usual command line tools and parsed here, and Git repositories are read
//! with the `git` command line tool.

pub mod attrs;
pub mod cache;
pub mod download;
pub mod git;
mod github;
pub mod input;
pub mod registry;
pub mod settings;
pub mod storeutil;
pub mod tar;
pub mod url;

pub use attrs::{Attr, Attrs};
pub use input::Input;
pub use settings::{settings, set_settings, Settings};

pub type Result<T> = std::result::Result<T, String>;

/// A temporary directory removed when dropped.
pub struct TempDir(pub std::path::PathBuf);

impl TempDir {
    /// Creates a fresh directory below `parent`.
    pub fn new_in(parent: &std::path::Path, prefix: &str) -> Result<TempDir> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        std::fs::create_dir_all(parent).map_err(|e| format!("creating '{}': {e}", parent.display()))?;
        loop {
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p = parent.join(format!("{prefix}-{}-{n}", std::process::id()));
            match std::fs::create_dir(&p) {
                Ok(()) => return Ok(TempDir(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("creating '{}': {e}", p.display())),
            }
        }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        storeutil::remove_tree(&self.0);
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// `20231225143000`-style UTC timestamp, as in `lastModifiedDate`.
pub fn format_date(t: u64) -> String {
    format_date_signed(t as i64)
}

/// `format_date` for times that may lie before 1970.
pub fn format_date_signed(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}{:02}{:02}{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

pub fn warn(msg: impl AsRef<str>) {
    eprintln!("warning: {}", msg.as_ref());
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::format_date(0), "19700101000000");
        assert_eq!(super::format_date(1700000000), "20231114221320");
        assert_eq!(super::format_date(951782400), "20000229000000");
    }
}
