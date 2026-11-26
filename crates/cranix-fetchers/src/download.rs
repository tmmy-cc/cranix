//! HTTP(S) and `file://` downloads through `curl`, with ETag revalidation
//! and the `Link: <…>; rel="immutable"` header of the lockable tarball
//! protocol, plus `downloadFile`, which stores a download as a flat
//! fixed-output path.

use std::path::Path;
use std::process::Command;

use cranix_core::hash::{Hash, HashAlgo};
use cranix_core::{FileIngestion, StorePath};
use cranix_store::Store;

use crate::attrs::{self, Attr, Attrs};
use crate::{cache, Result};

pub type Headers = Vec<(String, String)>;

pub struct Transfer {
    /// The server answered 304 Not Modified; nothing was written.
    pub not_modified: bool,
    pub etag: String,
    /// The requested URL followed by every redirect target.
    pub urls: Vec<String>,
    pub immutable_url: Option<String>,
}

/// Downloads `url` into `dest`.
pub fn download(url: &str, headers: &Headers, expected_etag: Option<&str>, dest: &Path) -> Result<Transfer> {
    let hdr_file = dest.with_extension("headers");
    let mut cmd = Command::new("curl");
    cmd.args(["--silent", "--show-error", "--location", "--fail", "--compressed", "--retry", "2"]);
    cmd.args(["--user-agent", "curl/8 Nix/2.24.10"]);
    cmd.arg("--dump-header").arg(&hdr_file).arg("--output").arg(dest);
    cmd.args(["--write-out", "%{http_code} %{url_effective}"]);
    for (k, v) in headers {
        cmd.arg("--header").arg(format!("{k}: {v}"));
    }
    if let Some(e) = expected_etag.filter(|e| !e.is_empty()) {
        cmd.arg("--header").arg(format!("If-None-Match: {e}"));
    }
    cmd.arg("--").arg(url);
    let out = cmd.output().map_err(|e| format!("running curl: {e}"))?;
    let hdrs = std::fs::read_to_string(&hdr_file).unwrap_or_default();
    let _ = std::fs::remove_file(&hdr_file);
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr);
        return Err(format!("unable to download '{url}': {}", msg.trim().trim_start_matches("curl: ")));
    }
    let w = String::from_utf8_lossy(&out.stdout);
    let (code, effective) = w.split_once(' ').unwrap_or((&w, url));
    let mut urls = vec![url.to_string()];
    let mut etag = String::new();
    let mut immutable_url = None;
    // Each response of a redirect chain starts with its status line; the
    // ETag is the final response's, an immutable link may come from any.
    for line in hdrs.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("HTTP/") {
            etag.clear();
            continue;
        }
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        match k.to_ascii_lowercase().as_str() {
            "etag" => etag = v.to_string(),
            "location" => {}
            "link" | "x-amz-meta-link" => {
                for part in v.split(',') {
                    let part = part.trim();
                    if let Some(rest) = part.strip_prefix('<') {
                        if let Some((u, params)) = rest.split_once('>') {
                            if params.eq_ignore_ascii_case("; rel=\"immutable\"") {
                                immutable_url = Some(u.to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if !effective.is_empty() && effective != url {
        urls.push(effective.to_string());
    }
    Ok(Transfer { not_modified: code == "304", etag, urls, immutable_url })
}

pub struct DownloadFileResult {
    pub store_path: StorePath,
    pub etag: String,
    pub effective_url: String,
    pub immutable_url: Option<String>,
}

/// Downloads `url` into the store as a flat file named `name`, reusing
/// a cached copy younger than `tarball-ttl` and revalidating older ones.
pub fn download_file(store: &Store, url: &str, name: &str, headers: &Headers) -> Result<DownloadFileResult> {
    let mut key: Attrs = [("url".into(), Attr::from(url)), ("name".into(), Attr::from(name))].into();
    let cached = cache::lookup_path(store, "file", &key);
    let use_cached = |(v, sp, _): &(Attrs, StorePath, bool)| -> Result<DownloadFileResult> {
        Ok(DownloadFileResult {
            store_path: sp.clone(),
            etag: attrs::get_str(v, "etag")?.unwrap_or_default(),
            effective_url: attrs::get_str(v, "url")?.unwrap_or_else(|| url.to_string()),
            immutable_url: attrs::get_str(v, "immutableUrl")?,
        })
    };
    if let Some(c) = &cached {
        if !c.2 {
            return use_cached(c);
        }
    }
    let tmp = crate::TempDir::new_in(&store.state_dir().join("tmp"), "download")?;
    let dest = tmp.path().join("file");
    let etag = cached.as_ref().and_then(|c| attrs::get_str(&c.0, "etag").ok().flatten());
    let res = match download(url, headers, etag.as_deref(), &dest) {
        Ok(r) => r,
        Err(e) => match &cached {
            Some(c) => {
                crate::warn(format!("{e}; using cached version"));
                return use_cached(c);
            }
            None => return Err(e),
        },
    };
    let mut info: Attrs = [("etag".into(), Attr::Str(res.etag.clone()))].into();
    if let Some(u) = &res.immutable_url {
        info.insert("immutableUrl".into(), Attr::Str(u.clone()));
    }
    let sp = match (&cached, res.not_modified) {
        (Some(c), true) => c.1.clone(),
        _ => store.add_path(&dest, name, FileIngestion::Flat, None)?,
    };
    let last = res.urls.last().cloned().unwrap_or_else(|| url.to_string());
    info.insert("url".into(), Attr::Str(last.clone()));
    for u in &res.urls {
        key.insert("url".into(), Attr::Str(u.clone()));
        cache::upsert_path(store, "file", &key, &info, &sp);
    }
    Ok(DownloadFileResult { store_path: sp, etag: res.etag, effective_url: last, immutable_url: res.immutable_url })
}

/// SHA-256 of a file's contents.
pub fn hash_file(p: &Path) -> Result<Hash> {
    let data = std::fs::read(p).map_err(|e| format!("reading '{}': {e}", p.display()))?;
    Ok(Hash::digest(HashAlgo::Sha256, &data))
}
