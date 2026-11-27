//! Package registries as binary cache backends.
//!
//! `gitlab://HOST/GROUP/PROJECT` keeps files in the GitLab generic package
//! registry of a project, `github://OWNER/REPO` in the GitHub container
//! registry, one OCI manifest per file with the file as its only layer.
//!
//! Files are grouped into registry packages:
//!
//! - `<hash>.narinfo` goes to `nix-<first two characters of hash>`;
//! - `nar/<file>` goes to `nix-<first two characters of file>`;
//! - `nar/<group>/<file>` goes to the package `<group>`, which the layout
//!   picks when the NAR is uploaded (see [`Layout`]);
//! - everything else goes to `nix-meta`.
//!
//! The package of a NAR is part of the URL in its narinfo, so reading a
//! cache works with any layout. `nix-cache-info` is answered locally.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cranix_core::hash::{base64_encode, Hash, HashAlgo, HashSink};
use cranix_core::StorePath;

use crate::binary_cache::redact_url;
use crate::http::{HttpClient, Response};
use crate::Result;

/// How NARs are grouped into registry packages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Layout {
    /// By the first two characters of the NAR's file hash.
    Hash,
    /// By the name of the store path without its version.
    Name,
    /// Everything in one package, for example all a release needs.
    Group(String),
}

impl Layout {
    /// From the `layout` and `group` parameters of a cache URL.
    pub fn from_params(params: &BTreeMap<String, String>) -> Result<Layout> {
        let group = params.get("group").filter(|g| !g.is_empty());
        match (params.get("layout").map(String::as_str), group) {
            (None, Some(g)) | (Some("group"), Some(g)) => Ok(Layout::Group(package_name(g)?)),
            (Some("group"), None) => Err("layout 'group' needs a 'group' parameter".into()),
            (None | Some("hash"), None) => Ok(Layout::Hash),
            (Some("name"), None) => Ok(Layout::Name),
            (Some(l), _) => Err(format!("unknown registry layout '{l}'; use 'hash', 'name' or 'group'")),
        }
    }

    /// The cache-relative name of the NAR `file` of `path`.
    pub fn nar_rel(&self, path: &StorePath, file: &str) -> String {
        match self {
            Layout::Hash => format!("nar/{file}"),
            Layout::Name => format!("nar/{}/{file}", name_package(path.name())),
            Layout::Group(g) => format!("nar/{g}/{file}"),
        }
    }
}

/// The package for a store path name: the part before the version (the
/// first `-` followed by a digit), with characters outside
/// `[a-z0-9._-]` replaced by `_`.
fn name_package(name: &str) -> String {
    let b = name.as_bytes();
    let end = (0..b.len()).find(|&i| b[i] == b'-' && b.get(i + 1).is_some_and(u8::is_ascii_digit)).unwrap_or(b.len());
    let p: String = name[..end]
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c.to_ascii_lowercase() } else { '_' })
        .collect();
    let p = p.trim_start_matches(['.', '-', '_']);
    if p.is_empty() { "nix-unnamed".into() } else { p.to_string() }
}

/// Checks a package name given by the user: lower-case letters, digits,
/// `.`, `_` and `-`, starting with a letter or digit.
fn package_name(g: &str) -> Result<String> {
    let ok = g.len() <= 100
        && g.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && g.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if ok { Ok(g.to_string()) } else { Err(format!("invalid registry package name '{g}'")) }
}

/// Checks a cache-relative file name: segments of `[A-Za-z0-9._+:!=-]`,
/// none empty, `.` or `..`, so a request stays at the registry endpoint.
pub fn validate_rel(rel: &str) -> Result<()> {
    let ok = !rel.is_empty()
        && rel.split('/').all(|s| {
            !s.is_empty() && s != "." && s != ".." && s.chars().all(|c| c.is_ascii_alphanumeric() || "._+:!=-".contains(c))
        });
    if ok { Ok(()) } else { Err(format!("invalid binary cache file name '{rel}'")) }
}

/// Where a file lives in a registry: its package and its file name.
#[derive(Debug, PartialEq, Eq)]
pub struct Place {
    pub package: String,
    pub file: String,
}

fn nix32_prefix(s: &str) -> Option<&str> {
    let head = s.get(..2)?;
    head.bytes().all(|c| cranix_core::base32::ALPHABET.contains(&c)).then_some(head)
}

/// The place of `rel`. File names outside `[A-Za-z0-9._-]` are encoded by
/// `escape`.
pub fn place(rel: &str, escape: fn(&str) -> String) -> Result<Place> {
    validate_rel(rel)?;
    let segs: Vec<&str> = rel.split('/').collect();
    let meta = || Place { package: "nix-meta".into(), file: escape(rel) };
    Ok(match segs.as_slice() {
        [f] if f.ends_with(".narinfo") => match nix32_prefix(f) {
            Some(p) => Place { package: format!("nix-{p}"), file: f.to_string() },
            None => meta(),
        },
        ["nar", f] => match nix32_prefix(f) {
            Some(p) => Place { package: format!("nix-{p}"), file: escape(f) },
            None => meta(),
        },
        ["nar", g, f] => Place { package: package_name(g)?, file: escape(f) },
        _ => meta(),
    })
}

/// Escapes for GitLab file names: other characters than `[A-Za-z0-9._-]`
/// become `+XX`.
fn escape_plus(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
            out.push(b as char);
        } else {
            out.push_str(&format!("+{b:02X}"));
        }
    }
    out
}

/// Escapes for OCI tags: other characters than `[A-Za-z0-9.-]` become
/// `_XX`.
fn escape_underscore(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-') {
            out.push(b as char);
        } else {
            out.push_str(&format!("_{b:02X}"));
        }
    }
    out
}

/// The tokens a registry cache sends: `read` with `GET` and `HEAD`,
/// `write` with uploads. Each falls back to the other.
#[derive(Clone, Default)]
pub struct Tokens {
    pub read: Option<String>,
    pub write: Option<String>,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tokens {{ read: {}, write: {} }}", self.read.is_some(), self.write.is_some())
    }
}

fn read_token_file(path: &str) -> Result<String> {
    let t = fs::read_to_string(path).map_err(|e| format!("reading token file '{path}': {e}"))?;
    Ok(t.trim().to_string())
}

impl Tokens {
    /// From the `token-file`, `read-token-file` and `write-token-file`
    /// parameters.
    pub fn from_params(params: &BTreeMap<String, String>) -> Result<Tokens> {
        let file = |k: &str| params.get(k).filter(|v| !v.is_empty()).map(|p| read_token_file(p)).transpose();
        let both = file("token-file")?;
        Ok(Tokens { read: file("read-token-file")?.or(both.clone()), write: file("write-token-file")?.or(both) })
    }

    /// Uses `token` for whatever has no token yet.
    pub fn or(&mut self, token: Option<&String>) {
        if let Some(t) = token {
            self.read.get_or_insert_with(|| t.clone());
            self.write.get_or_insert_with(|| t.clone());
        }
    }

    fn get(&self, write: bool) -> Option<&str> {
        let (a, b) = if write { (&self.write, &self.read) } else { (&self.read, &self.write) };
        a.as_deref().or(b.as_deref())
    }
}

/// A registry that holds the files of a binary cache.
pub trait Registry: Send + Sync {
    /// The host whose `access-tokens` entry this registry uses.
    fn token_host(&self) -> &str;
    fn set_tokens(&mut self, tokens: Tokens);
    /// The file `rel`; `None` when it is missing.
    fn get(&self, http: &HttpClient, rel: &str) -> Result<Option<Vec<u8>>>;
    /// Streams the file `rel`, which must exist.
    fn open(&self, http: &HttpClient, rel: &str) -> Result<Box<dyn Read + Send>>;
    fn exists(&self, http: &HttpClient, rel: &str) -> Result<bool>;
    fn put(&self, http: &HttpClient, rel: &str, src: &Path, content_type: &str) -> Result<()>;
}

/// Opens `gitlab://…` or `github://…`; `None` for other URLs.
pub fn open(url: &str, params: &BTreeMap<String, String>) -> Result<Option<Box<dyn Registry>>> {
    let tokens = Tokens::from_params(params)?;
    let version = params.get("version").cloned().unwrap_or_else(|| "v1".into());
    if !version.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) || version.is_empty() {
        return Err(format!("invalid registry package version '{version}'"));
    }
    if let Some(rest) = url.strip_prefix("gitlab://") {
        let (host, project) = rest.split_once('/').filter(|(h, p)| !h.is_empty() && !p.is_empty()).ok_or_else(|| {
            format!("binary cache URL '{}' must have the form gitlab://HOST/GROUP/PROJECT", redact_url(url))
        })?;
        let scheme = params.get("scheme").map_or("https", String::as_str);
        let api = format!("{scheme}://{host}/api/v4/projects/{}/packages/generic", project.replace('/', "%2F"));
        let token_type = params.get("token-type").cloned();
        return Ok(Some(Box::new(GitLab { host: host.to_string(), api, version, tokens, token_type })));
    }
    if let Some(rest) = url.strip_prefix("github://") {
        let mut it = rest.split('/');
        let (Some(owner), Some(repo), None) = (it.next(), it.next(), it.next()) else {
            return Err(format!("binary cache URL '{}' must have the form github://OWNER/REPO", redact_url(url)));
        };
        if owner.is_empty() || repo.is_empty() {
            return Err(format!("binary cache URL '{}' must have the form github://OWNER/REPO", redact_url(url)));
        }
        let base = params.get("registry").cloned().unwrap_or_else(|| "https://ghcr.io".into());
        let base = base.trim_end_matches('/').to_string();
        let service = base.split_once("://").map_or(base.as_str(), |(_, h)| h).to_string();
        return Ok(Some(Box::new(Oci {
            base,
            service,
            prefix: format!("{owner}/{repo}").to_ascii_lowercase(),
            version,
            tokens,
            bearer: Mutex::new(BTreeMap::new()),
        })));
    }
    Ok(None)
}

/// The GitLab generic package registry of one project.
struct GitLab {
    host: String,
    /// `…/api/v4/projects/<id>/packages/generic`.
    api: String,
    version: String,
    tokens: Tokens,
    /// `job` sends the token as `JOB-TOKEN`.
    token_type: Option<String>,
}

impl GitLab {
    fn url(&self, rel: &str) -> Result<String> {
        let p = place(rel, escape_plus)?;
        Ok(format!("{}/{}/{}/{}", self.api, p.package, self.version, p.file))
    }

    fn client(&self, http: &HttpClient, write: bool) -> HttpClient {
        match self.tokens.get(write) {
            None => http.clone(),
            Some(t) if self.token_type.as_deref() == Some("job") => http.clone().header("JOB-TOKEN", t),
            Some(t) if t.starts_with("gldt-") => http.clone().header("Deploy-Token", t),
            Some(t) => http.clone().header("PRIVATE-TOKEN", t),
        }
    }
}

fn denied(what: &str, url: &str, status: u16, write: bool) -> String {
    let token = if write { "write" } else { "read" };
    format!("{what} '{}': HTTP status {status}; check the {token} token of this cache", redact_url(url))
}

impl Registry for GitLab {
    fn token_host(&self) -> &str {
        &self.host
    }

    fn set_tokens(&mut self, tokens: Tokens) {
        self.tokens = tokens;
    }

    fn get(&self, http: &HttpClient, rel: &str) -> Result<Option<Vec<u8>>> {
        let url = self.url(rel)?;
        let resp = self.client(http, false).get(&url)?;
        match resp.status {
            200 => Ok(Some(resp.body)),
            404 => Ok(None),
            s @ (401 | 403) => Err(denied("downloading", &url, s, false)),
            s => Err(format!("downloading '{}': HTTP status {s}", redact_url(&url))),
        }
    }

    fn open(&self, http: &HttpClient, rel: &str) -> Result<Box<dyn Read + Send>> {
        Ok(Box::new(self.client(http, false).open(&self.url(rel)?)?))
    }

    fn exists(&self, http: &HttpClient, rel: &str) -> Result<bool> {
        let url = self.url(rel)?;
        match self.client(http, false).head(&url)? {
            200 => Ok(true),
            404 => Ok(false),
            s @ (401 | 403) => Err(denied("querying", &url, s, false)),
            s => Err(format!("querying '{}': HTTP status {s}", redact_url(&url))),
        }
    }

    fn put(&self, http: &HttpClient, rel: &str, src: &Path, _content_type: &str) -> Result<()> {
        let url = self.url(rel)?;
        let resp = self.client(http, true).send("PUT", &url, &[], Some(src))?;
        match resp.status {
            200..=299 => Ok(()),
            s @ (401 | 403) => Err(denied("uploading to", &url, s, true)),
            s => Err(format!("uploading to '{}': HTTP status {s}", redact_url(&url))),
        }
    }
}

const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const EMPTY_TYPE: &str = "application/vnd.oci.empty.v1+json";
const EMPTY_DIGEST: &str = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// An OCI registry (the GitHub container registry by default). Each file
/// is a manifest, tagged `<version>.<file>` in the repository
/// `<owner>/<repo>/<package>`, whose one layer is the file.
struct Oci {
    /// `https://ghcr.io`.
    base: String,
    /// The `service` the token endpoint expects, the registry host.
    service: String,
    /// `<owner>/<repo>`, lower case.
    prefix: String,
    version: String,
    tokens: Tokens,
    /// Bearer tokens by `<repository> <actions>`.
    bearer: Mutex<BTreeMap<String, Option<String>>>,
}

fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let mut f = fs::File::open(path).map_err(|e| format!("reading '{}': {e}", path.display()))?;
    let mut sink = HashSink::new(HashAlgo::Sha256);
    io::copy(&mut f, &mut sink).map_err(|e| format!("reading '{}': {e}", path.display()))?;
    let (h, n) = sink.finish();
    Ok((format!("sha256:{}", h.to_base16()), n))
}

impl Oci {
    fn repo_tag(&self, rel: &str) -> Result<(String, String)> {
        let p = place(rel, escape_underscore)?;
        let mut tag = format!("{}.{}", self.version, p.file);
        if tag.len() > 128 {
            tag = format!("{}.h{}", self.version, Hash::sha256(p.file.as_bytes()).to_base16());
        }
        Ok((format!("{}/{}", self.prefix, p.package), tag))
    }

    /// A bearer token for `actions` (`pull` or `pull,push`) on `repo`,
    /// from the registry's token endpoint; `None` when it has none.
    fn bearer(&self, http: &HttpClient, repo: &str, write: bool) -> Result<Option<String>> {
        let actions = if write { "pull,push" } else { "pull" };
        let key = format!("{repo} {actions}");
        if let Some(t) = self.bearer.lock().unwrap().get(&key) {
            return Ok(t.clone());
        }
        let url = format!("{}/token?service={}&scope=repository:{repo}:{actions}", self.base, self.service);
        let client = match self.tokens.get(write) {
            Some(t) => http.clone().header("Authorization", &format!("Basic {}", base64_encode(format!("cranix:{t}").as_bytes()))),
            None => http.clone(),
        };
        let resp = client.get(&url)?;
        let token = match resp.status {
            200 => {
                let v: serde_json::Value =
                    serde_json::from_slice(&resp.body).map_err(|e| format!("parsing the answer of '{}': {e}", redact_url(&url)))?;
                v.get("token").or_else(|| v.get("access_token")).and_then(|t| t.as_str()).map(str::to_string)
            }
            404 => None,
            s @ (401 | 403) => return Err(denied("authenticating at", &url, s, write)),
            s => return Err(format!("authenticating at '{}': HTTP status {s}", redact_url(&url))),
        };
        self.bearer.lock().unwrap().insert(key, token.clone());
        Ok(token)
    }

    fn client(&self, http: &HttpClient, repo: &str, write: bool) -> Result<HttpClient> {
        Ok(match self.bearer(http, repo, write)? {
            Some(t) => http.clone().bearer_token(&t),
            None => http.clone(),
        })
    }

    /// The digest of the one layer of the manifest `tag`.
    fn layer(&self, client: &HttpClient, repo: &str, tag: &str) -> Result<Option<String>> {
        let url = format!("{}/v2/{repo}/manifests/{tag}", self.base);
        let resp = client.send("GET", &url, &[("Accept", MANIFEST_TYPE)], None)?;
        match resp.status {
            200 => {
                let v: serde_json::Value =
                    serde_json::from_slice(&resp.body).map_err(|e| format!("parsing manifest '{}': {e}", redact_url(&url)))?;
                let d = v["layers"][0]["digest"].as_str().ok_or_else(|| format!("manifest '{}' has no layer", redact_url(&url)))?;
                Ok(Some(d.to_string()))
            }
            404 => Ok(None),
            s => Err(oci_error("downloading", &url, &resp, s)),
        }
    }

    /// Uploads the blob `src` unless the repository has it.
    fn put_blob(&self, client: &HttpClient, repo: &str, src: &Path, digest: &str) -> Result<()> {
        let blob = format!("{}/v2/{repo}/blobs/{digest}", self.base);
        if client.send("HEAD", &blob, &[], None)?.status == 200 {
            return Ok(());
        }
        let start = format!("{}/v2/{repo}/blobs/uploads/", self.base);
        let resp = client.send("POST", &start, &[("Content-Length", "0")], None)?;
        if resp.status != 202 {
            return Err(oci_error("uploading to", &start, &resp, resp.status));
        }
        let loc = resp.header("location").ok_or_else(|| format!("uploading to '{}': no upload location", redact_url(&start)))?;
        let loc = if loc.starts_with('/') { format!("{}{loc}", self.base) } else { loc.to_string() };
        let sep = if loc.contains('?') { '&' } else { '?' };
        let put = format!("{loc}{sep}digest={digest}");
        let resp = client.send("PUT", &put, &[("Content-Type", "application/octet-stream")], Some(src))?;
        match resp.status {
            201 | 204 => Ok(()),
            s => Err(oci_error("uploading to", &blob, &resp, s)),
        }
    }
}

fn oci_error(what: &str, url: &str, resp: &Response, status: u16) -> String {
    let msg = serde_json::from_slice::<serde_json::Value>(&resp.body)
        .ok()
        .and_then(|v| v["errors"][0]["message"].as_str().map(str::to_string));
    let hint = match status {
        401 | 403 => "; check the token of this cache",
        _ => "",
    };
    match msg {
        Some(m) => format!("{what} '{}': HTTP status {status}: {m}{hint}", redact_url(url)),
        None => format!("{what} '{}': HTTP status {status}{hint}", redact_url(url)),
    }
}

fn tmp_file(data: &[u8]) -> Result<PathBuf> {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!(".tmp-oci-{}-{n}", std::process::id()));
    fs::write(&p, data).map_err(|e| format!("writing '{}': {e}", p.display()))?;
    Ok(p)
}

impl Registry for Oci {
    fn token_host(&self) -> &str {
        if self.service == "ghcr.io" { "github.com" } else { &self.service }
    }

    fn set_tokens(&mut self, tokens: Tokens) {
        self.tokens = tokens;
        self.bearer.lock().unwrap().clear();
    }

    fn get(&self, http: &HttpClient, rel: &str) -> Result<Option<Vec<u8>>> {
        let (repo, tag) = self.repo_tag(rel)?;
        let client = self.client(http, &repo, false)?;
        let Some(digest) = self.layer(&client, &repo, &tag)? else { return Ok(None) };
        let url = format!("{}/v2/{repo}/blobs/{digest}", self.base);
        let resp = client.get(&url)?;
        if resp.status != 200 {
            return Err(oci_error("downloading", &url, &resp, resp.status));
        }
        let got = format!("sha256:{}", Hash::sha256(&resp.body).to_base16());
        if got != digest {
            return Err(format!("downloading '{}': digest mismatch, got {got}", redact_url(&url)));
        }
        Ok(Some(resp.body))
    }

    fn open(&self, http: &HttpClient, rel: &str) -> Result<Box<dyn Read + Send>> {
        let (repo, tag) = self.repo_tag(rel)?;
        let client = self.client(http, &repo, false)?;
        let digest = self.layer(&client, &repo, &tag)?.ok_or_else(|| format!("file '{rel}' is missing from the registry"))?;
        Ok(Box::new(client.open(&format!("{}/v2/{repo}/blobs/{digest}", self.base))?))
    }

    fn exists(&self, http: &HttpClient, rel: &str) -> Result<bool> {
        let (repo, tag) = self.repo_tag(rel)?;
        let client = self.client(http, &repo, false)?;
        let url = format!("{}/v2/{repo}/manifests/{tag}", self.base);
        let resp = client.send("HEAD", &url, &[("Accept", MANIFEST_TYPE)], None)?;
        match resp.status {
            200 => Ok(true),
            404 => Ok(false),
            s => Err(oci_error("querying", &url, &resp, s)),
        }
    }

    fn put(&self, http: &HttpClient, rel: &str, src: &Path, content_type: &str) -> Result<()> {
        let (repo, tag) = self.repo_tag(rel)?;
        let client = self.client(http, &repo, true)?;
        let (digest, size) = sha256_file(src)?;
        self.put_blob(&client, &repo, src, &digest)?;
        let empty = tmp_file(b"{}")?;
        let r = self.put_blob(&client, &repo, &empty, EMPTY_DIGEST);
        let _ = fs::remove_file(&empty);
        r?;
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST_TYPE,
            "artifactType": "application/vnd.cranix.cache-file.v1",
            "config": { "mediaType": EMPTY_TYPE, "digest": EMPTY_DIGEST, "size": 2 },
            "layers": [{
                "mediaType": content_type,
                "digest": digest,
                "size": size,
                "annotations": { "org.opencontainers.image.title": rel },
            }],
        });
        let m = tmp_file(manifest.to_string().as_bytes())?;
        let url = format!("{}/v2/{repo}/manifests/{tag}", self.base);
        let resp = client.send("PUT", &url, &[("Content-Type", MANIFEST_TYPE)], Some(&m));
        let _ = fs::remove_file(&m);
        let resp = resp?;
        match resp.status {
            200..=299 => Ok(()),
            s => Err(oci_error("uploading to", &url, &resp, s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn places() {
        let h = "0123456789abcdfghijklmnpqrsvwxyz";
        assert_eq!(place(&format!("{h}.narinfo"), escape_plus).unwrap(), Place { package: "nix-01".into(), file: format!("{h}.narinfo") });
        assert_eq!(place("nar/ab12.nar.xz", escape_plus).unwrap().package, "nix-ab");
        assert_eq!(place("nar/hello/ab12.nar.xz", escape_plus).unwrap(), Place { package: "hello".into(), file: "ab12.nar.xz".into() });
        let r = place("realisations/sha256:00!out.doi", escape_plus).unwrap();
        assert_eq!(r, Place { package: "nix-meta".into(), file: "realisations+2Fsha256+3A00+21out.doi".into() });
        assert_eq!(place("log/x", escape_underscore).unwrap().file, "log_2Fx");
        for bad in ["", "/x", "a//b", "../x", "nar/../x", "a/./b", "a b", "a%2Fb", "nar/Upper/x", "x?y"] {
            assert!(place(bad, escape_plus).is_err(), "{bad}");
        }
    }

    #[test]
    fn layouts() {
        let p = StorePath::from_base_name("0123456789abcdfghijklmnpqrsvwxyz-Hello+World-2.12.1").unwrap();
        let params = |kv: &[(&str, &str)]| kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        assert_eq!(Layout::from_params(&params(&[])).unwrap().nar_rel(&p, "f.nar"), "nar/f.nar");
        assert_eq!(Layout::from_params(&params(&[("layout", "name")])).unwrap().nar_rel(&p, "f.nar"), "nar/hello_world/f.nar");
        assert_eq!(Layout::from_params(&params(&[("group", "rel-1.0")])).unwrap().nar_rel(&p, "f.nar"), "nar/rel-1.0/f.nar");
        assert!(Layout::from_params(&params(&[("layout", "group")])).is_err());
        assert!(Layout::from_params(&params(&[("group", "../x")])).is_err());
        assert!(Layout::from_params(&params(&[("layout", "other")])).is_err());
    }

    #[test]
    fn urls() {
        let none = BTreeMap::new();
        assert!(open("gitlab://host", &none).is_err());
        assert!(open("github://owner", &none).is_err());
        assert!(open("github://a/b/c", &none).is_err());
        assert!(open("https://x", &none).unwrap().is_none());
        let g = open("github://Owner/Repo", &none).unwrap().unwrap();
        assert_eq!(g.token_host(), "github.com");
        let l = open("gitlab://gitlab.example.com/group/sub/project", &none).unwrap().unwrap();
        assert_eq!(l.token_host(), "gitlab.example.com");
    }

    #[test]
    fn tokens_fall_back() {
        let mut t = Tokens { read: Some("r".into()), write: None };
        assert_eq!((t.get(false), t.get(true)), (Some("r"), Some("r")));
        t.or(Some(&"w".to_string()));
        assert_eq!((t.get(false), t.get(true)), (Some("r"), Some("w")));
        assert!(!format!("{t:?}").contains('r') || format!("{t:?}").contains("read: true"));
    }
}
