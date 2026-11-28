//! Client for binary caches in Nix's format: a `nix-cache-info` file,
//! one `<hash>.narinfo` per store path and compressed NARs under `nar/`.
//! `file://` caches are directories; `http(s)://` caches are accessed
//! through an [`HttpClient`], which also uploads to caches that accept
//! `PUT`, `s3://` caches through [`crate::s3`]. A [`NarinfoCache`] can remember lookups between runs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use cranix_core::hash::{HashAlgo, HashSink};
use cranix_core::signing::SecretKey;
use cranix_core::{nar, NarInfo, StoreDir};

use crate::http::HttpClient;
use crate::narinfo_cache::NarinfoCache;
use crate::registry::{Layout, Registry};
use crate::{fsutil, PathInfo, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    Xz,
    Zstd,
    Bzip2,
}

impl Compression {
    pub fn parse(s: &str) -> Result<Compression> {
        match s {
            "none" | "" => Ok(Compression::None),
            "xz" => Ok(Compression::Xz),
            "zstd" => Ok(Compression::Zstd),
            "bzip2" => Ok(Compression::Bzip2),
            c => Err(format!("unsupported compression method '{c}'")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Compression::None => "none",
            Compression::Xz => "xz",
            Compression::Zstd => "zstd",
            Compression::Bzip2 => "bzip2",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Compression::None => "",
            Compression::Xz => ".xz",
            Compression::Zstd => ".zst",
            Compression::Bzip2 => ".bz2",
        }
    }

    /// Wraps `r` in the matching decompressor.
    pub fn decoder<'a>(self, r: impl Read + 'a) -> io::Result<Box<dyn Read + 'a>> {
        Ok(match self {
            Compression::None => Box::new(r),
            Compression::Xz => Box::new(xz2::read::XzDecoder::new_multi_decoder(r)),
            Compression::Zstd => Box::new(zstd::stream::read::Decoder::new(r)?),
            Compression::Bzip2 => Box::new(bzip2::read::MultiBzDecoder::new(r)),
        })
    }
}

/// A compressor that hands back its output writer when finished.
enum Encoder<W: Write> {
    None(W),
    Xz(xz2::write::XzEncoder<W>),
    Zstd(zstd::stream::write::Encoder<'static, W>),
    Bzip2(bzip2::write::BzEncoder<W>),
}

impl<W: Write> Encoder<W> {
    fn new(c: Compression, w: W) -> io::Result<Encoder<W>> {
        Ok(match c {
            Compression::None => Encoder::None(w),
            Compression::Xz => Encoder::Xz(xz2::write::XzEncoder::new(w, 6)),
            Compression::Zstd => Encoder::Zstd(zstd::stream::write::Encoder::new(w, 3)?),
            Compression::Bzip2 => Encoder::Bzip2(bzip2::write::BzEncoder::new(w, bzip2::Compression::best())),
        })
    }

    fn finish(self) -> io::Result<W> {
        match self {
            Encoder::None(w) => Ok(w),
            Encoder::Xz(e) => e.finish(),
            Encoder::Zstd(e) => e.finish(),
            Encoder::Bzip2(e) => e.finish(),
        }
    }
}

impl<W: Write> Write for Encoder<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Encoder::None(w) => w.write(b),
            Encoder::Xz(e) => e.write(b),
            Encoder::Zstd(e) => e.write(b),
            Encoder::Bzip2(e) => e.write(b),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Encoder::None(w) => w.flush(),
            Encoder::Xz(e) => e.flush(),
            Encoder::Zstd(e) => e.flush(),
            Encoder::Bzip2(e) => e.flush(),
        }
    }
}

/// Passes reads through while hashing and counting the bytes.
struct HashingReader<R> {
    inner: R,
    sink: HashSink,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.sink.write_all(&buf[..n])?;
        Ok(n)
    }
}

/// Passes writes through while hashing and counting the bytes.
struct HashingWriter<W> {
    inner: W,
    sink: HashSink,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(b)?;
        self.sink.write_all(&b[..n])?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Feeds the NAR stream to both the NAR hasher and the compressor.
struct Tee<'a, A, B>(&'a mut A, &'a mut B);

impl<A: Write, B: Write> Write for Tee<'_, A, B> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.write_all(b)?;
        self.1.write_all(b)?;
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.1.flush()
    }
}

#[derive(Clone, Debug)]
pub struct CacheInfo {
    pub store_dir: String,
    pub priority: u32,
    pub want_mass_query: bool,
}

/// Prefixes of access tokens issued by GitLab and GitHub.
const TOKEN_PREFIXES: &[&str] = &["glpat-", "glptt-", "gldt-", "ghp_", "gho_", "ghs_", "ghu_", "github_pat_"];

/// Whether a URL path segment looks like a secret: a known token prefix,
/// or 20 or more characters of `[A-Za-z0-9_.-]` holding a run of 16 or more
/// letters and digits with a digit among them (random strings, unlike
/// names made of words), that are not a store path hash, a NAR file name
/// or a narinfo name.
fn looks_like_token(seg: &str) -> bool {
    if TOKEN_PREFIXES.iter().any(|p| seg.starts_with(p)) {
        return true;
    }
    let charset = seg.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    let random_run = seg.split(|c: char| !c.is_ascii_alphanumeric()).any(|r| r.len() >= 16 && r.chars().any(|c| c.is_ascii_digit()));
    if seg.len() < 20 || !charset || !random_run {
        return false;
    }
    // `<hash>`, `<hash>-name`, `<hash>.narinfo`, `<filehash>.nar.xz`.
    let head = seg.split(['.', '-']).next().unwrap_or("");
    let nix32 = |s: &str| s.bytes().all(|c| cranix_core::base32::ALPHABET.contains(&c));
    !((head.len() == 32 || head.len() == 52) && nix32(head))
}

/// Whether a query parameter's value is a secret, judged by its name.
fn secret_param(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    ["token", "key", "secret", "password", "passwd", "auth", "credential"].iter().any(|w| k.contains(w))
}

/// `url` with its secrets hidden, for messages: the password of the user
/// information becomes `***`, path segments that look like access tokens
/// become `<redacted>`, and so do the values of query parameters named like
/// tokens, keys, secrets, passwords or authentication. The scheme, host,
/// port and the other parameters stay as they are.
pub fn redact_url(url: &str) -> String {
    let (main, query) = match url.split_once('?') {
        Some((m, q)) => (m, Some(q)),
        None => (url, None),
    };
    let (scheme, rest) = match main.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, main),
    };
    let (authority, path) = match (scheme, rest.split_once('/')) {
        (Some(_), Some((a, p))) => (Some(a), Some(p)),
        (Some(_), None) => (Some(rest), None),
        (None, _) => (None, Some(rest)),
    };
    let mut out = String::new();
    if let Some(s) = scheme {
        out.push_str(s);
        out.push_str("://");
    }
    if let Some(a) = authority {
        match a.rsplit_once('@') {
            Some((userinfo, host)) => {
                let user = match userinfo.split_once(':') {
                    Some((u, _)) => format!("{u}:***"),
                    None if looks_like_token(userinfo) => "<redacted>".to_string(),
                    None => userinfo.to_string(),
                };
                out.push_str(&format!("{user}@{host}"));
            }
            None => out.push_str(a),
        }
    }
    if let Some(p) = path {
        if authority.is_some() {
            out.push('/');
        }
        let segs: Vec<&str> = p.split('/').collect();
        let shown: Vec<&str> = segs
            .iter()
            .enumerate()
            .map(|(i, s)| if looks_like_token(s) && !(i > 0 && segs[i - 1] == "nar") { "<redacted>" } else { s })
            .collect();
        out.push_str(&shown.join("/"));
    }
    if let Some(q) = query {
        out.push('?');
        let params: Vec<String> = q
            .split('&')
            .map(|kv| match kv.split_once('=') {
                Some((k, _)) if secret_param(k) => format!("{k}=<redacted>"),
                _ => kv.to_string(),
            })
            .collect();
        out.push_str(&params.join("&"));
    }
    out
}

enum Location {
    File(PathBuf),
    Http,
    Registry(Box<dyn Registry>),
    S3(Box<crate::s3::S3>),
}

pub struct BinaryCache {
    /// The cache URL without its query parameters.
    pub url: String,
    location: Location,
    params: BTreeMap<String, String>,
    /// Where uploaded NARs go.
    layout: Layout,
    http: HttpClient,
    disk: Option<NarinfoCache>,
    info: OnceLock<std::result::Result<CacheInfo, String>>,
}

static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp_name(what: &str) -> String {
    format!(".tmp-{what}-{}-{}", std::process::id(), TMP_COUNTER.fetch_add(1, Ordering::Relaxed))
}

impl BinaryCache {
    /// Opens `file:///dir`, `http(s)://host/path`, `s3://bucket`, `gitlab://host/group/project`
    /// or `github://owner/repo`, with optional
    /// `?compression=…&secret-key=…&priority=…` parameters.
    pub fn open(url: &str) -> Result<BinaryCache> {
        let (base, query) = url.split_once('?').unwrap_or((url, ""));
        let base = base.trim_end_matches('/').to_string();
        let mut params = BTreeMap::new();
        for kv in query.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            params.insert(k.to_string(), v.to_string());
        }
        let location = if let Some(p) = base.strip_prefix("file://") {
            if !p.starts_with('/') {
                return Err(format!("binary cache URL '{}' must name an absolute path", redact_url(url)));
            }
            Location::File(PathBuf::from(p))
        } else if base.starts_with("http://") || base.starts_with("https://") {
            Location::Http
        } else if base.starts_with("s3://") {
            Location::S3(Box::new(crate::s3::S3::open(&base, &params)?))
        } else if let Some(r) = crate::registry::open(&base, &params)? {
            Location::Registry(r)
        } else {
            return Err(format!(
                "don't know how to open binary cache '{}'; use a file://, https://, s3://, gitlab:// or github:// URL",
                redact_url(url)
            ));
        };
        let layout = Layout::from_params(&params)?;
        Ok(BinaryCache { url: base, location, params, layout, http: HttpClient::default(), disk: None, info: OnceLock::new() })
    }

    /// Makes HTTP requests with `http`, which carries for example the
    /// credentials for this cache.
    pub fn with_http(mut self, http: HttpClient) -> BinaryCache {
        self.http = http;
        self
    }

    /// Takes the token of a registry cache from `tokens` (Nix's
    /// `access-tokens`, by host) where its URL names no token file.
    pub fn with_access_tokens(mut self, tokens: &BTreeMap<String, String>) -> BinaryCache {
        if let Location::Registry(r) = &mut self.location {
            let mut t = crate::registry::Tokens::from_params(&self.params).unwrap_or_default();
            t.or(tokens.get(r.token_host()));
            r.set_tokens(t);
        }
        self
    }

    /// Whether this cache is a package registry.
    pub fn is_registry(&self) -> bool {
        matches!(self.location, Location::Registry(_))
    }

    /// Remembers narinfo lookups in `disk`, and answers from it while
    /// its entries are fresh.
    pub fn with_narinfo_cache(mut self, disk: NarinfoCache) -> BinaryCache {
        self.disk = Some(disk);
        self
    }

    /// The URL for messages, with its secrets hidden.
    pub fn shown(&self) -> String {
        redact_url(&self.url)
    }

    /// The `trusted` parameter: paths and realisations from this cache are
    /// used even without a signature by one of `trusted-public-keys`.
    pub fn is_trusted(&self) -> bool {
        self.param("trusted") == Some("true")
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    fn file_path(&self, rel: &str) -> Option<PathBuf> {
        match &self.location {
            Location::File(d) => Some(d.join(rel)),
            _ => None,
        }
    }

    fn registry(&self) -> Option<&dyn Registry> {
        match &self.location {
            Location::Registry(r) => Some(r.as_ref()),
            _ => None,
        }
    }

    /// The `nix-cache-info` of a registry, made from the URL parameters.
    fn s3(&self) -> Option<&crate::s3::S3> {
        match &self.location {
            Location::S3(s) => Some(s),
            _ => None,
        }
    }

    fn registry_cache_info(&self) -> Vec<u8> {
        let dir = self.param("store-dir").unwrap_or("/nix/store");
        let prio = self.param("priority").unwrap_or("50");
        format!("StoreDir: {dir}\nWantMassQuery: 1\nPriority: {prio}\n").into_bytes()
    }

    fn http_url(&self, rel: &str) -> String {
        format!("{}/{rel}", self.url)
    }

    /// Reads a small file; `None` when the cache does not have it.
    pub fn get_file(&self, rel: &str) -> Result<Option<Vec<u8>>> {
        if let Some(p) = self.file_path(rel) {
            return match fs::read(&p) {
                Ok(d) => Ok(Some(d)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(format!("reading '{}': {e}", p.display())),
            };
        }
        if let Some(r) = self.registry() {
            if rel == "nix-cache-info" {
                return Ok(Some(self.registry_cache_info()));
            }
            return r.get(&self.http, rel);
        }
        if let Some(s) = self.s3() {
            crate::registry::validate_rel(rel)?;
            return s.get(&self.http, rel);
        }
        let url = self.http_url(rel);
        let resp = self.http.get(&url)?;
        match resp.status {
            200 => Ok(Some(resp.body)),
            // S3 answers 403 for objects that do not exist.
            404 | 403 | 410 => Ok(None),
            c => Err(format!("downloading '{}': HTTP status {c}", redact_url(&url))),
        }
    }

    /// Streams a file that must exist.
    pub fn open_file(&self, rel: &str) -> Result<Box<dyn Read + Send>> {
        if let Some(p) = self.file_path(rel) {
            let f = fs::File::open(&p).map_err(|e| format!("opening '{}': {e}", p.display()))?;
            return Ok(Box::new(io::BufReader::new(f)));
        }
        if let Some(r) = self.registry() {
            if rel == "nix-cache-info" {
                return Ok(Box::new(io::Cursor::new(self.registry_cache_info())));
            }
            return r.open(&self.http, rel);
        }
        if let Some(s) = self.s3() {
            crate::registry::validate_rel(rel)?;
            return s.open_file(&self.http, rel);
        }
        Ok(Box::new(self.http.open(&self.http_url(rel))?))
    }

    pub fn file_exists(&self, rel: &str) -> Result<bool> {
        if let Some(p) = self.file_path(rel) {
            return Ok(p.exists());
        }
        if let Some(r) = self.registry() {
            return if rel == "nix-cache-info" { Ok(true) } else { r.exists(&self.http, rel) };
        }
        if let Some(s) = self.s3() {
            crate::registry::validate_rel(rel)?;
            return s.exists(&self.http, rel);
        }
        Ok(self.http.head(&self.http_url(rel))? == 200)
    }

    /// Stores the file at `src` as `rel`, replacing any previous one.
    pub fn put_file(&self, rel: &str, src: &Path, content_type: &str) -> Result<()> {
        if let Some(dest) = self.file_path(rel) {
            let dir = dest.parent().unwrap();
            fs::create_dir_all(dir).map_err(|e| format!("creating '{}': {e}", dir.display()))?;
            let tmp = dir.join(tmp_name("upload"));
            fs::copy(src, &tmp).map_err(|e| format!("writing '{}': {e}", tmp.display()))?;
            return fs::rename(&tmp, &dest).map_err(|e| format!("writing '{}': {e}", dest.display()));
        }
        if let Some(r) = self.registry() {
            return if rel == "nix-cache-info" { Ok(()) } else { r.put(&self.http, rel, src, content_type) };
        }
        if let Some(s) = self.s3() {
            crate::registry::validate_rel(rel)?;
            return s.put(&self.http, rel, src, content_type);
        }
        self.http.put_file(&self.http_url(rel), src, content_type)
    }

    pub fn put_bytes(&self, rel: &str, data: &[u8], content_type: &str) -> Result<()> {
        let tmp = std::env::temp_dir().join(tmp_name("put"));
        fs::write(&tmp, data).map_err(|e| format!("writing '{}': {e}", tmp.display()))?;
        let r = self.put_file(rel, &tmp, content_type);
        let _ = fs::remove_file(&tmp);
        r
    }

    /// The realisation `id` (`sha256:<hex>!<output>`) the cache holds in
    /// `realisations/<id>.doi`.
    pub fn query_realisation(&self, id: &crate::realisation::DrvOutput) -> Result<Option<crate::realisation::Realisation>> {
        let Some(data) = self.get_file(&format!("realisations/{id}.doi"))? else { return Ok(None) };
        let v: serde_json::Value = serde_json::from_slice(&data).map_err(|e| format!("parsing realisation '{id}' from '{}': {e}", self.shown()))?;
        crate::realisation::Realisation::from_json(&v).map(Some)
    }

    /// Uploads a realisation, signed with `keys` in addition to the
    /// signatures it has.
    pub fn add_realisation(&self, r: &crate::realisation::Realisation, keys: &[SecretKey]) -> Result<()> {
        let mut r = r.clone();
        for k in keys {
            r.sign(k);
        }
        self.put_bytes(&format!("realisations/{}.doi", r.id), r.to_json().to_string().as_bytes(), "application/json")
    }

    /// `nix-cache-info`, fetched once. A cache without one is taken to
    /// hold `/nix/store` paths.
    pub fn info(&self) -> Result<CacheInfo> {
        self.info
            .get_or_init(|| {
                let mut info = CacheInfo { store_dir: "/nix/store".into(), priority: 50, want_mass_query: false };
                let data = match self.disk.as_ref().and_then(NarinfoCache::cache_info) {
                    Some(d) => d,
                    None => {
                        let d = self.get_file("nix-cache-info")?;
                        if let Some(disk) = &self.disk {
                            disk.put_cache_info(&d);
                        }
                        d
                    }
                };
                if let Some(data) = data {
                    for line in String::from_utf8_lossy(&data).lines() {
                        match line.split_once(':').map(|(k, v)| (k.trim(), v.trim())) {
                            Some(("StoreDir", v)) => info.store_dir = v.to_string(),
                            Some(("Priority", v)) => info.priority = v.parse().unwrap_or(info.priority),
                            Some(("WantMassQuery", v)) => info.want_mass_query = v == "1",
                            _ => {}
                        }
                    }
                }
                if let Some(p) = self.param("priority").and_then(|p| p.parse().ok()) {
                    info.priority = p;
                }
                Ok(info)
            })
            .clone()
    }

    /// Creates `nix-cache-info` for a new cache, and checks the store
    /// directory of an existing one.
    pub fn init_for_writing(&self, dir: &StoreDir) -> Result<()> {
        if self.get_file("nix-cache-info")?.is_none() {
            self.put_bytes("nix-cache-info", format!("StoreDir: {}\n", dir.as_str()).as_bytes(), "text/x-nix-cache-info")?;
        }
        let info = self.info()?;
        if info.store_dir != dir.as_str() {
            return Err(format!("binary cache '{}' is for store directory '{}', not '{}'", self.shown(), info.store_dir, dir.as_str()));
        }
        Ok(())
    }

    pub fn query_narinfo(&self, dir: &StoreDir, hash_part: &str) -> Result<Option<NarInfo>> {
        let rel = format!("{hash_part}.narinfo");
        let data = match self.disk.as_ref().and_then(|d| d.narinfo(hash_part)) {
            Some(d) => d,
            None => {
                let d = self.get_file(&rel)?;
                if let Some(disk) = &self.disk {
                    disk.put_narinfo(hash_part, &d);
                }
                d
            }
        };
        match data {
            Some(d) => NarInfo::parse(dir, &String::from_utf8_lossy(&d), &format!("{}/{rel}", self.shown())).map(Some),
            None => Ok(None),
        }
    }

    /// Downloads the NAR of `ni`, unpacks it to `dest` and checks the file
    /// and NAR hashes and sizes while streaming. `dest` is removed again
    /// when anything does not match.
    pub fn fetch_nar(&self, dir: &StoreDir, ni: &NarInfo, dest: &Path) -> Result<()> {
        let r = self.fetch_nar_inner(dir, ni, dest);
        if r.is_err() {
            let _ = fsutil::remove_all(dest);
        }
        r
    }

    fn fetch_nar_inner(&self, dir: &StoreDir, ni: &NarInfo, dest: &Path) -> Result<()> {
        let what = dir.print(&ni.path);
        let compression = Compression::parse(&ni.compression)?;
        let file_algo = ni.file_hash.as_ref().map_or(HashAlgo::Sha256, |h| h.algo);
        let mut file_r = HashingReader { inner: self.open_file(&ni.url)?, sink: HashSink::new(file_algo) };
        let err = |e: io::Error| format!("unpacking '{what}' from '{}': {e}", self.shown());
        let (nar_hash, nar_size) = {
            let dec = compression.decoder(&mut file_r).map_err(err)?;
            let mut nar_r = HashingReader { inner: dec, sink: HashSink::new(ni.nar_hash.algo) };
            nar::restore(&mut nar_r, dest).map_err(err)?;
            io::copy(&mut nar_r, &mut io::sink()).map_err(err)?;
            nar_r.sink.finish()
        };
        io::copy(&mut file_r, &mut io::sink()).map_err(err)?;
        let (file_hash, file_size) = file_r.sink.finish();
        if let Some(want) = &ni.file_hash {
            if *want != file_hash {
                return Err(format!(
                    "hash mismatch in '{}' of '{what}':\n  specified: {}\n  got:       {}",
                    ni.url,
                    want.to_sri(),
                    file_hash.to_sri()
                ));
            }
        }
        if ni.file_size.is_some_and(|n| n != file_size) {
            return Err(format!("size mismatch in '{}' of '{what}': expected {}, got {file_size}", ni.url, ni.file_size.unwrap()));
        }
        if nar_hash != ni.nar_hash || nar_size != ni.nar_size {
            return Err(format!(
                "NAR hash mismatch in '{what}' from '{}':\n  specified: {} ({} bytes)\n  got:       {} ({nar_size} bytes)",
                self.shown(),
                ni.nar_hash.to_sri(),
                ni.nar_size,
                nar_hash.to_sri()
            ));
        }
        Ok(())
    }

    /// Uploads `real` (the contents of `info.path`) as a compressed NAR
    /// and writes its narinfo, carrying `sigs` plus a signature by each of
    /// `keys`. The NAR must match `info`'s hash.
    pub fn add_path(
        &self,
        dir: &StoreDir,
        real: &Path,
        info: &PathInfo,
        sigs: &[String],
        keys: &[SecretKey],
    ) -> Result<NarInfo> {
        let compression = Compression::parse(self.param("compression").unwrap_or("xz"))?;
        let tmp = std::env::temp_dir().join(tmp_name("nar"));
        let r = (|| {
            let what = dir.print(&info.path);
            let err = |e: io::Error| format!("archiving '{what}': {e}");
            let file = fs::File::create(&tmp).map_err(|e| format!("creating '{}': {e}", tmp.display()))?;
            let out = HashingWriter { inner: io::BufWriter::new(file), sink: HashSink::new(HashAlgo::Sha256) };
            let mut enc = Encoder::new(compression, out).map_err(err)?;
            let mut nar_sink = HashSink::new(HashAlgo::Sha256);
            nar::dump(real, Tee(&mut nar_sink, &mut enc)).map_err(err)?;
            let mut out = enc.finish().map_err(err)?;
            out.flush().map_err(err)?;
            let (nar_hash, nar_size) = nar_sink.finish();
            if nar_hash != info.nar_hash || nar_size != info.nar_size {
                return Err(format!("path '{what}' was modified: its contents no longer match the NAR hash in the store"));
            }
            let (file_hash, file_size) = out.sink.finish();
            let url = self.layout.nar_rel(&info.path, &format!("{}.nar{}", file_hash.to_nix32(), compression.extension()));
            if !self.file_exists(&url)? {
                self.put_file(&url, &tmp, "application/x-nix-nar")?;
            }
            let mut ni = NarInfo {
                path: info.path.clone(),
                url,
                compression: compression.name().into(),
                file_hash: Some(file_hash),
                file_size: Some(file_size),
                nar_hash,
                nar_size,
                references: info.references.clone(),
                deriver: info.deriver.clone(),
                sigs: Vec::new(),
                ca: info.ca.clone(),
            };
            let fp = ni.fingerprint(dir)?;
            let mut all: BTreeSet<String> = sigs.iter().cloned().collect();
            all.extend(keys.iter().map(|k| k.sign(fp.as_bytes())));
            ni.sigs = all.into_iter().collect();
            // The narinfo goes up last, so that a cache never offers a
            // path whose NAR is missing.
            let text = ni.to_text(dir);
            self.put_bytes(&format!("{}.narinfo", info.path.hash_part()), text.as_bytes(), "text/x-nix-narinfo")?;
            if let Some(disk) = &self.disk {
                disk.put_narinfo(info.path.hash_part(), &Some(text.into_bytes()));
            }
            Ok(ni)
        })();
        let _ = fs::remove_file(&tmp);
        r
    }
}

impl std::fmt::Debug for BinaryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BinaryCache({})", self.shown())
    }
}

/// Reads the secret keys named by `secret-key-files` (or a cache's
/// `secret-key` parameter).
pub fn read_secret_keys<'a>(files: impl IntoIterator<Item = &'a str>) -> Result<Vec<SecretKey>> {
    files
        .into_iter()
        .map(|f| {
            let t = fs::read_to_string(f).map_err(|e| format!("reading secret key file '{f}': {e}"))?;
            SecretKey::parse(&t)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use cranix_core::signing::PublicKey;
    use cranix_core::StorePath;

    #[test]
    fn redacts_secrets_in_urls() {
        let r = redact_url;
        assert_eq!(r("http://host:5080/glpat-TESTTOKEN0123456789/?priority=10&trusted=true"), "http://host:5080/<redacted>/?priority=10&trusted=true");
        assert_eq!(r("https://user:hunter2@cache.example.org/"), "https://user:***@cache.example.org/");
        assert_eq!(r("https://glpat-TESTTOKEN0123456789@cache.example.org"), "https://<redacted>@cache.example.org");
        assert_eq!(r("https://c.example/x?token=abc&compression=zstd&secret-key=/k&priority=40"), "https://c.example/x?token=<redacted>&compression=zstd&secret-key=<redacted>&priority=40");
        assert_eq!(r("https://h/api/v4/projects/12/packages/AbCdEf0123456789xyzQRS/nix"), "https://h/api/v4/projects/12/packages/<redacted>/nix");
        assert_eq!(r("https://h/ghp_short"), "https://h/<redacted>");
        // Store hashes, NAR files, narinfos and plain names stay.
        let plain = [
            "https://cache.nixos.org",
            "https://cache.nixos.org/nix-cache-info",
            "https://cache.nixos.org/0mji3qb7l6i7ywfyqm2xrriavjlxmnfn.narinfo",
            "https://h/nar/1i7bv7ya2j2z5y4y7kzig8b3c20d07hkh07wgiipv0ha9k3rxgh1.nar.xz",
            "https://h/my-company-binary-cache-prod/",
            "file:///var/cache/nix-binary-cache-2024",
            "file:///tmp/c?trusted=true",
        ];
        for u in plain {
            assert_eq!(r(u), u);
        }
    }

    #[test]
    fn file_cache_round_trip() {
        let root = std::env::temp_dir().join(format!("cranix-bc-{}", std::process::id()));
        let _ = fsutil::remove_all(&root);
        let src = root.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("sub/file"), b"contents").unwrap();
        let dir = StoreDir::default();
        let (nar_hash, nar_size) = crate::Store::nar_hash(&src).unwrap();
        let path = StorePath::from_base_name("00000000000000000000000000000000-example").unwrap();
        let info = PathInfo { path: path.clone(), nar_hash, nar_size, references: BTreeSet::new(), deriver: None, ca: None };
        let key = SecretKey::from_seed("test-1", &[3; 32]);
        for comp in ["xz", "zstd", "bzip2", "none"] {
            let cache = BinaryCache::open(&format!("file://{}/cache-{comp}?compression={comp}", root.display())).unwrap();
            cache.init_for_writing(&dir).unwrap();
            assert_eq!(cache.info().unwrap().store_dir, "/nix/store");
            let ni = cache.add_path(&dir, &src, &info, &[], std::slice::from_ref(&key)).unwrap();
            let back = cache.query_narinfo(&dir, path.hash_part()).unwrap().unwrap();
            assert_eq!(back, ni);
            assert_eq!(back.compression, comp);
            assert!(back.is_trusted(&dir, &[key.to_public()]));
            assert!(!back.is_trusted(&dir, &[PublicKey::parse(crate::settings::DEFAULT_CACHE_KEY).unwrap()]));
            let dest = root.join(format!("out-{comp}"));
            cache.fetch_nar(&dir, &back, &dest).unwrap();
            assert_eq!(fs::read(dest.join("sub/file")).unwrap(), b"contents");
            let mut bad = back.clone();
            bad.nar_size += 1;
            let dest2 = root.join(format!("bad-{comp}"));
            assert!(cache.fetch_nar(&dir, &bad, &dest2).unwrap_err().contains("mismatch"));
            assert!(!dest2.exists());
        }
        assert!(BinaryCache::open("ftp://x").is_err());
        assert!(BinaryCache::open(&format!("file://{}/none", root.display())).unwrap().query_narinfo(&dir, "x").unwrap().is_none());
        fsutil::remove_all(&root).unwrap();
    }
}
