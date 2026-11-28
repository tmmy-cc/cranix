//! S3 and S3 compatible object stores as binary cache backends.
//!
//! `s3://BUCKET[/PREFIX]?region=…&endpoint=…&scheme=…&profile=…` names a
//! bucket. Requests are made with an [`HttpClient`] and signed with AWS
//! signature version 4. Credentials come, in this order, from the
//! environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
//! `AWS_SESSION_TOKEN`), the shared credentials and config files (the
//! `profile` parameter, else `AWS_PROFILE`, else `default`), the container
//! credentials endpoint and the instance role of an EC2 instance. Without
//! any, requests go unsigned, which reads public buckets.
//!
//! Without `endpoint` the bucket is at AWS, addressed as
//! `BUCKET.s3.REGION.amazonaws.com`; with one (`host[:port]` or a URL) it
//! is addressed by path, `ENDPOINT/BUCKET/KEY`, which is what S3
//! compatible services expect. `addressing-style=path|virtual` overrides
//! either. Files larger than `multipart-threshold` bytes (default 64 MiB)
//! go up in parts of `buffer-size` bytes (default 16 MiB, at least 5 MiB).
//!
//! Signing keys and session tokens go to curl on its standard input with
//! the other headers, and never appear in messages.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::binary_cache::redact_url;
use crate::http::{HttpClient, Response};
use crate::Result;

/// The SHA-256 of nothing, the payload hash of requests without a body.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// S3's smallest part, except for the last one.
const MIN_PART: u64 = 5 << 20;

/// An access key, its secret and, for temporary credentials, a session
/// token.
#[derive(Clone)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credentials {{ session_token: {} }}", self.session_token.is_some())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Percent-encodes everything but the unreserved characters
/// `A-Za-z0-9-._~`, and `/` when `slash` is false.
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') || (b == b'/' && !encode_slash) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `secs` since the epoch as `YYYYMMDDTHHMMSSZ`.
pub fn amz_date(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", rem / 3600, rem / 60 % 60, rem % 60)
}

/// What one request signs.
pub struct Request<'a> {
    pub method: &'a str,
    /// The path, already URI-encoded.
    pub path: &'a str,
    /// Query parameters, not encoded.
    pub query: &'a [(&'a str, &'a str)],
    /// The headers to sign, `host` and `x-amz-date` among them.
    pub headers: &'a [(&'a str, &'a str)],
    /// The hex SHA-256 of the body, or `UNSIGNED-PAYLOAD`.
    pub payload_hash: &'a str,
}

/// The `Authorization` header of AWS signature version 4 for `req`, made
/// at `date` (`YYYYMMDDTHHMMSSZ`) for `service` in `region`.
pub fn authorization(creds: &Credentials, region: &str, service: &str, date: &str, req: &Request) -> String {
    let mut query: Vec<(String, String)> = req.query.iter().map(|(k, v)| (uri_encode(k, true), uri_encode(v, true))).collect();
    query.sort();
    let query: Vec<String> = query.into_iter().map(|(k, v)| format!("{k}={v}")).collect();
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (n, v) in req.headers {
        let v = v.split_whitespace().collect::<Vec<_>>().join(" ");
        headers.entry(n.to_ascii_lowercase()).or_default().push(v);
    }
    let canonical_headers: String = headers.iter().map(|(n, v)| format!("{n}:{}\n", v.join(","))).collect();
    let signed_headers = headers.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{}",
        req.method,
        req.path,
        query.join("&"),
        req.payload_hash
    );
    let day = &date[..8];
    let scope = format!("{day}/{region}/{service}/aws4_request");
    let to_sign = format!("AWS4-HMAC-SHA256\n{date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    let mut key = hmac_sha256(format!("AWS4{}", creds.secret_key).as_bytes(), day.as_bytes());
    for part in [region, service, "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let sig = hex(&hmac_sha256(&key, to_sign.as_bytes()));
    format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={sig}", creds.access_key)
}

/// Credentials from the `[name]` (or `[profile name]`) section of an INI
/// file.
fn profile_from_ini(text: &str, name: &str) -> Option<Credentials> {
    let mut section = None;
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let s = s.trim();
            section = Some(s.strip_prefix("profile ").map(str::trim).unwrap_or(s).to_string());
            continue;
        }
        if section.as_deref() == Some(name) {
            if let Some((k, v)) = line.split_once('=') {
                found.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
    }
    Some(Credentials {
        access_key: found.remove("aws_access_key_id")?,
        secret_key: found.remove("aws_secret_access_key")?,
        session_token: found.remove("aws_session_token"),
    })
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn home_file(var: &str, rel: &str) -> Option<PathBuf> {
    env(var).map(PathBuf::from).or_else(|| env("HOME").map(|h| Path::new(&h).join(rel)))
}

/// Credentials from the shared files for `profile`.
fn from_profile(profile: &str) -> Option<Credentials> {
    for f in [home_file("AWS_SHARED_CREDENTIALS_FILE", ".aws/credentials"), home_file("AWS_CONFIG_FILE", ".aws/config")].into_iter().flatten() {
        if let Some(c) = fs::read_to_string(f).ok().and_then(|t| profile_from_ini(&t, profile)) {
            return Some(c);
        }
    }
    None
}

/// Credentials from the JSON that the container and instance metadata
/// endpoints return.
fn from_json(body: &[u8]) -> Option<Credentials> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    Some(Credentials { access_key: s("AccessKeyId")?, secret_key: s("SecretAccessKey")?, session_token: s("Token") })
}

fn metadata_client() -> HttpClient {
    HttpClient::new().attempts(1).timeout(Duration::from_secs(2))
}

/// Credentials of an ECS task or another container credentials provider.
fn from_container() -> Option<Credentials> {
    let url = match (env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"), env("AWS_CONTAINER_CREDENTIALS_FULL_URI")) {
        (Some(rel), _) => format!("http://169.254.170.2{rel}"),
        (None, Some(full)) => full,
        _ => return None,
    };
    let mut client = metadata_client();
    if let Some(t) = env("AWS_CONTAINER_AUTHORIZATION_TOKEN") {
        client = client.header("Authorization", &t);
    }
    let resp = client.get(&url).ok().filter(|r| r.status == 200)?;
    from_json(&resp.body)
}

/// Credentials of the instance role, through IMDSv2.
fn from_instance() -> Option<Credentials> {
    if env("AWS_EC2_METADATA_DISABLED").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        return None;
    }
    let base = env("AWS_EC2_METADATA_SERVICE_ENDPOINT").unwrap_or_else(|| "http://169.254.169.254".into());
    let base = base.trim_end_matches('/');
    let client = metadata_client();
    let token = client
        .send("PUT", &format!("{base}/latest/api/token"), &[("X-aws-ec2-metadata-token-ttl-seconds", "21600")], None)
        .ok()
        .filter(|r| r.status == 200)?;
    let client = client.header("X-aws-ec2-metadata-token", String::from_utf8_lossy(&token.body).trim());
    let roles = client.get(&format!("{base}/latest/meta-data/iam/security-credentials/")).ok().filter(|r| r.status == 200)?;
    let role = String::from_utf8_lossy(&roles.body).lines().next()?.trim().to_string();
    let resp = client.get(&format!("{base}/latest/meta-data/iam/security-credentials/{role}")).ok().filter(|r| r.status == 200)?;
    from_json(&resp.body)
}

/// The credentials for `profile` (the `profile` parameter), or with none,
/// the first of the environment, the default profile, the container and
/// the instance role.
pub fn find_credentials(profile: Option<&str>) -> Option<Credentials> {
    if let Some(p) = profile.filter(|p| !p.is_empty()) {
        return from_profile(p);
    }
    if let (Some(a), Some(s)) = (env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY")) {
        return Some(Credentials { access_key: a, secret_key: s, session_token: env("AWS_SESSION_TOKEN") });
    }
    from_profile(&env("AWS_PROFILE").unwrap_or_else(|| "default".into())).or_else(from_container).or_else(from_instance)
}

/// A bucket, or a prefix in one.
pub struct S3 {
    bucket: String,
    prefix: String,
    region: String,
    /// `scheme://host[:port]`.
    origin: String,
    /// `host[:port]`, as signed.
    host: String,
    /// Whether the bucket is the first path segment instead of part of
    /// the host name.
    path_style: bool,
    profile: Option<String>,
    multipart_threshold: u64,
    part_size: u64,
    creds: OnceLock<Option<Credentials>>,
}

impl std::fmt::Debug for S3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "S3({}/{})", self.origin, self.bucket)
    }
}

/// Whether `b` can be part of a host name: no dots (they break TLS
/// certificates), lower case.
fn dns_bucket(b: &str) -> bool {
    (3..=63).contains(&b.len())
        && b.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && !b.starts_with('-')
        && !b.ends_with('-')
}

fn size_param(params: &BTreeMap<String, String>, name: &str, default: u64) -> Result<u64> {
    match params.get(name) {
        None => Ok(default),
        Some(v) => v.parse().map_err(|_| format!("invalid value '{v}' for S3 parameter '{name}'")),
    }
}

impl S3 {
    /// Opens `s3://bucket[/prefix]` with the parameters of the cache URL.
    pub fn open(url: &str, params: &BTreeMap<String, String>) -> Result<S3> {
        let rest = url.strip_prefix("s3://").ok_or_else(|| format!("'{}' is not an s3:// URL", redact_url(url)))?;
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        let ok = !bucket.is_empty() && bucket.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'));
        if !ok {
            return Err(format!("invalid S3 bucket name in '{}'", redact_url(url)));
        }
        let prefix = prefix.trim_matches('/');
        if !prefix.is_empty() {
            crate::registry::validate_rel(prefix).map_err(|_| format!("invalid S3 key prefix in '{}'", redact_url(url)))?;
        }
        let region = params.get("region").filter(|r| !r.is_empty()).cloned().unwrap_or_else(|| "us-east-1".into());
        let scheme = params.get("scheme").map(String::as_str).unwrap_or("https");
        if !matches!(scheme, "http" | "https") {
            return Err(format!("unsupported S3 scheme '{scheme}'; use 'http' or 'https'"));
        }
        let endpoint = params.get("endpoint").filter(|e| !e.is_empty());
        let style = params.get("addressing-style").map(String::as_str).unwrap_or("auto");
        let path_style = match style {
            "path" => true,
            "virtual" => false,
            "auto" => endpoint.is_some() || !dns_bucket(bucket),
            s => return Err(format!("unknown S3 addressing style '{s}'; use 'auto', 'path' or 'virtual'")),
        };
        let (scheme, base_host) = match endpoint {
            Some(e) => match e.split_once("://") {
                Some((s, h)) => (s.to_string(), h.trim_end_matches('/').to_string()),
                None => (scheme.to_string(), e.trim_end_matches('/').to_string()),
            },
            None => (scheme.to_string(), format!("s3.{region}.amazonaws.com")),
        };
        if base_host.is_empty() || base_host.contains(['/', '@', '?', '#']) {
            return Err(format!("invalid S3 endpoint '{}'", redact_url(&base_host)));
        }
        let host = if path_style { base_host } else { format!("{bucket}.{base_host}") };
        let part_size = size_param(params, "buffer-size", 16 << 20)?.max(MIN_PART);
        Ok(S3 {
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
            region,
            origin: format!("{scheme}://{host}"),
            host,
            path_style,
            profile: params.get("profile").cloned(),
            multipart_threshold: size_param(params, "multipart-threshold", 64 << 20)?,
            part_size,
            creds: OnceLock::new(),
        })
    }

    fn credentials(&self) -> Option<&Credentials> {
        self.creds.get_or_init(|| find_credentials(self.profile.as_deref())).as_ref()
    }

    /// The encoded path of `rel`.
    fn path(&self, rel: &str) -> String {
        let key = if self.prefix.is_empty() { rel.to_string() } else { format!("{}/{rel}", self.prefix) };
        let key = uri_encode(&key, false);
        if self.path_style { format!("/{}/{key}", uri_encode(&self.bucket, true)) } else { format!("/{key}") }
    }

    fn url(&self, path: &str, query: &[(&str, &str)]) -> String {
        let mut u = format!("{}{path}", self.origin);
        for (i, (k, v)) in query.iter().enumerate() {
            u.push(if i == 0 { '?' } else { '&' });
            u.push_str(&uri_encode(k, true));
            if !v.is_empty() || *k != "uploads" {
                u.push('=');
                u.push_str(&uri_encode(v, true));
            }
        }
        u
    }

    /// `http` with the signature headers of a `method` request for `path`.
    fn signed(&self, http: &HttpClient, method: &str, path: &str, query: &[(&str, &str)], payload_hash: &str) -> HttpClient {
        let Some(creds) = self.credentials() else { return http.clone() };
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let date = amz_date(secs);
        let mut headers = vec![("host", self.host.as_str()), ("x-amz-content-sha256", payload_hash), ("x-amz-date", date.as_str())];
        if let Some(t) = &creds.session_token {
            headers.push(("x-amz-security-token", t));
        }
        let auth = authorization(creds, &self.region, "s3", &date, &Request { method, path, query, headers: &headers, payload_hash });
        let mut c = http.clone();
        for (n, v) in headers.iter().skip(1) {
            c = c.header(n, v);
        }
        c.header("Authorization", &auth)
    }

    fn error(&self, what: &str, url: &str, resp: &Response) -> String {
        let body = String::from_utf8_lossy(&resp.body);
        let code = xml_value(&body, "Code").map(|c| format!(" ({c})")).unwrap_or_default();
        format!("{what} '{}': HTTP status {}{code}", redact_url(url), resp.status)
    }

    /// Reads `rel`; `None` when it does not exist. S3 answers 403 for a
    /// missing object when the caller may not list the bucket.
    pub fn get(&self, http: &HttpClient, rel: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path(rel);
        let url = self.url(&path, &[]);
        let resp = self.signed(http, "GET", &path, &[], EMPTY_SHA256).get(&url)?;
        match resp.status {
            200 => Ok(Some(resp.body)),
            404 | 403 => Ok(None),
            _ => Err(self.error("downloading", &url, &resp)),
        }
    }

    pub fn open_file(&self, http: &HttpClient, rel: &str) -> Result<Box<dyn Read + Send>> {
        let path = self.path(rel);
        Ok(Box::new(self.signed(http, "GET", &path, &[], EMPTY_SHA256).open(&self.url(&path, &[]))?))
    }

    pub fn exists(&self, http: &HttpClient, rel: &str) -> Result<bool> {
        let path = self.path(rel);
        let url = self.url(&path, &[]);
        match self.signed(http, "HEAD", &path, &[], EMPTY_SHA256).head(&url)? {
            200 => Ok(true),
            404 | 403 => Ok(false),
            s => Err(format!("querying '{}': HTTP status {s}", redact_url(&url))),
        }
    }

    /// Sends one signed request with the file `body`.
    fn send(&self, http: &HttpClient, method: &str, rel_path: &str, query: &[(&str, &str)], headers: &[(&str, &str)], body: &Path) -> Result<(String, Response)> {
        let hash = sha256_file(body)?;
        let url = self.url(rel_path, query);
        let resp = self.signed(http, method, rel_path, query, &hash).send(method, &url, headers, Some(body))?;
        Ok((url, resp))
    }

    /// Stores the file at `src` as `rel`.
    pub fn put(&self, http: &HttpClient, rel: &str, src: &Path, content_type: &str) -> Result<()> {
        let size = fs::metadata(src).map_err(|e| format!("reading '{}': {e}", src.display()))?.len();
        let path = self.path(rel);
        if size > self.multipart_threshold && size > self.part_size {
            return self.put_multipart(http, &path, src, size, content_type);
        }
        let (url, resp) = self.send(http, "PUT", &path, &[], &[("Content-Type", content_type)], src)?;
        match resp.status {
            200..=299 => Ok(()),
            _ => Err(self.error("uploading to", &url, &resp)),
        }
    }

    fn put_multipart(&self, http: &HttpClient, path: &str, src: &Path, size: u64, content_type: &str) -> Result<()> {
        let empty = TempFile::new(b"")?;
        let (url, resp) = self.send(http, "POST", path, &[("uploads", "")], &[("Content-Type", content_type)], &empty.0)?;
        if resp.status != 200 {
            return Err(self.error("starting multipart upload to", &url, &resp));
        }
        let body = String::from_utf8_lossy(&resp.body).to_string();
        let id = xml_value(&body, "UploadId").ok_or_else(|| format!("starting multipart upload to '{}': no upload ID in the reply", redact_url(&url)))?;
        let r = self.upload_parts(http, path, src, size, &id);
        if r.is_err() {
            let _ = self.send(http, "DELETE", path, &[("uploadId", &id)], &[], &empty.0);
        }
        r
    }

    fn upload_parts(&self, http: &HttpClient, path: &str, src: &Path, size: u64, id: &str) -> Result<()> {
        let mut f = fs::File::open(src).map_err(|e| format!("reading '{}': {e}", src.display()))?;
        let mut etags = Vec::new();
        let mut left = size;
        while left > 0 {
            let n = left.min(self.part_size);
            let mut buf = Vec::with_capacity(n as usize);
            (&mut f).take(n).read_to_end(&mut buf).map_err(|e| format!("reading '{}': {e}", src.display()))?;
            left -= n;
            let part = TempFile::new(&buf)?;
            let number = (etags.len() + 1).to_string();
            let (url, resp) = self.send(http, "PUT", path, &[("partNumber", &number), ("uploadId", id)], &[], &part.0)?;
            let etag = resp.header("etag").map(str::to_string);
            match (resp.status, etag) {
                (200, Some(e)) => etags.push(e),
                _ => return Err(self.error("uploading part to", &url, &resp)),
            }
        }
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (i, e) in etags.iter().enumerate() {
            xml.push_str(&format!("<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>", i + 1, xml_escape(e)));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let done = TempFile::new(xml.as_bytes())?;
        let (url, resp) = self.send(http, "POST", path, &[("uploadId", id)], &[("Content-Type", "application/xml")], &done.0)?;
        // S3 may answer 200 and report a failure in the body.
        if resp.status != 200 || String::from_utf8_lossy(&resp.body).contains("<Error>") {
            return Err(self.error("completing multipart upload to", &url, &resp));
        }
        Ok(())
    }
}

/// The text of the first `<tag>` element in `xml`.
fn xml_value(xml: &str, tag: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = start + xml[start..].find(&format!("</{tag}>"))?;
    Some(xml[start..end].replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path).map_err(|e| format!("reading '{}': {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("reading '{}': {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

/// A temporary file, removed when dropped.
struct TempFile(PathBuf);

impl TempFile {
    fn new(data: &[u8]) -> Result<TempFile> {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(".tmp-s3-{}-{n}", std::process::id()));
        fs::write(&p, data).map_err(|e| format!("writing '{}': {e}", p.display()))?;
        Ok(TempFile(p))
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(a: &str, s: &str) -> Credentials {
        Credentials { access_key: a.into(), secret_key: s.into(), session_token: None }
    }

    /// From the AWS Signature Version 4 test suite.
    #[test]
    fn sigv4_test_suite() {
        let c = creds("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        let date = "20150830T123600Z";
        let headers = [("Host", "example.amazonaws.com"), ("X-Amz-Date", date)];
        let auth = |path, query: &[(&str, &str)]| {
            authorization(&c, "us-east-1", "service", date, &Request { method: "GET", path, query, headers: &headers, payload_hash: EMPTY_SHA256 })
        };
        // get-vanilla
        assert_eq!(
            auth("/", &[]),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        // get-vanilla-query-order-key-case
        assert!(auth("/", &[("Param2", "value2"), ("Param1", "value1")]).ends_with("Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"));
    }

    /// The examples of the S3 documentation on signing with the
    /// `Authorization` header.
    #[test]
    fn sigv4_s3_examples() {
        let c = creds("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        let date = "20130524T000000Z";
        let host = "examplebucket.s3.amazonaws.com";
        // GET Object
        let headers = [("host", host), ("range", "bytes=0-9"), ("x-amz-content-sha256", EMPTY_SHA256), ("x-amz-date", date)];
        let a = authorization(&c, "us-east-1", "s3", date, &Request { method: "GET", path: "/test.txt", query: &[], headers: &headers, payload_hash: EMPTY_SHA256 });
        assert_eq!(
            a,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        // PUT Object
        let body = sha256_hex(b"Welcome to Amazon S3.");
        assert_eq!(body, "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072");
        let headers = [
            ("date", "Fri, 24 May 2013 00:00:00 GMT"),
            ("host", host),
            ("x-amz-content-sha256", &body),
            ("x-amz-date", date),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ];
        let path = uri_encode("/test$file.text", false);
        let a = authorization(&c, "us-east-1", "s3", date, &Request { method: "PUT", path: &path, query: &[], headers: &headers, payload_hash: &body });
        assert!(a.ends_with("Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"), "{a}");
        // GET Bucket lifecycle
        let headers = [("host", host), ("x-amz-content-sha256", EMPTY_SHA256), ("x-amz-date", date)];
        let a = authorization(&c, "us-east-1", "s3", date, &Request { method: "GET", path: "/", query: &[("lifecycle", "")], headers: &headers, payload_hash: EMPTY_SHA256 });
        assert!(a.ends_with("Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"), "{a}");
    }

    #[test]
    fn hmac_rfc4231() {
        assert_eq!(hex(&hmac_sha256(&[0x0b; 20], b"Hi There")), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(hex(&hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    #[test]
    fn dates() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1369353600), "20130524T000000Z");
        assert_eq!(amz_date(1440938160), "20150830T123600Z");
        assert_eq!(amz_date(951782400), "20000229T000000Z");
    }

    #[test]
    fn addressing() {
        let p = |q: &[(&str, &str)]| q.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>();
        let s = S3::open("s3://my-cache", &p(&[("region", "eu-west-1")])).unwrap();
        assert_eq!(s.url(&s.path("nar/x.nar.xz"), &[]), "https://my-cache.s3.eu-west-1.amazonaws.com/nar/x.nar.xz");
        let s = S3::open("s3://my.cache/pre", &p(&[])).unwrap();
        assert_eq!(s.url(&s.path("a:b"), &[]), "https://s3.us-east-1.amazonaws.com/my.cache/pre/a%3Ab");
        let s = S3::open("s3://c", &p(&[("endpoint", "localhost:9000"), ("scheme", "http")])).unwrap();
        assert_eq!(s.url(&s.path("x"), &[("uploads", "")]), "http://localhost:9000/c/x?uploads");
        assert_eq!(s.host, "localhost:9000");
        let s = S3::open("s3://cache", &p(&[("endpoint", "https://minio.example:9000"), ("addressing-style", "virtual")])).unwrap();
        assert_eq!(s.url(&s.path("x"), &[("partNumber", "1"), ("uploadId", "a/b")]), "https://cache.minio.example:9000/x?partNumber=1&uploadId=a%2Fb");
        for bad in ["s3://", "s3://a b", "s3://b/../x"] {
            assert!(S3::open(bad, &p(&[])).is_err(), "{bad}");
        }
        assert!(S3::open("s3://b", &p(&[("scheme", "ftp")])).is_err());
        assert!(S3::open("s3://b", &p(&[("endpoint", "user:pw@host")])).is_err());
    }

    #[test]
    fn profiles() {
        let ini = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=s1\n\n[profile ci]\n# x\naws_access_key_id=AKIDCI\naws_secret_access_key = s2\naws_session_token = t\n";
        let d = profile_from_ini(ini, "default").unwrap();
        assert_eq!((d.access_key.as_str(), d.secret_key.as_str(), d.session_token), ("AKIAIOSFODNN7EXAMPLE", "s1", None));
        let ci = profile_from_ini(ini, "ci").unwrap();
        assert_eq!(ci.session_token.as_deref(), Some("t"));
        assert!(profile_from_ini(ini, "other").is_none());
        assert!(!format!("{ci:?}").contains("s2"));
        assert_eq!(xml_value("<a><UploadId>x&amp;y</UploadId></a>", "UploadId").as_deref(), Some("x&y"));
    }
}
