//! Client for binary caches in Nix's format: a `nix-cache-info` file,
//! one `<hash>.narinfo` per store path and compressed NARs under `nar/`.
//! `file://` caches are directories; `http(s)://` caches are accessed
//! through an [`HttpClient`], which also uploads to caches that accept
//! `PUT`. A [`NarinfoCache`] can remember lookups between runs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use oxnix_core::hash::{HashAlgo, HashSink};
use oxnix_core::signing::SecretKey;
use oxnix_core::{nar, NarInfo, StoreDir};

use crate::http::HttpClient;
use crate::narinfo_cache::NarinfoCache;
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

enum Location {
    File(PathBuf),
    Http,
}

pub struct BinaryCache {
    /// The cache URL without its query parameters.
    pub url: String,
    location: Location,
    params: BTreeMap<String, String>,
    http: HttpClient,
    disk: Option<NarinfoCache>,
    info: OnceLock<std::result::Result<CacheInfo, String>>,
}

static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp_name(what: &str) -> String {
    format!(".tmp-{what}-{}-{}", std::process::id(), TMP_COUNTER.fetch_add(1, Ordering::Relaxed))
}

impl BinaryCache {
    /// Opens `file:///dir` or `http(s)://host/path`, with optional
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
                return Err(format!("binary cache URL '{url}' must name an absolute path"));
            }
            Location::File(PathBuf::from(p))
        } else if base.starts_with("http://") || base.starts_with("https://") {
            Location::Http
        } else {
            return Err(format!("don't know how to open binary cache '{url}'; use a file:// or https:// URL"));
        };
        Ok(BinaryCache { url: base, location, params, http: HttpClient::default(), disk: None, info: OnceLock::new() })
    }

    /// Makes HTTP requests with `http`, which carries for example the
    /// credentials for this cache.
    pub fn with_http(mut self, http: HttpClient) -> BinaryCache {
        self.http = http;
        self
    }

    /// Remembers narinfo lookups in `disk`, and answers from it while
    /// its entries are fresh.
    pub fn with_narinfo_cache(mut self, disk: NarinfoCache) -> BinaryCache {
        self.disk = Some(disk);
        self
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    fn file_path(&self, rel: &str) -> Option<PathBuf> {
        match &self.location {
            Location::File(d) => Some(d.join(rel)),
            Location::Http => None,
        }
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
        let url = self.http_url(rel);
        let resp = self.http.get(&url)?;
        match resp.status {
            200 => Ok(Some(resp.body)),
            // S3 answers 403 for objects that do not exist.
            404 | 403 | 410 => Ok(None),
            c => Err(format!("downloading '{url}': HTTP status {c}")),
        }
    }

    /// Streams a file that must exist.
    pub fn open_file(&self, rel: &str) -> Result<Box<dyn Read + Send>> {
        if let Some(p) = self.file_path(rel) {
            let f = fs::File::open(&p).map_err(|e| format!("opening '{}': {e}", p.display()))?;
            return Ok(Box::new(io::BufReader::new(f)));
        }
        Ok(Box::new(self.http.open(&self.http_url(rel))?))
    }

    pub fn file_exists(&self, rel: &str) -> Result<bool> {
        if let Some(p) = self.file_path(rel) {
            return Ok(p.exists());
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
        self.http.put_file(&self.http_url(rel), src, content_type)
    }

    fn put_bytes(&self, rel: &str, data: &[u8], content_type: &str) -> Result<()> {
        let tmp = std::env::temp_dir().join(tmp_name("put"));
        fs::write(&tmp, data).map_err(|e| format!("writing '{}': {e}", tmp.display()))?;
        let r = self.put_file(rel, &tmp, content_type);
        let _ = fs::remove_file(&tmp);
        r
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
            return Err(format!("binary cache '{}' is for store directory '{}', not '{}'", self.url, info.store_dir, dir.as_str()));
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
            Some(d) => NarInfo::parse(dir, &String::from_utf8_lossy(&d), &format!("{}/{rel}", self.url)).map(Some),
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
        let err = |e: io::Error| format!("unpacking '{what}' from '{}': {e}", self.url);
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
                self.url,
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
            let url = format!("nar/{}.nar{}", file_hash.to_nix32(), compression.extension());
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
        write!(f, "BinaryCache({})", self.url)
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

    use oxnix_core::signing::PublicKey;
    use oxnix_core::StorePath;

    #[test]
    fn file_cache_round_trip() {
        let root = std::env::temp_dir().join(format!("oxnix-bc-{}", std::process::id()));
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
            assert!(!back.is_trusted(&dir, &[PublicKey::parse(crate::config::DEFAULT_CACHE_KEY).unwrap()]));
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
