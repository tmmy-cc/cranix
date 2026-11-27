//! A local store: a store directory holding immutable objects, plus a
//! metadata directory recording which of them are valid, their NAR hashes
//! and their references.
//!
//! The logical store directory (the one baked into store paths) may differ
//! from where objects physically live, so a store rooted at e.g.
//! `~/.local/share/cranix` can still compute and hold `/nix/store` paths.

pub mod binary_cache;
pub mod build;
mod ca;
pub mod settings;
mod fsutil;
pub mod gc_roots;
pub mod http;
mod nar_import;
pub mod narinfo_cache;
pub mod realisation;
pub mod refs;
pub mod registry;
pub mod select;
pub mod substitute;
pub mod upload;
pub mod sandbox;

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cranix_core::hash::{Hash, HashAlgo, HashSink};
use cranix_core::{nar, DrvHash, FileIngestion, StoreDir, StorePath};

pub use fsutil::canonicalise;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathInfo {
    pub path: StorePath,
    pub nar_hash: Hash,
    pub nar_size: u64,
    pub references: BTreeSet<StorePath>,
    pub deriver: Option<StorePath>,
    pub ca: Option<String>,
}

#[derive(Debug)]
pub struct Store {
    pub dir: StoreDir,
    real: PathBuf,
    state: PathBuf,
    /// Shared `flock` on `state/gc.lock`, held for the handle's lifetime so
    /// garbage collection can tell the store is in use.
    lock: fs::File,
    /// Binary caches consulted for missing paths; none by default.
    subst: substitute::Substituters,
    /// `hashDerivationModulo` of `.drv` files, which content-addressed
    /// builds need to name realisations.
    drv_hashes: Mutex<HashMap<StorePath, DrvHash>>,
    /// `secret-key-files`: keys that sign the realisations registered here.
    signing_keys: SigningKeys,
}

/// Secret keys, printed by their names only.
#[derive(Default)]
pub(crate) struct SigningKeys(pub(crate) Vec<cranix_core::signing::SecretKey>);

impl std::fmt::Debug for SigningKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.iter().map(|k| k.to_public().to_string())).finish()
    }
}

fn flock(f: &fs::File, op: i32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: flock only reads the descriptor, which `f` keeps open.
    if unsafe { libc::flock(f.as_raw_fd(), op) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub type Result<T> = std::result::Result<T, String>;

fn io_err(ctx: impl std::fmt::Display) -> impl FnOnce(io::Error) -> String {
    move |e| format!("{ctx}: {e}")
}

impl Store {
    /// Opens (creating if needed) a store whose objects live in `real` and
    /// whose metadata lives in `state`.
    pub fn open(dir: StoreDir, real: PathBuf, state: PathBuf) -> Result<Store> {
        for d in [&real, &state.join("db"), &state.join("gcroots"), &state.join("log"), &state.join("realisations")] {
            fs::create_dir_all(d).map_err(io_err(format!("creating '{}'", d.display())))?;
        }
        let lock_path = state.join("gc.lock");
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(io_err(format!("opening '{}'", lock_path.display())))?;
        flock(&lock, libc::LOCK_SH).map_err(io_err("locking the store"))?;
        Ok(Store { dir, real, state, lock, subst: Default::default(), drv_hashes: Mutex::new(HashMap::new()), signing_keys: SigningKeys::default() })
    }

    /// A store where the logical and physical directories coincide; this is
    /// the layout in which derivations can be built.
    pub fn open_at(root: &Path) -> Result<Store> {
        let real = root.join("store");
        fs::create_dir_all(&real).map_err(io_err(format!("creating '{}'", real.display())))?;
        let real = real.canonicalize().map_err(io_err("resolving store directory"))?;
        let dir = StoreDir::new(real.to_string_lossy().into_owned());
        Store::open(dir, real, root.join("var"))
    }

    /// Keeps `/nix/store` as the logical directory and stores objects below
    /// `root/nix/store`, like Nix's chroot stores.
    pub fn open_chroot(root: &Path) -> Result<Store> {
        let dir = StoreDir::default();
        let real = root.join(dir.as_str().trim_start_matches('/'));
        Store::open(dir, real, root.join("nix/var/cranix"))
    }

    pub fn can_build(&self) -> bool {
        Path::new(self.dir.as_str()) == self.real
    }

    pub fn state_dir(&self) -> &Path {
        &self.state
    }

    pub fn real_path(&self, p: &StorePath) -> PathBuf {
        self.real.join(p.base_name())
    }

    /// Maps a logical path to where it can be read on this machine. Paths
    /// under the store directory are looked up in this store first, then in
    /// the host's store at the same location.
    pub fn resolve(&self, logical: &str) -> PathBuf {
        if let Some(rest) = logical.strip_prefix(self.dir.as_str()).and_then(|r| r.strip_prefix('/')) {
            let candidate = self.real.join(rest);
            if candidate.symlink_metadata().is_ok() {
                return candidate;
            }
        }
        PathBuf::from(logical)
    }

    fn info_file(&self, p: &StorePath) -> PathBuf {
        self.state.join("db").join(p.base_name())
    }

    pub fn is_valid(&self, p: &StorePath) -> bool {
        self.info_file(p).exists()
    }

    pub fn query_info(&self, p: &StorePath) -> Result<Option<PathInfo>> {
        let text = match fs::read_to_string(self.info_file(p)) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("reading metadata of '{p}': {e}")),
        };
        let mut info = PathInfo {
            path: p.clone(),
            nar_hash: Hash::sha256(b""),
            nar_size: 0,
            references: BTreeSet::new(),
            deriver: None,
            ca: None,
        };
        for line in text.lines() {
            let Some((k, v)) = line.split_once(": ") else { continue };
            match k {
                "NarHash" => info.nar_hash = Hash::parse(v, None)?,
                "NarSize" => info.nar_size = v.parse().map_err(|_| "bad NarSize")?,
                "References" => {
                    for r in v.split_whitespace() {
                        info.references.insert(StorePath::from_base_name(r)?);
                    }
                }
                "Deriver" => info.deriver = Some(StorePath::from_base_name(v)?),
                "CA" => info.ca = Some(v.to_string()),
                _ => {}
            }
        }
        Ok(Some(info))
    }

    pub fn register(&self, info: &PathInfo) -> Result<()> {
        let mut s = format!(
            "StorePath: {}\nNarHash: {}\nNarSize: {}\nReferences:",
            self.dir.print(&info.path),
            info.nar_hash,
            info.nar_size
        );
        for r in &info.references {
            s.push(' ');
            s.push_str(r.base_name());
        }
        s.push('\n');
        if let Some(d) = &info.deriver {
            s.push_str(&format!("Deriver: {d}\n"));
        }
        if let Some(ca) = &info.ca {
            s.push_str(&format!("CA: {ca}\n"));
        }
        fsutil::write_atomic(&self.info_file(&info.path), s.as_bytes())
    }

    pub fn nar_hash(path: &Path) -> Result<(Hash, u64)> {
        let mut sink = HashSink::new(HashAlgo::Sha256);
        nar::dump(path, &mut sink).map_err(io_err(format!("archiving '{}'", path.display())))?;
        Ok(sink.finish())
    }

    /// Adds a text object (`builtins.toFile`, `.drv` files).
    pub fn add_text(&self, name: &str, contents: &[u8], refs: &BTreeSet<StorePath>) -> Result<StorePath> {
        let p = self.dir.make_text_path(name, &Hash::sha256(contents), refs)?;
        if self.is_valid(&p) {
            return Ok(p);
        }
        let real = self.real_path(&p);
        fsutil::remove_all(&real)?;
        fsutil::write_atomic(&real, contents)?;
        canonicalise(&real)?;
        let mut sink = HashSink::new(HashAlgo::Sha256);
        nar::dump_bytes(contents, false, &mut sink).map_err(|e| e.to_string())?;
        let (nar_hash, nar_size) = sink.finish();
        self.register(&PathInfo {
            path: p.clone(),
            nar_hash,
            nar_size,
            references: refs.clone(),
            deriver: None,
            ca: Some(format!("text:sha256:{}", Hash::sha256(contents).to_nix32())),
        })?;
        Ok(p)
    }

    /// Computes the store path `src` would get when added recursively,
    /// honouring `filter`, without copying anything.
    pub fn compute_path(&self, src: &Path, name: &str, filter: Option<nar::Filter<'_>>) -> Result<(StorePath, Hash, u64)> {
        let mut sink = HashSink::new(HashAlgo::Sha256);
        nar::dump_filtered(src, &mut sink, filter).map_err(io_err(format!("archiving '{}'", src.display())))?;
        let (h, size) = sink.finish();
        let p = self.dir.make_fixed_output_path(FileIngestion::Recursive, &h, name, &BTreeSet::new(), false)?;
        Ok((p, h, size))
    }

    /// Copies a file system object into the store (`./path` coercion,
    /// `builtins.path`, `filterSource`).
    pub fn add_path(
        &self,
        src: &Path,
        name: &str,
        method: FileIngestion,
        mut filter: Option<nar::Filter<'_>>,
    ) -> Result<StorePath> {
        let (p, nar_hash, nar_size, ca) = match method {
            FileIngestion::Recursive => {
                let (p, h, size) = self.compute_path(src, name, filter.as_mut().map(|f| &mut **f as nar::Filter<'_>))?;
                let ca = format!("fixed:r:sha256:{}", h.to_nix32());
                (p, h, size, ca)
            }
            FileIngestion::Flat => {
                let data = fs::read(src).map_err(io_err(format!("reading '{}'", src.display())))?;
                let h = Hash::sha256(&data);
                let p = self.dir.make_fixed_output_path(FileIngestion::Flat, &h, name, &BTreeSet::new(), false)?;
                let mut sink = HashSink::new(HashAlgo::Sha256);
                nar::dump_bytes(&data, false, &mut sink).map_err(|e| e.to_string())?;
                let (nh, ns) = sink.finish();
                (p, nh, ns, format!("fixed:sha256:{}", h.to_nix32()))
            }
        };
        if self.is_valid(&p) {
            return Ok(p);
        }
        let real = self.real_path(&p);
        fsutil::remove_all(&real)?;
        let tmp = self.real.join(format!(".tmp-{}-{}", std::process::id(), p.hash_part()));
        fsutil::remove_all(&tmp)?;
        match method {
            FileIngestion::Recursive => fsutil::copy_tree(src, &tmp, &mut filter)?,
            FileIngestion::Flat => {
                fs::copy(src, &tmp).map_err(io_err("copying into store"))?;
            }
        }
        // Directories are renamed while still writable (macOS requires
        // that to update their `..` entry), then made read-only in place.
        fs::rename(&tmp, &real).map_err(io_err("moving into store"))?;
        canonicalise(&real)?;
        self.register(&PathInfo { path: p.clone(), nar_hash, nar_size, references: BTreeSet::new(), deriver: None, ca: Some(ca) })?;
        Ok(p)
    }

    /// All paths reachable from `roots` through references.
    pub fn closure(&self, roots: impl IntoIterator<Item = StorePath>) -> Result<BTreeSet<StorePath>> {
        let mut seen = BTreeSet::new();
        let mut todo: Vec<StorePath> = roots.into_iter().collect();
        while let Some(p) = todo.pop() {
            if !seen.insert(p.clone()) {
                continue;
            }
            if let Some(info) = self.query_info(&p)? {
                todo.extend(info.references.into_iter().filter(|r| !seen.contains(r)));
            }
        }
        Ok(seen)
    }

    pub fn valid_paths(&self) -> Result<Vec<StorePath>> {
        let mut v = Vec::new();
        for e in fs::read_dir(self.state.join("db")).map_err(io_err("listing metadata"))? {
            let e = e.map_err(io_err("listing metadata"))?;
            if let Ok(p) = StorePath::from_base_name(&e.file_name().to_string_lossy()) {
                v.push(p);
            }
        }
        v.sort();
        Ok(v)
    }

    /// Registers `link` (e.g. a `result` symlink) as an indirect GC root.
    pub fn add_indirect_root(&self, link: &Path) -> Result<()> {
        let abs = std::path::absolute(link).map_err(io_err("resolving root"))?;
        let name = Hash::sha256(abs.as_os_str().as_encoded_bytes()).to_nix32();
        let root = self.state.join("gcroots").join(&name[..32]);
        let _ = fs::remove_file(&root);
        std::os::unix::fs::symlink(&abs, &root).map_err(io_err("creating GC root"))
    }

    fn roots(&self) -> Result<BTreeSet<StorePath>> {
        let mut roots = BTreeSet::new();
        for e in fs::read_dir(self.state.join("gcroots")).map_err(io_err("listing GC roots"))? {
            let e = e.map_err(io_err("listing GC roots"))?;
            let mut target = e.path();
            // Indirect roots point at a symlink that points into the store.
            for _ in 0..2 {
                match fs::read_link(&target) {
                    Ok(t) => target = t,
                    Err(_) => break,
                }
            }
            let t = target.to_string_lossy();
            let found = self.dir.to_store_path(&t).map(|(p, _)| p).or_else(|| {
                let rel = target.strip_prefix(&self.real).ok()?;
                StorePath::from_base_name(rel.components().next()?.as_os_str().to_str()?).ok()
            });
            match found {
                Some(p) => {
                    roots.insert(p);
                }
                None => {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        Ok(roots)
    }

    /// Deletes every object not reachable from a GC root. Returns the
    /// deleted paths and the bytes freed (as NAR size).
    /// Fails while another process has the store open, since its new paths
    /// may not be rooted yet.
    pub fn collect_garbage(&self, dry_run: bool) -> Result<(Vec<StorePath>, u64)> {
        flock(&self.lock, libc::LOCK_EX | libc::LOCK_NB)
            .map_err(|_| "another cranix process is using the store; run garbage collection when it has finished".to_string())?;
        let r = self.collect_garbage_locked(dry_run);
        flock(&self.lock, libc::LOCK_SH).map_err(io_err("locking the store"))?;
        r
    }

    fn collect_garbage_locked(&self, dry_run: bool) -> Result<(Vec<StorePath>, u64)> {
        let live = self.closure(self.roots()?)?;
        let mut dead = Vec::new();
        let mut freed = 0;
        for p in self.valid_paths()? {
            if live.contains(&p) {
                continue;
            }
            if let Some(info) = self.query_info(&p)? {
                freed += info.nar_size;
            }
            if !dry_run {
                fs::remove_file(self.info_file(&p)).map_err(io_err("unregistering path"))?;
                fsutil::remove_all(&self.real_path(&p))?;
            }
            dead.push(p);
        }
        if !dry_run {
            self.drop_realisations_of(&dead.iter().cloned().collect())?;
        }
        Ok((dead, freed))
    }

    pub fn verify(&self, p: &StorePath) -> Result<bool> {
        let info = self.query_info(p)?.ok_or_else(|| format!("path '{p}' is not valid"))?;
        let (h, size) = Store::nar_hash(&self.real_path(p))?;
        Ok(h == info.nar_hash && size == info.nar_size)
    }

    pub fn log_path(&self, drv: &StorePath) -> PathBuf {
        self.state.join("log").join(drv.base_name())
    }
}
