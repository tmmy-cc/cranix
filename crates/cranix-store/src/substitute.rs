//! Substitution: making paths valid by downloading them, with their
//! closures, from binary caches instead of building them.
//!
//! Signatures a path arrived with are kept as `Sig:` lines in its metadata
//! file, so that copying it on to another cache preserves them.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

use cranix_core::signing::{PublicKey, SecretKey};
use cranix_core::{NarInfo, StorePath};

use crate::binary_cache::BinaryCache;
use crate::config::Settings;
use crate::http::HttpClient;
use crate::narinfo_cache::{self, NarinfoCache};
use crate::{canonicalise, fsutil, PathInfo, Result, Store};

/// The caches a store substitutes from, and how much it trusts them.
#[derive(Debug, Default)]
pub struct Substituters {
    caches: Vec<BinaryCache>,
    keys: Vec<PublicKey>,
    require_sigs: bool,
    jobs: usize,
    /// How long lookups are remembered in the store's narinfo cache.
    ttls: (u64, u64),
    /// Indices into `caches` of the usable ones, by priority; fetching
    /// `nix-cache-info` is deferred until a lookup needs it.
    order: OnceLock<Vec<usize>>,
    lookups: Mutex<HashMap<StorePath, Option<(usize, NarInfo)>>>,
}

impl Substituters {
    pub fn new(caches: Vec<BinaryCache>, keys: Vec<PublicKey>, require_sigs: bool, jobs: usize) -> Substituters {
        Substituters {
            caches,
            keys,
            require_sigs,
            jobs: jobs.max(1),
            ttls: (narinfo_cache::DEFAULT_POSITIVE_TTL, narinfo_cache::DEFAULT_NEGATIVE_TTL),
            ..Default::default()
        }
    }

    /// Sets how long the store remembers that a cache has a path, and
    /// that it does not; 0 turns that kind of record off.
    pub fn narinfo_ttls(mut self, positive: u64, negative: u64) -> Substituters {
        self.ttls = (positive, negative);
        self
    }

    pub fn from_settings(s: &Settings) -> Result<Substituters> {
        if !s.substitute {
            return Ok(Substituters::default());
        }
        let mut caches = Vec::new();
        for u in &s.substituters {
            match BinaryCache::open(u) {
                Ok(c) => caches.push(c.with_http(http_client(s))),
                Err(e) => eprintln!("warning: ignoring substituter: {e}"),
            }
        }
        Ok(Substituters::new(caches, trusted_keys(&s.trusted_public_keys), s.require_sigs, s.max_substitution_jobs)
            .narinfo_ttls(s.narinfo_cache_positive_ttl, s.narinfo_cache_negative_ttl))
    }

    pub fn is_empty(&self) -> bool {
        self.caches.is_empty()
    }
}

/// The HTTP client for caches, configured by `s`.
pub fn http_client(s: &Settings) -> HttpClient {
    HttpClient::new().netrc_file(Some(s.netrc_file.clone().into())).attempts(s.download_attempts)
}

/// Parses `trusted-public-keys`, warning about malformed entries.
pub fn trusted_keys(keys: &[String]) -> Vec<PublicKey> {
    keys.iter()
        .filter_map(|k| match PublicKey::parse(k) {
            Ok(k) => Some(k),
            Err(e) => {
                eprintln!("warning: ignoring trusted public key: {e}");
                None
            }
        })
        .collect()
}

/// Runs `f` on each item with up to `jobs` threads.
fn parallel<T: Sync>(items: &[T], jobs: usize, f: impl Fn(&T) + Sync) {
    let next = Mutex::new(0usize);
    std::thread::scope(|s| {
        for _ in 0..jobs.max(1).min(items.len()) {
            s.spawn(|| loop {
                let i = {
                    let mut n = next.lock().unwrap();
                    *n += 1;
                    *n - 1
                };
                match items.get(i) {
                    Some(x) => f(x),
                    None => return,
                }
            });
        }
    });
}

impl Store {
    /// Substitutes from `s`, remembering its answers in the store's
    /// narinfo cache.
    pub fn set_substituters(&mut self, mut s: Substituters) {
        let (pos, neg) = s.ttls;
        s.caches = s
            .caches
            .into_iter()
            .map(|c| {
                let disk = self.narinfo_cache(&c.url, pos, neg);
                c.with_narinfo_cache(disk)
            })
            .collect();
        self.subst = s;
    }

    /// The store's record of lookups in the cache at `url`.
    pub fn narinfo_cache(&self, url: &str, positive_ttl: u64, negative_ttl: u64) -> NarinfoCache {
        NarinfoCache::new(&self.state.join("narinfo-cache"), url, positive_ttl, negative_ttl)
    }

    pub fn substituters(&self) -> &Substituters {
        &self.subst
    }

    fn cache_order(&self) -> &[usize] {
        self.subst.order.get_or_init(|| {
            let mut v = Vec::new();
            for (i, c) in self.subst.caches.iter().enumerate() {
                match c.info() {
                    Ok(info) if info.store_dir == self.dir.as_str() => v.push((info.priority, i)),
                    Ok(info) => eprintln!(
                        "warning: ignoring substituter '{}': it holds paths of '{}', not '{}'",
                        c.url,
                        info.store_dir,
                        self.dir.as_str()
                    ),
                    Err(e) => eprintln!("warning: ignoring substituter '{}': {e}", c.url),
                }
            }
            v.sort();
            v.into_iter().map(|(_, i)| i).collect()
        })
    }

    /// The first cache, by priority, offering a trusted copy of `p`.
    fn lookup(&self, p: &StorePath) -> Option<(usize, NarInfo)> {
        if let Some(r) = self.subst.lookups.lock().unwrap().get(p) {
            return r.clone();
        }
        let mut found = None;
        for &i in self.cache_order() {
            let c = &self.subst.caches[i];
            match c.query_narinfo(&self.dir, p.hash_part()) {
                Ok(Some(ni)) if ni.path != *p => {
                    eprintln!("warning: substituter '{}' returned the narinfo of '{}' for '{p}'", c.url, ni.path)
                }
                Ok(Some(ni)) if self.subst.require_sigs && !ni.is_trusted(&self.dir, &self.subst.keys) => eprintln!(
                    "warning: ignoring substitute for '{}' from '{}', as it's not signed by any of the keys in 'trusted-public-keys'",
                    self.dir.print(p),
                    c.url
                ),
                Ok(Some(ni)) => {
                    found = Some((i, ni));
                    break;
                }
                Ok(None) => {}
                Err(e) => eprintln!("warning: {e}"),
            }
        }
        self.subst.lookups.lock().unwrap().insert(p.clone(), found.clone());
        found
    }

    /// Looks up `paths` in parallel so later `lookup`s hit the cache.
    fn prefetch(&self, paths: &[StorePath]) {
        let todo: Vec<StorePath> = {
            let l = self.subst.lookups.lock().unwrap();
            paths.iter().filter(|p| !l.contains_key(*p)).cloned().collect()
        };
        if todo.len() > 1 {
            self.cache_order();
            parallel(&todo, self.subst.jobs, |p| {
                self.lookup(p);
            });
        }
    }

    /// Whether every one of `paths` is valid or can be substituted (its
    /// references are checked when it is fetched).
    pub fn substitutable(&self, paths: &[StorePath]) -> bool {
        if self.subst.is_empty() {
            return false;
        }
        let missing: Vec<StorePath> = paths.iter().filter(|p| !self.is_valid(p)).cloned().collect();
        self.prefetch(&missing);
        missing.iter().all(|p| self.lookup(p).is_some())
    }

    /// Queries substitutes for many paths at once.
    pub fn query_substitutable(&self, paths: &[StorePath]) {
        if !self.subst.is_empty() {
            self.prefetch(paths);
        }
    }

    /// Makes `paths` and their closures valid by downloading what is
    /// missing, in parallel. Returns the requested paths that are still
    /// invalid afterwards.
    pub fn substitute_paths(&self, paths: &[StorePath]) -> Result<BTreeSet<StorePath>> {
        let requested: Vec<StorePath> = paths.iter().filter(|p| !self.is_valid(p)).cloned().collect();
        if requested.is_empty() || self.subst.is_empty() {
            return Ok(requested.into_iter().collect());
        }

        // Work out the missing part of the closure from the narinfos.
        let mut plan: HashMap<StorePath, (usize, NarInfo)> = HashMap::new();
        let mut unavailable = BTreeSet::new();
        let mut frontier = requested.clone();
        while !frontier.is_empty() {
            self.prefetch(&frontier);
            let mut next = BTreeSet::new();
            for p in frontier {
                if plan.contains_key(&p) || unavailable.contains(&p) {
                    continue;
                }
                match self.lookup(&p) {
                    Some(x) => {
                        for r in &x.1.references {
                            if *r != p && !self.is_valid(r) && !plan.contains_key(r) {
                                next.insert(r.clone());
                            }
                        }
                        plan.insert(p, x);
                    }
                    None => {
                        unavailable.insert(p);
                    }
                }
            }
            frontier = next.into_iter().collect();
        }

        let items: Vec<(&StorePath, &(usize, NarInfo))> = plan.iter().collect();
        let fetched = Mutex::new(Vec::new());
        parallel(&items, self.subst.jobs, |(p, (i, ni))| {
            let cache = &self.subst.caches[*i];
            eprintln!("copying path '{}' from '{}'...", self.dir.print(p), cache.url);
            match self.fetch_one(cache, ni) {
                Ok(()) => fetched.lock().unwrap().push((*p).clone()),
                Err(e) => eprintln!("error: {e}"),
            }
        });

        // Register in dependency order so every valid path has a valid
        // closure.
        let mut pending: BTreeSet<StorePath> = fetched.into_inner().unwrap().into_iter().collect();
        loop {
            let ready: Vec<StorePath> = pending
                .iter()
                .filter(|p| plan[*p].1.references.iter().all(|r| r == *p || self.is_valid(r)))
                .cloned()
                .collect();
            if ready.is_empty() {
                break;
            }
            for p in ready {
                let ni = &plan[&p].1;
                self.register(&PathInfo {
                    path: p.clone(),
                    nar_hash: ni.nar_hash.clone(),
                    nar_size: ni.nar_size,
                    references: ni.references.clone(),
                    deriver: ni.deriver.clone(),
                    ca: ni.ca.clone(),
                })?;
                self.add_signatures(&p, &ni.sigs)?;
                self.mark_substituted(&p)?;
                pending.remove(&p);
            }
        }
        // Downloaded objects whose closure is incomplete are not kept.
        for p in &pending {
            let _ = fsutil::remove_all(&self.real_path(p));
        }
        Ok(requested.into_iter().filter(|p| !self.is_valid(p)).collect())
    }

    fn fetch_one(&self, cache: &BinaryCache, ni: &NarInfo) -> Result<()> {
        let real = self.real_path(&ni.path);
        let tmp = real.with_file_name(format!(".tmp-subst-{}-{}", std::process::id(), ni.path.hash_part()));
        fsutil::remove_all(&tmp)?;
        cache.fetch_nar(&self.dir, ni, &tmp)?;
        fsutil::remove_all(&real)?;
        fs::rename(&tmp, &real).map_err(|e| format!("moving '{}' into the store: {e}", ni.path))?;
        canonicalise(&real)
    }

    /// Makes `p` valid, substituting it if needed.
    pub fn ensure_path(&self, p: &StorePath) -> Result<()> {
        if self.is_valid(p) || self.substitute_paths(std::slice::from_ref(p))?.is_empty() {
            Ok(())
        } else {
            Err(format!("path '{}' does not exist and cannot be created", self.dir.print(p)))
        }
    }

    /// Signatures recorded for a valid path.
    pub fn query_sigs(&self, p: &StorePath) -> Result<Vec<String>> {
        let text = fs::read_to_string(self.info_file(p)).map_err(|e| format!("reading metadata of '{p}': {e}"))?;
        Ok(text.lines().filter_map(|l| l.strip_prefix("Sig: ")).map(str::to_string).collect())
    }

    /// Records the signatures in `sigs` that `p` does not have yet.
    pub fn add_signatures(&self, p: &StorePath, sigs: &[String]) -> Result<()> {
        let have: BTreeSet<String> = self.query_sigs(p)?.into_iter().collect();
        let new: BTreeSet<&String> = sigs.iter().filter(|s| !have.contains(*s)).collect();
        if new.is_empty() {
            return Ok(());
        }
        let lines: Vec<String> = new.into_iter().map(|s| format!("Sig: {s}")).collect();
        self.append_meta(p, &lines)
    }

    fn append_meta(&self, p: &StorePath, lines: &[String]) -> Result<()> {
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(self.info_file(p))
            .map_err(|e| format!("updating metadata of '{p}': {e}"))?;
        for l in lines {
            writeln!(f, "{l}").map_err(|e| format!("updating metadata of '{p}': {e}"))?;
        }
        Ok(())
    }

    fn mark_substituted(&self, p: &StorePath) -> Result<()> {
        self.append_meta(p, &["Substituted: 1".into()])
    }

    /// Whether `p` was built or added here (Nix's "ultimate" trust), as
    /// opposed to fetched from a substituter.
    pub fn is_ultimate(&self, p: &StorePath) -> Result<bool> {
        let text = fs::read_to_string(self.info_file(p)).map_err(|e| format!("reading metadata of '{p}': {e}"))?;
        Ok(!text.lines().any(|l| l == "Substituted: 1"))
    }

    /// When `p` was registered, in seconds since the epoch.
    pub fn registration_time(&self, p: &StorePath) -> Option<u64> {
        let m = fs::metadata(self.info_file(p)).ok()?.modified().ok()?;
        m.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs())
    }

    /// Signs `p` with each of `keys`.
    pub fn sign_path(&self, p: &StorePath, keys: &[SecretKey]) -> Result<()> {
        let info = self.query_info(p)?.ok_or_else(|| format!("path '{}' is not valid", self.dir.print(p)))?;
        let fp = cranix_core::signing::fingerprint(&self.dir, p, &info.nar_hash, info.nar_size, &info.references)?;
        let sigs: Vec<String> = keys.iter().map(|k| k.sign(fp.as_bytes())).collect();
        self.add_signatures(p, &sigs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_closure_from_file_cache() {
        let root = std::env::temp_dir().join(format!("cranix-subst-{}", std::process::id()));
        let _ = fsutil::remove_all(&root);
        let src = Store::open_chroot(&root.join("src")).unwrap();
        let a = src.add_text("a", b"leaf", &BTreeSet::new()).unwrap();
        let b = src.add_text("b", src.dir.print(&a).as_bytes(), &[a.clone()].into()).unwrap();
        let key = SecretKey::from_seed("test-1", &[9; 32]);
        let cache_url = format!("file://{}/cache", root.display());
        let cache = BinaryCache::open(&cache_url).unwrap();
        cache.init_for_writing(&src.dir).unwrap();
        for p in [&a, &b] {
            let info = src.query_info(p).unwrap().unwrap();
            // Text paths are content-addressed; drop CA so the signature matters.
            let info = PathInfo { ca: None, ..info };
            cache.add_path(&src.dir, &src.real_path(p), &info, &[], std::slice::from_ref(&key)).unwrap();
        }

        // Without the key nothing is trusted.
        let mut dst = Store::open_chroot(&root.join("dst")).unwrap();
        dst.set_substituters(Substituters::new(vec![BinaryCache::open(&cache_url).unwrap()], vec![], true, 4));
        assert!(!dst.substitutable(std::slice::from_ref(&b)));

        let mut dst = Store::open_chroot(&root.join("dst")).unwrap();
        dst.set_substituters(Substituters::new(vec![BinaryCache::open(&cache_url).unwrap()], vec![key.to_public()], true, 4));
        assert!(dst.substitutable(std::slice::from_ref(&b)));
        assert!(dst.substitute_paths(std::slice::from_ref(&b)).unwrap().is_empty());
        assert!(dst.is_valid(&a) && dst.is_valid(&b));
        assert!(dst.verify(&b).unwrap());
        assert_eq!(dst.query_sigs(&b).unwrap().len(), 1);
        assert_eq!(fs::read(dst.real_path(&a)).unwrap(), b"leaf");
        fsutil::remove_all(&root).unwrap();
    }
}
