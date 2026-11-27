//! Uploading outputs to a binary cache while a build runs (`upload-to`).
//!
//! Each finished output is handed to an [`Uploads`] queue, which uploads
//! it with its closure on `upload-jobs` threads. A path goes up only once
//! every path it references is in the cache, and [`BinaryCache::add_path`]
//! writes the NAR before the narinfo, so the cache holds complete closures
//! at every moment, also when the build is stopped half way.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};

use cranix_core::signing::SecretKey;
use cranix_core::StorePath;

use crate::binary_cache::{read_secret_keys, BinaryCache};
use crate::build::{log_message, BuildLogger};
use crate::settings::Settings;
use crate::{Result, Store};

/// Where a build uploads its outputs, from the `upload-to`, `upload-jobs`,
/// `upload-required` and `secret-key-files` settings.
pub struct UploadTarget {
    /// The cache, or why it could not be opened.
    cache: std::result::Result<BinaryCache, String>,
    keys: Vec<SecretKey>,
    pub jobs: usize,
    /// Whether a failed upload fails the build.
    pub required: bool,
}

impl std::fmt::Debug for UploadTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cache = self.cache.as_ref().map(BinaryCache::shown);
        write!(f, "UploadTarget({cache:?}, {} keys, jobs {}, required {})", self.keys.len(), self.jobs, self.required)
    }
}

impl UploadTarget {
    /// The target `s` describes; `None` when `upload-to` is empty.
    pub fn from_settings(s: &Settings) -> Option<Arc<UploadTarget>> {
        if s.upload_to.is_empty() {
            return None;
        }
        let opened = crate::substitute::open_cache(&s.upload_to, s).and_then(|cache| {
            let mut files: Vec<&str> = s.secret_key_files.iter().map(String::as_str).collect();
            files.extend(cache.param("secret-key"));
            let keys = read_secret_keys(files)?;
            Ok((cache, keys))
        });
        let (cache, keys) = match opened {
            Ok((c, k)) => (Ok(c), k),
            Err(e) => (Err(e), Vec::new()),
        };
        Some(Arc::new(UploadTarget { cache, keys, jobs: s.upload_jobs.max(1), required: s.upload_required }))
    }

    /// A target for `cache`, for callers that open the cache themselves.
    pub fn new(cache: BinaryCache, keys: Vec<SecretKey>, jobs: usize, required: bool) -> UploadTarget {
        UploadTarget { cache: Ok(cache), keys, jobs: jobs.max(1), required }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    /// Waiting for this many references.
    Waiting(usize),
    Ready,
    Done,
    Failed,
}

#[derive(Default)]
struct State {
    status: HashMap<StorePath, Status>,
    dependents: HashMap<StorePath, Vec<StorePath>>,
    ready: VecDeque<StorePath>,
    running: usize,
    closed: bool,
    errors: Vec<String>,
}

/// The upload queue of one realisation.
pub(crate) struct Uploads<'a> {
    store: &'a Store,
    cache: &'a BinaryCache,
    target: &'a UploadTarget,
    logger: Option<Arc<dyn BuildLogger>>,
    state: Mutex<State>,
    cv: Condvar,
}

impl<'a> Uploads<'a> {
    pub(crate) fn new(store: &'a Store, target: &'a UploadTarget, logger: Option<Arc<dyn BuildLogger>>) -> Result<Uploads<'a>> {
        let cache = target.cache.as_ref().map_err(|e| format!("cannot upload build outputs: {e}"))?;
        cache.init_for_writing(&store.dir)?;
        Ok(Uploads { store, cache, target, logger, state: Mutex::new(State::default()), cv: Condvar::new() })
    }

    pub(crate) fn jobs(&self) -> usize {
        self.target.jobs
    }

    /// Queues `paths` and their closures; each path is uploaded once.
    pub(crate) fn submit<'p>(&self, paths: impl IntoIterator<Item = &'p StorePath>) {
        let mut st = self.state.lock().unwrap();
        for p in paths {
            if let Err(e) = self.add(&mut st, p) {
                st.errors.push(e);
            }
        }
        self.cv.notify_all();
    }

    /// Adds `p` after its references, iteratively in post-order.
    fn add(&self, st: &mut State, root: &StorePath) -> Result<()> {
        let mut stack: Vec<(StorePath, Option<Vec<StorePath>>)> = vec![(root.clone(), None)];
        while let Some((p, refs)) = stack.pop() {
            if st.status.contains_key(&p) {
                continue;
            }
            let Some(refs) = refs else {
                let info = self.store.query_info(&p)?.ok_or_else(|| format!("path '{}' is not valid", self.store.dir.print(&p)))?;
                let refs: Vec<StorePath> = info.references.into_iter().filter(|r| *r != p).collect();
                let todo: Vec<StorePath> = refs.iter().filter(|r| !st.status.contains_key(*r)).cloned().collect();
                stack.push((p, Some(refs)));
                stack.extend(todo.into_iter().map(|r| (r, None)));
                continue;
            };
            let mut waiting = 0;
            let mut failed = false;
            for r in &refs {
                match st.status.get(r) {
                    Some(Status::Done) => {}
                    Some(Status::Failed) => failed = true,
                    _ => {
                        waiting += 1;
                        st.dependents.entry(r.clone()).or_default().push(p.clone());
                    }
                }
            }
            if failed {
                st.status.insert(p, Status::Failed);
            } else if waiting == 0 {
                st.status.insert(p.clone(), Status::Ready);
                st.ready.push_back(p);
            } else {
                st.status.insert(p, Status::Waiting(waiting));
            }
        }
        Ok(())
    }

    /// Runs uploads until the queue is closed and empty.
    pub(crate) fn work(&self) {
        loop {
            let p = {
                let mut st = self.state.lock().unwrap();
                loop {
                    if let Some(p) = st.ready.pop_front() {
                        st.running += 1;
                        break p;
                    }
                    if st.closed && st.running == 0 {
                        self.cv.notify_all();
                        return;
                    }
                    st = self.cv.wait(st).unwrap();
                }
            };
            let r = self.upload(&p);
            let mut st = self.state.lock().unwrap();
            st.running -= 1;
            match r {
                Ok(()) => {
                    st.status.insert(p.clone(), Status::Done);
                    for d in st.dependents.remove(&p).unwrap_or_default() {
                        if let Some(Status::Waiting(n)) = st.status.get(&d).copied() {
                            if n == 1 {
                                st.status.insert(d.clone(), Status::Ready);
                                st.ready.push_back(d);
                            } else {
                                st.status.insert(d, Status::Waiting(n - 1));
                            }
                        }
                    }
                }
                Err(e) => {
                    let msg = format!("uploading '{}' to '{}': {e}", self.store.dir.print(&p), self.cache.shown());
                    log_message(self.logger.as_ref(), &format!("warning: {msg}"));
                    st.errors.push(msg);
                    // Paths that refer to a failed one stay out of the cache.
                    let mut todo = vec![p];
                    while let Some(q) = todo.pop() {
                        st.status.insert(q.clone(), Status::Failed);
                        todo.extend(st.dependents.remove(&q).unwrap_or_default());
                    }
                }
            }
            self.cv.notify_all();
        }
    }

    fn upload(&self, p: &StorePath) -> Result<()> {
        let store = self.store;
        if !self.cache.file_exists(&format!("{}.narinfo", p.hash_part()))? {
            let info = store.query_info(p)?.ok_or_else(|| format!("path '{}' is not valid", store.dir.print(p)))?;
            log_message(self.logger.as_ref(), &format!("copying path '{}' to '{}'...", store.dir.print(p), self.cache.shown()));
            self.cache.add_path(&store.dir, &store.real_path(p), &info, &store.query_sigs(p)?, &self.target.keys)?;
        }
        for r in store.realisations_of(&BTreeSet::from([p.clone()]))? {
            self.cache.add_realisation(&r, &self.target.keys)?;
        }
        Ok(())
    }

    /// Lets the workers finish once the queue is empty.
    pub(crate) fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.cv.notify_all();
    }

    /// The failures, as one message; `Ok` when all uploads succeeded or
    /// failures are allowed.
    pub(crate) fn result(&self) -> Result<()> {
        let st = self.state.lock().unwrap();
        if st.errors.is_empty() || !self.target.required {
            return Ok(());
        }
        Err(st.errors.join("\n"))
    }
}

/// Runs `f` with an upload queue for `opts.upload`, served by worker
/// threads, and waits for the queued uploads before returning.
pub(crate) fn with_uploads<T>(
    store: &Store,
    opts: &crate::build::BuildOptions,
    f: impl FnOnce(Option<&Uploads>) -> Result<T>,
) -> Result<T> {
    let Some(target) = opts.upload.as_deref() else { return f(None) };
    let up = Uploads::new(store, target, opts.logger.clone())?;
    let r = std::thread::scope(|scope| {
        for _ in 0..up.jobs() {
            scope.spawn(|| up.work());
        }
        let r = f(Some(&up));
        up.close();
        r
    });
    let r = r?;
    up.result()?;
    Ok(r)
}
