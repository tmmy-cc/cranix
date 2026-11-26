//! Flakes: reading `flake.nix`, computing and writing `flake.lock`, and
//! calling a locked flake's `outputs` function.

pub mod flakeref;
pub mod lockfile;

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use oxnix_core::StorePath;
use oxnix_fetchers::Attr;

use crate::eval::{err, Eval, EvalError, R};
use crate::value::*;
pub use flakeref::FlakeRef;
use lockfile::{print_input_path, Edge, InputPath, LockFile, Locked, Node};

/// `call-flake.nix` from Nix 2.24: turns a lock file plus the trees
/// fetched while locking into the flake's outputs.
const CALL_FLAKE_NIX: &str = include_str!("call-flake.nix");

fn lift<T>(r: Result<T, String>) -> R<T> {
    r.or_else(err)
}

fn trace<T>(r: R<T>, f: impl FnOnce() -> String) -> R<T> {
    r.map_err(|mut e: Box<EvalError>| {
        e.trace.push(f());
        e
    })
}

#[derive(Clone, Debug, Default)]
pub struct FlakeInput {
    pub r#ref: Option<FlakeRef>,
    pub is_flake: bool,
    pub follows: Option<InputPath>,
    pub overrides: BTreeMap<String, FlakeInput>,
}

pub type FlakeInputs = BTreeMap<String, FlakeInput>;

#[derive(Clone, Debug)]
pub enum ConfigValue {
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct Flake {
    pub original_ref: FlakeRef,
    pub resolved_ref: FlakeRef,
    pub locked_ref: FlakeRef,
    pub store_path: StorePath,
    /// Logical path of the directory holding `flake.nix`.
    pub dir: String,
    pub description: Option<String>,
    pub inputs: FlakeInputs,
    pub config: BTreeMap<String, ConfigValue>,
    pub force_dirty: bool,
}

impl Flake {
    pub fn lock_file_path(&self) -> String {
        format!("{}/flake.lock", self.dir)
    }
}

type FlakeCache = Vec<(FlakeRef, (StorePath, FlakeRef))>;

fn fetch_or_substitute_tree(ev: &Eval, original: &FlakeRef, allow_lookup: bool, cache: &mut FlakeCache) -> R<(StorePath, FlakeRef, FlakeRef)> {
    let find = |c: &FlakeCache, r: &FlakeRef| c.iter().find(|(k, _)| k == r).map(|(_, v)| v.clone());
    let mut resolved = original.clone();
    let fetched = match find(cache, original) {
        Some(f) => f,
        None => {
            let f = if original.input.is_direct() {
                lift(original.fetch_tree(&ev.store))?
            } else if allow_lookup {
                resolved = lift(original.resolve(&ev.store))?;
                let f = match find(cache, original) {
                    Some(f) => f,
                    None => lift(resolved.fetch_tree(&ev.store))?,
                };
                cache.push((resolved.clone(), f.clone()));
                f
            } else {
                return err(format!("'{}' is an indirect flake reference, but registry lookups are not allowed", original.to_string()));
            };
            cache.push((original.clone(), f.clone()));
            f
        }
    };
    Ok((fetched.0, resolved, fetched.1))
}

fn expect_str(ev: &Eval, v: &Value, what: &str) -> R<String> {
    match ev.force(v)? {
        Value::Str(s) => Ok(s.s.clone()),
        v => err(format!("expected a string but got {} at {what}", v.type_name())),
    }
}

fn parse_inputs(ev: &Eval, v: &Value, base_dir: &str, lock_root: &InputPath) -> R<FlakeInputs> {
    let a = match ev.force(v)? {
        Value::Attrs(a) => a,
        v => return err(format!("expected a set but got {}", v.type_name())),
    };
    let mut out = FlakeInputs::new();
    for (k, v) in a.iter() {
        let i = trace(parse_input(ev, k.as_str(), v, base_dir, lock_root), || format!("while evaluating flake input '{}'", k.as_str()))?;
        out.insert(k.as_str().to_string(), i);
    }
    Ok(out)
}

fn parse_input(ev: &Eval, name: &str, v: &Value, base_dir: &str, lock_root: &InputPath) -> R<FlakeInput> {
    let a = match ev.force(v)? {
        Value::Attrs(a) => a,
        v => return err(format!("expected a set but got {}", v.type_name())),
    };
    let mut input = FlakeInput { is_flake: true, ..Default::default() };
    let mut attrs = oxnix_fetchers::Attrs::new();
    let mut url = None;
    for (k, v) in a.iter() {
        let r: R<()> = (|| {
            match k.as_str() {
                "url" => {
                    let s = expect_str(ev, v, "url")?;
                    attrs.insert("url".into(), Attr::Str(s.clone()));
                    url = Some(s);
                }
                "flake" => input.is_flake = ev.force_bool(v)?,
                "inputs" => input.overrides = parse_inputs(ev, v, base_dir, lock_root)?,
                "follows" => {
                    let s = expect_str(ev, v, "follows")?;
                    let mut p = lock_root.clone();
                    p.extend(lift(lockfile::parse_input_path(&s))?);
                    input.follows = Some(p);
                }
                n => {
                    let x = match ev.force(v)? {
                        Value::Str(s) => Attr::Str(s.s.clone()),
                        Value::Bool(b) => Attr::Bool(b),
                        Value::Int(i) => Attr::Int(i as u64),
                        v => {
                            return err(format!(
                                "flake input attribute '{n}' is {} while a string, Boolean, or integer is expected",
                                v.describe()
                            ))
                        }
                    };
                    attrs.insert(n.to_string(), x);
                }
            }
            Ok(())
        })();
        trace(r, || format!("while evaluating flake attribute '{}'", k.as_str()))?;
    }
    if attrs.contains_key("type") {
        input.r#ref = Some(lift(FlakeRef::from_attrs(attrs))?);
    } else {
        attrs.remove("url");
        if let Some(k) = attrs.keys().next() {
            return err(format!("unexpected flake input attribute '{k}'"));
        }
        if let Some(u) = url {
            input.r#ref = Some(lift(flakeref::parse(&u, Some(base_dir), true, input.is_flake))?);
        }
    }
    if input.follows.is_none() && input.r#ref.is_none() {
        let mut a = oxnix_fetchers::Attrs::new();
        a.insert("type".into(), "indirect".into());
        a.insert("id".into(), Attr::Str(name.into()));
        input.r#ref = Some(lift(FlakeRef::from_attrs(a))?);
    }
    Ok(input)
}

fn read_flake(ev: &Eval, original: FlakeRef, resolved: FlakeRef, locked: FlakeRef, sp: StorePath, lock_root: &InputPath) -> R<Flake> {
    let root = ev.store.dir.print(&sp);
    let dir = if resolved.subdir.is_empty() { root.clone() } else { oxnix_fetchers::input::canon(&format!("{root}/{}", resolved.subdir)) };
    let file = format!("{dir}/flake.nix");
    if !ev.store.resolve(&file).exists() {
        return err(format!(
            "source tree referenced by '{}' does not contain a '{}flake.nix' file",
            resolved.to_string(),
            if resolved.subdir.is_empty() { String::new() } else { format!("{}/", resolved.subdir) }
        ));
    }
    let v = ev.import(&file)?;
    let a = match ev.force(&v)? {
        Value::Attrs(a) => a,
        v => return err(format!("file '{file}' must be an attribute set, but it is {}", v.describe())),
    };
    let mut flake = Flake {
        original_ref: original,
        resolved_ref: resolved.clone(),
        locked_ref: locked,
        store_path: sp,
        dir: dir.clone(),
        description: None,
        inputs: FlakeInputs::new(),
        config: BTreeMap::new(),
        force_dirty: false,
    };
    if let Some(d) = a.get_str("description") {
        flake.description = Some(expect_str(ev, d, "description")?);
    }
    if let Some(i) = a.get_str("inputs") {
        flake.inputs = parse_inputs(ev, i, &dir, lock_root)?;
    }
    match a.get_str("outputs") {
        Some(o) => match ev.force(o)? {
            Value::Lambda(c) => {
                if let Some(f) = &c.def.formals {
                    for (s, _) in f.entries.iter() {
                        if s.as_str() != "self" && !flake.inputs.contains_key(s.as_str()) {
                            let r = lift(flakeref::parse(s.as_str(), None, false, true))?;
                            flake.inputs.insert(s.as_str().into(), FlakeInput { r#ref: Some(r), is_flake: true, ..Default::default() });
                        }
                    }
                }
            }
            Value::PrimOp(_) => {}
            v => return err(format!("expected a function but got {}", v.type_name())),
        },
        None => return err(format!("flake '{}' lacks attribute 'outputs'", resolved.to_string())),
    }
    if let Some(c) = a.get_str("nixConfig") {
        for (k, v) in ev.force_attrs(c)?.iter() {
            let cv = match ev.force(v)? {
                Value::Str(s) => ConfigValue::Str(s.s.clone()),
                Value::Path(p) => ConfigValue::Str(p.to_string()),
                Value::Int(n) => ConfigValue::Int(n),
                Value::Bool(b) => ConfigValue::Bool(b),
                Value::List(l) => {
                    let mut ss = Vec::new();
                    for x in l.iter() {
                        ss.push(ev.force_plain_str(x)?);
                    }
                    ConfigValue::List(ss)
                }
                v => return err(format!("flake configuration setting '{}' is {}", k.as_str(), v.describe())),
            };
            flake.config.insert(k.as_str().into(), cv);
        }
    }
    for (k, _) in a.iter() {
        if !matches!(k.as_str(), "description" | "inputs" | "outputs" | "nixConfig") {
            return err(format!("flake '{}' has an unsupported attribute '{}'", resolved.to_string(), k.as_str()));
        }
    }
    Ok(flake)
}

fn get_flake_inner(ev: &Eval, r: &FlakeRef, allow_lookup: bool, cache: &mut FlakeCache, lock_root: &InputPath) -> R<Flake> {
    let (sp, resolved, locked) = fetch_or_substitute_tree(ev, r, allow_lookup, cache)?;
    read_flake(ev, r.clone(), resolved, locked, sp, lock_root)
}

pub fn get_flake(ev: &Eval, r: &FlakeRef, allow_lookup: bool) -> R<Flake> {
    get_flake_inner(ev, r, allow_lookup, &mut Vec::new(), &Vec::new())
}

#[derive(Clone, Debug, Default)]
pub struct LockFlags {
    pub recreate_lock_file: bool,
    pub update_lock_file: bool,
    pub write_lock_file: bool,
    pub use_registries: Option<bool>,
    pub allow_unlocked: bool,
    pub commit_lock_file: bool,
    pub reference_lock_file: Option<String>,
    pub output_lock_file: Option<String>,
    pub input_overrides: Vec<(InputPath, FlakeRef)>,
    pub input_updates: BTreeSet<InputPath>,
}

impl LockFlags {
    pub fn cli() -> LockFlags {
        LockFlags { update_lock_file: true, write_lock_file: true, allow_unlocked: true, ..Default::default() }
    }
}

pub struct LockedFlake {
    pub flake: Flake,
    pub lock_file: LockFile,
    /// Where each node fetched while locking lives (logical paths).
    pub node_paths: Vec<(Rc<Node>, String)>,
}

impl LockedFlake {
    /// Nix's flake fingerprint (the evaluation cache key).
    pub fn fingerprint(&self, store: &oxnix_store::Store) -> Option<String> {
        if self.lock_file.is_unlocked().is_some() {
            return None;
        }
        let r = &self.flake.locked_ref;
        let mut f = r.input.fingerprint(store)?;
        f.push_str(&format!(";{};{}", r.subdir, self.lock_file.to_string()));
        if let Ok(Some(n)) = r.input.get_rev_count() {
            f.push_str(&format!(";revCount={n}"));
        }
        if let Ok(Some(n)) = r.input.get_last_modified() {
            f.push_str(&format!(";lastModified={n}"));
        }
        Some(oxnix_core::Hash::sha256(f.as_bytes()).to_base16())
    }
}

fn read_lock_file(ev: &Eval, path: &str) -> R<LockFile> {
    let real = ev.store.resolve(path);
    match std::fs::read_to_string(&real) {
        Ok(t) => lift(LockFile::parse(&t, path)),
        Err(_) => Ok(LockFile::default()),
    }
}

struct Locker<'a> {
    ev: &'a Eval,
    flags: &'a LockFlags,
    use_registries: bool,
    cache: FlakeCache,
    overrides: BTreeMap<InputPath, FlakeInput>,
    explicit_cli: BTreeSet<InputPath>,
    overrides_used: BTreeSet<InputPath>,
    updates_used: BTreeSet<InputPath>,
    node_paths: Vec<(Rc<Node>, String)>,
    parents: Vec<FlakeRef>,
}

impl Locker<'_> {
    #[allow(clippy::too_many_arguments)]
    fn compute(
        &mut self,
        inputs: &FlakeInputs,
        node: &Rc<Node>,
        prefix: &InputPath,
        old_node: Option<Rc<Node>>,
        lock_root: &InputPath,
        parent_path: &str,
        trust_lock: bool,
    ) -> R<()> {
        for (id, input) in inputs {
            for (oid, o) in &input.overrides {
                let mut p = prefix.clone();
                p.push(id.clone());
                p.push(oid.clone());
                self.overrides.insert(p, o.clone());
            }
        }
        for p in self.overrides.keys() {
            let (last, head) = p.split_last().unwrap();
            if head == prefix.as_slice() && !inputs.contains_key(last) {
                oxnix_fetchers::warn(format!(
                    "input '{}' has an override for a non-existent input '{last}'",
                    print_input_path(prefix)
                ));
            }
        }
        for (id, input2) in inputs {
            let mut path = prefix.clone();
            path.push(id.clone());
            let ps = print_input_path(&path);
            let r = self.compute_one(id, input2, node, &path, old_node.clone(), lock_root, parent_path, trust_lock);
            trace(r, || format!("while updating the flake input '{ps}'"))?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_one(
        &mut self,
        id: &str,
        input2: &FlakeInput,
        node: &Rc<Node>,
        path: &InputPath,
        old_node: Option<Rc<Node>>,
        lock_root: &InputPath,
        parent_path: &str,
        trust_lock: bool,
    ) -> R<()> {
        let has_override = self.overrides.contains_key(path);
        let has_cli = self.explicit_cli.contains(path);
        if has_override {
            self.overrides_used.insert(path.clone());
            self.overrides.get_mut(path).unwrap().is_flake = input2.is_flake;
        }
        let input = if has_override { self.overrides[path].clone() } else { input2.clone() };
        if let Some(f) = &input.follows {
            node.inputs.borrow_mut().insert(id.into(), Edge::Follows(f.clone()));
            return Ok(());
        }
        let iref = input.r#ref.clone().unwrap();
        self.updates_used.insert(path.clone());
        let mut old_lock: Option<Rc<Node>> = None;
        if let Some(on) = &old_node {
            if !self.flags.input_updates.contains(path) {
                if let Some(Edge::Node(n)) = on.inputs.borrow().get(id) {
                    old_lock = Some(n.clone());
                }
            }
        }
        if let Some(ol) = old_lock.as_ref().filter(|ol| ol.locked.as_ref().unwrap().original == iref && !has_cli) {
            let l = ol.locked.clone().unwrap();
            let child = Node::locked(l.clone());
            node.inputs.borrow_mut().insert(id.into(), Edge::Node(child.clone()));
            let mut must_refetch = self.flags.input_updates.iter().any(|u| u.len() > path.len() && u.starts_with(path));
            let mut fake = FlakeInputs::new();
            if !must_refetch {
                for (k, e) in ol.inputs.borrow().iter() {
                    match e {
                        Edge::Node(n) => {
                            let nl = n.locked.as_ref().unwrap();
                            fake.insert(k.clone(), FlakeInput { r#ref: Some(nl.original.clone()), is_flake: nl.is_flake, ..Default::default() });
                        }
                        Edge::Follows(f) => {
                            if !trust_lock {
                                let mut op = path.clone();
                                op.push(k.clone());
                                if !self.overrides.contains_key(&op) {
                                    must_refetch = true;
                                    break;
                                }
                            }
                            let mut abs = lock_root.clone();
                            abs.extend(f.iter().cloned());
                            fake.insert(k.clone(), FlakeInput { follows: Some(abs), is_flake: true, ..Default::default() });
                        }
                    }
                }
            }
            if must_refetch {
                let f = get_flake_inner(self.ev, &l.locked, false, &mut self.cache, path)?;
                self.node_paths.push((child.clone(), f.dir.clone()));
                self.compute(&f.inputs, &child, path, Some(ol.clone()), lock_root, parent_path, false)?;
            } else {
                self.compute(&fake, &child, path, Some(ol.clone()), lock_root, parent_path, true)?;
            }
            return Ok(());
        }
        if !self.flags.allow_unlocked && !iref.input.is_locked() {
            return err(format!("cannot update unlocked flake input '{}' in pure mode", print_input_path(path)));
        }
        let original = match (&input2.r#ref, has_cli) {
            (Some(r), true) => r.clone(),
            _ => iref.clone(),
        };
        if input.is_flake {
            let mut local_path = parent_path.to_string();
            if iref.input.ty() == "path" {
                if let Some(p) = iref.input.get_source_path() {
                    local_path = if p.starts_with('/') { p } else { oxnix_fetchers::input::canon(&format!("{parent_path}/{p}")) };
                }
            }
            let f = get_flake_inner(self.ev, &iref, self.use_registries, &mut self.cache, path)?;
            let child = Node::locked(Locked { locked: f.locked_ref.clone(), original, is_flake: true });
            node.inputs.borrow_mut().insert(id.into(), Edge::Node(child.clone()));
            if self.parents.contains(&iref) {
                return err(format!("found circular import of flake '{}'", iref.to_string()));
            }
            self.parents.push(iref.clone());
            self.node_paths.push((child.clone(), f.dir.clone()));
            let (old, root) = match &old_lock {
                Some(ol) => (Some(ol.clone()), lock_root.clone()),
                None => (Some(read_lock_file(self.ev, &f.lock_file_path())?.root), path.clone()),
            };
            let r = self.compute(&f.inputs, &child, path, old, &root, &local_path, false);
            self.parents.pop();
            r?;
        } else {
            let (sp, _, locked) = fetch_or_substitute_tree(self.ev, &iref, self.use_registries, &mut self.cache)?;
            let child = Node::locked(Locked { locked, original, is_flake: false });
            self.node_paths.push((child.clone(), self.ev.store.dir.print(&sp)));
            node.inputs.borrow_mut().insert(id.into(), Edge::Node(child));
        }
        Ok(())
    }
}

/// Computes the lock file of `top`, writing it back when it changed and
/// `flags` allow it.
pub fn lock_flake(ev: &Eval, top: &FlakeRef, flags: &LockFlags) -> R<LockedFlake> {
    let use_registries = flags.use_registries.unwrap_or_else(|| oxnix_fetchers::settings().use_registries);
    let mut cache = FlakeCache::new();
    let mut flake = get_flake_inner(ev, top, use_registries, &mut cache, &Vec::new())?;
    let r: R<LockedFlake> = (|| {
        let old = read_lock_file(ev, flags.reference_lock_file.as_deref().unwrap_or(&flake.lock_file_path()))?;
        let mut locker = Locker {
            ev,
            flags,
            use_registries,
            cache,
            overrides: BTreeMap::new(),
            explicit_cli: BTreeSet::new(),
            overrides_used: BTreeSet::new(),
            updates_used: BTreeSet::new(),
            node_paths: Vec::new(),
            parents: Vec::new(),
        };
        for (p, r) in &flags.input_overrides {
            locker.overrides.insert(p.clone(), FlakeInput { r#ref: Some(r.clone()), is_flake: true, ..Default::default() });
            locker.explicit_cli.insert(p.clone());
        }
        let new = LockFile::default();
        locker.node_paths.push((new.root.clone(), flake.dir.clone()));
        let old_root = if flags.recreate_lock_file { None } else { Some(old.root.clone()) };
        let parent = flake.dir.clone();
        locker.compute(&flake.inputs.clone(), &new.root, &Vec::new(), old_root, &Vec::new(), &parent, false)?;
        for (p, r) in &flags.input_overrides {
            if !locker.overrides_used.contains(p) {
                oxnix_fetchers::warn(format!("the flag '--override-input {} {}' does not match any input", print_input_path(p), r.to_string()));
            }
        }
        for p in &flags.input_updates {
            if !locker.updates_used.contains(p) {
                oxnix_fetchers::warn(format!("'{}' does not match any input of this flake", print_input_path(p)));
            }
        }
        lift(new.check())?;
        let source_path = top.input.get_source_path();
        if new != old || flags.output_lock_file.is_some() {
            let diff = LockFile::diff(&old, &new);
            let diff = diff.trim_end();
            if flags.write_lock_file {
                if source_path.is_some() || flags.output_lock_file.is_some() {
                    if let Some(u) = new.is_unlocked() {
                        oxnix_fetchers::warn(format!(
                            "will not write lock file of flake '{}' because it has an unlocked input ('{}')",
                            top.to_string(),
                            u.to_string()
                        ));
                    } else {
                        if !flags.update_lock_file {
                            return err(format!(
                                "flake '{}' requires lock file changes but they're not allowed due to '--no-update-lock-file'",
                                top.to_string()
                            ));
                        }
                        let text = format!("{}\n", new.to_string());
                        if let Some(out) = &flags.output_lock_file {
                            std::fs::write(out, &text).or_else(|e| err(format!("writing '{out}': {e}")))?;
                        } else {
                            let rel = if top.subdir.is_empty() { "flake.lock".to_string() } else { format!("{}/flake.lock", top.subdir) };
                            let out = format!("{}/{rel}", source_path.unwrap());
                            let exists = std::path::Path::new(&out).exists();
                            if exists {
                                if diff.is_empty() {
                                    oxnix_fetchers::warn(format!("updating lock file '{out}'"));
                                } else {
                                    oxnix_fetchers::warn(format!("updating lock file '{out}':\n{diff}"));
                                }
                            } else {
                                oxnix_fetchers::warn(format!("creating lock file '{out}': \n{diff}"));
                            }
                            lift(top.input.put_file(&rel, &text))?;
                            if flags.commit_lock_file {
                                commit_lock_file(top, &rel, exists, diff)?;
                            }
                        }
                        // The source changed; the root keeps the tree it
                        // was locked from, as in Nix.
                        flake = get_flake_inner(ev, top, use_registries, &mut Vec::new(), &Vec::new())?;
                    }
                } else {
                    return err(format!(
                        "cannot write modified lock file of flake '{}' (use '--no-write-lock-file' to ignore)",
                        top.to_string()
                    ));
                }
            } else {
                oxnix_fetchers::warn(format!("not writing modified lock file of flake '{}':\n{diff}", top.to_string()));
                flake.force_dirty = true;
            }
        }
        Ok(LockedFlake { flake: flake.clone(), lock_file: new, node_paths: locker.node_paths })
    })();
    let locked = flake.locked_ref.to_string();
    trace(r, || format!("while updating the lock file of flake '{locked}'"))
}

fn commit_lock_file(top: &FlakeRef, rel: &str, existed: bool, diff: &str) -> R<()> {
    let Some(dir) = top.input.get_source_path() else { return Ok(()) };
    let msg = format!("{rel}: {}\n\nFlake lock file updates:\n\n{diff}\n", if existed { "Update" } else { "Add" });
    let mut child = std::process::Command::new("git")
        .arg("-C")
        .arg(&dir)
        .args(["commit", rel, "-F", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .or_else(|e| err(format!("running git: {e}")))?;
    use std::io::Write;
    child.stdin.take().unwrap().write_all(msg.as_bytes()).ok();
    if !child.wait().map(|s| s.success()).unwrap_or(false) {
        return err("committing the lock file failed");
    }
    Ok(())
}

/// Evaluates a locked flake: its outputs with `self`, `inputs`,
/// `sourceInfo` and the source attributes.
pub fn call_flake(ev: &Eval, lf: &LockedFlake) -> R<Value> {
    let (json, keys) = lf.lock_file.to_json();
    let lock_str = serde_json::to_string_pretty(&json).unwrap();
    let mut overrides = Vec::new();
    for (node, path) in &lf.node_paths {
        let (sp, sub) = ev.store.dir.to_store_path(path).ok_or(()).or_else(|_| err(format!("'{path}' is not in the store")))?;
        let (input, dirty) = match &node.locked {
            Some(l) => (&l.locked.input, false),
            None => (&lf.flake.locked_ref.input, lf.flake.force_dirty),
        };
        let si = crate::fetch::emit_tree_attrs(ev, &sp, input, false, dirty)?;
        let key = keys.iter().find(|(n, _)| Rc::ptr_eq(n, node)).map(|(_, k)| k.clone()).unwrap();
        let o = Value::attrs(Attrs::from_unsorted(vec![
            (Sym::new("sourceInfo"), si),
            (Sym::new("dir"), Value::str(sub.trim_start_matches('/'))),
        ]));
        overrides.push((Sym::new(&key), o));
    }
    let e = ev.parse(CALL_FLAKE_NIX, "<nix/call-flake.nix>", "/")?;
    let f = ev.eval(e, &ev.base_env().clone())?;
    let f2 = ev.call(&f, Value::str(lock_str))?;
    ev.call(&f2, Value::attrs(Attrs::from_unsorted(overrides)))
}

pub fn prim_get_flake(ev: &Eval, a: &[Value]) -> R<Value> {
    let s = ev.force_plain_str(&a[0])?;
    let r = lift(flakeref::parse(&s, None, true, true))?;
    if ev.opts.pure && !r.input.is_locked() {
        return err(format!("cannot call 'getFlake' on unlocked flake reference '{s}' (use --impure to override)"));
    }
    let flags = LockFlags {
        update_lock_file: false,
        write_lock_file: false,
        use_registries: Some(!ev.opts.pure && oxnix_fetchers::settings().use_registries),
        allow_unlocked: !ev.opts.pure,
        ..Default::default()
    };
    let lf = lock_flake(ev, &r, &flags)?;
    call_flake(ev, &lf)
}

pub fn prim_parse_flake_ref(ev: &Eval, a: &[Value]) -> R<Value> {
    let s = ev.force_plain_str(&a[0])?;
    let r = lift(flakeref::parse(&s, None, true, true))?;
    Ok(attrs_value(&r.to_attrs()))
}

pub fn attrs_value(a: &oxnix_fetchers::Attrs) -> Value {
    Value::attrs(Attrs::from_unsorted(
        a.iter()
            .map(|(k, v)| {
                let x = match v {
                    Attr::Str(s) => Value::str(s.as_str()),
                    Attr::Int(n) => Value::Int(*n as i64),
                    Attr::Bool(b) => Value::Bool(*b),
                };
                (Sym::new(k), x)
            })
            .collect(),
    ))
}

pub fn prim_flake_ref_to_string(ev: &Eval, a: &[Value]) -> R<Value> {
    let attrs = ev.force_attrs(&a[0])?;
    let fa = crate::fetch::value_to_input_attrs(ev, &attrs, false, "flakeRefToString")?;
    let r = lift(FlakeRef::from_attrs(fa))?;
    Ok(Value::str(r.to_string()))
}
