//! Fetcher inputs: attribute sets with a `type` naming the scheme, their
//! URL syntax, locking rules and fetching into the store.

use std::path::PathBuf;

use oxnix_core::hash::{Hash, HashAlgo};
use oxnix_core::StorePath;
use oxnix_store::Store;

use crate::attrs::{self, get_bool, get_int, get_str, req_str, Attr, Attrs};
use crate::url::{self, parse_url, ParsedUrl};
use crate::{cache, storeutil, Result, TempDir};

#[derive(Clone, Debug, Default)]
pub struct Input {
    pub attrs: Attrs,
    /// Directory relative `path:` inputs are resolved against.
    pub parent: Option<String>,
}

impl PartialEq for Input {
    fn eq(&self, o: &Input) -> bool {
        self.attrs == o.attrs
    }
}
impl Eq for Input {}

/// A fetched file system tree, before it is copied into the store.
pub enum Tree {
    /// A directory (or file) on disk; `keep` filters entries by their path
    /// relative to the root.
    Dir { path: PathBuf, keep: Option<Box<dyn Fn(&str) -> bool>>, tmp: Option<TempDir> },
    /// A store object that already holds the tree.
    Store(StorePath),
}

const SCHEMES: &[&str] = &["file", "git", "github", "gitlab", "indirect", "path", "sourcehut", "tarball"];

fn allowed_attrs(ty: &str) -> &'static [&'static str] {
    match ty {
        "file" | "tarball" => &["type", "url", "narHash", "name", "unpack", "rev", "revCount", "lastModified"],
        "path" => &["type", "path", "rev", "revCount", "lastModified", "narHash"],
        "git" => &[
            "type", "url", "ref", "rev", "shallow", "submodules", "exportIgnore", "lastModified", "revCount", "narHash", "allRefs",
            "name", "dirtyRev", "dirtyShortRev", "verifyCommit", "keytype", "publicKey", "publicKeys",
        ],
        "github" | "gitlab" | "sourcehut" => &["type", "owner", "repo", "ref", "rev", "narHash", "lastModified", "host", "treeHash"],
        "indirect" => &["type", "id", "ref", "rev", "narHash"],
        _ => &[],
    }
}

fn has_tarball_ext(p: &str) -> bool {
    [".zip", ".tar", ".tgz", ".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst"].iter().any(|e| p.ends_with(e))
}

/// Parses a Git revision (40 hex digits or another SHA-1 encoding) into
/// lowercase hex.
pub fn parse_rev(s: &str) -> Result<String> {
    let s2 = s.strip_prefix("sha1:").unwrap_or(s);
    Hash::parse_bare(s2, HashAlgo::Sha1).map(|h| h.to_base16()).map_err(|_| format!("invalid Git revision '{s}'"))
}

impl Input {
    pub fn from_attrs_unchecked(attrs: Attrs) -> Input {
        Input { attrs, parent: None }
    }

    pub fn from_url(u: &str, require_tree: bool) -> Result<Input> {
        Input::from_parsed_url(&parse_url(u)?, require_tree)
    }

    pub fn from_parsed_url(u: &ParsedUrl, require_tree: bool) -> Result<Input> {
        let (app, transport) = url::split_scheme(&u.scheme);
        // Schemes are tried in name order, as in Nix's scheme registry.
        if ["file", "http", "https"].contains(&transport) {
            let ext = has_tarball_ext(&u.path);
            let ty = match app {
                Some("file") => Some("file"),
                Some("tarball") => Some("tarball"),
                Some(_) => None,
                None if !require_tree && !ext => Some("file"),
                None => Some("tarball"),
            };
            if let Some(ty) = ty {
                return curl_from_url(u, ty, transport);
            }
        }
        match u.scheme.as_str() {
            "git" | "git+http" | "git+https" | "git+ssh" | "git+file" => return git_from_url(u),
            "github" | "gitlab" | "sourcehut" => return crate::github::from_url(u),
            "flake" => return indirect_from_url(u),
            "path" => return path_from_url(u),
            _ => {}
        }
        Err(format!("input '{}' is unsupported", u.url))
    }

    pub fn from_attrs(attrs: Attrs) -> Result<Input> {
        let ty = get_str(&attrs, "type")?.ok_or("'type' attribute to specify input scheme is required but not provided")?;
        let input = Input { attrs, parent: None };
        if !SCHEMES.contains(&ty.as_str()) {
            input.fixup()?;
            return Ok(input);
        }
        let allowed = allowed_attrs(&ty);
        for k in input.attrs.keys() {
            if !allowed.contains(&k.as_str()) {
                return Err(format!("input attribute '{k}' not supported by scheme '{ty}'"));
            }
        }
        let mut input = input;
        match ty.as_str() {
            "path" => {
                req_str(&input.attrs, "path")?;
            }
            "git" => {
                for k in ["verifyCommit", "keytype", "publicKey", "publicKeys"] {
                    if input.attrs.contains_key(k) {
                        return Err(format!("input attribute '{k}' requires the 'verified-fetches' experimental feature"));
                    }
                }
                if let Some(r) = input.get_ref()? {
                    if url::is_bad_git_ref(&r) {
                        return Err(format!("invalid Git branch/tag name '{r}'"));
                    }
                }
                let u = url::fix_git_url(&req_str(&input.attrs, "url")?);
                parse_url(&u)?;
                input.attrs.insert("url".into(), Attr::Str(u));
                for k in ["shallow", "submodules", "allRefs", "exportIgnore"] {
                    get_bool(&input.attrs, k)?;
                }
            }
            "github" | "gitlab" | "sourcehut" => {
                req_str(&input.attrs, "owner")?;
                req_str(&input.attrs, "repo")?;
            }
            "indirect" => {
                let id = req_str(&input.attrs, "id")?;
                if !url::flake_id_regex().is_match(&id) {
                    return Err(format!("'{id}' is not a valid flake ID"));
                }
            }
            _ => {}
        }
        input.fixup()?;
        Ok(input)
    }

    fn fixup(&self) -> Result<()> {
        self.get_ref()?;
        get_int(&self.attrs, "revCount")?;
        get_int(&self.attrs, "lastModified")?;
        Ok(())
    }

    pub fn ty(&self) -> String {
        get_str(&self.attrs, "type").ok().flatten().unwrap_or_default()
    }

    fn known(&self) -> bool {
        SCHEMES.contains(&self.ty().as_str())
    }

    pub fn get_ref(&self) -> Result<Option<String>> {
        get_str(&self.attrs, "ref")
    }

    pub fn get_rev(&self) -> Result<Option<String>> {
        get_str(&self.attrs, "rev")?.map(|r| parse_rev(&r)).transpose()
    }

    pub fn get_nar_hash(&self) -> Result<Option<Hash>> {
        match get_str(&self.attrs, "narHash")? {
            None => Ok(None),
            Some(s) if s.is_empty() => Ok(Some(Hash::from_bytes(HashAlgo::Sha256, &[0; 32]))),
            Some(s) => {
                let h = Hash::parse(&s, None)?;
                if h.algo != HashAlgo::Sha256 {
                    return Err("narHash must use SHA-256".into());
                }
                Ok(Some(h))
            }
        }
    }

    pub fn get_last_modified(&self) -> Result<Option<u64>> {
        get_int(&self.attrs, "lastModified")
    }

    pub fn get_rev_count(&self) -> Result<Option<u64>> {
        get_int(&self.attrs, "revCount")
    }

    pub fn get_name(&self) -> String {
        get_str(&self.attrs, "name").ok().flatten().unwrap_or_else(|| "source".into())
    }

    pub fn set(&mut self, k: &str, v: impl Into<Attr>) {
        self.attrs.insert(k.into(), v.into());
    }

    pub fn is_direct(&self) -> bool {
        self.ty() != "indirect"
    }

    pub fn is_locked(&self) -> bool {
        match self.ty().as_str() {
            "file" | "tarball" | "path" => matches!(self.get_nar_hash(), Ok(Some(_))),
            "git" | "github" | "gitlab" | "sourcehut" => matches!(self.get_rev(), Ok(Some(_))),
            _ => false,
        }
    }

    pub fn to_url(&self) -> Result<ParsedUrl> {
        let a = &self.attrs;
        let nar_query = |u: &mut ParsedUrl| -> Result<()> {
            if let Some(h) = self.get_nar_hash()? {
                u.query.insert("narHash".into(), h.to_sri());
            }
            Ok(())
        };
        match self.ty().as_str() {
            "file" | "tarball" => {
                let mut u = parse_url(&req_str(a, "url")?)?;
                nar_query(&mut u)?;
                Ok(u)
            }
            "path" => {
                let mut q = attrs::to_query(a);
                q.remove("path");
                q.remove("type");
                let mut u = ParsedUrl::new("path", None, &req_str(a, "path")?);
                u.query = q;
                Ok(u)
            }
            "git" => {
                let mut u = parse_url(&req_str(a, "url")?)?;
                if u.scheme != "git" {
                    u.scheme = format!("git+{}", u.scheme);
                }
                if let Some(r) = self.get_rev()? {
                    u.query.insert("rev".into(), r);
                }
                if let Some(r) = self.get_ref()? {
                    u.query.insert("ref".into(), r);
                }
                for k in ["shallow", "submodules", "exportIgnore", "verifyCommit"] {
                    if get_bool(a, k)?.unwrap_or(false) {
                        u.query.insert(k.into(), "1".into());
                    }
                }
                Ok(u)
            }
            "github" | "gitlab" | "sourcehut" => {
                let mut path = format!("{}/{}", req_str(a, "owner")?, req_str(a, "repo")?);
                if let Some(r) = self.get_ref()? {
                    path = format!("{path}/{r}");
                }
                if let Some(r) = self.get_rev()? {
                    path = format!("{path}/{r}");
                }
                let mut u = ParsedUrl::new(&self.ty(), None, &path);
                nar_query(&mut u)?;
                Ok(u)
            }
            "indirect" => {
                let mut path = req_str(a, "id")?;
                if let Some(r) = self.get_ref()? {
                    path = format!("{path}/{r}");
                }
                if let Some(r) = self.get_rev()? {
                    path = format!("{path}/{r}");
                }
                Ok(ParsedUrl::new("flake", None, &path))
            }
            _ => Err(format!("cannot show unsupported input '{}'", attrs::to_json_string(a))),
        }
    }

    pub fn to_url_string(&self, extra: &[(&str, &str)]) -> String {
        match self.to_url() {
            Ok(mut u) => {
                for (k, v) in extra {
                    u.query.entry(k.to_string()).or_insert(v.to_string());
                }
                u.to_url_string()
            }
            Err(_) => attrs::to_json_string(&self.attrs),
        }
    }

    pub fn to_string(&self) -> String {
        self.to_url_string(&[])
    }

    /// Whether `other` equals this input, possibly after removing its
    /// `ref` and `rev`.
    pub fn contains(&self, other: &Input) -> bool {
        if self == other {
            return true;
        }
        let mut o = other.attrs.clone();
        o.remove("ref");
        o.remove("rev");
        self.attrs == o
    }

    pub fn apply_overrides(&self, r#ref: Option<String>, rev: Option<String>) -> Result<Input> {
        let mut i = self.clone();
        match self.ty().as_str() {
            "indirect" => {
                if let Some(rev) = rev {
                    i.set("rev", rev);
                }
                if let Some(r) = r#ref {
                    i.set("ref", r);
                }
            }
            "git" => {
                if let Some(rev) = rev {
                    i.set("rev", rev);
                }
                if let Some(r) = r#ref {
                    i.set("ref", r);
                }
                if i.get_ref()?.is_none() && i.get_rev()?.is_some() {
                    return Err(format!("Git input '{}' has a commit hash but no branch/tag name", i.to_string()));
                }
            }
            "github" | "gitlab" | "sourcehut" => {
                if rev.is_some() && r#ref.is_some() {
                    return Err(format!("cannot apply both a commit hash and a branch/tag name to input '{}'", self.to_string()));
                }
                if let Some(rev) = rev {
                    i.set("rev", rev);
                    i.attrs.remove("ref");
                }
                if let Some(r) = r#ref {
                    i.set("ref", r);
                    i.attrs.remove("rev");
                }
            }
            _ => {
                if let Some(r) = r#ref {
                    return Err(format!("don't know how to set branch/tag name of input '{}' to '{r}'", self.to_string()));
                }
                if let Some(r) = rev {
                    return Err(format!("don't know how to set revision of input '{}' to '{r}'", self.to_string()));
                }
            }
        }
        Ok(i)
    }

    /// The local directory holding this input's source, for inputs whose
    /// files can be edited in place.
    pub fn get_source_path(&self) -> Option<String> {
        match self.ty().as_str() {
            "path" => get_str(&self.attrs, "path").ok().flatten(),
            "git" => crate::git::local_path(self),
            _ => None,
        }
    }

    /// Writes a file into the input's source (used for `flake.lock`).
    pub fn put_file(&self, rel: &str, contents: &str) -> Result<()> {
        match self.ty().as_str() {
            "path" => {
                let p = format!("{}/{rel}", req_str(&self.attrs, "path")?);
                std::fs::write(&p, contents).map_err(|e| format!("writing '{p}': {e}"))
            }
            "git" => crate::git::put_file(self, rel, contents),
            _ => Err(format!("input '{}' does not support modifying file '{rel}'", self.to_string())),
        }
    }

    pub fn compute_store_path(&self, store: &Store) -> Result<StorePath> {
        let h = self.get_nar_hash()?.ok_or_else(|| format!("cannot compute store path for unlocked input '{}'", self.to_string()))?;
        storeutil::fixed_path(store, &self.get_name(), &h)
    }

    /// Identifies the tree's contents for caching; `None` for unlocked inputs.
    pub fn fingerprint(&self, store: &Store) -> Option<String> {
        match self.ty().as_str() {
            "git" => {
                let rev = self.get_rev().ok()??;
                let s = if get_bool(&self.attrs, "submodules").ok()?.unwrap_or(false) { ";s" } else { "" };
                let e = if get_bool(&self.attrs, "exportIgnore").ok()?.unwrap_or(false) { ";e" } else { "" };
                Some(format!("{rev}{s}{e}"))
            }
            "github" | "gitlab" | "sourcehut" => self.get_rev().ok()?,
            "path" => {
                let p = get_str(&self.attrs, "path").ok()??;
                let (sp, rest) = store.dir.to_store_path(&p)?;
                let h = storeutil::nar_hash(store, &sp).ok()?;
                Some(format!("path:{}:{rest}", h.to_base16()))
            }
            _ => match self.get_nar_hash().ok()? {
                Some(h) => Some(h.to_sri()),
                None => self.get_rev().ok()?,
            },
        }
    }

    /// Fetches the tree without copying it into the store.
    pub fn fetch_tree(&self, store: &Store) -> Result<(Tree, Input)> {
        match self.ty().as_str() {
            "path" => fetch_path(store, self),
            "file" => {
                let mut i = self.clone();
                let f = crate::download::download_file(store, &req_str(&i.attrs, "url")?, &i.get_name(), &Vec::new())?;
                let h = storeutil::nar_hash(store, &f.store_path)?;
                i.set("narHash", h.to_sri());
                Ok((Tree::Store(f.store_path), i))
            }
            "tarball" => fetch_tarball_input(store, self),
            "git" => crate::git::fetch(store, self),
            "github" | "gitlab" | "sourcehut" => crate::github::fetch(store, self),
            "indirect" => Err(format!("indirect input '{}' cannot be fetched directly", self.to_string())),
            _ => Err(format!("cannot fetch unsupported input '{}'", attrs::to_json_string(&self.attrs))),
        }
    }

    /// Fetches the tree and checks it against the locked attributes.
    pub fn fetch_checked(&self, store: &Store) -> Result<(Tree, Input)> {
        let (t, f) = self.fetch_tree(store).map_err(|e| self.trace(e))?;
        check_locks(self, &f).map_err(|e| self.trace(e))?;
        Ok((t, f))
    }

    fn trace(&self, e: String) -> String {
        format!("{e}\n       … while fetching the input '{}'", self.to_string())
    }

    /// Fetches the input into the store, returning its path and the final
    /// (locked) input with `narHash` set.
    pub fn fetch_to_store(&self, store: &Store) -> Result<(StorePath, Input)> {
        if !self.known() {
            return Err(format!("cannot fetch unsupported input '{}'", attrs::to_json_string(&self.attrs)));
        }
        if self.get_nar_hash()?.is_some() {
            let sp = self.compute_store_path(store)?;
            if storeutil::is_available(store, &sp) {
                return Ok((sp, self.clone()));
            }
        }
        let r = (|| {
            let (tree, mut fin) = self.fetch_tree(store)?;
            let sp = tree_to_store(store, tree, fin.fingerprint(store), &fin.get_name())?;
            fin.set("narHash", storeutil::nar_hash(store, &sp)?.to_sri());
            check_locks(self, &fin)?;
            Ok((sp, fin))
        })();
        r.map_err(|e| self.trace(e))
    }
}

/// Copies a fetched tree into the store under `name`, remembering the
/// result per fingerprint.
pub fn tree_to_store(store: &Store, tree: Tree, fingerprint: Option<String>, name: &str) -> Result<StorePath> {
    let key: Option<Attrs> = fingerprint.map(|f| {
        [
            ("name".to_string(), Attr::Str(name.into())),
            ("fingerprint".to_string(), Attr::Str(f)),
            ("method".to_string(), Attr::from("nar")),
            ("path".to_string(), Attr::from("/")),
        ]
        .into()
    });
    if let Some(k) = &key {
        if let Some((_, sp, _)) = cache::lookup_path(store, "fetchToStore", k) {
            return Ok(sp);
        }
    }
    let sp = match tree {
        Tree::Store(sp) => {
            let real = storeutil::real_path(store, &sp);
            if sp.name() == name && real.is_dir() {
                // A recursive store object of the same name is its own copy.
                if let Ok(h) = storeutil::nar_hash(store, &sp) {
                    if storeutil::fixed_path(store, name, &h)? == sp {
                        return Ok(sp);
                    }
                }
            }
            storeutil::add_to_store(store, &real, name)?.0
        }
        Tree::Dir { path, keep: Some(keep), .. } => storeutil::add_filtered(store, &path, name, &*keep)?.0,
        Tree::Dir { path, keep: None, .. } => storeutil::add_to_store(store, &path, name)?.0,
    };
    if let Some(k) = &key {
        cache::upsert_path(store, "fetchToStore", k, &Attrs::new(), &sp);
    }
    Ok(sp)
}

pub fn check_locks(specified: &Input, fin: &Input) -> Result<()> {
    if let Some(prev) = specified.get_nar_hash()? {
        match fin.get_nar_hash()? {
            Some(h) if h == prev => {}
            Some(h) => {
                return Err(format!(
                    "NAR hash mismatch in input '{}', expected '{}' but got '{}'",
                    specified.to_string(),
                    prev.to_sri(),
                    h.to_sri()
                ))
            }
            None => return Err(format!("NAR hash mismatch in input '{}', expected '{}' but got none", specified.to_string(), prev.to_sri())),
        }
    }
    if let Some(prev) = specified.get_last_modified()? {
        if fin.get_last_modified()? != Some(prev) {
            return Err(format!("'lastModified' attribute mismatch in input '{}', expected {prev}", fin.to_string()));
        }
    }
    if let Some(prev) = specified.get_rev()? {
        if fin.get_rev()? != Some(prev.clone()) {
            return Err(format!("'rev' attribute mismatch in input '{}', expected {prev}", fin.to_string()));
        }
    }
    if let Some(prev) = specified.get_rev_count()? {
        if fin.get_rev_count()? != Some(prev) {
            return Err(format!("'revCount' attribute mismatch in input '{}', expected {prev}", fin.to_string()));
        }
    }
    Ok(())
}

fn curl_from_url(u: &ParsedUrl, ty: &str, transport: &str) -> Result<Input> {
    let mut u = u.clone();
    u.scheme = transport.to_string();
    let mut i = Input::default();
    if let Some(h) = u.query.get("narHash") {
        i.set("narHash", h.clone());
    }
    if let Some(r) = u.query.get("rev") {
        i.set("rev", r.clone());
    }
    for k in ["revCount", "lastModified"] {
        if let Some(n) = u.query.get(k).and_then(|v| v.parse::<u64>().ok()) {
            i.set(k, n);
        }
    }
    for k in allowed_attrs(ty) {
        u.query.remove(*k);
    }
    i.set("type", ty);
    i.set("url", u.to_url_string());
    Ok(i)
}

fn git_from_url(u: &ParsedUrl) -> Result<Input> {
    let mut u2 = u.clone();
    if let Some(s) = u2.scheme.strip_prefix("git+") {
        u2.scheme = s.to_string();
    }
    u2.query.clear();
    let mut a = Attrs::new();
    a.insert("type".into(), "git".into());
    for (k, v) in &u.query {
        match k.as_str() {
            "rev" | "ref" | "keytype" | "publicKey" | "publicKeys" => {
                a.insert(k.clone(), Attr::Str(v.clone()));
            }
            "shallow" | "submodules" | "exportIgnore" | "allRefs" | "verifyCommit" => {
                a.insert(k.clone(), Attr::Bool(v == "1"));
            }
            _ => {
                u2.query.insert(k.clone(), v.clone());
            }
        }
    }
    a.insert("url".into(), Attr::Str(u2.to_url_string()));
    Input::from_attrs(a)
}

fn indirect_from_url(u: &ParsedUrl) -> Result<Input> {
    let parts: Vec<&str> = u.path.split('/').filter(|s| !s.is_empty()).collect();
    let (mut r, mut rev) = (None, None);
    match parts.len() {
        1 => {}
        2 => {
            if url::rev_regex().is_match(parts[1]) {
                rev = Some(parse_rev(parts[1])?);
            } else if url::ref_regex().is_match(parts[1]) {
                r = Some(parts[1].to_string());
            } else {
                return Err(format!("in flake URL '{}', '{}' is not a commit hash or branch/tag name", u.url, parts[1]));
            }
        }
        3 => {
            if !url::ref_regex().is_match(parts[1]) {
                return Err(format!("in flake URL '{}', '{}' is not a branch/tag name", u.url, parts[1]));
            }
            r = Some(parts[1].to_string());
            if !url::rev_regex().is_match(parts[2]) {
                return Err(format!("in flake URL '{}', '{}' is not a commit hash", u.url, parts[2]));
            }
            rev = Some(parse_rev(parts[2])?);
        }
        _ => return Err(format!("GitHub URL '{}' is invalid", u.url)),
    }
    let id = parts.first().copied().unwrap_or("");
    if !url::flake_id_regex().is_match(id) {
        return Err(format!("'{id}' is not a valid flake ID"));
    }
    let mut i = Input::default();
    i.set("type", "indirect");
    i.set("id", id);
    if let Some(rev) = rev {
        i.set("rev", rev);
    }
    if let Some(r) = r {
        i.set("ref", r);
    }
    Ok(i)
}

fn path_from_url(u: &ParsedUrl) -> Result<Input> {
    if u.authority.as_deref().is_some_and(|a| !a.is_empty()) {
        return Err(format!("path URL '{}' should not have an authority ('{}')", u.url, u.authority.as_deref().unwrap()));
    }
    let mut i = Input::default();
    i.set("type", "path");
    i.set("path", u.path.clone());
    for (k, v) in &u.query {
        match k.as_str() {
            "rev" | "narHash" => i.set(k, v.clone()),
            "revCount" | "lastModified" => match v.parse::<u64>() {
                Ok(n) => i.set(k, n),
                Err(_) => return Err(format!("path URL '{}' has invalid parameter '{k}'", u.to_url_string())),
            },
            _ => return Err(format!("path URL '{}' has unsupported parameter '{k}'", u.to_url_string())),
        }
    }
    Ok(i)
}

fn fetch_path(store: &Store, input: &Input) -> Result<(Tree, Input)> {
    let mut i = input.clone();
    let path = req_str(&i.attrs, "path")?;
    let abs = if path.starts_with('/') {
        path
    } else {
        let parent = i.parent.clone().ok_or_else(|| format!("cannot fetch input '{}' because it uses a relative path", input.to_string()))?;
        let abs = canon(&format!("{parent}/{path}"));
        if let Some((sp, _)) = store.dir.to_store_path(&parent) {
            let root = store.dir.print(&sp);
            if abs != root && !abs.starts_with(&format!("{root}/")) {
                return Err(format!("relative path '{path}' points outside of its parent's store path '{root}'"));
            }
        }
        abs
    };
    let as_store_path = store.dir.to_store_path(&abs).filter(|(_, rest)| rest.is_empty()).map(|(p, _)| p);
    let (tree, mtime) = match as_store_path {
        Some(sp) if sp.name() == "source" && storeutil::is_available(store, &sp) => (Tree::Store(sp), 0),
        _ => {
            let real = store.resolve(&abs);
            if real.symlink_metadata().is_err() {
                return Err(format!("path '{abs}' does not exist"));
            }
            let m = storeutil::max_mtime(&real);
            // The tree is always stored under the name "source".
            let (sp, _) = storeutil::add_to_store(store, &real, "source")?;
            (Tree::Store(sp), m)
        }
    };
    i.set("lastModified", mtime);
    Ok((tree, i))
}

/// Normalises `.` and `..` components of an absolute path.
pub fn canon(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    format!("/{}", out.join("/"))
}

pub struct TarballResult {
    pub store_path: StorePath,
    pub last_modified: u64,
    pub immutable_url: Option<String>,
}

/// Downloads and unpacks a tarball into a store path named `source`,
/// cached per URL with `tarball-ttl` and ETag revalidation.
pub fn download_tarball(store: &Store, u: &str, headers: &crate::download::Headers) -> Result<TarballResult> {
    let mut key: Attrs = [("url".to_string(), Attr::from(u))].into();
    let cached = cache::lookup_path(store, "tarball", &key);
    let to_result = |v: &Attrs, sp: &StorePath| -> Result<TarballResult> {
        Ok(TarballResult {
            store_path: sp.clone(),
            last_modified: get_int(v, "lastModified")?.unwrap_or(0),
            immutable_url: get_str(v, "immutableUrl")?,
        })
    };
    if let Some((v, sp, false)) = &cached {
        return to_result(v, sp);
    }
    let tmp = TempDir::new_in(&store.state_dir().join("tmp"), "tarball")?;
    let file = tmp.path().join("archive");
    let etag = cached.as_ref().and_then(|c| get_str(&c.0, "etag").ok().flatten());
    let res = crate::download::download(u, headers, etag.as_deref(), &file)?;
    let (info, sp) = match (&cached, res.not_modified) {
        (Some((v, sp, _)), true) => (v.clone(), sp.clone()),
        _ => {
            let dest = tmp.path().join("unpacked");
            std::fs::create_dir(&dest).map_err(|e| e.to_string())?;
            let last_modified = crate::tar::unpack(&file, &dest)?;
            let root = crate::tar::singleton_root(&dest);
            let (sp, _) = storeutil::add_to_store(store, &root, "source")?;
            let mut info: Attrs = [("etag".to_string(), Attr::Str(res.etag.clone())), ("lastModified".to_string(), Attr::Int(last_modified))].into();
            if let Some(iu) = &res.immutable_url {
                info.insert("immutableUrl".into(), Attr::Str(iu.clone()));
            }
            (info, sp)
        }
    };
    for x in &res.urls {
        key.insert("url".into(), Attr::Str(x.clone()));
        cache::upsert_path(store, "tarball", &key, &info, &sp);
    }
    to_result(&info, &sp)
}

fn fetch_tarball_input(store: &Store, input: &Input) -> Result<(Tree, Input)> {
    let mut i = input.clone();
    let r = download_tarball(store, &req_str(&i.attrs, "url")?, &Vec::new())?;
    if let Some(iu) = &r.immutable_url {
        let imm = Input::from_url(iu, false)?;
        if imm.ty() != "tarball" {
            return Err("tarball 'Link' headers that redirect to non-tarball URLs are not supported".into());
        }
        i = imm;
    }
    if r.last_modified != 0 && !i.attrs.contains_key("lastModified") {
        i.set("lastModified", r.last_modified);
    }
    i.set("narHash", storeutil::nar_hash(store, &r.store_path)?.to_sri());
    Ok((Tree::Store(r.store_path), i))
}
