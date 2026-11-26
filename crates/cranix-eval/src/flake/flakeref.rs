//! Flake references: an input plus a subdirectory, written as URLs
//! (`github:o/r?dir=x`), flake IDs (`nixpkgs/nixos-24.05`) or paths.

use std::path::Path;
use std::sync::OnceLock;

use cranix_core::StorePath;
use cranix_fetchers::attrs::{self, Attr, Attrs};
use cranix_fetchers::input::{canon, Input};
use cranix_fetchers::url::{self, parse_url, percent_decode, ParsedUrl};
use cranix_store::Store;
use regex::Regex;

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlakeRef {
    pub input: Input,
    pub subdir: String,
}

impl FlakeRef {
    pub fn new(input: Input, subdir: impl Into<String>) -> FlakeRef {
        FlakeRef { input, subdir: subdir.into() }
    }

    pub fn to_string(&self) -> String {
        if self.subdir.is_empty() {
            self.input.to_url_string(&[])
        } else {
            self.input.to_url_string(&[("dir", &self.subdir)])
        }
    }

    pub fn to_attrs(&self) -> Attrs {
        let mut a = self.input.attrs.clone();
        if !self.subdir.is_empty() {
            a.entry("dir".into()).or_insert(Attr::Str(self.subdir.clone()));
        }
        a
    }

    pub fn from_attrs(a: Attrs) -> Result<FlakeRef> {
        let mut a2 = a.clone();
        a2.remove("dir");
        let dir = attrs::get_str(&a, "dir")?.unwrap_or_default();
        Ok(FlakeRef::new(Input::from_attrs(a2)?, dir))
    }

    /// Resolves an indirect reference through the registries.
    pub fn resolve(&self, store: &Store) -> Result<FlakeRef> {
        let (i, extra) = cranix_fetchers::registry::lookup(store, &self.input)?;
        let dir = attrs::get_str(&extra, "dir")?.unwrap_or_else(|| self.subdir.clone());
        Ok(FlakeRef::new(i, dir))
    }

    pub fn fetch_tree(&self, store: &Store) -> Result<(StorePath, FlakeRef)> {
        let (p, i) = self.input.fetch_to_store(store)?;
        Ok((p, FlakeRef::new(i, self.subdir.clone())))
    }
}

pub fn parse(u: &str, base_dir: Option<&str>, allow_missing: bool, is_flake: bool) -> Result<FlakeRef> {
    let (r, frag) = parse_with_fragment(u, base_dir, allow_missing, is_flake)?;
    if !frag.is_empty() {
        return Err(format!("unexpected fragment '{frag}' in flake reference '{u}'"));
    }
    Ok(r)
}

fn flake_id_ref_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        let ref_and_rev = format!("(?:({rev})|(?:({r})(?:/({rev}))?))", rev = url::REV_REGEX, r = url::REF_REGEX);
        Regex::new(&format!("^(({})(?:/(?:{ref_and_rev}))?)(?:#({}))?$", url::FLAKE_ID_REGEX, url::fragment_regex())).unwrap()
    })
}

pub fn parse_with_fragment(u: &str, base_dir: Option<&str>, allow_missing: bool, is_flake: bool) -> Result<(FlakeRef, String)> {
    if let Some(m) = flake_id_ref_regex().captures(u) {
        let mut pu = ParsedUrl::new("flake", Some(""), &m[1]);
        pu.url = u.to_string();
        pu.base = format!("flake:{}", &m[1]);
        let i = Input::from_parsed_url(&pu, is_flake)?;
        return Ok((FlakeRef::new(i, ""), percent_decode(m.get(6).map_or("", |f| f.as_str()))?));
    }
    if let Ok(mut pu) = parse_url(u) {
        let frag = std::mem::take(&mut pu.fragment);
        let mut i = Input::from_parsed_url(&pu, is_flake)?;
        i.parent = base_dir.map(String::from);
        let dir = pu.query.get("dir").cloned().unwrap_or_default();
        return Ok((FlakeRef::new(i, dir), frag));
    }
    parse_path(u, base_dir, allow_missing, is_flake)
}

fn exists(p: &str) -> bool {
    Path::new(p).symlink_metadata().is_ok()
}

fn dir_of(p: &str) -> String {
    match p.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => p[..i].into(),
    }
}

fn parse_path(u: &str, base_dir: Option<&str>, allow_missing: bool, is_flake: bool) -> Result<(FlakeRef, String)> {
    let path_end = u.find(['#', '?']);
    let mut frag_start = path_end;
    if let Some(pe) = path_end {
        if u.as_bytes()[pe] == b'?' {
            frag_start = u.find('#');
        }
    }
    let mut path = match path_end {
        Some(pe) => u[..pe].to_string(),
        None => u.to_string(),
    };
    let fragment = match frag_start {
        Some(fs) => percent_decode(&u[fs + 1..])?,
        None => String::new(),
    };
    let query = match (path_end, frag_start) {
        (Some(pe), fs) if u.as_bytes()[pe] == b'?' => url::decode_query(&u[pe + 1..fs.unwrap_or(u.len())])?,
        _ => Default::default(),
    };
    if let Some(base) = base_dir {
        path = if path.starts_with('/') { canon(&path) } else { canon(&format!("{base}/{path}")) };
        if is_flake {
            let md = std::fs::symlink_metadata(&path).map_err(|e| format!("getting status of '{path}': {e}"))?;
            if !md.is_dir() {
                if path.ends_with("/flake.nix") {
                    let d = dir_of(&path);
                    cranix_fetchers::warn(format!(
                        "Path '{path}' should point at the directory containing the 'flake.nix' file, not the file itself. Pretending that you meant '{d}'"
                    ));
                    path = d;
                } else {
                    return Err(format!("path '{path}' is not a flake (because it's not a directory)"));
                }
            }
            if !allow_missing && !exists(&format!("{path}/flake.nix")) {
                eprintln!("path '{path}' does not contain a 'flake.nix', searching up");
                let mut found = false;
                while path != "/" {
                    if exists(&format!("{path}/flake.nix")) {
                        found = true;
                        break;
                    } else if exists(&format!("{path}/.git")) {
                        return Err(format!(
                            "path '{path}' is not part of a flake (neither it nor its parent directories contain a 'flake.nix' file)"
                        ));
                    }
                    path = dir_of(&path);
                }
                if !found {
                    return Err("could not find a flake.nix file".into());
                }
            }
            if !allow_missing && !exists(&format!("{path}/flake.nix")) {
                return Err(format!("path '{path}' is not a flake (because it doesn't contain a 'flake.nix' file)"));
            }
            let mut root = path.clone();
            let mut subdir = String::new();
            while root != "/" {
                if exists(&format!("{root}/.git")) {
                    let mut pu = ParsedUrl::new("git+file", Some(""), &root);
                    pu.base = format!("git+file://{root}");
                    pu.url = pu.base.clone();
                    pu.query = query.clone();
                    if !subdir.is_empty() {
                        if pu.query.contains_key("dir") {
                            return Err(format!("flake URL '{u}' has an inconsistent 'dir' parameter"));
                        }
                        pu.query.insert("dir".into(), subdir.clone());
                    }
                    if exists(&format!("{root}/.git/shallow")) {
                        pu.query.insert("shallow".into(), "1".into());
                    }
                    let dir = pu.query.get("dir").cloned().unwrap_or_default();
                    return Ok((FlakeRef::new(Input::from_parsed_url(&pu, false)?, dir), fragment));
                }
                let base = root.rsplit('/').next().unwrap_or("").to_string();
                subdir = if subdir.is_empty() { base } else { format!("{base}/{subdir}") };
                root = dir_of(&root);
            }
        }
    } else {
        if !path.starts_with('/') {
            return Err(format!("flake reference '{u}' is not an absolute path"));
        }
        path = canon(&format!("{path}/{}", query.get("dir").map_or("", |s| s.as_str())));
    }
    let mut a = Attrs::new();
    a.insert("type".into(), "path".into());
    a.insert("path".into(), Attr::Str(path));
    Ok((FlakeRef::new(Input::from_attrs(a)?, ""), fragment))
}
