//! Flake registries (version 2): the command line overrides, the user
//! registry, the system registry and the global registry, consulted in
//! that order to resolve indirect inputs such as `flake:nixpkgs`.

use std::sync::{Mutex, OnceLock};

use cranix_store::Store;
use serde_json::json;

use crate::attrs::{self, Attrs};
use crate::input::Input;
use crate::{storeutil, Result};

#[derive(Clone, Debug)]
pub struct Entry {
    pub from: Input,
    pub to: Input,
    pub extra: Attrs,
    pub exact: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Registry {
    pub entries: Vec<Entry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Flag,
    User,
    System,
    Global,
}

impl Registry {
    pub fn parse(text: &str, path: &str) -> Registry {
        let mut r = Registry::default();
        let j: serde_json::Value = match serde_json::from_str(text) {
            Ok(j) => j,
            Err(e) => {
                crate::warn(format!("cannot parse flake registry '{path}': {e}"));
                return r;
            }
        };
        if j.get("version").and_then(|v| v.as_u64()) != Some(2) {
            crate::warn(format!("cannot read flake registry '{path}': flake registry '{path}' has unsupported version"));
            return r;
        }
        let res: Result<()> = (|| {
            for e in j.get("flakes").and_then(|f| f.as_array()).into_iter().flatten() {
                let mut to = attrs::from_json(e.get("to").ok_or("missing 'to'")?)?;
                let mut extra = Attrs::new();
                if let Some(d) = to.remove("dir") {
                    extra.insert("dir".into(), d);
                }
                r.entries.push(Entry {
                    from: Input::from_attrs(attrs::from_json(e.get("from").ok_or("missing 'from'")?)?)?,
                    to: Input::from_attrs(to)?,
                    extra,
                    exact: e.get("exact").and_then(|x| x.as_bool()).unwrap_or(false),
                });
            }
            Ok(())
        })();
        if let Err(e) = res {
            crate::warn(format!("cannot read flake registry '{path}': {e}"));
        }
        r
    }

    pub fn read(path: &str) -> Registry {
        match std::fs::read_to_string(path) {
            Ok(t) => Registry::parse(&t, path),
            Err(_) => Registry::default(),
        }
    }

    pub fn to_json_string(&self) -> String {
        let flakes: Vec<_> = self
            .entries
            .iter()
            .map(|e| {
                let mut to = attrs::to_json(&e.to.attrs);
                if let (Some(o), serde_json::Value::Object(x)) = (to.as_object_mut(), attrs::to_json(&e.extra)) {
                    o.extend(x);
                }
                let mut obj = json!({ "from": attrs::to_json(&e.from.attrs), "to": to });
                if e.exact {
                    obj["exact"] = json!(true);
                }
                obj
            })
            .collect();
        serde_json::to_string_pretty(&json!({ "flakes": flakes, "version": 2 })).unwrap()
    }

    pub fn write(&self, path: &str) -> Result<()> {
        if let Some(d) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, self.to_json_string()).map_err(|e| format!("writing '{path}': {e}"))
    }

    pub fn add(&mut self, from: Input, to: Input, extra: Attrs) {
        self.entries.push(Entry { from, to, extra, exact: false });
    }

    pub fn remove(&mut self, from: &Input) {
        self.entries.retain(|e| &e.from != from);
    }
}

fn flag_registry() -> &'static Mutex<Registry> {
    static R: OnceLock<Mutex<Registry>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Registry::default()))
}

/// `--override-flake FROM TO`.
pub fn override_registry(from: Input, to: Input, extra: Attrs) {
    flag_registry().lock().unwrap().add(from, to, extra);
}

pub fn user_registry_path() -> String {
    format!("{}/nix/registry.json", crate::settings::config_dir())
}

pub fn system_registry_path() -> String {
    format!("{}/registry.json", crate::settings().nix_conf_dir)
}

fn global_registry(store: &Store) -> Registry {
    static G: OnceLock<Mutex<Option<Registry>>> = OnceLock::new();
    let m = G.get_or_init(|| Mutex::new(None));
    let mut g = m.lock().unwrap();
    if let Some(r) = &*g {
        return r.clone();
    }
    let path = crate::settings().flake_registry;
    let r = if path.is_empty() {
        Registry::default()
    } else if path.starts_with('/') {
        Registry::read(&path)
    } else {
        match crate::download::download_file(store, &path, "flake-registry.json", &Vec::new()) {
            Ok(f) => {
                let p = storeutil::real_path(store, &f.store_path);
                let link = store.state_dir().join("flake-registry.json");
                let _ = std::fs::remove_file(&link);
                let _ = std::os::unix::fs::symlink(store.dir.print(&f.store_path), &link);
                let _ = store.add_indirect_root(&link);
                Registry::read(&p.to_string_lossy())
            }
            Err(e) => {
                crate::warn(format!("cannot fetch the global flake registry: {e}"));
                Registry::default()
            }
        }
    };
    *g = Some(r.clone());
    r
}

pub fn registries(store: &Store) -> Vec<(Kind, Registry)> {
    vec![
        (Kind::Flag, flag_registry().lock().unwrap().clone()),
        (Kind::User, Registry::read(&user_registry_path())),
        (Kind::System, Registry::read(&system_registry_path())),
        (Kind::Global, global_registry(store)),
    ]
}

/// Resolves an indirect input to a direct one. Returns the input and
/// extra attributes (`dir`) of the matching entry.
pub fn lookup(store: &Store, input: &Input) -> Result<(Input, Attrs)> {
    let regs = registries(store);
    let mut input = input.clone();
    let mut extra = Attrs::new();
    let orig = input.clone();
    'restart: for _ in 0..100 {
        for (_, reg) in &regs {
            for e in &reg.entries {
                if e.exact {
                    if e.from == input {
                        input = e.to.clone();
                        extra = e.extra.clone();
                        continue 'restart;
                    }
                } else if e.from.contains(&input) {
                    let r = if e.from.get_ref()?.is_none() { input.get_ref()? } else { None };
                    let rev = if e.from.get_rev()?.is_none() { input.get_rev()? } else { None };
                    input = e.to.apply_overrides(r, rev)?;
                    extra = e.extra.clone();
                    continue 'restart;
                }
            }
        }
        if !input.is_direct() {
            return Err(format!("cannot find flake '{}' in the flake registries", input.to_string()));
        }
        return Ok((input, extra));
    }
    Err(format!("cycle detected in flake registry for '{}'", orig.to_string()))
}
