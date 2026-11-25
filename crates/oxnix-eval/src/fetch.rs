//! `builtins.fetchurl`, `fetchTarball`, `fetchGit` and `fetchTree`.

use oxnix_core::hash::{Encoding, Hash, HashAlgo};
use oxnix_core::{FileIngestion, StorePath};
use oxnix_fetchers::{attrs as fattrs, input::Input, Attr};

use crate::eval::{err, CoerceOpts, Eval, R};
use crate::value::*;

fn lift<T>(r: oxnix_fetchers::Result<T>) -> R<T> {
    r.or_else(err)
}

pub fn store_path_value(ev: &Eval, sp: &StorePath) -> Value {
    let s = ev.store.dir.print(sp);
    Value::str_ctx(s.clone(), [CtxElem::Opaque(s)].into())
}

/// The attribute set `fetchTree` and friends return for a fetched input.
pub fn emit_tree_attrs(ev: &Eval, sp: &StorePath, input: &Input, empty_rev_fallback: bool, force_dirty: bool) -> R<Value> {
    let mut v: Vec<(Sym, Value)> = Vec::new();
    v.push((Sym::new("outPath"), store_path_value(ev, sp)));
    let nar = lift(input.get_nar_hash())?.ok_or(()).or_else(|_| err("fetched input has no NAR hash"))?;
    v.push((Sym::new("narHash"), Value::str(nar.to_sri())));
    if input.ty() == "git" {
        let s = lift(fattrs::get_bool(&input.attrs, "submodules"))?.unwrap_or(false);
        v.push((Sym::new("submodules"), Value::Bool(s)));
    }
    if !force_dirty {
        if let Some(rev) = lift(input.get_rev())? {
            v.push((Sym::new("shortRev"), Value::str(&rev[..7])));
            v.push((Sym::new("rev"), Value::str(rev)));
        } else if empty_rev_fallback {
            let z = "0".repeat(40);
            v.push((Sym::new("shortRev"), Value::str(&z[..7])));
            v.push((Sym::new("rev"), Value::str(z)));
        }
        if let Some(n) = lift(input.get_rev_count())? {
            v.push((Sym::new("revCount"), Value::Int(n as i64)));
        } else if empty_rev_fallback {
            v.push((Sym::new("revCount"), Value::Int(0)));
        }
    }
    if let Some(d) = lift(fattrs::get_str(&input.attrs, "dirtyRev"))? {
        v.push((Sym::new("dirtyRev"), Value::str(d)));
        let s = lift(fattrs::get_str(&input.attrs, "dirtyShortRev"))?.unwrap_or_default();
        v.push((Sym::new("dirtyShortRev"), Value::str(s)));
    }
    if let Some(lm) = lift(input.get_last_modified())? {
        v.push((Sym::new("lastModified"), Value::Int(lm as i64)));
        v.push((Sym::new("lastModifiedDate"), Value::str(oxnix_fetchers::format_date(lm))));
    }
    Ok(Value::attrs(Attrs::from_unsorted(v)))
}

pub struct FetchTreeParams {
    pub empty_rev_fallback: bool,
    pub allow_name: bool,
    pub is_fetch_git: bool,
}

/// Converts a `fetchTree`-style argument set into input attributes.
pub fn value_to_input_attrs(ev: &Eval, a: &Attrs, is_fetch_git: bool, what: &str) -> R<fattrs::Attrs> {
    let mut out = fattrs::Attrs::new();
    for (k, v) in a.iter() {
        let v = ev.force(v)?;
        let x = match &v {
            Value::Str(_) | Value::Path(_) => {
                let s = ev.coerce_to_string(&v, &CoerceOpts { more: false, copy: false }, &mut Context::new())?;
                if is_fetch_git && k.as_str() == "url" {
                    Attr::Str(oxnix_fetchers::url::fix_git_url(&s))
                } else {
                    Attr::Str(s)
                }
            }
            Value::Bool(b) => Attr::Bool(*b),
            Value::Int(n) => Attr::Int(*n as u64),
            v => {
                return err(format!(
                    "{what} argument '{}' is {} while a string, Boolean or integer is expected",
                    k.as_str(),
                    v.describe()
                ))
            }
        };
        out.insert(k.as_str().to_string(), x);
    }
    Ok(out)
}

pub fn fetch_tree(ev: &Eval, arg: &Value, p: &FetchTreeParams) -> R<Value> {
    let arg = ev.force(arg)?;
    let mut input = match &arg {
        Value::Attrs(a) => {
            let mut attrs = value_to_input_attrs(ev, a, p.is_fetch_git, "fetchTree")?;
            match (attrs.contains_key("type"), p.is_fetch_git) {
                (true, true) => return err("unexpected attribute 'type'"),
                (false, true) => {
                    attrs.insert("type".into(), "git".into());
                }
                (false, false) => return err("attribute 'type' is missing in call to 'fetchTree'"),
                (true, false) => {
                    if !matches!(attrs.get("type"), Some(Attr::Str(_))) {
                        return err("expected the `type` attribute passed to builtins.fetchTree to be a string");
                    }
                }
            }
            let submodules = matches!(attrs.get("submodules"), Some(Attr::Bool(true)));
            if p.is_fetch_git && !attrs.contains_key("exportIgnore") && !submodules {
                attrs.insert("exportIgnore".into(), Attr::Bool(true));
            }
            if !p.is_fetch_git && matches!(attrs.get("type"), Some(Attr::Str(t)) if t == "git") && !attrs.contains_key("shallow") {
                attrs.insert("shallow".into(), Attr::Bool(true));
            }
            if !p.allow_name && attrs.contains_key("name") {
                return err("attribute 'name' isn’t supported in call to 'fetchTree'");
            }
            lift(Input::from_attrs(attrs))?
        }
        _ => {
            let url = ev.coerce_to_string(&arg, &CoerceOpts { more: false, copy: false }, &mut Context::new())?;
            if p.is_fetch_git {
                let mut attrs = fattrs::Attrs::new();
                attrs.insert("type".into(), "git".into());
                attrs.insert("url".into(), Attr::Str(oxnix_fetchers::url::fix_git_url(&url)));
                attrs.insert("exportIgnore".into(), Attr::Bool(true));
                lift(Input::from_attrs(attrs))?
            } else {
                lift(Input::from_url(&url, false))?
            }
        }
    };
    if !ev.opts.pure && !input.is_direct() {
        input = lift(oxnix_fetchers::registry::lookup(&ev.store, &input))?.0;
    }
    if ev.opts.pure && !input.is_locked() {
        let f = if p.is_fetch_git { "fetchGit" } else { "fetchTree" };
        return err(format!("in pure evaluation mode, '{f}' will not fetch unlocked input '{}'", input.to_string()));
    }
    let (sp, fin) = lift(input.fetch_to_store(&ev.store))?;
    emit_tree_attrs(ev, &sp, &fin, p.empty_rev_fallback, false)
}

fn base_name_of(s: &str) -> &str {
    let s = s.strip_suffix('/').unwrap_or(s);
    match s.rfind('/') {
        Some(i) => &s[i + 1..],
        None => s,
    }
}

/// `fetchurl` (flat file) and `fetchTarball` (unpacked tree).
pub fn fetch(ev: &Eval, arg: &Value, who: &str, unpack: bool, default_name: &str) -> R<Value> {
    let arg = ev.force(arg)?;
    let mut url = None;
    let mut expected: Option<Hash> = None;
    let mut name = default_name.to_string();
    let is_attrs = matches!(arg, Value::Attrs(_));
    let mut name_passed = false;
    if let Value::Attrs(a) = &arg {
        for (k, v) in a.iter() {
            match k.as_str() {
                "url" => url = Some(ev.force_plain_str(v)?),
                "sha256" => {
                    let s = ev.force_plain_str(v)?;
                    expected = Some(if s.is_empty() {
                        Hash::from_bytes(HashAlgo::Sha256, &[0; 32])
                    } else {
                        Hash::parse(&s, Some(HashAlgo::Sha256)).or_else(err)?
                    });
                }
                "name" => {
                    name_passed = true;
                    name = ev.force_plain_str(v)?;
                }
                n => return err(format!("unsupported argument '{n}' to '{who}'")),
            }
        }
        if url.is_none() {
            return err("'url' argument required");
        }
    } else {
        url = Some(ev.force_plain_str(&arg)?);
    }
    let mut url = url.unwrap();
    if who == "fetchTarball" {
        if let Some(c) = url.strip_prefix("channel:") {
            url = format!("https://nixos.org/channels/{c}/nixexprs.tar.xz");
        }
    }
    if name.is_empty() {
        name = base_name_of(&url).to_string();
    }
    if let Err(e) = oxnix_core::store_path::validate_name(&name) {
        let hint = if name_passed {
            format!("Please change the value for the 'name' attribute passed to '{who}', so that it can create a valid store path.")
        } else if is_attrs {
            format!("Please add a valid 'name' attribute to the argument for '{who}', so that it can create a valid store path.")
        } else {
            format!("Please pass an attribute set with 'url' and 'name' attributes to '{who}',  so that it can create a valid store path.")
        };
        return err(format!("invalid store path name when fetching URL '{url}': {e}. {hint}"));
    }
    if ev.opts.pure && expected.is_none() {
        return err(format!("in pure evaluation mode, '{who}' requires a 'sha256' argument"));
    }
    let method = if unpack { FileIngestion::Recursive } else { FileIngestion::Flat };
    if let Some(h) = &expected {
        let p = ev.store.dir.make_fixed_output_path(method, h, &name, &Default::default(), false).or_else(err)?;
        if oxnix_fetchers::storeutil::is_available(&ev.store, &p) {
            return Ok(store_path_value(ev, &p));
        }
    }
    let sp = if unpack {
        let mut a = fattrs::Attrs::new();
        a.insert("type".into(), "tarball".into());
        a.insert("url".into(), Attr::Str(url.clone()));
        let input = lift(Input::from_attrs(a))?;
        let (tree, fin) = lift(input.fetch_checked(&ev.store))?;
        let fp = fin.get_nar_hash().ok().flatten().map(|h| h.to_sri());
        lift(oxnix_fetchers::input::tree_to_store(&ev.store, tree, fp, &name))?
    } else {
        lift(oxnix_fetchers::download::download_file(&ev.store, &url, &name, &Vec::new()))?.store_path
    };
    if let Some(h) = &expected {
        let got = if unpack {
            lift(oxnix_fetchers::storeutil::nar_hash(&ev.store, &sp))?
        } else {
            lift(oxnix_fetchers::download::hash_file(&oxnix_fetchers::storeutil::real_path(&ev.store, &sp)))?
        };
        if &got != h {
            return err(format!(
                "hash mismatch in file downloaded from '{url}':\n  specified: {}\n  got:       {}",
                h.encode(Encoding::Nix32, true),
                got.encode(Encoding::Nix32, true)
            ));
        }
    }
    Ok(store_path_value(ev, &sp))
}

pub fn prim_fetchurl(ev: &Eval, a: &[Value]) -> R<Value> {
    fetch(ev, &a[0], "fetchurl", false, "")
}

pub fn prim_fetch_tarball(ev: &Eval, a: &[Value]) -> R<Value> {
    fetch(ev, &a[0], "fetchTarball", true, "source")
}

pub fn prim_fetch_git(ev: &Eval, a: &[Value]) -> R<Value> {
    fetch_tree(ev, &a[0], &FetchTreeParams { empty_rev_fallback: true, allow_name: true, is_fetch_git: true })
}

pub fn prim_fetch_tree(ev: &Eval, a: &[Value]) -> R<Value> {
    fetch_tree(ev, &a[0], &FetchTreeParams { empty_rev_fallback: false, allow_name: false, is_fetch_git: false })
}
