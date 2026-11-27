//! The `builtins` set and the global names of the base environment.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use cranix_core::hash::{Encoding, Hash, HashAlgo};
use cranix_core::FileIngestion;

use crate::eval::{err, err_kind, CoerceOpts, ErrKind, Eval, Options, R};
use crate::parser::canon_path;
use crate::value::*;

macro_rules! prim {
    ($name:literal, $arity:literal, $f:expr) => {
        PrimOp { name: $name, arity: $arity, f: $f }
    };
}

pub static PRIMOPS: &[PrimOp] = &[
    prim!("abort", 1, |ev, a| {
        let s = ev.coerce_to_string(&a[0], &CoerceOpts { more: true, copy: false }, &mut Context::new())?;
        err_kind(ErrKind::Abort, format!("evaluation aborted with the following error message: '{s}'"))
    }),
    prim!("add", 2, |ev, a| {
        let x = ev.force(&a[0])?;
        let y = ev.force(&a[1])?;
        ev.arith(crate::ast::BinOp::Add, &x, &y)
    }),
    prim!("sub", 2, |ev, a| {
        let x = ev.force(&a[0])?;
        let y = ev.force(&a[1])?;
        ev.arith(crate::ast::BinOp::Sub, &x, &y)
    }),
    prim!("mul", 2, |ev, a| {
        let x = ev.force(&a[0])?;
        let y = ev.force(&a[1])?;
        ev.arith(crate::ast::BinOp::Mul, &x, &y)
    }),
    prim!("div", 2, |ev, a| {
        let x = ev.force(&a[0])?;
        let y = ev.force(&a[1])?;
        ev.arith(crate::ast::BinOp::Div, &x, &y)
    }),
    prim!("addErrorContext", 2, |ev, a| {
        ev.force(&a[1]).map_err(|mut e| {
            if let Ok(s) = ev.force_str(&a[0]) {
                e.trace.push(s.s.clone());
            }
            e
        })
    }),
    prim!("all", 2, |ev, a| {
        let f = ev.force_fn(&a[0])?;
        for x in ev.force_list(&a[1])?.iter() {
            if !ev.force_bool(&ev.call(&f, x.clone())?)? {
                return Ok(Value::Bool(false));
            }
        }
        Ok(Value::Bool(true))
    }),
    prim!("any", 2, |ev, a| {
        let f = ev.force_fn(&a[0])?;
        for x in ev.force_list(&a[1])?.iter() {
            if ev.force_bool(&ev.call(&f, x.clone())?)? {
                return Ok(Value::Bool(true));
            }
        }
        Ok(Value::Bool(false))
    }),
    prim!("appendContext", 2, |ev, a| {
        let s = ev.force_str(&a[0])?;
        let mut ctx = s.ctx.clone();
        for (k, v) in ev.force_attrs(&a[1])?.iter() {
            let path = k.as_str().to_string();
            let info = ev.force_attrs(v)?;
            if let Some(p) = info.get_str("path") {
                if ev.force_bool(p)? {
                    ctx.insert(CtxElem::Opaque(path.clone()));
                }
            }
            if let Some(p) = info.get_str("allOutputs") {
                if ev.force_bool(p)? {
                    ctx.insert(CtxElem::DrvDeep(path.clone()));
                }
            }
            if let Some(o) = info.get_str("outputs") {
                for o in ev.force_list(o)?.iter() {
                    ctx.insert(CtxElem::Built { drv: path.clone(), output: ev.force_plain_str(o)? });
                }
            }
        }
        Ok(Value::str_ctx(s.s.clone(), ctx))
    }),
    prim!("attrNames", 1, |ev, a| {
        let s = ev.force_attrs(&a[0])?;
        Ok(Value::list(s.iter().map(|(k, _)| k.as_value()).collect()))
    }),
    prim!("attrValues", 1, |ev, a| {
        let s = ev.force_attrs(&a[0])?;
        Ok(Value::list(s.iter().map(|(_, v)| v.clone()).collect()))
    }),
    prim!("baseNameOf", 1, |ev, a| {
        let mut ctx = Context::new();
        let s = ev.coerce_to_string(&a[0], &CoerceOpts { more: false, copy: false }, &mut ctx)?;
        let t = s.strip_suffix('/').unwrap_or(&s);
        let b = match t.rfind('/') {
            Some(i) => &t[i + 1..],
            None => t,
        };
        Ok(Value::str_ctx(b, ctx))
    }),
    prim!("bitAnd", 2, |ev, a| Ok(Value::Int(ev.force_int(&a[0])? & ev.force_int(&a[1])?))),
    prim!("bitOr", 2, |ev, a| Ok(Value::Int(ev.force_int(&a[0])? | ev.force_int(&a[1])?))),
    prim!("bitXor", 2, |ev, a| Ok(Value::Int(ev.force_int(&a[0])? ^ ev.force_int(&a[1])?))),
    prim!("break", 1, |ev, a| ev.force(&a[0])),
    prim!("catAttrs", 2, |ev, a| {
        let name = Sym::new(&ev.force_plain_str(&a[0])?);
        let mut out = Vec::new();
        for x in ev.force_list(&a[1])?.iter() {
            if let Some(v) = ev.force_attrs(x)?.get(&name) {
                out.push(v.clone());
            }
        }
        Ok(Value::list(out))
    }),
    prim!("ceil", 1, |ev, a| match ev.force(&a[0])? {
        Value::Float(f) => Ok(Value::Int(f.ceil() as i64)),
        Value::Int(n) => Ok(Value::Int(n)),
        v => err(format!("expected a float but found {}", v.describe())),
    }),
    prim!("floor", 1, |ev, a| match ev.force(&a[0])? {
        Value::Float(f) => Ok(Value::Int(f.floor() as i64)),
        Value::Int(n) => Ok(Value::Int(n)),
        v => err(format!("expected a float but found {}", v.describe())),
    }),
    prim!("compareVersions", 2, |ev, a| {
        let x = ev.force_plain_str(&a[0])?;
        let y = ev.force_plain_str(&a[1])?;
        Ok(Value::Int(match compare_versions(&x, &y) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }))
    }),
    prim!("concatLists", 1, |ev, a| {
        let mut out = Vec::new();
        for l in ev.force_list(&a[0])?.iter() {
            out.extend(ev.force_list(l)?.iter().cloned());
        }
        Ok(Value::list(out))
    }),
    prim!("concatMap", 2, |ev, a| {
        let f = ev.force_fn(&a[0])?;
        let mut out = Vec::new();
        for x in ev.force_list(&a[1])?.iter() {
            out.extend(ev.force_list(&ev.call(&f, x.clone())?)?.iter().cloned());
        }
        Ok(Value::list(out))
    }),
    prim!("concatStringsSep", 2, |ev, a| {
        let mut ctx = Context::new();
        let sep = ev.force_str(&a[0])?;
        ctx.extend(sep.ctx.iter().cloned());
        let mut out = String::new();
        let o = CoerceOpts { more: false, copy: true };
        for (i, x) in ev.force_list(&a[1])?.iter().enumerate() {
            if i > 0 {
                out.push_str(&sep.s);
            }
            out.push_str(&ev.coerce_to_string(x, &o, &mut ctx)?);
        }
        Ok(Value::str_ctx(out, ctx))
    }),
    prim!("convertHash", 1, |ev, a| {
        let args = ev.force_attrs(&a[0])?;
        let get = |k: &str| -> R<Option<String>> {
            match args.get_str(k) {
                Some(v) => Ok(Some(ev.force_plain_str(v)?)),
                None => Ok(None),
            }
        };
        let hash = get("hash")?.ok_or(()).or_else(|_| err("convertHash: missing 'hash'"))?;
        let algo = match get("hashAlgo")? {
            Some(a) => Some(HashAlgo::parse(&a).ok_or(()).or_else(|_| err(format!("unknown hash algorithm '{a}'")))?),
            None => None,
        };
        let fmt = get("toHashFormat")?.ok_or(()).or_else(|_| err("convertHash: missing 'toHashFormat'"))?;
        let h = Hash::parse(&hash, algo).or_else(err)?;
        Ok(Value::str(encode_hash(&h, &fmt)?))
    }),
    prim!("deepSeq", 2, |ev, a| {
        ev.deep_force(&a[0])?;
        ev.force(&a[1])
    }),
    prim!("derivationStrict", 1, |ev, a| crate::derivation::derivation_strict(ev, &a[0])),
    prim!("dirOf", 1, |ev, a| {
        let v = ev.force(&a[0])?;
        let dir = |s: &str| -> String {
            match s.rfind('/') {
                Some(0) => "/".into(),
                Some(i) => s[..i].into(),
                None => ".".into(),
            }
        };
        match &v {
            Value::Path(p) => Ok(Value::Path(dir(p).into())),
            _ => {
                let mut ctx = Context::new();
                let s = ev.coerce_to_string(&v, &CoerceOpts { more: false, copy: false }, &mut ctx)?;
                Ok(Value::str_ctx(dir(&s), ctx))
            }
        }
    }),
    prim!("elem", 2, |ev, a| {
        for x in ev.force_list(&a[1])?.iter() {
            if ev.eq(&a[0], x)? {
                return Ok(Value::Bool(true));
            }
        }
        Ok(Value::Bool(false))
    }),
    prim!("elemAt", 2, |ev, a| {
        let l = ev.force_list(&a[0])?;
        let i = ev.force_int(&a[1])?;
        match usize::try_from(i).ok().and_then(|i| l.get(i)) {
            Some(v) => ev.force(v),
            None => err(format!("list index {i} is out of bounds")),
        }
    }),
    prim!("fetchGit", 1, crate::fetch::prim_fetch_git),
    prim!("flakeRefToString", 1, crate::flake::prim_flake_ref_to_string),
    prim!("fetchMercurial", 1, |_, _| err("builtins.fetchMercurial is not supported")),
    prim!("fetchTarball", 1, crate::fetch::prim_fetch_tarball),
    prim!("fetchTree", 1, crate::fetch::prim_fetch_tree),
    prim!("fetchurl", 1, crate::fetch::prim_fetchurl),
    prim!("filter", 2, |ev, a| {
        let f = ev.force_fn(&a[0])?;
        let l = ev.force_list(&a[1])?;
        let mut out = Vec::new();
        for x in l.iter() {
            if ev.force_bool(&ev.call(&f, x.clone())?)? {
                out.push(x.clone());
            }
        }
        if out.len() == l.len() {
            return Ok(Value::List(l));
        }
        Ok(Value::list(out))
    }),
    prim!("filterSource", 2, |ev, a| {
        let mut ctx = Context::new();
        let p = ev.coerce_to_path(&a[1], &mut ctx)?;
        let name = p.rsplit('/').next().unwrap_or("source").to_string();
        add_path_filtered(ev, &p, &name, Some(a[0].clone()), FileIngestion::Recursive)
    }),
    prim!("findFile", 2, |ev, a| find_file(ev, &a[0], &ev.force_plain_str(&a[1])?)),
    prim!("foldl'", 3, |ev, a| {
        // The initial accumulator is forced only for an empty list; each
        // result of the function is forced before the next step.
        let f = ev.force_fn(&a[0])?;
        let list = ev.force_list(&a[2])?;
        let mut acc = a[1].clone();
        for x in list.iter() {
            acc = ev.force(&ev.call2(&f, acc, x.clone())?)?;
        }
        ev.force(&acc)
    }),
    prim!("fromJSON", 1, |ev, a| crate::print::from_json(&ev.force_str(&a[0])?.s)),
    prim!("fromTOML", 1, |ev, a| crate::toml::from_toml(&ev.force_str(&a[0])?.s)),
    prim!("functionArgs", 1, |ev, a| match ev.force(&a[0])? {
        Value::Lambda(c) => match &c.def.formals {
            Some(f) => Ok(Value::attrs(Attrs::from_unsorted(
                f.entries.iter().map(|(k, d)| (k.clone(), Value::Bool(d.is_some()))).collect(),
            ))),
            None => Ok(Value::attrs(Attrs::default())),
        },
        Value::PrimOp(_) => Ok(Value::attrs(Attrs::default())),
        v => err(format!("expected a function but found {}", v.describe())),
    }),
    prim!("genList", 2, |ev, a| {
        let n = ev.force_int(&a[1])?;
        if n < 0 {
            return err(format!("cannot create list of size {n}"));
        }
        let f = a[0].clone();
        Ok(Value::list((0..n).map(|i| Value::app_thunk(f.clone(), Value::Int(i))).collect()))
    }),
    prim!("genericClosure", 1, generic_closure),
    prim!("getFlake", 1, crate::flake::prim_get_flake),
    prim!("getAttr", 2, |ev, a| {
        let k = ev.force_plain_str(&a[0])?;
        match ev.force_attrs(&a[1])?.get_str(&k) {
            Some(v) => ev.force(v),
            None => err(format!("attribute '{k}' missing")),
        }
    }),
    prim!("getContext", 1, |ev, a| {
        let s = ev.force_str(&a[0])?;
        let mut m: BTreeMap<String, (bool, bool, Vec<String>)> = BTreeMap::new();
        for c in &s.ctx {
            match c {
                CtxElem::Opaque(p) => m.entry(p.clone()).or_default().0 = true,
                CtxElem::DrvDeep(p) => m.entry(p.clone()).or_default().1 = true,
                CtxElem::Built { drv, output } => m.entry(drv.clone()).or_default().2.push(output.clone()),
            }
        }
        let entries = m
            .into_iter()
            .map(|(k, (path, all, outs))| {
                let mut info = Vec::new();
                if path {
                    info.push((Sym::new("path"), Value::Bool(true)));
                }
                if all {
                    info.push((Sym::new("allOutputs"), Value::Bool(true)));
                }
                if !outs.is_empty() {
                    info.push((Sym::new("outputs"), Value::list(outs.into_iter().map(Value::str).collect())));
                }
                (Sym::new(&k), Value::attrs(Attrs::from_unsorted(info)))
            })
            .collect();
        Ok(Value::attrs(Attrs::from_unsorted(entries)))
    }),
    prim!("getEnv", 1, |ev, a| {
        let k = ev.force_plain_str(&a[0])?;
        if ev.opts.pure {
            return Ok(Value::str(""));
        }
        Ok(Value::str(std::env::var(k).unwrap_or_default()))
    }),
    prim!("groupBy", 2, |ev, a| {
        let f = ev.force_fn(&a[0])?;
        let mut m: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for x in ev.force_list(&a[1])?.iter() {
            let k = ev.force_plain_str(&ev.call(&f, x.clone())?)?;
            m.entry(k).or_default().push(x.clone());
        }
        Ok(Value::attrs(Attrs::from_unsorted(m.into_iter().map(|(k, v)| (Sym::new(&k), Value::list(v))).collect())))
    }),
    prim!("hasAttr", 2, |ev, a| {
        let k = ev.force_plain_str(&a[0])?;
        Ok(Value::Bool(ev.force_attrs(&a[1])?.get_str(&k).is_some()))
    }),
    prim!("hasContext", 1, |ev, a| Ok(Value::Bool(!ev.force_str(&a[0])?.ctx.is_empty()))),
    prim!("hashFile", 2, |ev, a| {
        let algo = parse_algo(&ev.force_plain_str(&a[0])?)?;
        let p = ev.coerce_to_path(&a[1], &mut Context::new())?;
        let data = read_file(ev, &p)?;
        Ok(Value::str(Hash::digest(algo, &data).to_base16()))
    }),
    prim!("hashString", 2, |ev, a| {
        let algo = parse_algo(&ev.force_plain_str(&a[0])?)?;
        let s = ev.force_str(&a[1])?;
        Ok(Value::str(Hash::digest(algo, s.s.as_bytes()).to_base16()))
    }),
    prim!("head", 1, |ev, a| match ev.force_list(&a[0])?.first() {
        Some(v) => ev.force(v),
        None => err("'builtins.head' called on an empty list"),
    }),
    prim!("import", 1, |ev, a| {
        let p = realised_path(ev, &a[0])?;
        ev.import(&p)
    }),
    prim!("intersectAttrs", 2, |ev, a| {
        let x = ev.force_attrs(&a[0])?;
        let y = ev.force_attrs(&a[1])?;
        // `callPackage` intersects a few formals with the whole package set:
        // walk the smaller side so the large one is only probed.
        let v = if x.len() < y.len() {
            x.iter().filter_map(|(k, _)| Some((k.clone(), y.get(k)?.clone()))).collect()
        } else {
            y.iter().filter(|(k, _)| x.get(k).is_some()).cloned().collect()
        };
        Ok(Value::attrs(Attrs::from_sorted(v)))
    }),
    prim!("isAttrs", 1, |ev, a| Ok(Value::Bool(matches!(ev.force(&a[0])?, Value::Attrs(_))))),
    prim!("isBool", 1, |ev, a| Ok(Value::Bool(matches!(ev.force(&a[0])?, Value::Bool(_))))),
    prim!("isFloat", 1, |ev, a| Ok(Value::Bool(matches!(ev.force(&a[0])?, Value::Float(_))))),
    prim!("isFunction", 1, |ev, a| Ok(Value::Bool(matches!(ev.force(&a[0])?, Value::Lambda(_) | Value::PrimOp(_))))),
    prim!("isInt", 1, |ev, a| Ok(Value::Bool(matches!(ev.force(&a[0])?, Value::Int(_))))),
    prim!("isList", 1, |ev, a| Ok(Value::Bool(matches!(ev.force(&a[0])?, Value::List(_))))),
    prim!("isNull", 1, |ev, a| Ok(Value::Bool(matches!(ev.force(&a[0])?, Value::Null)))),
    prim!("isPath", 1, |ev, a| Ok(Value::Bool(matches!(ev.force(&a[0])?, Value::Path(_))))),
    prim!("isString", 1, |ev, a| Ok(Value::Bool(matches!(ev.force(&a[0])?, Value::Str(_))))),
    prim!("length", 1, |ev, a| Ok(Value::Int(ev.force_list(&a[0])?.len() as i64))),
    prim!("lessThan", 2, |ev, a| Ok(Value::Bool(ev.compare(&a[0], &a[1])? == Ordering::Less))),
    prim!("listToAttrs", 1, |ev, a| {
        let l = ev.force_list(&a[0])?;
        let mut v = Vec::with_capacity(l.len());
        for x in l.iter() {
            let e = ev.force_attrs(x)?;
            let name = e.get(&ev.syms.name).ok_or(()).or_else(|_| err("attribute 'name' missing in listToAttrs element"))?;
            let value = e.get(&ev.syms.value).ok_or(()).or_else(|_| err("attribute 'value' missing in listToAttrs element"))?;
            v.push((Sym::new(&ev.force_plain_str(name)?), value.clone()));
        }
        Ok(Value::attrs(Attrs::from_unsorted_first(v)))
    }),
    prim!("map", 2, |ev, a| {
        let l = ev.force_list(&a[1])?;
        let f = a[0].clone();
        Ok(Value::list(l.iter().map(|x| Value::app_thunk(f.clone(), x.clone())).collect()))
    }),
    prim!("mapAttrs", 2, |ev, a| {
        let s = ev.force_attrs(&a[1])?;
        let f = Rc::new(a[0].clone());
        Ok(Value::attrs(Attrs::from_sorted(
            s.iter().map(|(k, v)| (k.clone(), Value::attr_app_thunk(f.clone(), k.clone(), v.clone()))).collect(),
        )))
    }),
    prim!("match", 2, |ev, a| {
        let re = regex(ev, &ev.force_plain_str(&a[0])?, true)?;
        let s = ev.force_str(&a[1])?;
        match re.captures(&s.s) {
            None => Ok(Value::Null),
            Some(c) => Ok(Value::list(
                (1..c.len()).map(|i| c.get(i).map_or(Value::Null, |m| Value::str(m.as_str()))).collect(),
            )),
        }
    }),
    prim!("parseFlakeRef", 1, crate::flake::prim_parse_flake_ref),
    prim!("parseDrvName", 1, |ev, a| {
        let s = ev.force_plain_str(&a[0])?;
        let b = s.as_bytes();
        let split = (0..b.len()).find(|&i| b[i] == b'-' && b.get(i + 1).is_some_and(|c| !c.is_ascii_alphabetic()));
        let (n, v) = match split {
            Some(i) => (&s[..i], &s[i + 1..]),
            None => (s.as_str(), ""),
        };
        Ok(Value::attrs(Attrs::from_unsorted(vec![
            (Sym::new("name"), Value::str(n)),
            (Sym::new("version"), Value::str(v)),
        ])))
    }),
    prim!("partition", 2, |ev, a| {
        let f = ev.force_fn(&a[0])?;
        let (mut right, mut wrong) = (Vec::new(), Vec::new());
        for x in ev.force_list(&a[1])?.iter() {
            if ev.force_bool(&ev.call(&f, x.clone())?)? {
                right.push(x.clone());
            } else {
                wrong.push(x.clone());
            }
        }
        Ok(Value::attrs(Attrs::from_unsorted(vec![
            (Sym::new("right"), Value::list(right)),
            (Sym::new("wrong"), Value::list(wrong)),
        ])))
    }),
    prim!("path", 1, |ev, a| {
        let args = ev.force_attrs(&a[0])?;
        let mut ctx = Context::new();
        let p = match args.get_str("path") {
            Some(p) => ev.coerce_to_path(p, &mut ctx)?,
            None => return err("'path' required in builtins.path"),
        };
        let name = match args.get_str("name") {
            Some(n) => ev.force_plain_str(n)?,
            None => p.rsplit('/').next().unwrap_or("source").to_string(),
        };
        let filter = args.get_str("filter").cloned();
        let recursive = match args.get_str("recursive") {
            Some(r) => ev.force_bool(r)?,
            None => true,
        };
        let method = if recursive { FileIngestion::Recursive } else { FileIngestion::Flat };
        let r = add_path_filtered(ev, &p, &name, filter, method)?;
        if let Some(h) = args.get_str("sha256") {
            let want = Hash::parse(&ev.force_plain_str(h)?, Some(HashAlgo::Sha256)).or_else(err)?;
            let s = ev.force_str(&r)?;
            let sp = ev.store.dir.parse(&s.s).or_else(err)?;
            let info = ev.store.query_info(&sp).or_else(err)?.unwrap();
            if recursive && info.nar_hash != want {
                return err(format!("hash mismatch in builtins.path for '{p}': expected {}, got {}", want.to_sri(), info.nar_hash.to_sri()));
            }
        }
        Ok(r)
    }),
    prim!("pathExists", 1, |ev, a| {
        let mut ctx = Context::new();
        let p = ev.coerce_to_path(&a[0], &mut ctx)?;
        // A trailing `/` or `/.` asks whether the path is a directory.
        let must_be_dir = p.ends_with('/') || p.ends_with("/.");
        let real = ev.store.resolve(&canon_path(&p));
        Ok(Value::Bool(if must_be_dir { real.is_dir() } else { real.exists() }))
    }),
    prim!("placeholder", 1, |ev, a| {
        let o = ev.force_plain_str(&a[0])?;
        Ok(Value::str(format!("/{}", Hash::sha256(format!("nix-output:{o}").as_bytes()).to_nix32())))
    }),
    prim!("readDir", 1, |ev, a| {
        let p = realised_path(ev, &a[0])?;
        let real = ev.store.resolve(&p);
        let rd = std::fs::read_dir(&real).or_else(|e| err(format!("reading directory '{p}': {e}")))?;
        let mut v = Vec::new();
        for e in rd {
            let e = e.or_else(|e| err(e.to_string()))?;
            let ft = e.file_type().or_else(|e| err(e.to_string()))?;
            let t = file_type_name(&ft);
            v.push((Sym::new(&e.file_name().to_string_lossy()), Value::str(t)));
        }
        Ok(Value::attrs(Attrs::from_unsorted(v)))
    }),
    prim!("readFile", 1, |ev, a| {
        let p = realised_path(ev, &a[0])?;
        let data = read_file(ev, &p)?;
        Ok(Value::str(String::from_utf8_lossy(&data).into_owned()))
    }),
    prim!("readFileType", 1, |ev, a| {
        let p = realised_path(ev, &a[0])?;
        let md = std::fs::symlink_metadata(ev.store.resolve(&p)).or_else(|e| err(format!("reading '{p}': {e}")))?;
        Ok(Value::str(file_type_name(&md.file_type())))
    }),
    prim!("removeAttrs", 2, |ev, a| {
        let s = ev.force_attrs(&a[0])?;
        let names: BTreeSet<String> =
            ev.force_list(&a[1])?.iter().map(|n| ev.force_plain_str(n)).collect::<R<_>>()?;
        if names.is_empty() {
            return Ok(Value::Attrs(s));
        }
        Ok(Value::attrs(Attrs::from_sorted(s.iter().filter(|(k, _)| !names.contains(k.as_str())).cloned().collect())))
    }),
    prim!("replaceStrings", 3, replace_strings),
    prim!("scopedImport", 2, |ev, a| {
        let _ = ev.force_attrs(&a[0])?;
        let p = realised_path(ev, &a[1])?;
        ev.import(&p)
    }),
    prim!("seq", 2, |ev, a| {
        ev.force(&a[0])?;
        ev.force(&a[1])
    }),
    prim!("sort", 2, |ev, a| {
        let f = ev.force_fn(&a[0])?;
        let l = ev.force_list(&a[1])?;
        let mut v: Vec<Value> = l.iter().cloned().collect();
        merge_sort(&mut v, &mut |x, y| ev.force_bool(&ev.call2(&f, x.clone(), y.clone())?))?;
        Ok(Value::list(v))
    }),
    prim!("split", 2, |ev, a| {
        let re = regex(ev, &ev.force_plain_str(&a[0])?, false)?;
        let s = ev.force_str(&a[1])?;
        let mut out = Vec::new();
        let mut last = 0;
        for c in re.captures_iter(&s.s) {
            let m = c.get(0).unwrap();
            out.push(Value::str(&s.s[last..m.start()]));
            out.push(Value::list((1..c.len()).map(|i| c.get(i).map_or(Value::Null, |g| Value::str(g.as_str()))).collect()));
            last = m.end();
        }
        out.push(Value::str(&s.s[last..]));
        Ok(Value::list(out))
    }),
    prim!("splitVersion", 1, |ev, a| {
        let s = ev.force_plain_str(&a[0])?;
        let mut rest = s.as_str();
        let mut out = Vec::new();
        loop {
            let (c, r) = next_component(rest);
            if c.is_empty() {
                break;
            }
            out.push(Value::str(c));
            rest = r;
        }
        Ok(Value::list(out))
    }),
    prim!("storePath", 1, |ev, a| {
        let mut ctx = Context::new();
        let p = ev.coerce_to_path(&a[0], &mut ctx)?;
        let (sp, _) = ev.store.dir.to_store_path(&p).ok_or(()).or_else(|_| err(format!("path '{p}' is not in the Nix store")))?;
        let s = ev.store.dir.print(&sp);
        // Like Nix, fetch the path from a substituter when it is missing;
        // paths in the host's store at the same location count as present.
        if !ev.store.is_valid(&sp) && !ev.store.resolve(&s).exists() {
            ev.store.ensure_path(&sp).or_else(err)?;
        }
        ctx.insert(CtxElem::Opaque(s.clone()));
        Ok(Value::str_ctx(s, ctx))
    }),
    prim!("stringLength", 1, |ev, a| {
        let s = ev.coerce_to_string(&a[0], &CoerceOpts { more: false, copy: true }, &mut Context::new())?;
        Ok(Value::Int(s.len() as i64))
    }),
    prim!("substring", 3, |ev, a| {
        let start = ev.force_int(&a[0])?;
        let len = ev.force_int(&a[1])?;
        let mut ctx = Context::new();
        let s = ev.coerce_to_string(&a[2], &CoerceOpts { more: false, copy: true }, &mut ctx)?;
        if start < 0 {
            return err("negative start position in 'substring'");
        }
        let b = s.as_bytes();
        let start = (start as usize).min(b.len());
        let end = if len < 0 { b.len() } else { start.saturating_add(len as usize).min(b.len()) };
        Ok(Value::str_ctx(String::from_utf8_lossy(&b[start..end]).into_owned(), ctx))
    }),
    prim!("tail", 1, |ev, a| {
        let l = ev.force_list(&a[0])?;
        if l.is_empty() {
            return err("'builtins.tail' called on an empty list");
        }
        Ok(Value::list(l[1..].to_vec()))
    }),
    prim!("throw", 1, |ev, a| {
        let s = ev.coerce_to_string(&a[0], &CoerceOpts { more: true, copy: false }, &mut Context::new())?;
        err_kind(ErrKind::Throw, s)
    }),
    prim!("toFile", 2, |ev, a| {
        let name = ev.force_plain_str(&a[0])?;
        let c = ev.force_str(&a[1])?;
        let mut refs = BTreeSet::new();
        for e in &c.ctx {
            match e {
                CtxElem::Opaque(p) => {
                    refs.insert(ev.store.dir.parse(p).or_else(err)?);
                }
                _ => return err(format!("in 'toFile': the file named '{name}' must not contain a reference to a derivation")),
            }
        }
        let p = ev.store.add_text(&name, c.s.as_bytes(), &refs).or_else(err)?;
        let s = ev.store.dir.print(&p);
        Ok(Value::str_ctx(s.clone(), [CtxElem::Opaque(s)].into()))
    }),
    prim!("toJSON", 1, |ev, a| {
        let mut ctx = Context::new();
        let mut out = String::new();
        crate::print::to_json(ev, &a[0], &mut out, &mut ctx)?;
        Ok(Value::str_ctx(out, ctx))
    }),
    prim!("toPath", 1, |ev, a| {
        let mut ctx = Context::new();
        let p = ev.coerce_to_path(&a[0], &mut ctx)?;
        Ok(Value::str_ctx(canon_path(&p), ctx))
    }),
    prim!("toString", 1, |ev, a| {
        let mut ctx = Context::new();
        let s = ev.coerce_to_string(&a[0], &CoerceOpts { more: true, copy: false }, &mut ctx)?;
        Ok(Value::str_ctx(s, ctx))
    }),
    prim!("toXML", 1, |ev, a| {
        let (s, ctx) = crate::xml::to_xml(ev, &a[0])?;
        Ok(Value::str_ctx(s, ctx))
    }),
    prim!("trace", 2, |ev, a| {
        let v = ev.force(&a[0])?;
        match &v {
            Value::Str(s) => eprintln!("trace: {}", s.s),
            _ => eprintln!("trace: {}", crate::print::print_value(ev, &v, false)?),
        }
        ev.force(&a[1])
    }),
    prim!("traceVerbose", 2, |ev, a| {
        if ev.opts.trace_verbose {
            let v = ev.force(&a[0])?;
            eprintln!("trace: {}", crate::print::print_value(ev, &v, false)?);
        }
        ev.force(&a[1])
    }),
    prim!("tryEval", 1, |ev, a| {
        let (ok, v) = match ev.force(&a[0]) {
            Ok(v) => (true, v),
            Err(e) if matches!(e.kind, ErrKind::Throw | ErrKind::Assert) => (false, Value::Bool(false)),
            Err(e) => return Err(e),
        };
        Ok(Value::attrs(Attrs::from_unsorted(vec![(Sym::new("success"), Value::Bool(ok)), (Sym::new("value"), v)])))
    }),
    prim!("typeOf", 1, |ev, a| Ok(Value::str(ev.force(&a[0])?.type_name()))),
    prim!("unsafeDiscardOutputDependency", 1, |ev, a| {
        let s = ev.force_str(&a[0])?;
        let ctx = s
            .ctx
            .iter()
            .map(|c| match c {
                CtxElem::DrvDeep(p) => CtxElem::Opaque(p.clone()),
                c => c.clone(),
            })
            .collect();
        Ok(Value::str_ctx(s.s.clone(), ctx))
    }),
    prim!("unsafeDiscardStringContext", 1, |ev, a| {
        let s = ev.force_str(&a[0])?;
        Ok(Value::str(s.s.clone()))
    }),
    prim!("unsafeGetAttrPos", 2, |_, _| Ok(Value::Null)),
    prim!("warn", 2, |ev, a| {
        let s = ev.force_plain_str(&a[0])?;
        eprintln!("evaluation warning: {s}");
        ev.force(&a[1])
    }),
    prim!("zipAttrsWith", 2, |ev, a| {
        let mut m: BTreeMap<Sym, Vec<Value>> = BTreeMap::new();
        for s in ev.force_list(&a[1])?.iter() {
            for (k, v) in ev.force_attrs(s)?.iter() {
                m.entry(k.clone()).or_default().push(v.clone());
            }
        }
        let f = Rc::new(a[0].clone());
        Ok(Value::attrs(Attrs::from_sorted(
            m.into_iter().map(|(k, vs)| (k.clone(), Value::attr_app_thunk(f.clone(), k, Value::list(vs)))).collect(),
        )))
    }),
];

/// Names exposed directly in the base environment, besides `__<name>`.
const TOP_LEVEL: &[&str] = &[
    "abort", "baseNameOf", "break", "derivationStrict", "dirOf", "fetchGit", "fetchMercurial", "fetchTarball", "fetchTree",
    "fromTOML", "import", "isNull", "map", "placeholder", "removeAttrs", "scopedImport", "throw", "toString",
];

const DERIVATION_NIX: &str = r#"
drvAttrs @ { outputs ? [ "out" ], ... }:
let
  strict = derivationStrict drvAttrs;
  commonAttrs = drvAttrs // (builtins.listToAttrs outputsList) //
    { all = map (x: x.value) outputsList;
      inherit drvAttrs;
    };
  outputToAttrListElement = outputName:
    { name = outputName;
      value = commonAttrs // {
        outPath = builtins.getAttr outputName strict;
        drvPath = strict.drvPath;
        type = "derivation";
        inherit outputName;
      };
    };
  outputsList = map outputToAttrListElement outputs;
in (builtins.head outputsList).value
"#;

const FETCHURL_NIX: &str = r#"
{ system ? ""
, url
, hash ? ""
, md5 ? "", sha1 ? "", sha256 ? "", sha512 ? ""
, outputHash ?
    if hash != "" then hash else if sha512 != "" then sha512 else if sha1 != "" then sha1 else if md5 != "" then md5 else sha256
, outputHashAlgo ?
    if hash != "" then "" else if sha512 != "" then "sha512" else if sha1 != "" then "sha1" else if md5 != "" then "md5" else "sha256"
, executable ? false
, unpack ? false
, name ? baseNameOf (toString url)
, impure ? false
}:

derivation ({
  builder = "builtin:fetchurl";
  outputHashMode = if unpack || executable then "recursive" else "flat";
  inherit name url executable unpack;
  system = "builtin";
  preferLocalBuild = true;
  impureEnvVars = [
    "http_proxy" "https_proxy" "ftp_proxy" "all_proxy" "no_proxy"
  ];
  urls = [ url ];
} // (if impure
  then { __impure = true; }
  else { inherit outputHashAlgo outputHash; }))
"#;

/// Builds the base environment: its names (slot order) and values.
pub fn globals(opts: &Options) -> (Vec<Sym>, Vec<Value>) {
    let mut builtins: Vec<(Sym, Value)> = Vec::new();
    let mut top: Vec<(Sym, Value)> = Vec::new();
    for op in PRIMOPS {
        let v = Value::PrimOp(Rc::new(PrimOpApp { op, args: Vec::new() }));
        builtins.push((Sym::new(op.name), v.clone()));
        top.push((Sym::new(&format!("__{}", op.name)), v.clone()));
        if TOP_LEVEL.contains(&op.name) {
            top.push((Sym::new(op.name), v));
        }
    }
    let derivation = Value::native(|ev| {
        let e = ev.parse(DERIVATION_NIX, "<nix/derivation-internal.nix>", "/")?;
        ev.eval(e, &ev.base_env().clone())
    });
    let nix_path = Value::list(
        opts.search_path
            .iter()
            .map(|(prefix, path)| {
                Value::attrs(Attrs::from_unsorted(vec![
                    (Sym::new("prefix"), Value::str(prefix.as_str())),
                    (Sym::new("path"), Value::str(path.as_str())),
                ]))
            })
            .collect(),
    );
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    let consts: Vec<(&str, Value)> = vec![
        ("true", Value::Bool(true)),
        ("false", Value::Bool(false)),
        ("null", Value::Null),
        ("currentSystem", Value::str(opts.system.as_str())),
        ("currentTime", Value::Int(now)),
        ("langVersion", Value::Int(6)),
        ("nixVersion", Value::str("2.24.0")),
        ("nixPath", nix_path),
        ("derivation", derivation),
    ];
    for (k, v) in consts {
        builtins.push((Sym::new(k), v.clone()));
        if matches!(k, "true" | "false" | "null" | "derivation") {
            top.push((Sym::new(k), v));
        } else {
            top.push((Sym::new(&format!("__{k}")), v));
        }
    }
    // storeDir depends on the store; it is filled in lazily.
    let store_dir = Value::native(|ev| Ok(Value::str(ev.store.dir.as_str())));
    builtins.push((Sym::new("storeDir"), store_dir.clone()));
    top.push((Sym::new("__storeDir"), store_dir));

    // `builtins.builtins` refers to the set itself.
    let selfref = Rc::new(Thunk::new(ThunkState::Blackhole));
    builtins.push((Sym::new("builtins"), Value::Thunk(selfref.clone())));
    let set = Value::attrs(Attrs::from_unsorted(builtins));
    selfref.put(ThunkState::Done(set.clone()));
    top.push((Sym::new("builtins"), set));

    top.sort_by(|a, b| a.0.cmp(&b.0));
    top.dedup_by(|a, b| a.0 == b.0);
    top.into_iter().unzip()
}

/// Source of `<nix/fetchurl.nix>`, served from the evaluator itself.
pub fn corepkg(name: &str) -> Option<&'static str> {
    match name {
        "fetchurl.nix" => Some(FETCHURL_NIX),
        _ => None,
    }
}

fn parse_algo(s: &str) -> R<HashAlgo> {
    HashAlgo::parse(s).ok_or(()).or_else(|_| err(format!("unknown hash algorithm '{s}'")))
}

fn encode_hash(h: &Hash, fmt: &str) -> R<String> {
    Ok(match fmt {
        "base16" => h.encode(Encoding::Base16, false),
        "nix32" | "base32" => h.encode(Encoding::Nix32, false),
        "base64" => h.encode(Encoding::Base64, false),
        "sri" => h.to_sri(),
        f => return err(format!("unknown hash format '{f}'")),
    })
}

fn file_type_name(ft: &std::fs::FileType) -> &'static str {
    if ft.is_symlink() {
        "symlink"
    } else if ft.is_dir() {
        "directory"
    } else if ft.is_file() {
        "regular"
    } else {
        "unknown"
    }
}

fn read_file(ev: &Eval, p: &str) -> R<Vec<u8>> {
    std::fs::read(ev.store.resolve(&canon_path(p))).or_else(|e| err(format!("reading '{p}': {e}")))
}

/// Coerces to a path, building derivation outputs it refers to first
/// (import from derivation).
fn realised_path(ev: &Eval, v: &Value) -> R<String> {
    let v = ev.force(v)?;
    if let Value::Path(p) = &v {
        return Ok(p.to_string());
    }
    let mut ctx = Context::new();
    let p = ev.coerce_to_path(&v, &mut ctx)?;
    let drvs: Vec<_> = ctx
        .iter()
        .filter_map(|c| match c {
            CtxElem::Built { drv, .. } => ev.store.dir.parse(drv).ok(),
            _ => None,
        })
        .collect();
    if drvs.is_empty() {
        return Ok(p);
    }
    let opts = cranix_store::build::BuildOptions {
        system: ev.opts.system.clone(),
        ca_derivations: ev.opts.experimental_features.contains("ca-derivations"),
        impure_derivations: ev.opts.experimental_features.contains("impure-derivations"),
        ..Default::default()
    };
    let built = ev.store.realise(&drvs, &opts).or_else(|e| err(format!("building for import from derivation: {e}")))?;
    // Outputs of content-addressed derivations appear as placeholders
    // until they are built.
    let mut rewrites = std::collections::BTreeMap::new();
    for (drv, outs) in &built {
        for (o, path) in outs {
            rewrites.insert(cranix_core::derivation::downstream_placeholder(drv, o), ev.store.dir.print(path));
        }
    }
    Ok(cranix_core::derivation::rewrite_strings(&p, &rewrites))
}

fn find_file(ev: &Eval, path: &Value, name: &str) -> R<Value> {
    if let Some(core) = name.strip_prefix("nix/") {
        if let Some(src) = corepkg(core) {
            let _ = src;
            return Ok(Value::Path(format!("/__corepkgs__/{core}").into()));
        }
    }
    for e in ev.force_list(path)?.iter() {
        let e = ev.force_attrs(e)?;
        let prefix = match e.get_str("prefix") {
            Some(p) => ev.force_plain_str(p)?,
            None => String::new(),
        };
        let Some(p) = e.get_str("path") else { continue };
        let entry = ev.force_plain_str(p)?;
        let rest = if prefix.is_empty() {
            Some(format!("/{name}"))
        } else if name == prefix {
            Some(String::new())
        } else {
            name.strip_prefix(&format!("{prefix}/")).map(|r| format!("/{r}"))
        };
        if let Some(rest) = rest {
            let Some(base) = ev.resolve_search_entry(&entry) else { continue };
            let full = canon_path(&format!("{base}{rest}"));
            if ev.store.resolve(&full).exists() {
                return Ok(Value::Path(full.into()));
            }
        }
    }
    // Thrown so that `tryEval <name>` can probe for optional entries.
    err_kind(ErrKind::Throw, format!("file '{name}' was not found in the Nix search path (add it using $NIX_PATH or -I)"))
}

fn add_path_filtered(ev: &Eval, p: &str, name: &str, filter: Option<Value>, method: FileIngestion) -> R<Value> {
    let real = ev.store.resolve(&canon_path(p));
    let real_prefix = real.to_string_lossy().into_owned();
    let failure: RefCell<Option<Box<crate::eval::EvalError>>> = RefCell::new(None);
    let filter = match filter {
        Some(f) => Some(ev.force_fn(&f)?),
        None => None,
    };
    let mut cb = |path: &std::path::Path, md: &std::fs::Metadata| -> std::io::Result<bool> {
        let f = filter.as_ref().unwrap();
        let ps = path.to_string_lossy();
        let logical = format!("{}{}", canon_path(p), &ps[real_prefix.len()..]);
        let ty = file_type_name(&md.file_type());
        let r = ev.call2(f, Value::str(logical), Value::str(ty)).and_then(|v| ev.force_bool(&v));
        match r {
            Ok(b) => Ok(b),
            Err(e) => {
                *failure.borrow_mut() = Some(e);
                Err(std::io::Error::other("filter failed"))
            }
        }
    };
    let r = ev.store.add_path(
        &real,
        name,
        method,
        if filter.is_some() { Some(&mut cb as cranix_core::nar::Filter<'_>) } else { None },
    );
    if let Some(e) = failure.into_inner() {
        return Err(e);
    }
    let sp = r.or_else(|e| err(format!("adding '{p}' to the store: {e}")))?;
    let s = ev.store.dir.print(&sp);
    Ok(Value::str_ctx(s.clone(), [CtxElem::Opaque(s)].into()))
}

fn regex(ev: &Eval, pat: &str, anchored: bool) -> R<Rc<regex::Regex>> {
    let key = format!("{}{pat}", if anchored { "^" } else { "~" });
    if let Some(r) = ev.regex_cache.borrow().get(&key) {
        return Ok(r.clone());
    }
    let src = if anchored { format!("(?s)^(?:{pat})$") } else { format!("(?s){pat}") };
    let re = regex::Regex::new(&src).or_else(|e| err(format!("invalid regular expression '{pat}': {e}")))?;
    let re = Rc::new(re);
    ev.regex_cache.borrow_mut().insert(key, re.clone());
    Ok(re)
}

fn replace_strings(ev: &Eval, a: &[Value]) -> R<Value> {
    let from: Vec<Rc<NixStr>> = ev.force_list(&a[0])?.iter().map(|x| ev.force_str(x)).collect::<R<_>>()?;
    let to_l = ev.force_list(&a[1])?;
    if from.len() != to_l.len() {
        return err("'from' and 'to' arguments passed to builtins.replaceStrings have different lengths");
    }
    let mut to: Vec<Option<Rc<NixStr>>> = vec![None; to_l.len()];
    let s = ev.force_str(&a[2])?;
    let b = s.s.as_bytes();
    let mut ctx = s.ctx.clone();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut p = 0;
    while p <= b.len() {
        let mut found = false;
        for (i, f) in from.iter().enumerate() {
            let fb = f.s.as_bytes();
            if b[p..].starts_with(fb) {
                found = true;
                if to[i].is_none() {
                    to[i] = Some(ev.force_str(&to_l[i])?);
                }
                let t = to[i].as_ref().unwrap();
                out.extend_from_slice(t.s.as_bytes());
                ctx.extend(t.ctx.iter().cloned());
                if fb.is_empty() {
                    if p < b.len() {
                        out.push(b[p]);
                    }
                    p += 1;
                } else {
                    p += fb.len();
                }
                break;
            }
        }
        if !found {
            if p < b.len() {
                out.push(b[p]);
            }
            p += 1;
        }
    }
    Ok(Value::str_ctx(String::from_utf8_lossy(&out).into_owned(), ctx))
}

fn generic_closure(ev: &Eval, a: &[Value]) -> R<Value> {
    let args = ev.force_attrs(&a[0])?;
    let start = args.get_str("startSet").ok_or(()).or_else(|_| err("attribute 'startSet' required"))?;
    let op = ev.force_fn(args.get_str("operator").ok_or(()).or_else(|_| err("attribute 'operator' required"))?)?;
    let mut todo: std::collections::VecDeque<Value> = ev.force_list(start)?.iter().cloned().collect();
    let mut seen_keys: Vec<Value> = Vec::new();
    let mut seen_fast: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    let key_sym = Sym::new("key");
    while let Some(x) = todo.pop_front() {
        let e = ev.force_attrs(&x)?;
        let k = ev.force(e.get(&key_sym).ok_or(()).or_else(|_| err("attribute 'key' required in genericClosure element"))?)?;
        let fast = match &k {
            Value::Int(n) => Some(format!("i{n}")),
            Value::Str(s) => Some(format!("s{}", s.s)),
            Value::Path(p) => Some(format!("p{p}")),
            _ => None,
        };
        let new = match fast {
            Some(f) => seen_fast.insert(f),
            None => {
                let mut dup = false;
                for s in &seen_keys {
                    if ev.eq(s, &k)? {
                        dup = true;
                        break;
                    }
                }
                if !dup {
                    seen_keys.push(k.clone());
                }
                !dup
            }
        };
        if !new {
            continue;
        }
        out.push(x.clone());
        todo.extend(ev.force_list(&ev.call(&op, x)?)?.iter().cloned());
    }
    Ok(Value::list(out))
}

/// Stable merge sort with a fallible "less than" predicate.
fn merge_sort(v: &mut Vec<Value>, lt: &mut dyn FnMut(&Value, &Value) -> R<bool>) -> R<()> {
    if v.len() <= 1 {
        return Ok(());
    }
    // Insertion sort for short runs keeps comparator calls low.
    if v.len() <= 8 {
        for i in 1..v.len() {
            let mut j = i;
            while j > 0 && lt(&v[j], &v[j - 1])? {
                v.swap(j, j - 1);
                j -= 1;
            }
        }
        return Ok(());
    }
    let mut right = v.split_off(v.len() / 2);
    merge_sort(v, lt)?;
    merge_sort(&mut right, lt)?;
    let left = std::mem::take(v);
    let mut out = Vec::with_capacity(left.len() + right.len());
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        if lt(&right[j], &left[i])? {
            out.push(right[j].clone());
            j += 1;
        } else {
            out.push(left[i].clone());
            i += 1;
        }
    }
    out.extend_from_slice(&left[i..]);
    out.extend_from_slice(&right[j..]);
    *v = out;
    Ok(())
}

fn next_component(s: &str) -> (&str, &str) {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i] == b'.' || b[i] == b'-') {
        i += 1;
    }
    let start = i;
    if i < b.len() && b[i].is_ascii_digit() {
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    } else {
        while i < b.len() && !(b[i].is_ascii_digit() || b[i] == b'.' || b[i] == b'-') {
            i += 1;
        }
    }
    (&s[start..i], &s[i..])
}

fn components_lt(c1: &str, c2: &str) -> bool {
    let n1: Option<u64> = c1.parse().ok();
    let n2: Option<u64> = c2.parse().ok();
    match (n1, n2) {
        (Some(a), Some(b)) => a < b,
        _ if c1.is_empty() && n2.is_some() => true,
        _ if c1 == "pre" && c2 != "pre" => true,
        _ if c2 == "pre" => false,
        (_, Some(_)) => true,
        (Some(_), _) => false,
        _ => c1 < c2,
    }
}

pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let (mut x, mut y) = (a, b);
    loop {
        let (c1, r1) = next_component(x);
        let (c2, r2) = next_component(y);
        if c1.is_empty() && c2.is_empty() {
            return Ordering::Equal;
        }
        if components_lt(c1, c2) {
            return Ordering::Less;
        }
        if components_lt(c2, c1) {
            return Ordering::Greater;
        }
        x = r1;
        y = r2;
    }
}
