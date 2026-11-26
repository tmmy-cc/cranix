//! `derivationStrict`: turns an attribute set into a store derivation,
//! writes the `.drv` file and returns its output paths.

use std::collections::BTreeSet;
use std::rc::Rc;

use cranix_core::derivation::downstream_placeholder;
use cranix_core::{Derivation, DrvHash, Hash, HashAlgo, Output, StorePath};

use crate::eval::{err, CoerceOpts, Eval, R};
use crate::value::*;

impl Eval {
    /// The derivation at `p`, from this evaluation or the store.
    pub fn derivation(&self, p: &StorePath) -> R<Rc<Derivation>> {
        if let Some(d) = self.drvs.borrow().get(p) {
            return Ok(d.clone());
        }
        let d = Rc::new(self.store.read_derivation(p).or_else(err)?);
        self.drvs.borrow_mut().insert(p.clone(), d.clone());
        Ok(d)
    }

    /// `hashDerivationModulo(drv, maskOutputs = false)` of a `.drv` file.
    pub fn drv_hash(&self, p: &StorePath) -> R<DrvHash> {
        if let Some(h) = self.drv_hashes.borrow().get(p) {
            return Ok(h.clone());
        }
        let d = self.derivation(p)?;
        let mut failure = None;
        let h = d.hash_modulo(&self.store.dir, false, &mut |q| match self.drv_hash(q) {
            Ok(h) => Ok(h),
            Err(e) => {
                let msg = e.msg.clone();
                failure = Some(e);
                Err(msg)
            }
        });
        let h = match (h, failure) {
            (Ok(h), _) => h,
            (Err(_), Some(e)) => return Err(e),
            (Err(m), None) => return err(m),
        };
        self.drv_hashes.borrow_mut().insert(p.clone(), h.clone());
        Ok(h)
    }
}

fn parse_outputs(names: Vec<String>) -> R<Vec<String>> {
    let mut seen = BTreeSet::new();
    for n in &names {
        if n == "drv" {
            return err("invalid derivation output name 'drv'");
        }
        if !seen.insert(n.clone()) {
            return err(format!("duplicate derivation output '{n}'"));
        }
    }
    if names.is_empty() {
        return err("derivation cannot have an empty set of outputs");
    }
    Ok(names)
}

pub fn derivation_strict(ev: &Eval, arg: &Value) -> R<Value> {
    let attrs = ev.force_attrs(arg)?;
    let name = match attrs.get(&ev.syms.name) {
        Some(n) => ev.force_plain_str(n)?,
        None => return err("required attribute 'name' missing"),
    };
    let r = derivation_inner(ev, &attrs, &name);
    r.map_err(|mut e| {
        e.trace.push(format!("while evaluating derivation '{name}'"));
        e
    })
}

fn derivation_inner(ev: &Eval, attrs: &Attrs, name: &str) -> R<Value> {
    let get_bool = |k: &str| -> R<bool> {
        match attrs.get_str(k) {
            Some(v) => ev.force_bool(v),
            None => Ok(false),
        }
    };
    let structured = get_bool("__structuredAttrs")?;
    let ignore_nulls = get_bool("__ignoreNulls")?;

    let mut drv = Derivation { name: name.to_string(), ..Default::default() };
    let mut ctx = Context::new();
    let mut json = String::from("{");
    let mut json_first = true;
    let mut outputs: Vec<String> = vec!["out".into()];
    let mut output_hash: Option<String> = None;
    let mut output_hash_algo: Option<String> = None;
    let mut hash_mode: Option<String> = None;
    let mut content_addressed = false;
    let mut impure = false;
    let coerce = CoerceOpts { more: true, copy: true };

    for (k, v) in attrs.iter() {
        let key = k.as_str();
        if key == "__ignoreNulls" {
            continue;
        }
        let ctxmsg = |e: Box<crate::eval::EvalError>| {
            let mut e = e;
            e.trace.push(format!("while evaluating attribute '{key}' of derivation '{name}'"));
            e
        };
        if ignore_nulls && matches!(ev.force(v).map_err(ctxmsg)?, Value::Null) {
            continue;
        }
        // Enabled `__contentAddressed` and `__impure` are not passed to the
        // builder.
        if key == "__contentAddressed" && ev.force_bool(v).map_err(ctxmsg)? {
            ev.opts.require_feature("ca-derivations").map_err(ctxmsg)?;
            content_addressed = true;
            continue;
        }
        if key == "__impure" && ev.force_bool(v).map_err(ctxmsg)? {
            ev.opts.require_feature("impure-derivations").map_err(ctxmsg)?;
            impure = true;
            continue;
        }
        if key == "args" {
            for a in ev.force_list(v).map_err(ctxmsg)?.iter() {
                drv.args.push(ev.coerce_to_string(a, &coerce, &mut ctx).map_err(ctxmsg)?);
            }
            continue;
        }
        if structured {
            if key == "__structuredAttrs" {
                continue;
            }
            if !json_first {
                json.push(',');
            }
            json_first = false;
            crate::print::json_string(key, &mut json);
            json.push(':');
            crate::print::to_json(ev, v, &mut json, &mut ctx).map_err(ctxmsg)?;
            match key {
                "builder" => drv.builder = ev.force_str(v)?.s.clone(),
                "system" => drv.platform = ev.force_plain_str(v)?,
                "outputHash" => output_hash = Some(ev.force_plain_str(v)?),
                "outputHashAlgo" => output_hash_algo = Some(ev.force_plain_str(v)?),
                "outputHashMode" => hash_mode = Some(ev.force_plain_str(v)?),
                "outputs" => {
                    let l = ev.force_list(v)?;
                    outputs = parse_outputs(l.iter().map(|o| ev.force_plain_str(o)).collect::<R<_>>()?)?;
                }
                _ => {}
            }
        } else {
            let s = ev.coerce_to_string(v, &coerce, &mut ctx).map_err(ctxmsg)?;
            match key {
                "builder" => drv.builder = s.clone(),
                "system" => drv.platform = s.clone(),
                "outputHash" => output_hash = Some(s.clone()),
                "outputHashAlgo" => output_hash_algo = Some(s.clone()),
                "outputHashMode" => hash_mode = Some(s.clone()),
                "outputs" => outputs = parse_outputs(s.split_whitespace().map(String::from).collect())?,
                _ => {}
            }
            drv.env.insert(key.to_string(), s);
        }
    }
    if structured {
        json.push('}');
        drv.env.insert("__json".into(), json);
    }

    let sd = &ev.store.dir;
    for c in &ctx {
        match c {
            CtxElem::Opaque(p) => {
                drv.input_srcs.insert(sd.parse(p).or_else(err)?);
            }
            CtxElem::Built { drv: d, output } => {
                drv.input_drvs.entry(sd.parse(d).or_else(err)?).or_default().insert(output.clone());
            }
            CtxElem::DrvDeep(d) => {
                let p = sd.parse(d).or_else(err)?;
                for q in drv_closure(ev, &p)? {
                    if q.is_derivation() {
                        let outs = ev.derivation(&q)?.outputs.keys().cloned().collect();
                        drv.input_drvs.insert(q.clone(), outs);
                    }
                    drv.input_srcs.insert(q);
                }
            }
        }
    }

    if drv.builder.is_empty() {
        return err("required attribute 'builder' missing");
    }
    if drv.platform.is_empty() {
        return err("required attribute 'system' missing");
    }
    if name.ends_with(".drv") {
        return err("derivation names are not allowed to end in '.drv'");
    }

    if let Some(h) = output_hash {
        if outputs != ["out"] {
            return err("multiple outputs are not supported in fixed-output derivations");
        }
        let algo = match output_hash_algo.as_deref() {
            Some("") | None => None,
            Some(a) => Some(HashAlgo::parse(a).ok_or(()).or_else(|_| err(format!("unknown hash algorithm '{a}'")))?),
        };
        let hash = if h.is_empty() {
            let a = algo.unwrap_or(HashAlgo::Sha256);
            eprintln!("warning: found empty hash, assuming '{}'", Hash::from_bytes(a, &vec![0; a.size()]).to_sri());
            Hash::from_bytes(a, &vec![0; a.size()])
        } else {
            Hash::parse(&h, algo).or_else(|e| err(format!("invalid outputHash: {e}")))?
        };
        let prefix = match hash_mode.as_deref() {
            None | Some("flat") => "",
            Some("recursive") | Some("nar") => "r:",
            Some("text") => {
                ev.opts.require_feature("dynamic-derivations")?;
                "text:"
            }
            Some("git") => {
                ev.opts.require_feature("git-hashing")?;
                return err("git-hashed derivation outputs are not supported");
            }
            Some(m) => return err(format!("invalid value '{m}' for 'outputHashMode'")),
        };
        drv.outputs.insert(
            "out".into(),
            Output { path: None, hash_algo: format!("{prefix}{}", hash.algo), hash: hash.to_base16() },
        );
    } else if content_addressed || impure {
        if content_addressed && impure {
            return err("derivation cannot be both content-addressed and impure");
        }
        let algo = match output_hash_algo.as_deref() {
            Some("") | None => HashAlgo::Sha256,
            Some(a) => HashAlgo::parse(a).ok_or(()).or_else(|_| err(format!("unknown hash algorithm '{a}'")))?,
        };
        let prefix = match hash_mode.as_deref() {
            None | Some("recursive") | Some("nar") => "r:",
            Some("flat") => "",
            Some("text") => {
                ev.opts.require_feature("dynamic-derivations")?;
                "text:"
            }
            Some("git") => {
                ev.opts.require_feature("git-hashing")?;
                return err("git-hashed derivation outputs are not supported");
            }
            Some(m) => return err(format!("invalid value '{m}' for 'outputHashMode'")),
        };
        let hash = if impure { "impure" } else { "" };
        for o in &outputs {
            drv.outputs.insert(o.clone(), Output { path: None, hash_algo: format!("{prefix}{algo}"), hash: hash.into() });
        }
    } else {
        for o in &outputs {
            drv.outputs.insert(o.clone(), Output::default());
        }
    }

    let mut failure = None;
    let r = drv.fill_output_paths(sd, &mut |p| match ev.drv_hash(p) {
        Ok(h) => Ok(h),
        Err(e) => {
            let m = e.msg.clone();
            failure = Some(e);
            Err(m)
        }
    });
    if let Err(m) = r {
        return Err(failure.unwrap_or_else(|| Box::new(crate::eval::EvalError::new(crate::eval::ErrKind::Other, m))));
    }

    let text = drv.to_aterm(sd);
    let drv_path = ev.store.add_text(&format!("{name}.drv"), text.as_bytes(), &drv.references()).or_else(err)?;
    let drv_s = sd.print(&drv_path);

    let mut out = vec![(ev.syms.drv_path.clone(), Value::str_ctx(drv_s.clone(), [CtxElem::DrvDeep(drv_s.clone())].into()))];
    for (o, info) in &drv.outputs {
        // Outputs whose paths are only known after building are referred
        // to by a placeholder that the builder of a dependent rewrites.
        let p = match &info.path {
            Some(p) => sd.print(p),
            None => downstream_placeholder(&drv_path, o),
        };
        out.push((Sym::new(o), Value::str_ctx(p, [CtxElem::Built { drv: drv_s.clone(), output: o.clone() }].into())));
    }
    let drv = Rc::new(drv);
    ev.drvs.borrow_mut().insert(drv_path.clone(), drv.clone());
    let h = drv
        .hash_modulo(sd, false, &mut |p| ev.drv_hash(p).map_err(|e| e.msg.clone()))
        .or_else(err)?;
    ev.drv_hashes.borrow_mut().insert(drv_path, h);
    Ok(Value::attrs(Attrs::from_unsorted(out)))
}

/// File system closure of a `.drv` file through derivation inputs.
fn drv_closure(ev: &Eval, p: &StorePath) -> R<BTreeSet<StorePath>> {
    let mut seen = BTreeSet::new();
    let mut todo = vec![p.clone()];
    while let Some(q) = todo.pop() {
        if !seen.insert(q.clone()) {
            continue;
        }
        if q.is_derivation() {
            let d = ev.derivation(&q)?;
            todo.extend(d.references());
        } else if let Some(info) = ev.store.query_info(&q).or_else(err)? {
            todo.extend(info.references);
        }
    }
    Ok(seen)
}

