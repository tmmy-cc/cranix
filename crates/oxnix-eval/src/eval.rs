//! The evaluator: forces thunks, applies functions and implements the
//! language's operators and coercions.

use std::cell::{Cell, OnceCell, RefCell};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;

use oxnix_core::{Derivation, FileIngestion, Hash, StorePath};
use oxnix_store::Store;

use crate::ast::{BinOp, Pos};
use crate::compile::{Compiler, Expr, Key, LambdaDef};
use crate::parser::{canon_path, Parser};
use crate::value::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrKind {
    /// `throw`; catchable by `tryEval`.
    Throw,
    /// Failed `assert`; catchable by `tryEval`.
    Assert,
    Abort,
    Other,
}

#[derive(Debug, Clone)]
pub struct EvalError {
    pub kind: ErrKind,
    pub msg: String,
    pub trace: Vec<String>,
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for t in self.trace.iter().rev() {
            writeln!(f, "       … {t}")?;
        }
        write!(f, "error: {}", self.msg)
    }
}

pub type R<T> = Result<T, Box<EvalError>>;

pub fn err<T>(msg: impl Into<String>) -> R<T> {
    Err(Box::new(EvalError { kind: ErrKind::Other, msg: msg.into(), trace: Vec::new() }))
}

pub fn err_kind<T>(kind: ErrKind, msg: impl Into<String>) -> R<T> {
    Err(Box::new(EvalError { kind, msg: msg.into(), trace: Vec::new() }))
}

const MAX_CALL_DEPTH: usize = 100_000;
const MAX_TRACE: usize = 12;

pub struct Syms {
    pub out_path: Sym,
    pub to_string: Sym,
    pub functor: Sym,
    pub ty: Sym,
    pub drv_path: Sym,
    pub name: Sym,
    pub value: Sym,
    pub file: Sym,
    pub line: Sym,
    pub column: Sym,
}

pub struct Options {
    pub search_path: Vec<(String, String)>,
    pub system: String,
    pub pure: bool,
    pub trace_verbose: bool,
}

pub struct Eval {
    pub store: Store,
    pub opts: Options,
    pub files: RefCell<Vec<(String, Rc<str>)>>,
    pub syms: Syms,
    globals: Vec<Sym>,
    base_env: OnceCell<Rc<Env>>,
    import_cache: RefCell<HashMap<String, Value>>,
    pub path_cache: RefCell<HashMap<String, StorePath>>,
    /// Derivations instantiated (or read) during this evaluation.
    pub drvs: RefCell<HashMap<StorePath, Rc<Derivation>>>,
    /// `hashDerivationModulo` results, keyed by `.drv` path.
    pub drv_hashes: RefCell<HashMap<StorePath, Hash>>,
    pub regex_cache: RefCell<HashMap<String, Rc<regex::Regex>>>,
    depth: Cell<usize>,
}

pub struct CoerceOpts {
    /// Also coerce null, Booleans, numbers and lists (`toString`).
    pub more: bool,
    /// Copy path values to the store.
    pub copy: bool,
}

impl Eval {
    pub fn new(store: Store, opts: Options) -> Rc<Eval> {
        let (names, values) = crate::builtins::globals(&opts);
        let ev = Rc::new(Eval {
            store,
            opts,
            files: RefCell::new(Vec::new()),
            syms: Syms {
                out_path: Sym::new("outPath"),
                to_string: Sym::new("__toString"),
                functor: Sym::new("__functor"),
                ty: Sym::new("type"),
                drv_path: Sym::new("drvPath"),
                name: Sym::new("name"),
                value: Sym::new("value"),
                file: Sym::new("file"),
                line: Sym::new("line"),
                column: Sym::new("column"),
            },
            globals: names,
            base_env: OnceCell::new(),
            import_cache: RefCell::new(HashMap::new()),
            path_cache: RefCell::new(HashMap::new()),
            drvs: RefCell::new(HashMap::new()),
            drv_hashes: RefCell::new(HashMap::new()),
            regex_cache: RefCell::new(HashMap::new()),
            depth: Cell::new(0),
        });
        let _ = ev.base_env.set(Env::new(None, values));
        ev
    }

    pub fn base_env(&self) -> &Rc<Env> {
        self.base_env.get().unwrap()
    }

    pub fn global(&self, name: &str) -> Option<Value> {
        let i = self.globals.iter().position(|s| s.as_str() == name)?;
        Some(self.base_env().slot(i))
    }

    // ---- positions and errors ----

    pub fn fmt_pos(&self, pos: Pos) -> String {
        let (file, line, col) = self.pos_info(pos);
        format!("{file}:{line}:{col}")
    }

    pub fn pos_info(&self, pos: Pos) -> (String, usize, usize) {
        let files = self.files.borrow();
        let Some((name, src)) = files.get(pos.file as usize) else {
            return ("«unknown»".into(), 0, 0);
        };
        let upto = &src.as_bytes()[..(pos.offset as usize).min(src.len())];
        let line = upto.iter().filter(|&&c| c == b'\n').count() + 1;
        let col = upto.len() - upto.iter().rposition(|&c| c == b'\n').map_or(0, |p| p + 1) + 1;
        (name.clone(), line, col)
    }

    fn with_frame<T>(&self, r: R<T>, frame: impl FnOnce() -> String) -> R<T> {
        r.map_err(|mut e| {
            if e.trace.len() < MAX_TRACE {
                e.trace.push(frame());
            }
            e
        })
    }

    // ---- parsing and import ----

    pub fn parse(&self, src: &str, file_name: &str, base_dir: &str) -> R<&'static Expr> {
        let file = {
            let mut files = self.files.borrow_mut();
            files.push((file_name.to_string(), src.into()));
            (files.len() - 1) as u32
        };
        let ast = Parser::new(src, file, base_dir).parse_file().map_err(|e| {
            let pos = Pos { file, offset: e.offset as u32 };
            Box::new(EvalError { kind: ErrKind::Other, msg: format!("{}\n       at {}", e.msg, self.fmt_pos(pos)), trace: Vec::new() })
        })?;
        Compiler::new(&self.globals).compile(ast).map_err(|e| {
            Box::new(EvalError { kind: ErrKind::Other, msg: format!("{}\n       at {}", e.msg, self.fmt_pos(e.pos)), trace: Vec::new() })
        })
    }

    pub fn eval_string(&self, src: &str, base_dir: &str) -> R<Value> {
        let e = self.parse(src, "«string»", base_dir)?;
        self.eval(e, &self.base_env().clone())
    }

    pub fn import(&self, path: &str) -> R<Value> {
        let mut path = canon_path(path);
        let real = self.store.resolve(&path);
        if real.is_dir() {
            path = format!("{path}/default.nix");
        }
        if let Some(v) = self.import_cache.borrow().get(&path) {
            return Ok(v.clone());
        }
        let src = match path.strip_prefix("/__corepkgs__/").and_then(crate::builtins::corepkg) {
            Some(s) => s.to_string(),
            None => {
                let real = self.store.resolve(&path);
                std::fs::read_to_string(&real).or_else(|e| err(format!("reading '{path}': {e}")))?
            }
        };
        let dir = match path.rfind('/') {
            Some(0) => "/".to_string(),
            Some(i) => path[..i].to_string(),
            None => ".".to_string(),
        };
        let e = self.parse(&src, &path, &dir)?;
        let v = self.eval(e, &self.base_env().clone())?;
        self.import_cache.borrow_mut().insert(path, v.clone());
        Ok(v)
    }

    // ---- core evaluation ----

    /// Creates a lazy value for `e` in `env`. `filled` says whether slots
    /// of `env` itself may be read already.
    fn lazy(&self, e: &'static Expr, env: &Rc<Env>, filled: bool) -> Value {
        match e {
            Expr::Const(v) => v.clone(),
            Expr::Lambda(def) => Value::Lambda(Rc::new(Closure { def, env: env.clone() })),
            Expr::Local { up, idx } if *up > 0 || filled => lookup(env, *up).slot(*idx as usize),
            _ => Value::thunk(e, env.clone()),
        }
    }

    pub fn force(&self, v: &Value) -> R<Value> {
        match v {
            Value::Thunk(t) => self.force_thunk(t),
            v => Ok(v.clone()),
        }
    }

    fn force_thunk(&self, t: &Rc<Thunk>) -> R<Value> {
        if let Some(v) = t.peek() {
            return Ok(v);
        }
        let st = t.take();
        let r = match &st {
            ThunkState::Pending(e, env) => self.eval(e, env),
            ThunkState::App(f, x) => self.force(f).and_then(|f| self.call(&f, x.clone())),
            ThunkState::AttrApp(f, name, x) => {
                self.force(f).and_then(|f| self.call2(&f, name.as_value(), x.clone()))
            }
            ThunkState::Native(f) => f(self).and_then(|v| self.force(&v)),
            ThunkState::Blackhole => {
                return err("infinite recursion encountered");
            }
            ThunkState::Done(_) => unreachable!(),
        };
        match r {
            Ok(v) => {
                t.put(ThunkState::Done(v.clone()));
                Ok(v)
            }
            Err(e) => {
                t.put(st);
                Err(e)
            }
        }
    }

    pub fn eval(&self, e: &'static Expr, env: &Rc<Env>) -> R<Value> {
        match e {
            Expr::Const(v) => Ok(v.clone()),
            Expr::Local { up, idx } => {
                let v = lookup(env, *up).slot(*idx as usize);
                self.force(&v)
            }
            Expr::WithVar { name, pos } => {
                let mut cur = Some(env);
                while let Some(en) = cur {
                    if let EnvKind::With(attrs) = &en.kind {
                        let a = self.force_attrs(attrs)?;
                        if let Some(v) = a.get(name) {
                            return self.force(v);
                        }
                    }
                    cur = en.parent.as_ref();
                }
                err(format!("undefined variable '{name}'\n       at {}", self.fmt_pos(*pos)))
            }
            Expr::Select { e, path, default, pos } => {
                let mut v = self.eval(e, env)?;
                for k in path.iter() {
                    let k = self.key(k, env)?;
                    match &v {
                        Value::Attrs(a) => match a.get(&k) {
                            Some(x) => {
                                let x = x.clone();
                                v = self.with_frame(self.force(&x), || {
                                    format!("while evaluating the attribute '{k}' at {}", self.fmt_pos(*pos))
                                })?;
                            }
                            None => {
                                if let Some(d) = default {
                                    return self.eval(d, env);
                                }
                                return err(format!(
                                    "attribute '{k}' missing{}\n       at {}",
                                    suggest(a, &k),
                                    self.fmt_pos(*pos)
                                ));
                            }
                        },
                        _ => {
                            if let Some(d) = default {
                                return self.eval(d, env);
                            }
                            return err(format!(
                                "expected a set but found {} while selecting '{k}'\n       at {}",
                                v.describe(),
                                self.fmt_pos(*pos)
                            ));
                        }
                    }
                }
                Ok(v)
            }
            Expr::HasAttr { e, path } => {
                // Each path element is forced only when the next one is
                // looked up in it, so the value at the end of the path
                // stays lazy.
                let mut v = self.eval(e, env)?;
                for (i, k) in path.iter().enumerate() {
                    if i > 0 {
                        v = self.force(&v)?;
                    }
                    let k = self.key(k, env)?;
                    match &v {
                        Value::Attrs(a) => match a.get(&k) {
                            Some(x) => v = x.clone(),
                            None => return Ok(Value::Bool(false)),
                        },
                        _ => return Ok(Value::Bool(false)),
                    }
                }
                Ok(Value::Bool(true))
            }
            Expr::Attrs(def) => {
                let env2 = if def.new_env {
                    let n = def.slots.len();
                    let en = Env::new(Some(env.clone()), vec![Value::Null; n]);
                    for (i, s) in def.slots.iter().enumerate() {
                        let v = if def.rec { self.lazy(s, &en, false) } else { self.lazy(s, env, true) };
                        en.set(i, v);
                    }
                    en
                } else {
                    env.clone()
                };
                let mut entries: Vec<(Sym, Value)> =
                    def.statics.iter().map(|(k, e)| (k.clone(), self.lazy(e, &env2, true))).collect();
                if !def.dynamics.is_empty() {
                    for (k, v) in def.dynamics.iter() {
                        let kv = self.eval(k, &env2)?;
                        if let Value::Null = kv {
                            continue;
                        }
                        let ks = Sym::new(&self.force_str(&kv)?.s);
                        entries.push((ks, self.lazy(v, &env2, true)));
                    }
                    entries.sort_by(|a, b| a.0.cmp(&b.0));
                    if entries.windows(2).any(|w| w[0].0 == w[1].0) {
                        let d = entries.windows(2).find(|w| w[0].0 == w[1].0).unwrap()[0].0.clone();
                        return err(format!("dynamic attribute '{d}' already defined"));
                    }
                }
                Ok(Value::attrs(Attrs::from_sorted(entries)))
            }
            Expr::Let { slots, body } => {
                let en = Env::new(Some(env.clone()), vec![Value::Null; slots.len()]);
                for (i, s) in slots.iter().enumerate() {
                    en.set(i, self.lazy(s, &en, false));
                }
                self.eval(body, &en)
            }
            Expr::List(items) => Ok(Value::list(items.iter().map(|i| self.lazy(i, env, true)).collect())),
            Expr::Lambda(def) => Ok(Value::Lambda(Rc::new(Closure { def, env: env.clone() }))),
            Expr::App { f, args, pos } => {
                let mut fv = self.eval(f, env)?;
                for a in args.iter() {
                    let arg = self.lazy(a, env, true);
                    fv = self.with_frame(self.call(&fv, arg), || format!("while calling a function at {}", self.fmt_pos(*pos)))?;
                }
                Ok(fv)
            }
            Expr::With { attrs, body } => {
                let en = Rc::new(Env { parent: Some(env.clone()), kind: EnvKind::With(self.lazy(attrs, env, true)) });
                self.eval(body, &en)
            }
            Expr::If { c, t, e, pos } => {
                let cv = self.eval(c, env)?;
                match cv {
                    Value::Bool(true) => self.eval(t, env),
                    Value::Bool(false) => self.eval(e, env),
                    v => err(format!("expected a Boolean but found {} in if condition\n       at {}", v.describe(), self.fmt_pos(*pos))),
                }
            }
            Expr::Assert { c, body, pos } => match self.eval(c, env)? {
                Value::Bool(true) => self.eval(body, env),
                Value::Bool(false) => err_kind(ErrKind::Assert, format!("assertion failed\n       at {}", self.fmt_pos(*pos))),
                v => err(format!("expected a Boolean but found {} in assertion", v.describe())),
            },
            Expr::BinOp { op, l, r, pos } => self.with_frame(self.binop(*op, l, r, env), || {
                format!("while evaluating an operator at {}", self.fmt_pos(*pos))
            }),
            Expr::Not(e, _) => Ok(Value::Bool(!self.eval_bool(e, env)?)),
            Expr::Neg(e, _) => match self.eval(e, env)? {
                Value::Int(n) => n.checked_neg().map(Value::Int).ok_or(()).or_else(|_| err("integer overflow in negation")),
                Value::Float(f) => Ok(Value::Float(-f)),
                v => err(format!("cannot negate {}", v.describe())),
            },
            Expr::Concat { parts, path, pos } => {
                if *path {
                    let mut s = match self.eval(parts[0], env)? {
                        Value::Str(s) => s.s.clone(),
                        _ => unreachable!(),
                    };
                    for p in &parts[1..] {
                        let v = self.eval(p, env)?;
                        let mut ctx = Context::new();
                        s.push_str(&self.coerce_to_string(&v, &CoerceOpts { more: false, copy: false }, &mut ctx)?);
                        if !ctx.is_empty() {
                            return err(format!(
                                "a string that refers to a store path cannot be appended to a path\n       at {}",
                                self.fmt_pos(*pos)
                            ));
                        }
                    }
                    return Ok(Value::Path(canon_path(&s).into()));
                }
                let mut s = String::new();
                let mut ctx = Context::new();
                for p in parts.iter() {
                    let v = self.eval(p, env)?;
                    let part = self.with_frame(self.coerce_to_string(&v, &CoerceOpts { more: false, copy: true }, &mut ctx), || {
                        format!("while evaluating a string interpolation at {}", self.fmt_pos(*pos))
                    })?;
                    s.push_str(&part);
                }
                Ok(Value::str_ctx(s, ctx))
            }
            Expr::CurPos(pos) => Ok(self.pos_value(*pos)),
        }
    }

    pub fn pos_value(&self, pos: Pos) -> Value {
        let (file, line, col) = self.pos_info(pos);
        Value::attrs(Attrs::from_unsorted(vec![
            (self.syms.file.clone(), Value::str(file)),
            (self.syms.line.clone(), Value::Int(line as i64)),
            (self.syms.column.clone(), Value::Int(col as i64)),
        ]))
    }

    fn key(&self, k: &Key, env: &Rc<Env>) -> R<Sym> {
        match k {
            Key::Static(s) => Ok(s.clone()),
            Key::Dynamic(e) => {
                let v = self.eval(e, env)?;
                Ok(Sym::new(&self.force_str(&v)?.s))
            }
        }
    }

    fn eval_bool(&self, e: &'static Expr, env: &Rc<Env>) -> R<bool> {
        match self.eval(e, env)? {
            Value::Bool(b) => Ok(b),
            v => err(format!("expected a Boolean but found {}", v.describe())),
        }
    }

    // ---- function application ----

    pub fn call(&self, f: &Value, arg: Value) -> R<Value> {
        match f {
            Value::Lambda(c) => self.call_lambda(c, arg),
            Value::PrimOp(app) => {
                if app.args.len() + 1 == app.op.arity {
                    let mut args = Vec::with_capacity(app.op.arity);
                    args.extend(app.args.iter().cloned());
                    args.push(arg);
                    self.with_frame((app.op.f)(self, &args), || format!("while calling the '{}' builtin", app.op.name))
                } else {
                    let mut args = app.args.clone();
                    args.push(arg);
                    Ok(Value::PrimOp(Rc::new(PrimOpApp { op: app.op, args })))
                }
            }
            Value::Attrs(a) => match a.get(&self.syms.functor) {
                Some(fun) => {
                    let fun = self.force(fun)?;
                    let g = self.call(&fun, f.clone())?;
                    self.call(&g, arg)
                }
                None => err("attempt to call something which is not a function but a set"),
            },
            Value::Thunk(_) => {
                let f = self.force(f)?;
                self.call(&f, arg)
            }
            v => err(format!("attempt to call something which is not a function but {}", v.describe())),
        }
    }

    pub fn call2(&self, f: &Value, a: Value, b: Value) -> R<Value> {
        let g = self.call(f, a)?;
        self.call(&g, b)
    }

    fn fn_name(def: &LambdaDef) -> String {
        match &def.name {
            Some(n) => format!("function '{n}'"),
            None => "anonymous function".to_string(),
        }
    }

    fn call_lambda(&self, c: &Rc<Closure>, arg: Value) -> R<Value> {
        let d = self.depth.get();
        if d > MAX_CALL_DEPTH {
            return err("stack overflow; max-call-depth exceeded");
        }
        self.depth.set(d + 1);
        let r = self.call_lambda_inner(c, arg);
        self.depth.set(d);
        r
    }

    fn call_lambda_inner(&self, c: &Rc<Closure>, arg: Value) -> R<Value> {
        let def = c.def;
        let Some(formals) = &def.formals else {
            let en = Env::new(Some(c.env.clone()), vec![arg]);
            return self.eval(def.body, &en);
        };
        let attrs = match self.force(&arg)? {
            Value::Attrs(a) => a,
            v => {
                return err(format!(
                    "{} at {} called with {} but expected a set",
                    Self::fn_name(def),
                    self.fmt_pos(def.pos),
                    v.describe()
                ))
            }
        };
        let en = Env::new(Some(c.env.clone()), vec![Value::Null; def.n_slots]);
        let mut matched = 0;
        for (i, (name, default)) in formals.entries.iter().enumerate() {
            match attrs.get(name) {
                Some(v) => {
                    matched += 1;
                    en.set(i, v.clone());
                }
                None => match default {
                    Some(d) => en.set(i, self.lazy(d, &en, false)),
                    None => {
                        return err(format!(
                            "{} called without required argument '{name}'\n       at {}",
                            Self::fn_name(def),
                            self.fmt_pos(def.pos)
                        ))
                    }
                },
            }
        }
        if !formals.ellipsis && matched != attrs.len() {
            let extra = attrs.iter().find(|(k, _)| !formals.entries.iter().any(|(n, _)| n == k)).unwrap();
            return err(format!(
                "{} called with unexpected argument '{}'\n       at {}",
                Self::fn_name(def),
                extra.0,
                self.fmt_pos(def.pos)
            ));
        }
        if def.arg.is_some() {
            en.set(def.n_slots - 1, arg);
        }
        self.eval(def.body, &en)
    }

    // ---- typed forcing ----

    pub fn force_attrs(&self, v: &Value) -> R<Rc<Attrs>> {
        match self.force(v)? {
            Value::Attrs(a) => Ok(a),
            v => err(format!("expected a set but found {}", v.describe())),
        }
    }

    pub fn force_list(&self, v: &Value) -> R<Rc<Vec<Value>>> {
        match self.force(v)? {
            Value::List(l) => Ok(l),
            v => err(format!("expected a list but found {}", v.describe())),
        }
    }

    pub fn force_int(&self, v: &Value) -> R<i64> {
        match self.force(v)? {
            Value::Int(n) => Ok(n),
            v => err(format!("expected an integer but found {}", v.describe())),
        }
    }

    pub fn force_bool(&self, v: &Value) -> R<bool> {
        match self.force(v)? {
            Value::Bool(b) => Ok(b),
            v => err(format!("expected a Boolean but found {}", v.describe())),
        }
    }

    pub fn force_str(&self, v: &Value) -> R<Rc<NixStr>> {
        match self.force(v)? {
            Value::Str(s) => Ok(s),
            v => err(format!("expected a string but found {}", v.describe())),
        }
    }

    /// A string without context (attribute names, regexes, …).
    pub fn force_plain_str(&self, v: &Value) -> R<String> {
        Ok(self.force_str(v)?.s.clone())
    }

    pub fn force_fn(&self, v: &Value) -> R<Value> {
        let v = self.force(v)?;
        match &v {
            Value::Lambda(_) | Value::PrimOp(_) => Ok(v),
            Value::Attrs(a) if a.get(&self.syms.functor).is_some() => Ok(v),
            _ => err(format!("expected a function but found {}", v.describe())),
        }
    }

    /// Forces `v` and everything reachable from it.
    pub fn deep_force(&self, v: &Value) -> R<Value> {
        let v = self.force(v)?;
        let mut seen = std::collections::HashSet::new();
        self.deep_force_inner(&v, &mut seen)?;
        Ok(v)
    }

    fn deep_force_inner(&self, v: &Value, seen: &mut std::collections::HashSet<usize>) -> R<()> {
        match v {
            Value::Attrs(a) => {
                if !seen.insert(Rc::as_ptr(a) as usize) {
                    return Ok(());
                }
                for (k, x) in a.iter() {
                    let x = self.with_frame(self.force(x), || format!("while evaluating the attribute '{k}'"))?;
                    self.deep_force_inner(&x, seen)?;
                }
            }
            Value::List(l) => {
                if !seen.insert(Rc::as_ptr(l) as usize) {
                    return Ok(());
                }
                for x in l.iter() {
                    let x = self.force(x)?;
                    self.deep_force_inner(&x, seen)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn is_derivation(&self, a: &Attrs) -> R<bool> {
        match a.get(&self.syms.ty) {
            Some(t) => match self.force(t)? {
                Value::Str(s) => Ok(s.s == "derivation"),
                _ => Ok(false),
            },
            None => Ok(false),
        }
    }

    // ---- coercion ----

    pub fn coerce_to_string(&self, v: &Value, o: &CoerceOpts, ctx: &mut Context) -> R<String> {
        let v = self.force(v)?;
        match &v {
            Value::Str(s) => {
                ctx.extend(s.ctx.iter().cloned());
                Ok(s.s.clone())
            }
            Value::Path(p) => {
                if o.copy {
                    let sp = self.copy_path_to_store(p)?;
                    let s = self.store.dir.print(&sp);
                    ctx.insert(CtxElem::Opaque(s.clone()));
                    Ok(s)
                } else {
                    Ok(p.to_string())
                }
            }
            Value::Attrs(a) => {
                if let Some(f) = a.get(&self.syms.to_string) {
                    let f = self.force(f)?;
                    let r = self.call(&f, v.clone())?;
                    return self.coerce_to_string(&r, o, ctx);
                }
                if let Some(p) = a.get(&self.syms.out_path) {
                    return self.coerce_to_string(p, o, ctx);
                }
                err("cannot coerce a set to a string")
            }
            Value::Null if o.more => Ok(String::new()),
            Value::Bool(b) if o.more => Ok(if *b { "1".into() } else { String::new() }),
            Value::Int(n) if o.more => Ok(n.to_string()),
            Value::Float(f) if o.more => Ok(format!("{f:.6}")),
            Value::List(l) if o.more => {
                let mut out = String::new();
                for (i, x) in l.iter().enumerate() {
                    out.push_str(&self.coerce_to_string(x, o, ctx)?);
                    if i + 1 < l.len() {
                        let x = self.force(x)?;
                        if !matches!(&x, Value::List(l2) if l2.is_empty()) {
                            out.push(' ');
                        }
                    }
                }
                Ok(out)
            }
            v => err(format!("cannot coerce {} to a string", v.describe())),
        }
    }

    /// Coerces to a path string, requiring an absolute path.
    pub fn coerce_to_path(&self, v: &Value, ctx: &mut Context) -> R<String> {
        let s = self.coerce_to_string(v, &CoerceOpts { more: false, copy: false }, ctx)?;
        if !s.starts_with('/') {
            return err(format!("string '{s}' doesn't represent an absolute path"));
        }
        Ok(s)
    }

    pub fn copy_path_to_store(&self, p: &str) -> R<StorePath> {
        if let Some(sp) = self.path_cache.borrow().get(p) {
            return Ok(sp.clone());
        }
        let name = p.rsplit('/').next().unwrap_or("source");
        let real = self.store.resolve(p);
        let sp = self.store.add_path(&real, name, FileIngestion::Recursive, None).or_else(|e| err(format!("copying '{p}' to the store: {e}")))?;
        self.path_cache.borrow_mut().insert(p.to_string(), sp.clone());
        Ok(sp)
    }

    // ---- operators ----

    fn binop(&self, op: BinOp, l: &'static Expr, r: &'static Expr, env: &Rc<Env>) -> R<Value> {
        match op {
            BinOp::And => return Ok(Value::Bool(self.eval_bool(l, env)? && self.eval_bool(r, env)?)),
            BinOp::Or => return Ok(Value::Bool(self.eval_bool(l, env)? || self.eval_bool(r, env)?)),
            BinOp::Impl => return Ok(Value::Bool(!self.eval_bool(l, env)? || self.eval_bool(r, env)?)),
            _ => {}
        }
        let a = self.eval(l, env)?;
        let b = self.eval(r, env)?;
        match op {
            BinOp::Eq => Ok(Value::Bool(self.eq(&a, &b)?)),
            BinOp::Neq => Ok(Value::Bool(!self.eq(&a, &b)?)),
            BinOp::Lt => Ok(Value::Bool(self.compare(&a, &b)? == Ordering::Less)),
            BinOp::Gt => Ok(Value::Bool(self.compare(&b, &a)? == Ordering::Less)),
            BinOp::Le => Ok(Value::Bool(self.compare(&b, &a)? != Ordering::Less)),
            BinOp::Ge => Ok(Value::Bool(self.compare(&a, &b)? != Ordering::Less)),
            BinOp::Update => {
                let x = self.as_attrs(&a)?;
                let y = self.as_attrs(&b)?;
                Ok(Value::Attrs(Attrs::update(&x, &y)))
            }
            BinOp::Concat => {
                let x = self.as_list(&a)?;
                let y = self.as_list(&b)?;
                if x.is_empty() {
                    return Ok(Value::List(y));
                }
                if y.is_empty() {
                    return Ok(Value::List(x));
                }
                let mut v = Vec::with_capacity(x.len() + y.len());
                v.extend(x.iter().cloned());
                v.extend(y.iter().cloned());
                Ok(Value::list(v))
            }
            BinOp::Add => self.add(&a, &b),
            BinOp::Sub | BinOp::Mul | BinOp::Div => self.arith(op, &a, &b),
            _ => unreachable!(),
        }
    }

    fn as_attrs(&self, v: &Value) -> R<Rc<Attrs>> {
        match v {
            Value::Attrs(a) => Ok(a.clone()),
            v => err(format!("expected a set but found {}", v.describe())),
        }
    }

    fn as_list(&self, v: &Value) -> R<Rc<Vec<Value>>> {
        match v {
            Value::List(l) => Ok(l.clone()),
            v => err(format!("expected a list but found {}", v.describe())),
        }
    }

    pub fn add(&self, a: &Value, b: &Value) -> R<Value> {
        match (a, b) {
            (Value::Int(_) | Value::Float(_), _) => self.arith(BinOp::Add, a, b),
            (Value::Path(p), _) => {
                let mut ctx = Context::new();
                let s = self.coerce_to_string(b, &CoerceOpts { more: false, copy: false }, &mut ctx)?;
                if !ctx.is_empty() {
                    return err("a string that refers to a store path cannot be appended to a path");
                }
                Ok(Value::Path(canon_path(&format!("{p}{s}")).into()))
            }
            _ => {
                let mut ctx = Context::new();
                let o = CoerceOpts { more: false, copy: true };
                let mut s = self.coerce_to_string(a, &o, &mut ctx)?;
                s.push_str(&self.coerce_to_string(b, &o, &mut ctx)?);
                Ok(Value::str_ctx(s, ctx))
            }
        }
    }

    pub fn arith(&self, op: BinOp, a: &Value, b: &Value) -> R<Value> {
        let name = match op {
            BinOp::Add => "add",
            BinOp::Sub => "subtract",
            BinOp::Mul => "multiply",
            _ => "divide",
        };
        match (a, b) {
            (Value::Int(x), Value::Int(y)) => {
                let r = match op {
                    BinOp::Add => x.checked_add(*y),
                    BinOp::Sub => x.checked_sub(*y),
                    BinOp::Mul => x.checked_mul(*y),
                    _ => {
                        if *y == 0 {
                            return err("division by zero");
                        }
                        x.checked_div(*y)
                    }
                };
                r.map(Value::Int).ok_or(()).or_else(|_| err(format!("integer overflow in {name}ing {x} and {y}")))
            }
            (Value::Int(_) | Value::Float(_), Value::Int(_) | Value::Float(_)) => {
                let x = num(a);
                let y = num(b);
                Ok(Value::Float(match op {
                    BinOp::Add => x + y,
                    BinOp::Sub => x - y,
                    BinOp::Mul => x * y,
                    _ => {
                        if y == 0.0 {
                            return err("division by zero");
                        }
                        x / y
                    }
                }))
            }
            (Value::Int(_) | Value::Float(_), _) => err(format!("cannot {name} {} and {}", a.describe(), b.describe())),
            _ => err(format!("expected an integer but found {}", a.describe())),
        }
    }

    pub fn eq(&self, a: &Value, b: &Value) -> R<bool> {
        let a = self.force(a)?;
        let b = self.force(b)?;
        Ok(match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => x == y,
            (Value::Int(_) | Value::Float(_), Value::Int(_) | Value::Float(_)) => num(&a) == num(&b),
            (Value::Bool(x), Value::Bool(y)) => x == y,
            (Value::Null, Value::Null) => true,
            (Value::Str(x), Value::Str(y)) => x.s == y.s,
            (Value::Path(x), Value::Path(y)) => x == y,
            (Value::List(x), Value::List(y)) => {
                if Rc::ptr_eq(x, y) {
                    return Ok(true);
                }
                if x.len() != y.len() {
                    return Ok(false);
                }
                for (p, q) in x.iter().zip(y.iter()) {
                    if !self.eq(p, q)? {
                        return Ok(false);
                    }
                }
                true
            }
            (Value::Attrs(x), Value::Attrs(y)) => {
                if Rc::ptr_eq(x, y) {
                    return Ok(true);
                }
                if self.is_derivation(x)? && self.is_derivation(y)? {
                    if let (Some(p), Some(q)) = (x.get(&self.syms.out_path), y.get(&self.syms.out_path)) {
                        return self.eq(p, q);
                    }
                }
                if x.len() != y.len() {
                    return Ok(false);
                }
                // Walk one side in key order and probe the other, so layered
                // sets are compared without caching a merged copy.
                for (k, v1) in x.entries_uncached().iter() {
                    match y.get(k) {
                        Some(v2) if self.eq(v1, v2)? => {}
                        _ => return Ok(false),
                    }
                }
                true
            }
            _ => false,
        })
    }

    pub fn compare(&self, a: &Value, b: &Value) -> R<Ordering> {
        let a = self.force(a)?;
        let b = self.force(b)?;
        match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => Ok(x.cmp(y)),
            (Value::Int(_) | Value::Float(_), Value::Int(_) | Value::Float(_)) => {
                Ok(num(&a).partial_cmp(&num(&b)).unwrap_or(Ordering::Equal))
            }
            (Value::Str(x), Value::Str(y)) => Ok(x.s.as_bytes().cmp(y.s.as_bytes())),
            (Value::Path(x), Value::Path(y)) => Ok(x.as_bytes().cmp(y.as_bytes())),
            (Value::List(x), Value::List(y)) => {
                for (p, q) in x.iter().zip(y.iter()) {
                    if self.eq(p, q)? {
                        continue;
                    }
                    return self.compare(p, q);
                }
                Ok(x.len().cmp(&y.len()))
            }
            _ => err(format!("cannot compare {} with {}", a.describe(), b.describe())),
        }
    }
}

fn num(v: &Value) -> f64 {
    match v {
        Value::Int(n) => *n as f64,
        Value::Float(f) => *f,
        _ => 0.0,
    }
}

fn lookup(env: &Rc<Env>, up: u32) -> &Rc<Env> {
    let mut e = env;
    for _ in 0..up {
        e = e.parent.as_ref().expect("environment depth mismatch");
    }
    e
}

fn suggest(a: &Attrs, k: &Sym) -> String {
    let close: Vec<&str> = a
        .iter()
        .map(|(s, _)| s.as_str())
        .filter(|s| levenshtein(s, k.as_str()) <= 2)
        .take(3)
        .collect();
    if close.is_empty() {
        String::new()
    } else {
        format!("; did you mean {}?", close.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", "))
    }
}

fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push((prev[j] + (ca != *cb) as usize).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}
