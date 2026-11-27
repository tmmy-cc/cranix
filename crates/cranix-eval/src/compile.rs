//! Lowers the syntax tree to an executable form in which every statically
//! bound variable is a (depth, slot) pair. Only names that can only be
//! resolved through `with` are looked up by name at run time.
//!
//! Compiled expressions are leaked: they live as long as the evaluator,
//! which lets thunks refer to them with a plain `&'static` pointer.

use std::collections::{BTreeMap, HashMap};

use crate::ast::{self, AttrName, Ast, BinOp, Binding, Pos, StrPart};
use crate::value::{Sym, Value};

pub enum Key {
    Static(Sym),
    Dynamic(&'static Expr),
}

pub struct FormalsDef {
    pub entries: Box<[(Sym, Option<&'static Expr>)]>,
    pub ellipsis: bool,
    /// Where each argument is named, sorted by name.
    pub positions: crate::value::PosTable,
}

pub struct LambdaDef {
    pub name: Option<Sym>,
    pub arg: Option<Sym>,
    pub formals: Option<FormalsDef>,
    pub n_slots: usize,
    pub body: &'static Expr,
    pub pos: Pos,
}

pub struct AttrsDef {
    /// Slots of the environment the attribute values are evaluated in.
    /// Recursive sets put every binding here; non-recursive sets only the
    /// sources of `inherit (expr)`. Empty means no new environment.
    pub slots: Box<[&'static Expr]>,
    pub new_env: bool,
    /// Slot expressions are evaluated in the new environment itself.
    pub rec: bool,
    pub statics: Box<[(Sym, &'static Expr)]>,
    pub dynamics: Box<[(&'static Expr, &'static Expr)]>,
    /// Where each static attribute is defined, sorted by name.
    pub positions: crate::value::PosTable,
}

pub enum Expr {
    Const(Value),
    Local { up: u32, idx: u32 },
    WithVar { name: Sym, pos: Pos },
    Select { e: &'static Expr, path: Box<[Key]>, default: Option<&'static Expr>, pos: Pos },
    HasAttr { e: &'static Expr, path: Box<[Key]> },
    Attrs(AttrsDef),
    Let { slots: Box<[&'static Expr]>, body: &'static Expr },
    List(Box<[&'static Expr]>),
    Lambda(&'static LambdaDef),
    App { f: &'static Expr, args: Box<[&'static Expr]>, pos: Pos },
    With { attrs: &'static Expr, body: &'static Expr },
    If { c: &'static Expr, t: &'static Expr, e: &'static Expr, pos: Pos },
    Assert { c: &'static Expr, body: &'static Expr, pos: Pos },
    BinOp { op: BinOp, l: &'static Expr, r: &'static Expr, pos: Pos },
    Not(&'static Expr, Pos),
    Neg(&'static Expr, Pos),
    Concat { parts: Box<[&'static Expr]>, path: bool, pos: Pos },
    CurPos(Pos),
    /// The expression run as bytecode, compiled on first use.
    Code(&'static crate::vm::Code),
}

fn leak<T>(t: T) -> &'static T {
    Box::leak(Box::new(t))
}

struct Scope {
    names: HashMap<Sym, u32>,
    with: bool,
}

pub struct Compiler {
    scopes: Vec<Scope>,
}

pub struct CompileError {
    pub pos: Pos,
    pub msg: String,
    /// An earlier definition the error refers to.
    pub prev: Option<Pos>,
    pub hint: Option<String>,
}

impl CompileError {
    fn new(pos: Pos, msg: impl Into<String>) -> CompileError {
        CompileError { pos, msg: msg.into(), prev: None, hint: None }
    }
}

type R<T> = Result<T, CompileError>;

enum Node {
    Leaf(Ast, Pos),
    Inherit(Sym, Pos),
    InheritFrom(usize, Sym, Pos),
    Nested(Tree, Pos),
}

/// A sorted position table, leaked like the rest of the compiled code.
fn pos_table(mut v: Vec<(Sym, Pos)>) -> crate::value::PosTable {
    v.sort_by(|a, b| a.0.cmp(&b.0));
    Box::leak(v.into_boxed_slice())
}

#[derive(Default)]
struct Tree {
    statics: BTreeMap<Sym, Node>,
    dynamics: Vec<(Ast, Node)>,
    sources: Vec<Ast>,
    /// A `rec` set that later definitions of the same name merge into.
    rec: bool,
}

fn dup(name: &Sym, pos: Pos, prev: Option<&Node>) -> CompileError {
    let mut e = CompileError::new(pos, format!("attribute '{name}' already defined"));
    e.prev = prev.map(Node::pos);
    e
}

impl Node {
    fn pos(&self) -> Pos {
        match self {
            Node::Leaf(_, p) | Node::Inherit(_, p) | Node::InheritFrom(_, _, p) | Node::Nested(_, p) => *p,
        }
    }
}

impl Tree {
    fn from_bindings(bindings: Vec<Binding>) -> R<Tree> {
        let mut t = Tree::default();
        for b in bindings {
            t.add(b)?;
        }
        Ok(t)
    }

    fn add(&mut self, b: Binding) -> R<()> {
        match b {
            Binding::Inherit(from, names) => {
                let src = from.map(|f| {
                    self.sources.push(f);
                    self.sources.len() - 1
                });
                for (n, pos) in names {
                    if let Some(prev) = self.statics.get(&n) {
                        return Err(dup(&n, pos, Some(prev)));
                    }
                    let node = match src {
                        Some(i) => Node::InheritFrom(i, n.clone(), pos),
                        None => Node::Inherit(n.clone(), pos),
                    };
                    self.statics.insert(n, node);
                }
                Ok(())
            }
            Binding::Attr(mut path, value, pos) => {
                let first = path.remove(0);
                let node = if path.is_empty() {
                    Node::Leaf(value, pos)
                } else {
                    let mut sub = Tree::default();
                    sub.add(Binding::Attr(path, value, pos))?;
                    Node::Nested(sub, pos)
                };
                match first {
                    AttrName::Dynamic(e) => {
                        self.dynamics.push((e, node));
                        Ok(())
                    }
                    AttrName::Static(name) => self.insert(name, node, pos),
                }
            }
        }
    }

    fn insert(&mut self, name: Sym, node: Node, pos: Pos) -> R<()> {
        let Some(existing) = self.statics.remove(&name) else {
            self.statics.insert(name, node);
            return Ok(());
        };
        // `a.b = 1; a.c = 2;` and `a = { b = 1; }; a.c = 2;` merge.
        let prev_pos = existing.pos();
        let mut merged = match existing {
            Node::Nested(t, p) => (t, p),
            // A recursive set stays recursive, and what merges into it can
            // refer to its attributes.
            Node::Leaf(Ast::Attrs { rec, bindings, .. }, p) => {
                let mut t = Tree::from_bindings(bindings)?;
                t.rec = rec;
                (t, p)
            }
            e => return Err(dup(&name, pos, Some(&e))),
        };
        let incoming = match node {
            Node::Nested(t, _) => t,
            Node::Leaf(Ast::Attrs { rec: false, bindings, .. }, _) => Tree::from_bindings(bindings)?,
            _ => {
                let mut e = dup(&name, pos, None);
                e.prev = Some(prev_pos);
                return Err(e);
            }
        };
        merged.0.merge(incoming)?;
        self.statics.insert(name, Node::Nested(merged.0, merged.1));
        Ok(())
    }

    fn merge(&mut self, other: Tree) -> R<()> {
        let offset = self.sources.len();
        self.sources.extend(other.sources);
        for (k, v) in other.statics {
            let v = match v {
                Node::InheritFrom(i, n, p) => Node::InheritFrom(i + offset, n, p),
                v => v,
            };
            let pos = v.pos();
            self.insert(k, v, pos)?;
        }
        self.dynamics.extend(other.dynamics);
        Ok(())
    }
}

impl Compiler {
    /// `globals` are the names in the base environment, in slot order.
    pub fn new(globals: &[Sym]) -> Compiler {
        let names = globals.iter().enumerate().map(|(i, s)| (s.clone(), i as u32)).collect();
        Compiler { scopes: vec![Scope { names, with: false }] }
    }

    pub fn compile(&mut self, ast: Ast) -> R<&'static Expr> {
        self.expr(ast, None)
    }

    /// Adds a scope of `names` in front of the globals, in slot order, as
    /// `scopedImport` does with the attributes it is given.
    pub fn with_scope(mut self, names: impl IntoIterator<Item = Sym>) -> Compiler {
        self.push(names);
        self
    }

    fn resolve(&self, name: &Sym, skip: usize, pos: Pos) -> R<Expr> {
        let mut has_with = false;
        for (depth, s) in self.scopes.iter().rev().enumerate().skip(skip) {
            if s.with {
                has_with = true;
                continue;
            }
            if let Some(&idx) = s.names.get(name) {
                return Ok(Expr::Local { up: depth as u32, idx });
            }
        }
        if has_with {
            Ok(Expr::WithVar { name: name.clone(), pos })
        } else {
            let mut e = CompileError::new(pos, format!("undefined variable '{name}'"));
            let names = self.scopes.iter().flat_map(|s| s.names.keys()).map(Sym::as_str).filter(|n| !n.starts_with("__"));
            e.hint = crate::error::did_you_mean(name.as_str(), names);
            Err(e)
        }
    }

    fn push(&mut self, names: impl IntoIterator<Item = Sym>) {
        let names = names.into_iter().enumerate().map(|(i, s)| (s, i as u32)).collect();
        self.scopes.push(Scope { names, with: false });
    }

    fn pop(&mut self) {
        self.scopes.pop();
    }

    fn keys(&mut self, path: Vec<AttrName>) -> R<Box<[Key]>> {
        path.into_iter()
            .map(|k| {
                Ok(match k {
                    AttrName::Static(s) => Key::Static(s),
                    AttrName::Dynamic(e) => Key::Dynamic(self.expr(e, None)?),
                })
            })
            .collect()
    }

    fn concat(&mut self, parts: Vec<StrPart>, path: bool, pos: Pos) -> R<&'static Expr> {
        if !path {
            if parts.is_empty() {
                return Ok(leak(Expr::Const(Value::str(""))));
            }
            if let [StrPart::Lit(_)] = parts.as_slice() {
                let Some(StrPart::Lit(s)) = parts.into_iter().next() else { unreachable!() };
                return Ok(leak(Expr::Const(Value::str(s))));
            }
        }
        let parts = parts
            .into_iter()
            .map(|p| match p {
                StrPart::Lit(s) => Ok(&*leak(Expr::Const(Value::str(s)))),
                StrPart::Interp(e) => self.expr(e, None),
            })
            .collect::<R<_>>()?;
        Ok(leak(Expr::Concat { parts, path, pos }))
    }

    fn expr(&mut self, ast: Ast, name: Option<&Sym>) -> R<&'static Expr> {
        Ok(match ast {
            Ast::Int(n) => leak(Expr::Const(Value::Int(n))),
            Ast::Float(f) => leak(Expr::Const(Value::Float(f))),
            Ast::Str(parts, pos) => self.concat(parts, false, pos)?,
            Ast::Path(p) => leak(Expr::Const(Value::Path(p.into()))),
            Ast::PathInterp(parts, pos) => self.concat(parts, true, pos)?,
            Ast::SearchPath(p, pos) => {
                let f = leak(self.resolve(&Sym::new("__findFile"), 0, pos)?);
                let np = leak(self.resolve(&Sym::new("__nixPath"), 0, pos)?);
                let s = leak(Expr::Const(Value::str(p)));
                leak(Expr::App { f, args: Box::new([np, s]), pos })
            }
            Ast::Var(n, pos) => leak(self.resolve(&n, 0, pos)?),
            Ast::CurPos(pos) => leak(Expr::CurPos(pos)),
            Ast::Select(e, path, def, pos) => {
                let e = self.expr(*e, None)?;
                let path = self.keys(path)?;
                let default = match def {
                    Some(d) => Some(self.expr(*d, None)?),
                    None => None,
                };
                leak(Expr::Select { e, path, default, pos })
            }
            Ast::HasAttr(e, path) => {
                let e = self.expr(*e, None)?;
                let path = self.keys(path)?;
                leak(Expr::HasAttr { e, path })
            }
            Ast::Attrs { rec, bindings, pos: _ } => {
                let tree = Tree::from_bindings(bindings)?;
                if rec {
                    self.rec_attrs(tree)?
                } else {
                    self.attrs(tree)?
                }
            }
            Ast::List(items) => {
                let items = items.into_iter().map(|i| self.expr(i, None)).collect::<R<_>>()?;
                leak(Expr::List(items))
            }
            Ast::Lambda { arg, formals, body, pos } => {
                let mut names: Vec<Sym> = Vec::new();
                if let Some(f) = &formals {
                    names.extend(f.entries.iter().map(|(s, _)| s.clone()));
                }
                if let Some(a) = &arg {
                    names.push(a.clone());
                }
                let n_slots = names.len();
                self.push(names);
                let formals = match formals {
                    Some(ast::Formals { entries, ellipsis, positions }) => {
                        let positions = pos_table(entries.iter().map(|(k, _)| k.clone()).zip(positions).collect());
                        let entries = entries
                            .into_iter()
                            .map(|(s, d)| Ok((s, d.map(|d| self.expr(d, None)).transpose()?)))
                            .collect::<R<_>>()?;
                        Some(FormalsDef { entries, ellipsis, positions })
                    }
                    None => None,
                };
                let body = self.expr(*body, None);
                self.pop();
                let def = leak(LambdaDef { name: name.cloned(), arg, formals, n_slots, body: body?, pos });
                leak(Expr::Lambda(def))
            }
            Ast::App(f, args, pos) => {
                let f = self.expr(*f, None)?;
                let args = args.into_iter().map(|a| self.expr(a, None)).collect::<R<_>>()?;
                leak(Expr::App { f, args, pos })
            }
            Ast::Let(bindings, body, pos) => {
                let tree = Tree::from_bindings(bindings)?;
                if !tree.dynamics.is_empty() {
                    return Err(CompileError::new(pos, "dynamic attributes not allowed in let"));
                }
                let (slots, _statics) = self.rec_scope(tree)?;
                let body = self.expr(*body, None);
                self.pop();
                leak(Expr::Let { slots, body: body? })
            }
            Ast::LegacyLet(bindings, pos) => {
                // `let { a = 1; body = a; }` evaluates to the `body` attribute.
                let tree = Tree::from_bindings(bindings)?;
                let attrs = self.rec_attrs(tree)?;
                leak(Expr::Select { e: attrs, path: Box::new([Key::Static(Sym::new("body"))]), default: None, pos })
            }
            Ast::With(a, body, _) => {
                let attrs = self.expr(*a, None)?;
                self.scopes.push(Scope { names: HashMap::new(), with: true });
                let body = self.expr(*body, None);
                self.pop();
                leak(Expr::With { attrs, body: body? })
            }
            Ast::If(c, t, e, pos) => {
                let c = self.expr(*c, None)?;
                let t = self.expr(*t, None)?;
                let e = self.expr(*e, None)?;
                leak(Expr::If { c, t, e, pos })
            }
            Ast::Assert(c, b, pos) => {
                let c = self.expr(*c, None)?;
                let body = self.expr(*b, None)?;
                leak(Expr::Assert { c, body, pos })
            }
            Ast::BinOp(op, l, r, pos) => {
                let l = self.expr(*l, None)?;
                let r = self.expr(*r, None)?;
                leak(Expr::BinOp { op, l, r, pos })
            }
            Ast::Not(e, pos) => leak(Expr::Not(self.expr(*e, None)?, pos)),
            Ast::Neg(e, pos) => leak(Expr::Neg(self.expr(*e, None)?, pos)),
        })
    }

    /// Value expression of a node inside a set whose own scope is on top of
    /// the stack. `inherit x` looks past that scope.
    fn node(&mut self, name: &Sym, node: Node, sources_base: Option<u32>) -> R<&'static Expr> {
        Ok(match node {
            Node::Leaf(ast, _) => self.expr(ast, Some(name))?,
            Node::Inherit(n, pos) => leak(self.resolve(&n, 1, pos)?),
            Node::InheritFrom(i, n, pos) => {
                let base = sources_base.expect("inherit source without environment");
                let src = leak(Expr::Local { up: 0, idx: base + i as u32 });
                leak(Expr::Select { e: src, path: Box::new([Key::Static(n)]), default: None, pos })
            }
            Node::Nested(tree, _) if tree.rec => self.rec_attrs(tree)?,
            Node::Nested(tree, _) => self.attrs(tree)?,
        })
    }

    fn attrs(&mut self, tree: Tree) -> R<&'static Expr> {
        let new_env = !tree.sources.is_empty();
        let mut slots = Vec::new();
        if new_env {
            // Sources are evaluated in the enclosing scope.
            for s in tree.sources {
                slots.push(self.expr(s, None)?);
            }
            self.push([]);
        }
        let result = (|| {
            let mut statics = Vec::new();
            let positions = pos_table(tree.statics.iter().map(|(k, v)| (k.clone(), v.pos())).collect());
            for (k, v) in tree.statics {
                let v = match v {
                    // Without a new scope `inherit x` resolves right here.
                    Node::Inherit(n, pos) if !new_env => leak(self.resolve(&n, 0, pos)?),
                    v => self.node(&k, v, Some(0))?,
                };
                statics.push((k, v));
            }
            let mut dynamics = Vec::new();
            for (k, v) in tree.dynamics {
                let k = self.expr(k, None)?;
                let v = self.node(&Sym::new("<dynamic>"), v, Some(0))?;
                dynamics.push((k, v));
            }
            Ok(leak(Expr::Attrs(AttrsDef {
                slots: slots.into_boxed_slice(),
                new_env,
                rec: false,
                statics: statics.into_boxed_slice(),
                dynamics: dynamics.into_boxed_slice(),
                positions,
            })))
        })();
        if new_env {
            self.pop();
        }
        result
    }

    /// Pushes a recursive scope holding the tree's bindings followed by its
    /// inherit sources and compiles them. The caller pops the scope.
    fn rec_scope(&mut self, tree: Tree) -> R<(Box<[&'static Expr]>, Vec<Sym>)> {
        let names: Vec<Sym> = tree.statics.keys().cloned().collect();
        let n = names.len() as u32;
        self.push(names.clone());
        let mut slots = Vec::new();
        for (k, v) in tree.statics {
            slots.push(self.node(&k, v, Some(n))?);
        }
        for s in tree.sources {
            slots.push(self.expr(s, None)?);
        }
        Ok((slots.into_boxed_slice(), names))
    }

    fn rec_attrs(&mut self, tree: Tree) -> R<&'static Expr> {
        let Tree { statics, dynamics: dyn_asts, sources, .. } = tree;
        let positions = pos_table(statics.iter().map(|(k, v)| (k.clone(), v.pos())).collect());
        let (slots, names) = self.rec_scope(Tree { statics, dynamics: Vec::new(), sources, rec: true })?;
        let result = (|| {
            let statics = names
                .into_iter()
                .enumerate()
                .map(|(i, k)| (k, &*leak(Expr::Local { up: 0, idx: i as u32 })))
                .collect();
            let mut dynamics = Vec::new();
            for (k, v) in dyn_asts {
                let k = self.expr(k, None)?;
                let v = self.node(&Sym::new("<dynamic>"), v, None)?;
                dynamics.push((k, v));
            }
            Ok(leak(Expr::Attrs(AttrsDef { slots, new_env: true, rec: true, statics, dynamics: dynamics.into_boxed_slice(), positions })))
        })();
        self.pop();
        result
    }
}
