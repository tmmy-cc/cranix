//! Bytecode for the resolved IR and the VM that runs it.
//!
//! [`lower`] wraps an expression the evaluator starts from (a file, a lambda
//! body, the value of a thunk) in an [`Expr::Code`] node. The first time the
//! node runs, its expression is compiled into a [`Chunk`]: a flat sequence of
//! [`Op`]s that evaluates it strictly on a value stack. The sub-expressions
//! that stay lazy (arguments, attribute values, `let` bindings, list items)
//! are wrapped the same way and referenced from the ops, so forcing their
//! thunks compiles and runs their own chunks.
//!
//! The ops reuse the tree walker's operations, which keeps results, error
//! messages and traces identical. Error frames and positions that the tree
//! walker adds around a whole sub-expression are recorded as regions over
//! the ops of that sub-expression and applied when an error leaves one.
//! Constants, local variables and lambdas in lazy positions stay plain
//! nodes, so they need no thunk.

use std::cell::OnceCell;
use std::rc::Rc;

use smallvec::SmallVec;

use crate::ast::{BinOp, Pos};
use crate::compile::{AttrsDef, Expr, FormalsDef, Key, LambdaDef};
use crate::eval::{Eval, R};
use crate::value::{Context, Env, Value};

pub enum Op {
    Const(Value),
    Local { up: u32, idx: u32 },
    /// Evaluates the expression with the tree walker.
    Tree(&'static Expr),
    Select { path: &'static [Key], default: Option<&'static Expr>, pos: Pos },
    HasAttr(&'static [Key]),
    Attrs(&'static AttrsDef),
    List(&'static [&'static Expr]),
    Closure(&'static LambdaDef),
    /// Applies the function on the stack to a lazy argument.
    Call { arg: &'static Expr, pos: Pos },
    PushLet(&'static [&'static Expr]),
    PushWith(&'static Expr),
    PopEnv,
    Jump(u32),
    /// Pops the condition of an `if`; jumps when it is false.
    Branch { target: u32, pos: Pos },
    Assert(Pos),
    /// Checks the Boolean operand of `&&`, `||` or `->`.
    BoolOperand { right: bool, op: BinOp, pos: Pos },
    /// Pops a Boolean; when it equals `when`, pushes `result` and jumps.
    ShortCircuit { when: bool, result: bool, target: u32 },
    BinOp(BinOp),
    Not(Pos),
    Neg(Pos),
    StrStart,
    StrPart(Pos),
    StrEnd,
    /// Starts an interpolated path with the string on the stack.
    PathStart,
    PathPart(Pos),
    PathEnd,
}

enum RegionKind {
    Locate(Pos),
    Cond(Pos),
    Assert(Pos),
}

struct Region {
    start: u32,
    end: u32,
    kind: RegionKind,
}

/// An expression and, once it has run, its chunk.
pub struct Code {
    src: &'static Expr,
    chunk: OnceCell<&'static Chunk>,
}

impl Code {
    fn chunk(&self) -> &'static Chunk {
        self.chunk.get_or_init(|| {
            let mut b = Builder { ops: Vec::new(), regions: Vec::new() };
            b.gen(self.src);
            b.regions.sort_by_key(|r| (r.end, std::cmp::Reverse(r.start)));
            leak(Chunk { ops: b.ops.into_boxed_slice(), regions: b.regions.into_boxed_slice() })
        })
    }
}

pub struct Chunk {
    ops: Box<[Op]>,
    /// Ordered by end, so inner regions come before the regions around them.
    regions: Box<[Region]>,
}

fn leak<T>(t: T) -> &'static T {
    Box::leak(Box::new(t))
}

fn leak_slice<T>(v: Vec<T>) -> &'static [T] {
    Box::leak(v.into_boxed_slice())
}

/// Rewrites `e`, an expression the evaluator starts from, into a chunk.
pub fn lower(e: &'static Expr) -> &'static Expr {
    match e {
        Expr::Const(_) | Expr::Local { .. } | Expr::Code(_) => e,
        Expr::Lambda(def) => leak(Expr::Lambda(lower_lambda(def))),
        _ => leak(Expr::Code(leak(Code { src: e, chunk: OnceCell::new() }))),
    }
}

fn lower_all(es: &[&'static Expr]) -> &'static [&'static Expr] {
    leak_slice(es.iter().map(|e| lower(e)).collect())
}

fn lower_lambda(def: &'static LambdaDef) -> &'static LambdaDef {
    let formals = def.formals.as_ref().map(|f| FormalsDef {
        entries: f.entries.iter().map(|(n, d)| (n.clone(), d.map(lower))).collect(),
        ellipsis: f.ellipsis,
        positions: f.positions,
    });
    leak(LambdaDef { name: def.name.clone(), arg: def.arg.clone(), formals, n_slots: def.n_slots, body: lower(def.body), pos: def.pos })
}

fn lower_keys(path: &[Key]) -> &'static [Key] {
    leak_slice(
        path.iter()
            .map(|k| match k {
                Key::Static(s) => Key::Static(s.clone()),
                Key::Dynamic(e) => Key::Dynamic(lower(e)),
            })
            .collect(),
    )
}

struct Builder {
    ops: Vec<Op>,
    regions: Vec<Region>,
}

impl Builder {
    fn here(&self) -> u32 {
        self.ops.len() as u32
    }

    fn region(&mut self, start: u32, kind: RegionKind) {
        self.regions.push(Region { start, end: self.here(), kind });
    }

    fn patch(&mut self, at: u32) {
        let to = self.here();
        match &mut self.ops[at as usize] {
            Op::Jump(t) | Op::Branch { target: t, .. } | Op::ShortCircuit { target: t, .. } => *t = to,
            _ => unreachable!(),
        }
    }

    /// Emits the ops that evaluate `e` strictly and push its value.
    fn gen(&mut self, e: &'static Expr) {
        match e {
            Expr::Const(v) => self.ops.push(Op::Const(v.clone())),
            Expr::Local { up, idx } => self.ops.push(Op::Local { up: *up, idx: *idx }),
            Expr::WithVar { .. } | Expr::CurPos(_) | Expr::Code(_) => self.ops.push(Op::Tree(e)),
            Expr::Select { e, path, default, pos } => {
                self.gen(e);
                self.ops.push(Op::Select { path: lower_keys(path), default: default.map(lower), pos: *pos });
            }
            Expr::HasAttr { e, path } => {
                self.gen(e);
                self.ops.push(Op::HasAttr(lower_keys(path)));
            }
            Expr::Attrs(def) => {
                let def = AttrsDef {
                    slots: lower_all(&def.slots).into(),
                    new_env: def.new_env,
                    rec: def.rec,
                    statics: def.statics.iter().map(|(k, e)| (k.clone(), lower(e))).collect(),
                    dynamics: def.dynamics.iter().map(|(k, v)| (lower(k), lower(v))).collect(),
                    positions: def.positions,
                };
                self.ops.push(Op::Attrs(leak(def)));
            }
            Expr::Let { slots, body } => {
                self.ops.push(Op::PushLet(lower_all(slots)));
                self.gen(body);
                self.ops.push(Op::PopEnv);
            }
            Expr::List(items) => self.ops.push(Op::List(lower_all(items))),
            Expr::Lambda(def) => self.ops.push(Op::Closure(lower_lambda(def))),
            Expr::App { f, args, pos } => {
                self.gen(f);
                for a in args.iter() {
                    self.ops.push(Op::Call { arg: lower(a), pos: *pos });
                }
            }
            Expr::With { attrs, body } => {
                self.ops.push(Op::PushWith(lower(attrs)));
                self.gen(body);
                self.ops.push(Op::PopEnv);
            }
            Expr::If { c, t, e, pos } => {
                let start = self.here();
                self.gen(c);
                self.region(start, RegionKind::Cond(*pos));
                let branch = self.here();
                self.ops.push(Op::Branch { target: 0, pos: *pos });
                self.gen(t);
                let jump = self.here();
                self.ops.push(Op::Jump(0));
                self.patch(branch);
                self.gen(e);
                self.patch(jump);
            }
            Expr::Assert { c, body, pos } => {
                let start = self.here();
                self.gen(c);
                self.region(start, RegionKind::Assert(*pos));
                self.ops.push(Op::Assert(*pos));
                self.gen(body);
            }
            Expr::BinOp { op, l, r, pos } => {
                let start = self.here();
                match op {
                    BinOp::And | BinOp::Or | BinOp::Impl => {
                        let (when, result) = match op {
                            BinOp::And => (false, false),
                            BinOp::Or => (true, true),
                            _ => (false, true),
                        };
                        self.gen(l);
                        self.ops.push(Op::BoolOperand { right: false, op: *op, pos: *pos });
                        let sc = self.here();
                        self.ops.push(Op::ShortCircuit { when, result, target: 0 });
                        self.gen(r);
                        self.ops.push(Op::BoolOperand { right: true, op: *op, pos: *pos });
                        self.patch(sc);
                    }
                    _ => {
                        self.gen(l);
                        self.gen(r);
                        self.ops.push(Op::BinOp(*op));
                    }
                }
                self.region(start, RegionKind::Locate(*pos));
            }
            Expr::Not(e, pos) => {
                self.gen(e);
                self.ops.push(Op::Not(*pos));
            }
            Expr::Neg(e, pos) => {
                self.gen(e);
                self.ops.push(Op::Neg(*pos));
            }
            Expr::Concat { parts, path, pos } => {
                if *path {
                    self.gen(parts[0]);
                    self.ops.push(Op::PathStart);
                    for p in &parts[1..] {
                        self.gen(p);
                        self.ops.push(Op::PathPart(*pos));
                    }
                    self.ops.push(Op::PathEnd);
                } else {
                    self.ops.push(Op::StrStart);
                    for p in parts.iter() {
                        self.gen(p);
                        self.ops.push(Op::StrPart(*pos));
                    }
                    self.ops.push(Op::StrEnd);
                }
            }
        }
    }
}

type Stack = SmallVec<[Value; 6]>;

fn lookup(env: &Rc<Env>, up: u32) -> &Rc<Env> {
    let mut e = env;
    for _ in 0..up {
        e = e.parent.as_ref().expect("environment depth");
    }
    e
}

impl Eval {
    /// Runs `chunk` in `env` and returns the value it computes.
    pub(crate) fn run(&self, code: &'static Code, env: &Rc<Env>) -> R<Value> {
        let chunk = code.chunk();
        let mut stack: Stack = SmallVec::new();
        let mut strs: Vec<(String, Context)> = Vec::new();
        let mut env = env.clone();
        let mut pc = 0usize;
        let ops = &chunk.ops;
        while pc < ops.len() {
            let at = pc;
            let r = self.step(&ops[at], &mut stack, &mut strs, &mut env, &mut pc);
            if let Err(e) = r {
                return Err(self.unwind(chunk, at as u32, e));
            }
        }
        Ok(stack.pop().expect("chunk result"))
    }

    /// Applies the regions around the op at `pc` to an error leaving it.
    fn unwind(&self, chunk: &Chunk, pc: u32, e: Box<crate::eval::EvalError>) -> Box<crate::eval::EvalError> {
        let mut r: R<()> = Err(e);
        for reg in chunk.regions.iter().filter(|g| g.start <= pc && pc < g.end) {
            r = match reg.kind {
                RegionKind::Locate(pos) => self.locate_at(r, pos),
                RegionKind::Cond(pos) => self.add_frame(r, || Eval::cond_frame(pos)),
                RegionKind::Assert(pos) => self.add_frame(r, || self.assert_frame(pos)),
            };
        }
        match r {
            Err(e) => e,
            Ok(()) => unreachable!(),
        }
    }

    #[inline(always)]
    fn step(&self, op: &'static Op, stack: &mut Stack, strs: &mut Vec<(String, Context)>, env: &mut Rc<Env>, pc: &mut usize) -> R<()> {
        *pc += 1;
        match op {
            Op::Const(v) => stack.push(v.clone()),
            Op::Local { up, idx } => {
                let v = lookup(env, *up).slot(*idx as usize);
                stack.push(self.force(&v)?);
            }
            Op::Tree(e) => stack.push(self.eval(e, env)?),
            Op::Select { path, default, pos } => {
                let v = stack.pop().unwrap();
                stack.push(self.select(v, path, *default, env, *pos)?);
            }
            Op::HasAttr(path) => {
                let v = stack.pop().unwrap();
                stack.push(self.has_attr(v, path, env)?);
            }
            Op::Attrs(def) => stack.push(self.make_attrs(def, env)?),
            Op::List(items) => stack.push(self.make_list(items, env)),
            Op::Closure(def) => stack.push(self.closure(def, env)),
            Op::Call { arg, pos } => {
                let f = stack.pop().unwrap();
                let arg = self.lazy_arg(arg, env);
                stack.push(self.locate_at(self.call_at(&f, arg, Some(*pos)), *pos)?);
            }
            Op::PushLet(slots) => *env = self.let_env(slots, env),
            Op::PushWith(attrs) => *env = self.with_env(attrs, env),
            Op::PopEnv => {
                let parent = env.parent.clone().expect("environment parent");
                *env = parent;
            }
            Op::Jump(t) => *pc = *t as usize,
            Op::Branch { target, pos } => {
                let v = stack.pop().unwrap();
                if !self.if_cond(v, *pos)? {
                    *pc = *target as usize;
                }
            }
            Op::Assert(pos) => {
                let v = stack.pop().unwrap();
                self.assert_check(v, *pos)?;
            }
            Op::BoolOperand { right, op, pos } => {
                let v = stack.pop().unwrap();
                let b = self.bool_operand(v, if *right { "right" } else { "left" }, *op, *pos)?;
                stack.push(Value::Bool(b));
            }
            Op::ShortCircuit { when, result, target } => {
                let Some(Value::Bool(b)) = stack.pop() else { unreachable!() };
                if b == *when {
                    stack.push(Value::Bool(*result));
                    *pc = *target as usize;
                }
            }
            Op::BinOp(op) => {
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(self.binop_values(*op, a, b)?);
            }
            Op::Not(pos) => {
                let v = stack.pop().unwrap();
                stack.push(self.not(v, *pos)?);
            }
            Op::Neg(pos) => {
                let v = stack.pop().unwrap();
                stack.push(self.neg(v, *pos)?);
            }
            Op::StrStart => strs.push((String::new(), Context::new())),
            Op::StrPart(pos) => {
                let v = stack.pop().unwrap();
                let (s, ctx) = strs.last_mut().unwrap();
                self.str_part(s, ctx, &v, *pos)?;
            }
            Op::StrEnd => {
                let (s, ctx) = strs.pop().unwrap();
                stack.push(Value::str_ctx(s, ctx));
            }
            Op::PathStart => match stack.pop() {
                Some(Value::Str(s)) => strs.push((s.s.clone(), Context::new())),
                _ => unreachable!(),
            },
            Op::PathPart(pos) => {
                let v = stack.pop().unwrap();
                let (s, _) = strs.last_mut().unwrap();
                self.path_part(s, &v, *pos)?;
            }
            Op::PathEnd => {
                let (s, _) = strs.pop().unwrap();
                stack.push(Value::Path(crate::parser::canon_path(&s).into()));
            }
        }
        Ok(())
    }
}

/// Whether evaluation uses the VM, which `CRANIX_EVAL=vm` selects.
pub fn enabled() -> bool {
    std::env::var("CRANIX_EVAL").is_ok_and(|v| v == "vm")
}
