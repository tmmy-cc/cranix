//! Runtime values, thunks, environments and interned symbols.

use std::borrow::{Borrow, Cow};
use std::cell::{OnceCell, RefCell, UnsafeCell};
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

use crate::compile::{Expr, LambdaDef};
use crate::eval::{Eval, R};

/// Interned identifier. Equality and hashing are by pointer; ordering is
/// by string so attribute sets iterate in Nix's lexicographic order.
#[derive(Clone)]
pub struct Sym(Rc<SymInner>);

struct SymInner {
    name: Box<str>,
    /// The name as a Nix string, shared by every `attrNames` and `mapAttrs`
    /// result that mentions it.
    value: OnceCell<Rc<NixStr>>,
}

/// Interner key: hashes and compares by name so lookups can use `&str`.
struct SymKey(Rc<SymInner>);

impl PartialEq for SymKey {
    fn eq(&self, o: &SymKey) -> bool {
        self.0.name == o.0.name
    }
}
impl Eq for SymKey {}
impl Hash for SymKey {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.0.name.hash(h)
    }
}
impl Borrow<str> for SymKey {
    fn borrow(&self) -> &str {
        &self.0.name
    }
}

thread_local! {
    static INTERNER: RefCell<HashSet<SymKey>> = RefCell::new(HashSet::new());
}

impl Sym {
    pub fn new(s: &str) -> Sym {
        INTERNER.with(|i| {
            let mut i = i.borrow_mut();
            if let Some(k) = i.get(s) {
                return Sym(k.0.clone());
            }
            let r = Rc::new(SymInner { name: s.into(), value: OnceCell::new() });
            i.insert(SymKey(r.clone()));
            Sym(r)
        })
    }
    pub fn as_str(&self) -> &str {
        &self.0.name
    }
    pub fn as_value(&self) -> Value {
        Value::Str(self.0.value.get_or_init(|| Rc::new(NixStr::plain(&*self.0.name))).clone())
    }
}

impl PartialEq for Sym {
    fn eq(&self, o: &Sym) -> bool {
        Rc::ptr_eq(&self.0, &o.0)
    }
}
impl Eq for Sym {}
impl Hash for Sym {
    fn hash<H: Hasher>(&self, h: &mut H) {
        (Rc::as_ptr(&self.0) as usize).hash(h)
    }
}
impl PartialOrd for Sym {
    fn partial_cmp(&self, o: &Sym) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Sym {
    fn cmp(&self, o: &Sym) -> std::cmp::Ordering {
        if Rc::ptr_eq(&self.0, &o.0) {
            std::cmp::Ordering::Equal
        } else {
            self.0.name.cmp(&o.0.name)
        }
    }
}
impl fmt::Debug for Sym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl fmt::Display for Sym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One element of a string's context: the store objects it refers to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CtxElem {
    /// A plain store path.
    Opaque(String),
    /// A derivation and its whole closure (`drvPath` references).
    DrvDeep(String),
    /// One output of a derivation.
    Built { drv: String, output: String },
}

impl CtxElem {
    pub fn encode(&self) -> String {
        match self {
            CtxElem::Opaque(p) => p.clone(),
            CtxElem::DrvDeep(p) => format!("={p}"),
            CtxElem::Built { drv, output } => format!("!{output}!{drv}"),
        }
    }
}

pub type Context = BTreeSet<CtxElem>;

#[derive(Clone, Debug, Default)]
pub struct NixStr {
    pub s: String,
    pub ctx: Context,
}

impl NixStr {
    pub fn plain(s: impl Into<String>) -> NixStr {
        NixStr { s: s.into(), ctx: Context::new() }
    }
}

pub type Entry = (Sym, Value);

/// Attribute set. Entries iterate sorted by key.
///
/// `a // b` with a small `b` and a large `a` is stored as a layer over a
/// shared `a`, so overlays on the package set share its entries.
pub struct Attrs {
    repr: Repr,
    len: usize,
    /// Where the attributes were defined: tables of the set expressions
    /// the set came from, the ones of `//`'s right side first.
    pos: Option<Rc<[PosTable]>>,
}

/// The positions of the static attributes of one set expression, sorted
/// by name.
pub type PosTable = &'static [(Sym, crate::ast::Pos)];

/// Position tables kept for a set made by `//`.
const POS_TABLES_MAX: usize = 8;

enum Repr {
    Flat(Vec<Entry>),
    Layered {
        base: Rc<Attrs>,
        top: Vec<Entry>,
        depth: u8,
        /// Sorted entries, materialised on first iteration.
        flat: OnceCell<Vec<Entry>>,
    },
}

/// Layering applies when the left side has at least this many entries and
/// the right side is at most an eighth of it.
const LAYER_MIN: usize = 64;
/// Deeper chains are flattened so lookups stay cheap.
const LAYER_MAX_DEPTH: u8 = 8;

impl Default for Attrs {
    fn default() -> Self {
        Attrs::from_sorted(Vec::new())
    }
}

fn find<'a>(v: &'a [Entry], k: &Sym) -> Option<&'a Value> {
    // Symbols are interned, so small sets are scanned by pointer identity;
    // string comparisons are only needed for binary search.
    if v.len() <= 24 {
        return v.iter().find(|(s, _)| s == k).map(|(_, x)| x);
    }
    v.binary_search_by(|(s, _)| s.cmp(k)).ok().map(|i| &v[i].1)
}

fn find_str<'a>(v: &'a [Entry], k: &str) -> Option<&'a Value> {
    v.binary_search_by(|(s, _)| s.as_str().cmp(k)).ok().map(|i| &v[i].1)
}

/// Merges two sorted entry lists; `b` wins on equal keys.
fn merge(a: &[Entry], b: &[Entry]) -> Vec<Entry> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => {
                out.push(a[i].clone());
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                out.push(b[j].clone());
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                out.push(b[j].clone());
                i += 1;
                j += 1;
            }
        }
    }
    out.extend_from_slice(&a[i..]);
    out.extend_from_slice(&b[j..]);
    out
}

impl Attrs {
    /// Wraps entries that are already sorted by key without duplicates.
    pub fn from_sorted(v: Vec<Entry>) -> Attrs {
        Attrs { len: v.len(), repr: Repr::Flat(v), pos: None }
    }

    /// The set with the attribute positions of one set expression.
    pub fn with_positions(mut self, table: PosTable) -> Attrs {
        if !table.is_empty() {
            self.pos = Some(Rc::from([table]));
        }
        self
    }

    /// Where the attribute `k` was defined, if a set expression made it.
    pub fn position(&self, k: &Sym) -> Option<crate::ast::Pos> {
        self.pos.as_ref()?.iter().find_map(|t| t.binary_search_by(|(s, _)| s.cmp(k)).ok().map(|i| t[i].1))
    }

    fn merged_positions(a: &Attrs, b: &Attrs) -> Option<Rc<[PosTable]>> {
        match (&a.pos, &b.pos) {
            (None, None) => None,
            (Some(x), None) => Some(x.clone()),
            (None, Some(y)) => Some(y.clone()),
            (Some(x), Some(y)) => Some(y.iter().chain(x.iter()).take(POS_TABLES_MAX).copied().collect()),
        }
    }

    pub fn get(&self, k: &Sym) -> Option<&Value> {
        match &self.repr {
            Repr::Flat(v) => find(v, k),
            Repr::Layered { base, top, .. } => find(top, k).or_else(|| base.get(k)),
        }
    }

    /// [`Attrs::get`] with an inline cache: `hint` is the index at which a
    /// lookup from the same place found the key last time. Sets built by
    /// the same expression share their layout, so the guess usually hits
    /// and skips the search.
    #[inline]
    pub fn get_hinted(&self, k: &Sym, hint: &std::cell::Cell<u32>) -> Option<&Value> {
        let v = match &self.repr {
            Repr::Flat(v) => v,
            Repr::Layered { top, .. } => top,
        };
        if let Some((s, x)) = v.get(hint.get() as usize) {
            if s == k {
                return Some(x);
            }
        }
        let i = if v.len() <= 24 { v.iter().position(|(s, _)| s == k) } else { v.binary_search_by(|(s, _)| s.cmp(k)).ok() };
        match (i, &self.repr) {
            (Some(i), _) => {
                hint.set(i as u32);
                Some(&v[i].1)
            }
            (None, Repr::Layered { base, .. }) => base.get(k),
            (None, Repr::Flat(_)) => None,
        }
    }

    pub fn get_str(&self, k: &str) -> Option<&Value> {
        match &self.repr {
            Repr::Flat(v) => find_str(v, k),
            Repr::Layered { base, top, .. } => find_str(top, k).or_else(|| base.get_str(k)),
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// All entries, sorted by key. A layered set keeps the merged list it
    /// builds here; its base layers keep only their own entries.
    pub fn entries(&self) -> &[Entry] {
        match &self.repr {
            Repr::Flat(v) => v,
            Repr::Layered { base, top, flat, .. } => flat.get_or_init(|| merge(&base.entries_uncached(), top)),
        }
    }

    /// All entries, sorted by key, merging layers into a temporary list when
    /// no merged list is cached yet.
    pub fn entries_uncached(&self) -> Cow<'_, [Entry]> {
        match &self.repr {
            Repr::Flat(v) => Cow::Borrowed(v),
            Repr::Layered { base, top, flat, .. } => match flat.get() {
                Some(v) => Cow::Borrowed(v),
                None => Cow::Owned(merge(&base.entries_uncached(), top)),
            },
        }
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Entry> {
        self.entries().iter()
    }

    fn depth(&self) -> u8 {
        match &self.repr {
            Repr::Flat(_) => 0,
            Repr::Layered { depth, .. } => *depth,
        }
    }

    /// `a // b`.
    pub fn update(a: &Rc<Attrs>, b: &Rc<Attrs>) -> Rc<Attrs> {
        if a.is_empty() {
            return b.clone();
        }
        if b.is_empty() {
            return a.clone();
        }
        if a.len >= LAYER_MIN && b.len * 8 <= a.len && a.depth() < LAYER_MAX_DEPTH {
            let top = b.entries().to_vec();
            let shadowed = top.iter().filter(|(k, _)| a.get(k).is_some()).count();
            return Rc::new(Attrs {
                len: a.len + top.len() - shadowed,
                repr: Repr::Layered { base: a.clone(), top, depth: a.depth() + 1, flat: OnceCell::new() },
                pos: Attrs::merged_positions(a, b),
            });
        }
        let mut out = Attrs::from_sorted(merge(&a.entries_uncached(), &b.entries_uncached()));
        out.pos = Attrs::merged_positions(a, b);
        Rc::new(out)
    }

    /// Builds a set from unsorted entries; later duplicates win.
    pub fn from_unsorted(mut v: Vec<Entry>) -> Attrs {
        v.reverse();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v.dedup_by(|a, b| a.0 == b.0);
        Attrs::from_sorted(v)
    }

    /// Builds a set from unsorted entries; earlier duplicates win.
    pub fn from_unsorted_first(mut v: Vec<Entry>) -> Attrs {
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v.dedup_by(|a, b| a.0 == b.0);
        Attrs::from_sorted(v)
    }
}

impl<'a> IntoIterator for &'a Attrs {
    type Item = &'a Entry;
    type IntoIter = std::slice::Iter<'a, Entry>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub type PrimFn = fn(&Eval, &[Value]) -> R<Value>;

pub struct PrimOp {
    pub name: &'static str,
    pub arity: usize,
    pub f: PrimFn,
}

pub struct PrimOpApp {
    pub op: &'static PrimOp,
    pub args: Vec<Value>,
}

pub struct Closure {
    pub def: &'static LambdaDef,
    pub env: Rc<Env>,
}

pub enum ThunkState {
    Pending(&'static Expr, Rc<Env>),
    /// Lazy `f x`, used by builtins such as `map`.
    App(Value, Value),
    /// Lazy `f name x` for one attribute of `mapAttrs` or `zipAttrsWith`;
    /// the function is shared by all attributes of one call.
    AttrApp(Rc<Value>, Sym, Value),
    Native(Rc<dyn Fn(&Eval) -> R<Value>>),
    Blackhole,
    Done(Value),
}

/// A lazy value. The state is only touched by `take`, `put` and `peek`,
/// none of which hold a reference across evaluation, so a plain
/// `UnsafeCell` is enough in this single-threaded evaluator.
pub struct Thunk(UnsafeCell<ThunkState>);

impl Thunk {
    pub fn new(st: ThunkState) -> Thunk {
        Thunk(UnsafeCell::new(st))
    }

    /// The value, if the thunk has been forced.
    pub fn peek(&self) -> Option<Value> {
        // SAFETY: shared read; no `&mut` to the state exists outside
        // `take`/`put`, which do not call back into evaluation.
        match unsafe { &*self.0.get() } {
            ThunkState::Done(v) => Some(v.clone()),
            _ => None,
        }
    }

    pub fn is_blackhole(&self) -> bool {
        // SAFETY: as in `peek`.
        matches!(unsafe { &*self.0.get() }, ThunkState::Blackhole)
    }

    /// Replaces the state with a black hole and returns the old one.
    pub fn take(&self) -> ThunkState {
        // SAFETY: as in `peek`; the swap itself runs no evaluator code.
        unsafe { std::ptr::replace(self.0.get(), ThunkState::Blackhole) }
    }

    pub fn put(&self, st: ThunkState) {
        // SAFETY: as in `take`. The old state is dropped after the write,
        // so its destructor cannot observe a half-written cell.
        let old = unsafe { std::ptr::replace(self.0.get(), st) };
        drop(old);
    }
}

#[derive(Clone)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Rc<NixStr>),
    // `Rc<String>` keeps the pointer thin, so `Value` stays 16 bytes.
    Path(Rc<String>),
    Attrs(Rc<Attrs>),
    List(Rc<Vec<Value>>),
    Lambda(Rc<Closure>),
    PrimOp(Rc<PrimOpApp>),
    Thunk(Rc<Thunk>),
}

impl Value {
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(Rc::new(NixStr::plain(s)))
    }
    pub fn str_ctx(s: impl Into<String>, ctx: Context) -> Value {
        Value::Str(Rc::new(NixStr { s: s.into(), ctx }))
    }
    pub fn attrs(a: Attrs) -> Value {
        Value::Attrs(Rc::new(a))
    }
    pub fn list(v: Vec<Value>) -> Value {
        Value::List(Rc::new(v))
    }
    pub fn thunk(e: &'static Expr, env: Rc<Env>) -> Value {
        Value::Thunk(Rc::new(Thunk::new(ThunkState::Pending(e, env))))
    }
    pub fn app_thunk(f: Value, x: Value) -> Value {
        Value::Thunk(Rc::new(Thunk::new(ThunkState::App(f, x))))
    }
    pub fn attr_app_thunk(f: Rc<Value>, name: Sym, x: Value) -> Value {
        Value::Thunk(Rc::new(Thunk::new(ThunkState::AttrApp(f, name, x))))
    }
    pub fn native(f: impl Fn(&Eval) -> R<Value> + 'static) -> Value {
        Value::Thunk(Rc::new(Thunk::new(ThunkState::Native(Rc::new(f)))))
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "string",
            Value::Path(_) => "path",
            Value::Attrs(_) => "set",
            Value::List(_) => "list",
            Value::Lambda(_) | Value::PrimOp(_) => "lambda",
            Value::Thunk(_) => "thunk",
        }
    }

    /// Wording used in type errors ("a string", "an integer").
    pub fn describe(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "a Boolean",
            Value::Int(_) => "an integer",
            Value::Float(_) => "a float",
            Value::Str(_) => "a string",
            Value::Path(_) => "a path",
            Value::Attrs(_) => "a set",
            Value::List(_) => "a list",
            Value::Lambda(_) => "a function",
            Value::PrimOp(_) => "a built-in function",
            Value::Thunk(_) => "a thunk",
        }
    }
}

pub enum EnvKind {
    Slots(RefCell<Vec<Value>>),
    /// Scope introduced by `with`; holds the (lazy) attribute set.
    With(Value),
}

pub struct Env {
    pub parent: Option<Rc<Env>>,
    pub kind: EnvKind,
}

impl Env {
    pub fn new(parent: Option<Rc<Env>>, slots: Vec<Value>) -> Rc<Env> {
        Rc::new(Env { parent, kind: EnvKind::Slots(RefCell::new(slots)) })
    }

    pub fn slot(&self, i: usize) -> Value {
        match &self.kind {
            EnvKind::Slots(s) => s.borrow()[i].clone(),
            EnvKind::With(v) => v.clone(),
        }
    }

    pub fn set(&self, i: usize, v: Value) {
        if let EnvKind::Slots(s) = &self.kind {
            s.borrow_mut()[i] = v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every value, set entry and thunk is multiplied by millions when
    /// evaluating nixpkgs; these sizes are part of the memory budget.
    #[test]
    fn sizes() {
        assert_eq!(std::mem::size_of::<Value>(), 16);
        assert_eq!(std::mem::size_of::<Entry>(), 24);
        assert_eq!(std::mem::size_of::<Thunk>(), 40);
    }

    fn set(keys: impl IntoIterator<Item = (String, i64)>) -> Rc<Attrs> {
        Rc::new(Attrs::from_unsorted(keys.into_iter().map(|(k, v)| (Sym::new(&k), Value::Int(v))).collect()))
    }

    fn dump(a: &Attrs) -> Vec<(String, i64)> {
        a.iter()
            .map(|(k, v)| match v {
                Value::Int(n) => (k.as_str().to_string(), *n),
                _ => unreachable!(),
            })
            .collect()
    }

    /// Layered updates must be indistinguishable from flat merges.
    #[test]
    fn layered_update_matches_flat_merge() {
        let mut layered = set((0..200).map(|i| (format!("k{i:03}"), i)));
        let mut flat = layered.clone();
        for round in 0..20i64 {
            // Overrides two existing keys and adds a new one.
            let b = set([
                (format!("k{:03}", round * 7 % 200), 1000 + round),
                (format!("k{:03}", round * 13 % 200), 2000 + round),
                (format!("new{round:02}"), 3000 + round),
            ]);
            layered = Attrs::update(&layered, &b);
            flat = Rc::new(Attrs::from_sorted(merge(flat.entries(), b.entries())));
            assert_eq!(layered.len(), flat.len());
            for (k, _) in flat.iter() {
                assert!(layered.get(k).is_some());
                assert!(layered.get_str(k.as_str()).is_some());
            }
            assert!(layered.get(&Sym::new("absent")).is_none());
        }
        assert!(layered.depth() <= LAYER_MAX_DEPTH);
        assert_eq!(dump(&layered), dump(&flat));
        let k = Sym::new("k007");
        assert!(matches!((layered.get(&k), flat.get(&k)), (Some(Value::Int(a)), Some(Value::Int(b))) if a == b));
    }
}
