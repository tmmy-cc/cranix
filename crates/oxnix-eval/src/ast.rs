//! Surface syntax tree produced by the parser.

use crate::value::Sym;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Pos {
    pub file: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Impl,
    Update,
    Concat,
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug)]
pub enum StrPart {
    Lit(String),
    Interp(Ast),
}

#[derive(Debug)]
pub enum AttrName {
    Static(Sym),
    Dynamic(Ast),
}

#[derive(Debug)]
pub enum Binding {
    Attr(Vec<AttrName>, Ast, Pos),
    Inherit(Option<Ast>, Vec<(Sym, Pos)>),
}

#[derive(Debug)]
pub struct Formals {
    pub entries: Vec<(Sym, Option<Ast>)>,
    pub ellipsis: bool,
}

#[derive(Debug)]
pub enum Ast {
    Int(i64),
    Float(f64),
    Str(Vec<StrPart>, Pos),
    /// Absolute, canonical path literal.
    Path(String),
    /// Path literal with interpolations; the first part is the absolute
    /// prefix.
    PathInterp(Vec<StrPart>, Pos),
    SearchPath(String, Pos),
    Var(Sym, Pos),
    CurPos(Pos),
    Select(Box<Ast>, Vec<AttrName>, Option<Box<Ast>>, Pos),
    HasAttr(Box<Ast>, Vec<AttrName>),
    Attrs { rec: bool, bindings: Vec<Binding>, pos: Pos },
    List(Vec<Ast>),
    Lambda { arg: Option<Sym>, formals: Option<Formals>, body: Box<Ast>, pos: Pos },
    App(Box<Ast>, Vec<Ast>, Pos),
    Let(Vec<Binding>, Box<Ast>, Pos),
    LegacyLet(Vec<Binding>, Pos),
    With(Box<Ast>, Box<Ast>, Pos),
    If(Box<Ast>, Box<Ast>, Box<Ast>, Pos),
    Assert(Box<Ast>, Box<Ast>, Pos),
    BinOp(BinOp, Box<Ast>, Box<Ast>, Pos),
    Not(Box<Ast>, Pos),
    Neg(Box<Ast>, Pos),
}
