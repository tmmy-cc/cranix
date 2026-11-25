//! Hand-written lexer and recursive-descent parser for the Nix language.
//!
//! The lexer is driven by the parser: string and path bodies are scanned
//! on demand so interpolations nest without a separate lexer state stack.

use crate::ast::*;
use crate::value::Sym;

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Id(String),
    Int(i64),
    Float(f64),
    Path(String),
    /// A path immediately followed by `${`.
    PathStart(String),
    HPath(String),
    SPath(String),
    Uri(String),
    DQuote,
    IndOpen,
    Interp, // ${
    Sym(&'static str),
    Kw(&'static str),
    Eof,
}

const KEYWORDS: &[&str] = &["if", "then", "else", "assert", "with", "let", "in", "rec", "inherit", "or"];

const PUNCT: &[&str] = &[
    "...", "->", "||", "&&", "==", "!=", "<=", ">=", "//", "++", "{", "}", "[", "]", "(", ")", ";", ":", ",", ".", "@",
    "=", "?", "!", "+", "-", "*", "/", "<", ">",
];

pub struct ParseError {
    pub offset: usize,
    pub msg: String,
}

type R<T> = Result<T, ParseError>;

pub struct Parser<'a> {
    src: &'a [u8],
    /// Last lexed token: lookahead and consumption hit the same position.
    cache: std::cell::RefCell<[Option<(usize, Tok, usize, usize)>; 2]>,
    pos: usize,
    file: u32,
    base_dir: String,
    home: String,
}

fn is_id_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}
fn is_id_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'\'' || c == b'-'
}
fn is_path_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'+')
}
fn is_uri_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"%/?:@&=+$,-_.!~*'".contains(&c)
}

/// Removes `.`/`..` components and duplicate or trailing slashes.
pub fn canon_path(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    let mut s = String::with_capacity(p.len());
    for c in &parts {
        s.push('/');
        s.push_str(c);
    }
    if s.is_empty() {
        s.push('/');
    }
    s
}

impl<'a> Parser<'a> {
    pub fn new(src: &'a str, file: u32, base_dir: &str) -> Parser<'a> {
        Parser {
            src: src.as_bytes(),
            cache: std::cell::RefCell::new([None, None]),
            pos: 0,
            file,
            base_dir: base_dir.to_string(),
            home: std::env::var("HOME").unwrap_or_default(),
        }
    }

    fn err<T>(&self, offset: usize, msg: impl Into<String>) -> R<T> {
        Err(ParseError { offset, msg: msg.into() })
    }

    fn mkpos(&self, off: usize) -> Pos {
        Pos { file: self.file, offset: off as u32 }
    }

    // ---- lexing ----

    fn skip_ws(&self, mut i: usize) -> R<usize> {
        let s = self.src;
        loop {
            while i < s.len() && s[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < s.len() && s[i] == b'#' {
                while i < s.len() && s[i] != b'\n' {
                    i += 1;
                }
            } else if s[i..].starts_with(b"/*") {
                let start = i;
                i += 2;
                loop {
                    if i + 1 >= s.len() {
                        return self.err(start, "unterminated comment");
                    }
                    if s[i] == b'*' && s[i + 1] == b'/' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            } else {
                return Ok(i);
            }
        }
    }

    /// Length of the longest path match at `i` (`PATH_CHAR*(/PATH_CHAR+)+`,
    /// or a prefix ending in `/` directly before `${`), plus whether an
    /// interpolation follows.
    fn match_path(&self, i: usize) -> Option<(usize, bool)> {
        let s = self.src;
        let mut j = i;
        while j < s.len() && is_path_char(s[j]) {
            j += 1;
        }
        let mut segs = 0;
        while j < s.len() && s[j] == b'/' {
            let mut k = j + 1;
            while k < s.len() && is_path_char(s[k]) {
                k += 1;
            }
            if k == j + 1 {
                if s[k..].starts_with(b"${") {
                    return Some((k - i, true));
                }
                break;
            }
            segs += 1;
            j = k;
        }
        if segs == 0 {
            return None;
        }
        Some((j - i, s[j..].starts_with(b"${")))
    }

    fn lex_at(&self, at: usize) -> R<(Tok, usize, usize)> {
        {
            let c = self.cache.borrow();
            for (p, t, s, e) in c.iter().flatten() {
                if *p == at {
                    return Ok((t.clone(), *s, *e));
                }
            }
        }
        let r = self.lex_uncached(at)?;
        let mut c = self.cache.borrow_mut();
        c[1] = c[0].take();
        c[0] = Some((at, r.0.clone(), r.1, r.2));
        Ok(r)
    }

    fn lex_uncached(&self, at: usize) -> R<(Tok, usize, usize)> {
        let i = self.skip_ws(at)?;
        let s = self.src;
        if i >= s.len() {
            return Ok((Tok::Eof, i, i));
        }
        let c = s[i];
        let text = |a: usize, b: usize| String::from_utf8_lossy(&s[a..b]).into_owned();

        if c == b'"' {
            return Ok((Tok::DQuote, i, i + 1));
        }
        if s[i..].starts_with(b"''") {
            let mut j = i + 2;
            // A whitespace-only first line is dropped.
            let mut k = j;
            while k < s.len() && s[k] == b' ' {
                k += 1;
            }
            if k < s.len() && s[k] == b'\n' {
                j = k + 1;
            }
            return Ok((Tok::IndOpen, i, j));
        }
        if s[i..].starts_with(b"${") {
            return Ok((Tok::Interp, i, i + 2));
        }
        if c == b'~' && s.get(i + 1) == Some(&b'/') {
            if let Some((n, interp)) = self.match_path(i + 1) {
                if interp {
                    return self.err(i, "interpolation in home paths is not supported");
                }
                return Ok((Tok::HPath(text(i + 1, i + 1 + n)), i, i + 1 + n));
            }
        }
        if c == b'<' {
            let mut j = i + 1;
            while j < s.len() && (is_path_char(s[j]) || s[j] == b'/') {
                j += 1;
            }
            if j > i + 1 && s.get(j) == Some(&b'>') {
                return Ok((Tok::SPath(text(i + 1, j)), i, j + 1));
            }
        }

        // Identifiers, numbers, paths and URIs: take the longest match.
        let mut best: Option<(Tok, usize)> = None;
        let mut consider = |t: Tok, len: usize| {
            if best.as_ref().map_or(true, |(_, l)| len > *l) {
                best = Some((t, len));
            }
        };
        if is_id_start(c) {
            let mut j = i;
            while j < s.len() && is_id_char(s[j]) {
                j += 1;
            }
            let w = text(i, j);
            match KEYWORDS.iter().find(|k| **k == w) {
                Some(k) => consider(Tok::Kw(k), j - i),
                None => consider(Tok::Id(w), j - i),
            }
            if c.is_ascii_alphabetic() {
                let mut k = i;
                while k < s.len() && (s[k].is_ascii_alphanumeric() || b"+-.".contains(&s[k])) {
                    k += 1;
                }
                if k < s.len() && s[k] == b':' {
                    let mut m = k + 1;
                    while m < s.len() && is_uri_char(s[m]) {
                        m += 1;
                    }
                    if m > k + 1 {
                        consider(Tok::Uri(text(i, m)), m - i);
                    }
                }
            }
        }
        if c.is_ascii_digit() || (c == b'.' && s.get(i + 1).is_some_and(|d| d.is_ascii_digit())) {
            let mut j = i;
            while j < s.len() && s[j].is_ascii_digit() {
                j += 1;
            }
            let int_end = j;
            if c != b'.' && j > i {
                if let Ok(n) = text(i, j).parse::<i64>() {
                    consider(Tok::Int(n), j - i);
                } else {
                    return self.err(i, format!("invalid integer '{}'", text(i, j)));
                }
            }
            // Float: ([1-9][0-9]*\.[0-9]*|0?\.[0-9]+)([Ee][+-]?[0-9]+)?
            let mut f_end = None;
            if j < s.len() && s[j] == b'.' && !(c == b'0' && int_end - i > 1) {
                let mut k = j + 1;
                while k < s.len() && s[k].is_ascii_digit() {
                    k += 1;
                }
                let valid = if c == b'0' || c == b'.' { k > j + 1 } else { true };
                if valid {
                    f_end = Some(k);
                }
            }
            if let Some(mut k) = f_end {
                if k < s.len() && (s[k] == b'e' || s[k] == b'E') {
                    let mut m = k + 1;
                    if m < s.len() && (s[m] == b'+' || s[m] == b'-') {
                        m += 1;
                    }
                    let d = m;
                    while m < s.len() && s[m].is_ascii_digit() {
                        m += 1;
                    }
                    if m > d {
                        k = m;
                    }
                }
                if let Ok(f) = text(i, k).parse::<f64>() {
                    consider(Tok::Float(f), k - i);
                }
            }
        }
        if is_path_char(c) || c == b'/' {
            if let Some((n, interp)) = self.match_path(i) {
                let t = text(i, i + n);
                consider(if interp { Tok::PathStart(t) } else { Tok::Path(t) }, n);
            }
        }
        if let Some((t, n)) = best {
            return Ok((t, i, i + n));
        }
        for p in PUNCT {
            if s[i..].starts_with(p.as_bytes()) {
                return Ok((Tok::Sym(p), i, i + p.len()));
            }
        }
        self.err(i, format!("unexpected character '{}'", c as char))
    }

    fn peek(&self) -> R<Tok> {
        Ok(self.lex_at(self.pos)?.0)
    }

    fn peek2(&self) -> R<(Tok, Tok)> {
        let (a, _, e) = self.lex_at(self.pos)?;
        // An opening quote or path prefix starts string text, which the
        // caller scans itself.
        if matches!(a, Tok::DQuote | Tok::IndOpen | Tok::PathStart(_) | Tok::Interp) {
            return Ok((a, Tok::Eof));
        }
        let (b, _, _) = self.lex_at(e)?;
        Ok((a, b))
    }

    fn next(&mut self) -> R<(Tok, usize)> {
        let (t, start, end) = self.lex_at(self.pos)?;
        self.pos = end;
        Ok((t, start))
    }

    fn tok_start(&self) -> R<usize> {
        Ok(self.lex_at(self.pos)?.1)
    }

    fn expect(&mut self, sym: &'static str) -> R<usize> {
        let (t, start) = self.next()?;
        match t {
            Tok::Sym(s) | Tok::Kw(s) if s == sym => Ok(start),
            t => self.err(start, format!("syntax error, unexpected {}, expecting '{sym}'", describe(&t))),
        }
    }

    fn is(&self, sym: &str) -> R<bool> {
        Ok(matches!(self.peek()?, Tok::Sym(s) | Tok::Kw(s) if s == sym))
    }

    // ---- grammar ----

    pub fn parse_file(&mut self) -> R<Ast> {
        let e = self.expr()?;
        let (t, at) = self.next()?;
        if t != Tok::Eof {
            return self.err(at, format!("syntax error, unexpected {}", describe(&t)));
        }
        Ok(e)
    }

    fn expr(&mut self) -> R<Ast> {
        let start = self.tok_start()?;
        let pos = self.mkpos(start);
        match self.peek2()? {
            (Tok::Id(name), Tok::Sym(":")) => {
                self.next()?;
                self.next()?;
                let body = self.expr()?;
                Ok(Ast::Lambda { arg: Some(Sym::new(&name)), formals: None, body: Box::new(body), pos })
            }
            (Tok::Id(name), Tok::Sym("@")) => {
                self.next()?;
                self.next()?;
                self.expect("{")?;
                let formals = self.formals()?;
                self.expect(":")?;
                let body = self.expr()?;
                Ok(Ast::Lambda { arg: Some(Sym::new(&name)), formals: Some(formals), body: Box::new(body), pos })
            }
            (Tok::Sym("{"), _) if self.looks_like_formals()? => {
                self.next()?;
                let formals = self.formals()?;
                let mut arg = None;
                if self.is("@")? {
                    self.next()?;
                    match self.next()? {
                        (Tok::Id(n), _) => arg = Some(Sym::new(&n)),
                        (t, at) => return self.err(at, format!("syntax error, unexpected {}", describe(&t))),
                    }
                }
                self.expect(":")?;
                let body = self.expr()?;
                Ok(Ast::Lambda { arg, formals: Some(formals), body: Box::new(body), pos })
            }
            (Tok::Kw("if"), _) => {
                self.next()?;
                let c = self.expr()?;
                self.expect("then")?;
                let t = self.expr()?;
                self.expect("else")?;
                let e = self.expr()?;
                Ok(Ast::If(Box::new(c), Box::new(t), Box::new(e), pos))
            }
            (Tok::Kw("assert"), _) => {
                self.next()?;
                let c = self.expr()?;
                self.expect(";")?;
                let b = self.expr()?;
                Ok(Ast::Assert(Box::new(c), Box::new(b), pos))
            }
            (Tok::Kw("with"), _) => {
                self.next()?;
                let a = self.expr()?;
                self.expect(";")?;
                let b = self.expr()?;
                Ok(Ast::With(Box::new(a), Box::new(b), pos))
            }
            (Tok::Kw("let"), Tok::Sym("{")) => {
                self.next()?;
                self.next()?;
                let b = self.bindings("}")?;
                self.expect("}")?;
                Ok(Ast::LegacyLet(b, pos))
            }
            (Tok::Kw("let"), _) => {
                self.next()?;
                let b = self.bindings("in")?;
                self.expect("in")?;
                let body = self.expr()?;
                Ok(Ast::Let(b, Box::new(body), pos))
            }
            _ => self.binop(0),
        }
    }

    fn looks_like_formals(&self) -> R<bool> {
        let (_, _, e1) = self.lex_at(self.pos)?;
        let (t1, _, e2) = self.lex_at(e1)?;
        Ok(match t1 {
            Tok::Sym("}") => {
                let (t2, _, _) = self.lex_at(e2)?;
                matches!(t2, Tok::Sym(":") | Tok::Sym("@"))
            }
            Tok::Sym("...") => true,
            Tok::Id(_) => {
                let (t2, _, _) = self.lex_at(e2)?;
                matches!(t2, Tok::Sym(",") | Tok::Sym("?") | Tok::Sym("}"))
            }
            _ => false,
        })
    }

    fn formals(&mut self) -> R<Formals> {
        let mut f = Formals { entries: Vec::new(), ellipsis: false };
        loop {
            match self.next()? {
                (Tok::Sym("}"), _) => break,
                (Tok::Sym("..."), _) => {
                    f.ellipsis = true;
                    self.expect("}")?;
                    break;
                }
                (Tok::Id(n), at) => {
                    let sym = Sym::new(&n);
                    if f.entries.iter().any(|(s, _)| *s == sym) {
                        return self.err(at, format!("duplicate formal function argument '{n}'"));
                    }
                    let def = if self.is("?")? {
                        self.next()?;
                        Some(self.expr()?)
                    } else {
                        None
                    };
                    f.entries.push((sym, def));
                    match self.next()? {
                        (Tok::Sym(","), _) => {}
                        (Tok::Sym("}"), _) => break,
                        (t, at) => return self.err(at, format!("syntax error, unexpected {} in formals", describe(&t))),
                    }
                }
                (t, at) => return self.err(at, format!("syntax error, unexpected {} in formals", describe(&t))),
            }
        }
        Ok(f)
    }

    fn bindings(&mut self, end: &str) -> R<Vec<Binding>> {
        let mut out = Vec::new();
        loop {
            if self.is(end)? {
                return Ok(out);
            }
            let start = self.tok_start()?;
            if self.is("inherit")? {
                self.next()?;
                let from = if self.is("(")? {
                    self.next()?;
                    let e = self.expr()?;
                    self.expect(")")?;
                    Some(e)
                } else {
                    None
                };
                let mut names = Vec::new();
                loop {
                    let at = self.tok_start()?;
                    match self.peek()? {
                        Tok::Sym(";") => {
                            self.next()?;
                            break;
                        }
                        Tok::Id(n) => {
                            self.next()?;
                            names.push((Sym::new(&n), self.mkpos(at)));
                        }
                        Tok::Kw("or") => {
                            self.next()?;
                            names.push((Sym::new("or"), self.mkpos(at)));
                        }
                        Tok::DQuote => {
                            self.next()?;
                            let parts = self.string_body()?;
                            match static_string(&parts) {
                                Some(s) => names.push((Sym::new(&s), self.mkpos(at))),
                                None => return self.err(at, "dynamic attributes not allowed in inherit"),
                            }
                        }
                        Tok::Interp => return self.err(at, "dynamic attributes not allowed in inherit"),
                        t => return self.err(at, format!("syntax error, unexpected {} in inherit", describe(&t))),
                    }
                }
                out.push(Binding::Inherit(from, names));
                continue;
            }
            let path = self.attrpath()?;
            self.expect("=")?;
            let e = self.expr()?;
            self.expect(";")?;
            out.push(Binding::Attr(path, e, self.mkpos(start)));
        }
    }

    fn attrpath(&mut self) -> R<Vec<AttrName>> {
        let mut path = vec![self.attrname()?];
        while self.is(".")? {
            self.next()?;
            path.push(self.attrname()?);
        }
        Ok(path)
    }

    fn attrname(&mut self) -> R<AttrName> {
        let (t, at) = self.next()?;
        match t {
            Tok::Id(n) => Ok(AttrName::Static(Sym::new(&n))),
            Tok::Kw(k) if k == "or" => Ok(AttrName::Static(Sym::new(k))),
            Tok::DQuote => {
                let parts = self.string_body()?;
                match static_string(&parts) {
                    Some(s) => Ok(AttrName::Static(Sym::new(&s))),
                    None => Ok(AttrName::Dynamic(Ast::Str(parts))),
                }
            }
            Tok::Interp => {
                let e = self.expr()?;
                self.expect("}")?;
                Ok(AttrName::Dynamic(e))
            }
            t => self.err(at, format!("syntax error, unexpected {}, expecting attribute name", describe(&t))),
        }
    }

    fn binop(&mut self, min: u8) -> R<Ast> {
        let mut lhs = self.prefix()?;
        loop {
            let at = self.tok_start()?;
            let t = self.peek()?;
            let Tok::Sym(s) = t else { break };
            let (prec, op, assoc) = match s {
                "->" => (1, BinOp::Impl, 'r'),
                "||" => (2, BinOp::Or, 'l'),
                "&&" => (3, BinOp::And, 'l'),
                "==" => (4, BinOp::Eq, 'n'),
                "!=" => (4, BinOp::Neq, 'n'),
                "<" => (5, BinOp::Lt, 'n'),
                ">" => (5, BinOp::Gt, 'n'),
                "<=" => (5, BinOp::Le, 'n'),
                ">=" => (5, BinOp::Ge, 'n'),
                "//" => (6, BinOp::Update, 'r'),
                "+" => (8, BinOp::Add, 'l'),
                "-" => (8, BinOp::Sub, 'l'),
                "*" => (9, BinOp::Mul, 'l'),
                "/" => (9, BinOp::Div, 'l'),
                "++" => (10, BinOp::Concat, 'r'),
                "?" => (11, BinOp::Eq, 'q'),
                _ => break,
            };
            if prec < min {
                break;
            }
            self.next()?;
            if assoc == 'q' {
                let path = self.attrpath()?;
                lhs = Ast::HasAttr(Box::new(lhs), path);
                continue;
            }
            let rhs = self.binop(if assoc == 'r' { prec } else { prec + 1 })?;
            lhs = Ast::BinOp(op, Box::new(lhs), Box::new(rhs), self.mkpos(at));
        }
        Ok(lhs)
    }

    fn prefix(&mut self) -> R<Ast> {
        let at = self.tok_start()?;
        if self.is("!")? {
            self.next()?;
            let e = self.binop(7)?;
            return Ok(Ast::Not(Box::new(e), self.mkpos(at)));
        }
        if self.is("-")? {
            self.next()?;
            let e = self.binop(12)?;
            return Ok(Ast::Neg(Box::new(e), self.mkpos(at)));
        }
        self.app()
    }

    fn starts_primary(t: &Tok) -> bool {
        match t {
            Tok::Id(_)
            | Tok::Int(_)
            | Tok::Float(_)
            | Tok::Path(_)
            | Tok::PathStart(_)
            | Tok::HPath(_)
            | Tok::SPath(_)
            | Tok::Uri(_)
            | Tok::DQuote
            | Tok::IndOpen => true,
            Tok::Sym(s) => matches!(*s, "{" | "[" | "("),
            Tok::Kw(k) => matches!(*k, "rec"),
            _ => false,
        }
    }

    fn app(&mut self) -> R<Ast> {
        let at = self.tok_start()?;
        let f = self.select()?;
        let mut args = Vec::new();
        loop {
            let t = self.peek()?;
            if t == Tok::Kw("let") {
                let (_, t2) = self.peek2()?;
                if t2 != Tok::Sym("{") {
                    break;
                }
            } else if !Self::starts_primary(&t) {
                break;
            }
            args.push(self.select()?);
        }
        if args.is_empty() {
            Ok(f)
        } else {
            Ok(Ast::App(Box::new(f), args, self.mkpos(at)))
        }
    }

    fn select(&mut self) -> R<Ast> {
        let at = self.tok_start()?;
        let e = self.primary()?;
        if !self.is(".")? {
            return Ok(e);
        }
        self.next()?;
        let path = self.attrpath()?;
        let def = if self.is("or")? {
            self.next()?;
            Some(Box::new(self.select()?))
        } else {
            None
        };
        Ok(Ast::Select(Box::new(e), path, def, self.mkpos(at)))
    }

    fn resolve_path(&self, raw: &str) -> String {
        if raw.starts_with('/') {
            canon_path(raw)
        } else {
            canon_path(&format!("{}/{}", self.base_dir, raw))
        }
    }

    fn primary(&mut self) -> R<Ast> {
        let (t, at) = self.next()?;
        let pos = self.mkpos(at);
        Ok(match t {
            Tok::Id(n) if n == "__curPos" => Ast::CurPos(pos),
            Tok::Id(n) => Ast::Var(Sym::new(&n), pos),
            Tok::Int(n) => Ast::Int(n),
            Tok::Float(f) => Ast::Float(f),
            Tok::Path(p) => Ast::Path(self.resolve_path(&p)),
            Tok::HPath(p) => Ast::Path(canon_path(&format!("{}{}", self.home, p))),
            Tok::SPath(p) => Ast::SearchPath(p, pos),
            Tok::Uri(u) => Ast::Str(vec![StrPart::Lit(u)]),
            Tok::PathStart(p) => {
                let mut prefix = self.resolve_path(&p);
                if p.ends_with('/') && !prefix.ends_with('/') {
                    prefix.push('/');
                }
                let mut parts = vec![StrPart::Lit(prefix)];
                self.expect_interp()?;
                loop {
                    let e = self.expr()?;
                    self.expect("}")?;
                    parts.push(StrPart::Interp(e));
                    let s = self.src;
                    let mut j = self.pos;
                    while j < s.len() && (is_path_char(s[j]) || s[j] == b'/') && !s[j..].starts_with(b"${") {
                        j += 1;
                    }
                    if j > self.pos {
                        parts.push(StrPart::Lit(String::from_utf8_lossy(&s[self.pos..j]).into_owned()));
                        self.pos = j;
                    }
                    if self.src[self.pos..].starts_with(b"${") {
                        self.pos += 2;
                        continue;
                    }
                    break;
                }
                Ast::PathInterp(parts, pos)
            }
            Tok::DQuote => Ast::Str(self.string_body()?),
            Tok::IndOpen => Ast::Str(self.ind_string_body()?),
            Tok::Sym("(") => {
                let e = self.expr()?;
                self.expect(")")?;
                e
            }
            Tok::Sym("[") => {
                let mut items = Vec::new();
                while !self.is("]")? {
                    items.push(self.select()?);
                }
                self.next()?;
                Ast::List(items)
            }
            Tok::Sym("{") => {
                let b = self.bindings("}")?;
                self.expect("}")?;
                Ast::Attrs { rec: false, bindings: b, pos }
            }
            Tok::Kw("rec") => {
                self.expect("{")?;
                let b = self.bindings("}")?;
                self.expect("}")?;
                Ast::Attrs { rec: true, bindings: b, pos }
            }
            Tok::Kw("let") => {
                self.expect("{")?;
                let b = self.bindings("}")?;
                self.expect("}")?;
                Ast::LegacyLet(b, pos)
            }
            t => return self.err(at, format!("syntax error, unexpected {}", describe(&t))),
        })
    }

    fn expect_interp(&mut self) -> R<()> {
        if self.src[self.pos..].starts_with(b"${") {
            self.pos += 2;
            Ok(())
        } else {
            self.err(self.pos, "expected '${'")
        }
    }

    /// Body of a `"..."` string; the opening quote is consumed.
    fn string_body(&mut self) -> R<Vec<StrPart>> {
        let s = self.src;
        let start = self.pos;
        let mut parts = Vec::new();
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let i = self.pos;
            if i >= s.len() {
                return self.err(start, "unterminated string");
            }
            match s[i] {
                b'"' => {
                    self.pos += 1;
                    break;
                }
                b'\\' if i + 1 < s.len() => {
                    buf.push(match s[i + 1] {
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        c => c,
                    });
                    self.pos += 2;
                }
                b'$' if s.get(i + 1) == Some(&b'{') => {
                    if !buf.is_empty() {
                        parts.push(StrPart::Lit(String::from_utf8_lossy(&std::mem::take(&mut buf)).into_owned()));
                    }
                    self.pos += 2;
                    let e = self.expr()?;
                    self.expect("}")?;
                    parts.push(StrPart::Interp(e));
                }
                b'$' => {
                    buf.push(b'$');
                    self.pos += 1;
                    if let Some(&c) = s.get(i + 1) {
                        if c != b'"' && c != b'\\' {
                            buf.push(c);
                            self.pos += 1;
                        }
                    }
                }
                c => {
                    buf.push(c);
                    self.pos += 1;
                }
            }
        }
        if !buf.is_empty() {
            parts.push(StrPart::Lit(String::from_utf8_lossy(&buf).into_owned()));
        }
        Ok(parts)
    }

    /// Body of a `''...''` string, with indentation stripped.
    fn ind_string_body(&mut self) -> R<Vec<StrPart>> {
        enum P {
            Text(Vec<u8>),
            Escaped(Vec<u8>),
            Interp(Ast),
        }
        let s = self.src;
        let start = self.pos;
        let mut raw: Vec<P> = Vec::new();
        let mut buf: Vec<u8> = Vec::new();
        let flush = |buf: &mut Vec<u8>, raw: &mut Vec<P>| {
            if !buf.is_empty() {
                raw.push(P::Text(std::mem::take(buf)));
            }
        };
        loop {
            let i = self.pos;
            if i >= s.len() {
                return self.err(start, "unterminated indented string");
            }
            if s[i] == b'\'' && s.get(i + 1) == Some(&b'\'') {
                match s.get(i + 2) {
                    Some(b'$') => {
                        flush(&mut buf, &mut raw);
                        raw.push(P::Escaped(b"$".to_vec()));
                        self.pos += 3;
                    }
                    Some(b'\'') => {
                        flush(&mut buf, &mut raw);
                        raw.push(P::Escaped(b"''".to_vec()));
                        self.pos += 3;
                    }
                    Some(b'\\') if i + 3 < s.len() => {
                        flush(&mut buf, &mut raw);
                        let c = match s[i + 3] {
                            b'n' => b'\n',
                            b'r' => b'\r',
                            b't' => b'\t',
                            c => c,
                        };
                        raw.push(P::Escaped(vec![c]));
                        self.pos += 4;
                    }
                    _ => {
                        self.pos += 2;
                        break;
                    }
                }
            } else if s[i] == b'$' && s.get(i + 1) == Some(&b'{') {
                flush(&mut buf, &mut raw);
                self.pos += 2;
                let e = self.expr()?;
                self.expect("}")?;
                raw.push(P::Interp(e));
            } else if s[i] == b'$' && s.get(i + 1).is_some_and(|&c| c != b'\'') {
                buf.push(b'$');
                buf.push(s[i + 1]);
                self.pos += 2;
            } else {
                buf.push(s[i]);
                self.pos += 1;
            }
        }
        flush(&mut buf, &mut raw);

        // Pass 1: minimum indentation over lines that have content.
        let mut min_indent = usize::MAX;
        let mut cur = 0;
        let mut at_sol = true;
        for p in &raw {
            match p {
                P::Text(t) => {
                    for &c in t {
                        if at_sol {
                            if c == b' ' {
                                cur += 1;
                            } else if c == b'\n' {
                                cur = 0;
                            } else {
                                at_sol = false;
                                min_indent = min_indent.min(cur);
                            }
                        } else if c == b'\n' {
                            at_sol = true;
                            cur = 0;
                        }
                    }
                }
                P::Escaped(_) | P::Interp(_) => {
                    if at_sol {
                        at_sol = false;
                        min_indent = min_indent.min(cur);
                    }
                }
            }
        }
        if min_indent == usize::MAX {
            min_indent = cur;
        }

        // Pass 2: drop the indentation and a whitespace-only last line.
        let n = raw.len();
        let mut out: Vec<StrPart> = Vec::new();
        let mut lit: Vec<u8> = Vec::new();
        let mut at_sol = true;
        let mut dropped = 0;
        for (idx, p) in raw.into_iter().enumerate() {
            match p {
                P::Text(t) => {
                    for c in t {
                        if at_sol {
                            if c == b' ' {
                                if dropped >= min_indent {
                                    lit.push(c);
                                }
                                dropped += 1;
                            } else if c == b'\n' {
                                dropped = 0;
                                lit.push(c);
                            } else {
                                at_sol = false;
                                dropped = 0;
                                lit.push(c);
                            }
                        } else {
                            lit.push(c);
                            if c == b'\n' {
                                at_sol = true;
                            }
                        }
                    }
                    if idx == n - 1 {
                        if let Some(p) = lit.iter().rposition(|&c| c == b'\n') {
                            if lit[p + 1..].iter().all(|&c| c == b' ') {
                                lit.truncate(p + 1);
                            }
                        }
                    }
                }
                P::Escaped(t) => {
                    at_sol = false;
                    dropped = 0;
                    lit.extend(t);
                }
                P::Interp(e) => {
                    at_sol = false;
                    dropped = 0;
                    if !lit.is_empty() {
                        out.push(StrPart::Lit(String::from_utf8_lossy(&std::mem::take(&mut lit)).into_owned()));
                    }
                    out.push(StrPart::Interp(e));
                }
            }
        }
        if !lit.is_empty() {
            out.push(StrPart::Lit(String::from_utf8_lossy(&lit).into_owned()));
        }
        Ok(out)
    }
}

fn static_string(parts: &[StrPart]) -> Option<String> {
    let mut s = String::new();
    for p in parts {
        match p {
            StrPart::Lit(l) => s.push_str(l),
            StrPart::Interp(_) => return None,
        }
    }
    Some(s)
}

fn describe(t: &Tok) -> String {
    match t {
        Tok::Id(n) => format!("identifier '{n}'"),
        Tok::Int(n) => format!("integer {n}"),
        Tok::Float(f) => format!("float {f}"),
        Tok::Path(p) | Tok::PathStart(p) | Tok::HPath(p) => format!("path '{p}'"),
        Tok::SPath(p) => format!("search path <{p}>"),
        Tok::Uri(u) => format!("URI '{u}'"),
        Tok::DQuote => "'\"'".into(),
        Tok::IndOpen => "''".into(),
        Tok::Interp => "'${'".into(),
        Tok::Sym(s) | Tok::Kw(s) => format!("'{s}'"),
        Tok::Eof => "end of file".into(),
    }
}
