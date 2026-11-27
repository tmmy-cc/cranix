//! On-disk cache of parsed files.
//!
//! Each entry holds the syntax tree of one file in a compact binary form,
//! stored under `$XDG_CACHE_HOME/cranix/ast` (or `~/.cache/cranix/ast`) by
//! the SHA-256 of the cranix version, the format version, the base directory
//! and home directory that path literals resolve against, and the source
//! text. Positions are stored without a file index and get the index of the
//! file being loaded. Setting `CRANIX_AST_CACHE=0` turns the cache off.

use std::collections::HashMap;
use std::path::PathBuf;

use cranix_core::hash::Hash;

use crate::ast::{AttrName, Ast, BinOp, Binding, Formals, Pos, StrPart};
use crate::value::Sym;

const FORMAT: u32 = 1;
const MAGIC: &[u8; 8] = b"cranixA\0";

/// Sources below this size are parsed directly; their entries would cost
/// more to read than to parse.
const MIN_SIZE: usize = 512;

pub struct AstCache {
    dir: PathBuf,
}

impl AstCache {
    /// Returns the cache in its default location, or `None` when it is
    /// turned off or no cache directory is known.
    pub fn open() -> Option<AstCache> {
        if std::env::var("CRANIX_AST_CACHE").is_ok_and(|v| v == "0") {
            return None;
        }
        let base = match std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
            Some(d) => PathBuf::from(d),
            None => PathBuf::from(std::env::var_os("HOME").filter(|v| !v.is_empty())?).join(".cache"),
        };
        Some(AstCache { dir: base.join("cranix").join("ast") })
    }

    pub fn wants(&self, src: &str) -> bool {
        src.len() >= MIN_SIZE
    }

    pub fn key(src: &str, base_dir: &str, home: &str) -> String {
        let mut data = Vec::with_capacity(src.len() + base_dir.len() + home.len() + 32);
        data.extend_from_slice(env!("CARGO_PKG_VERSION").as_bytes());
        data.push(0);
        data.extend_from_slice(&FORMAT.to_le_bytes());
        data.extend_from_slice(base_dir.as_bytes());
        data.push(0);
        data.extend_from_slice(home.as_bytes());
        data.push(0);
        data.extend_from_slice(src.as_bytes());
        Hash::sha256(&data).to_base16()
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(&key[..2]).join(&key[2..])
    }

    pub fn load(&self, key: &str, file: u32) -> Option<Ast> {
        let data = std::fs::read(self.path(key)).ok()?;
        decode(&data, file)
    }

    /// Queues an entry for the writer thread; failures leave the cache
    /// without it.
    pub fn store(&self, key: &str, ast: &Ast) {
        let job = (self.path(key), encode(ast));
        let mut w = WRITER.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, _) = w.get_or_insert_with(|| {
            let (tx, rx) = std::sync::mpsc::channel::<(PathBuf, Vec<u8>)>();
            (tx, std::thread::spawn(move || rx.into_iter().for_each(|(p, d)| write_entry(&p, &d))))
        });
        let _ = tx.send(job);
    }
}

type Writer = (std::sync::mpsc::Sender<(PathBuf, Vec<u8>)>, std::thread::JoinHandle<()>);

static WRITER: std::sync::Mutex<Option<Writer>> = std::sync::Mutex::new(None);

/// Waits until the writer thread has written every queued entry.
pub fn flush() {
    let w = WRITER.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some((tx, handle)) = w {
        drop(tx);
        let _ = handle.join();
    }
}

fn write_entry(path: &std::path::Path, data: &[u8]) {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else { return };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let tmp = dir.join(format!(".{}.{}", name.to_string_lossy(), std::process::id()));
    if std::fs::write(&tmp, data).is_ok() && std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

// ---- encoding ----

struct Enc {
    out: Vec<u8>,
    strs: Vec<u8>,
    n_strs: u32,
    ids: HashMap<String, u32>,
}

impl Enc {
    fn u(&mut self, mut n: u64) {
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                self.out.push(b);
                return;
            }
            self.out.push(b | 0x80);
        }
    }

    fn b(&mut self, b: u8) {
        self.out.push(b);
    }

    fn s(&mut self, s: &str) {
        let id = match self.ids.get(s) {
            Some(&id) => id,
            None => {
                let id = self.n_strs;
                self.n_strs += 1;
                let mut n = s.len() as u64;
                loop {
                    let b = (n & 0x7f) as u8;
                    n >>= 7;
                    if n == 0 {
                        self.strs.push(b);
                        break;
                    }
                    self.strs.push(b | 0x80);
                }
                self.strs.extend_from_slice(s.as_bytes());
                self.ids.insert(s.to_string(), id);
                id
            }
        };
        self.u(id as u64);
    }

    fn pos(&mut self, p: Pos) {
        self.u(p.offset as u64);
    }

    fn opt(&mut self, a: &Option<Box<Ast>>) {
        match a {
            Some(a) => {
                self.b(1);
                self.ast(a);
            }
            None => self.b(0),
        }
    }

    fn parts(&mut self, parts: &[StrPart]) {
        self.u(parts.len() as u64);
        for p in parts {
            match p {
                StrPart::Lit(s) => {
                    self.b(0);
                    self.s(s);
                }
                StrPart::Interp(a) => {
                    self.b(1);
                    self.ast(a);
                }
            }
        }
    }

    fn names(&mut self, names: &[AttrName]) {
        self.u(names.len() as u64);
        for n in names {
            match n {
                AttrName::Static(s) => {
                    self.b(0);
                    self.s(s.as_str());
                }
                AttrName::Dynamic(a) => {
                    self.b(1);
                    self.ast(a);
                }
            }
        }
    }

    fn bindings(&mut self, bs: &[Binding]) {
        self.u(bs.len() as u64);
        for b in bs {
            match b {
                Binding::Attr(names, v, pos) => {
                    self.b(0);
                    self.names(names);
                    self.ast(v);
                    self.pos(*pos);
                }
                Binding::Inherit(from, names) => {
                    match from {
                        Some(f) => {
                            self.b(2);
                            self.ast(f);
                        }
                        None => self.b(1),
                    }
                    self.u(names.len() as u64);
                    for (n, p) in names {
                        self.s(n.as_str());
                        self.pos(*p);
                    }
                }
            }
        }
    }

    fn ast(&mut self, a: &Ast) {
        match a {
            Ast::Int(n) => {
                self.b(0);
                self.out.extend_from_slice(&n.to_le_bytes());
            }
            Ast::Float(f) => {
                self.b(1);
                self.out.extend_from_slice(&f.to_bits().to_le_bytes());
            }
            Ast::Str(parts, pos) => {
                self.b(2);
                self.parts(parts);
                self.pos(*pos);
            }
            Ast::Path(p) => {
                self.b(3);
                self.s(p);
            }
            Ast::PathInterp(parts, pos) => {
                self.b(4);
                self.parts(parts);
                self.pos(*pos);
            }
            Ast::SearchPath(p, pos) => {
                self.b(5);
                self.s(p);
                self.pos(*pos);
            }
            Ast::Var(n, pos) => {
                self.b(6);
                self.s(n.as_str());
                self.pos(*pos);
            }
            Ast::CurPos(pos) => {
                self.b(7);
                self.pos(*pos);
            }
            Ast::Select(e, path, def, pos) => {
                self.b(8);
                self.ast(e);
                self.names(path);
                self.opt(def);
                self.pos(*pos);
            }
            Ast::HasAttr(e, path) => {
                self.b(9);
                self.ast(e);
                self.names(path);
            }
            Ast::Attrs { rec, bindings, pos } => {
                self.b(10);
                self.b(*rec as u8);
                self.bindings(bindings);
                self.pos(*pos);
            }
            Ast::List(items) => {
                self.b(11);
                self.u(items.len() as u64);
                for i in items {
                    self.ast(i);
                }
            }
            Ast::Lambda { arg, formals, body, pos } => {
                self.b(12);
                match arg {
                    Some(a) => {
                        self.b(1);
                        self.s(a.as_str());
                    }
                    None => self.b(0),
                }
                match formals {
                    Some(f) => {
                        self.b(1 + f.ellipsis as u8);
                        self.u(f.entries.len() as u64);
                        for (n, d) in &f.entries {
                            self.s(n.as_str());
                            match d {
                                Some(d) => {
                                    self.b(1);
                                    self.ast(d);
                                }
                                None => self.b(0),
                            }
                        }
                    }
                    None => self.b(0),
                }
                self.ast(body);
                self.pos(*pos);
            }
            Ast::App(f, args, pos) => {
                self.b(13);
                self.ast(f);
                self.u(args.len() as u64);
                for a in args {
                    self.ast(a);
                }
                self.pos(*pos);
            }
            Ast::Let(bs, body, pos) => {
                self.b(14);
                self.bindings(bs);
                self.ast(body);
                self.pos(*pos);
            }
            Ast::LegacyLet(bs, pos) => {
                self.b(15);
                self.bindings(bs);
                self.pos(*pos);
            }
            Ast::With(a, b, pos) => {
                self.b(16);
                self.ast(a);
                self.ast(b);
                self.pos(*pos);
            }
            Ast::If(c, t, e, pos) => {
                self.b(17);
                self.ast(c);
                self.ast(t);
                self.ast(e);
                self.pos(*pos);
            }
            Ast::Assert(c, b, pos) => {
                self.b(18);
                self.ast(c);
                self.ast(b);
                self.pos(*pos);
            }
            Ast::BinOp(op, l, r, pos) => {
                self.b(19);
                self.b(binop_code(*op));
                self.ast(l);
                self.ast(r);
                self.pos(*pos);
            }
            Ast::Not(e, pos) => {
                self.b(20);
                self.ast(e);
                self.pos(*pos);
            }
            Ast::Neg(e, pos) => {
                self.b(21);
                self.ast(e);
                self.pos(*pos);
            }
        }
    }
}

const BINOPS: [BinOp; 15] = [
    BinOp::Eq,
    BinOp::Neq,
    BinOp::Lt,
    BinOp::Le,
    BinOp::Gt,
    BinOp::Ge,
    BinOp::And,
    BinOp::Or,
    BinOp::Impl,
    BinOp::Update,
    BinOp::Concat,
    BinOp::Add,
    BinOp::Sub,
    BinOp::Mul,
    BinOp::Div,
];

fn binop_code(op: BinOp) -> u8 {
    BINOPS.iter().position(|&o| o == op).unwrap() as u8
}

/// Layout: magic, string count, string table length, string table, tree.
pub fn encode(a: &Ast) -> Vec<u8> {
    let mut e = Enc { out: Vec::new(), strs: Vec::new(), n_strs: 0, ids: HashMap::new() };
    e.ast(a);
    let tree = std::mem::take(&mut e.out);
    let (n, strs) = (e.n_strs, std::mem::take(&mut e.strs));
    e.out.extend_from_slice(MAGIC);
    e.u(n as u64);
    e.u(strs.len() as u64);
    e.out.extend_from_slice(&strs);
    e.out.extend_from_slice(&tree);
    e.out
}

// ---- decoding ----

struct Dec<'a> {
    data: &'a [u8],
    at: usize,
    file: u32,
    strs: Vec<&'a str>,
    syms: Vec<Option<Sym>>,
}

type D<T> = Option<T>;

impl<'a> Dec<'a> {
    fn b(&mut self) -> D<u8> {
        let b = *self.data.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    fn u(&mut self) -> D<u64> {
        let mut n = 0u64;
        let mut shift = 0;
        loop {
            let b = self.b()?;
            n |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Some(n);
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
    }

    fn len(&mut self) -> D<usize> {
        let n = self.u()? as usize;
        // Every element takes at least one byte.
        (n <= self.data.len() - self.at).then_some(n)
    }

    fn bytes8(&mut self) -> D<[u8; 8]> {
        let b = self.data.get(self.at..self.at + 8)?.try_into().ok()?;
        self.at += 8;
        Some(b)
    }

    fn s(&mut self) -> D<String> {
        let id = self.u()? as usize;
        Some(self.strs.get(id)?.to_string())
    }

    fn sym(&mut self) -> D<Sym> {
        let id = self.u()? as usize;
        let slot = self.syms.get_mut(id)?;
        if let Some(s) = slot {
            return Some(s.clone());
        }
        let s = Sym::new(self.strs[id]);
        *slot = Some(s.clone());
        Some(s)
    }

    fn pos(&mut self) -> D<Pos> {
        Some(Pos { file: self.file, offset: self.u()? as u32 })
    }

    fn boxed(&mut self) -> D<Box<Ast>> {
        Some(Box::new(self.ast()?))
    }

    fn parts(&mut self) -> D<Vec<StrPart>> {
        let n = self.len()?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(match self.b()? {
                0 => StrPart::Lit(self.s()?),
                1 => StrPart::Interp(self.ast()?),
                _ => return None,
            });
        }
        Some(v)
    }

    fn names(&mut self) -> D<Vec<AttrName>> {
        let n = self.len()?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(match self.b()? {
                0 => AttrName::Static(self.sym()?),
                1 => AttrName::Dynamic(self.ast()?),
                _ => return None,
            });
        }
        Some(v)
    }

    fn bindings(&mut self) -> D<Vec<Binding>> {
        let n = self.len()?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let tag = self.b()?;
            v.push(match tag {
                0 => {
                    let names = self.names()?;
                    let val = self.ast()?;
                    Binding::Attr(names, val, self.pos()?)
                }
                1 | 2 => {
                    let from = if tag == 2 { Some(self.ast()?) } else { None };
                    let k = self.len()?;
                    let mut names = Vec::with_capacity(k);
                    for _ in 0..k {
                        let s = self.sym()?;
                        names.push((s, self.pos()?));
                    }
                    Binding::Inherit(from, names)
                }
                _ => return None,
            });
        }
        Some(v)
    }

    fn ast(&mut self) -> D<Ast> {
        Some(match self.b()? {
            0 => Ast::Int(i64::from_le_bytes(self.bytes8()?)),
            1 => Ast::Float(f64::from_bits(u64::from_le_bytes(self.bytes8()?))),
            2 => {
                let p = self.parts()?;
                Ast::Str(p, self.pos()?)
            }
            3 => Ast::Path(self.s()?),
            4 => {
                let p = self.parts()?;
                Ast::PathInterp(p, self.pos()?)
            }
            5 => {
                let s = self.s()?;
                Ast::SearchPath(s, self.pos()?)
            }
            6 => {
                let s = self.sym()?;
                Ast::Var(s, self.pos()?)
            }
            7 => Ast::CurPos(self.pos()?),
            8 => {
                let e = self.boxed()?;
                let path = self.names()?;
                let def = match self.b()? {
                    0 => None,
                    1 => Some(self.boxed()?),
                    _ => return None,
                };
                Ast::Select(e, path, def, self.pos()?)
            }
            9 => {
                let e = self.boxed()?;
                Ast::HasAttr(e, self.names()?)
            }
            10 => {
                let rec = self.b()? != 0;
                let bindings = self.bindings()?;
                Ast::Attrs { rec, bindings, pos: self.pos()? }
            }
            11 => {
                let n = self.len()?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(self.ast()?);
                }
                Ast::List(v)
            }
            12 => {
                let arg = match self.b()? {
                    0 => None,
                    1 => Some(self.sym()?),
                    _ => return None,
                };
                let formals = match self.b()? {
                    0 => None,
                    t @ (1 | 2) => {
                        let n = self.len()?;
                        let mut entries = Vec::with_capacity(n);
                        for _ in 0..n {
                            let s = self.sym()?;
                            let d = match self.b()? {
                                0 => None,
                                1 => Some(self.ast()?),
                                _ => return None,
                            };
                            entries.push((s, d));
                        }
                        Some(Formals { entries, ellipsis: t == 2 })
                    }
                    _ => return None,
                };
                let body = self.boxed()?;
                Ast::Lambda { arg, formals, body, pos: self.pos()? }
            }
            13 => {
                let f = self.boxed()?;
                let n = self.len()?;
                let mut args = Vec::with_capacity(n);
                for _ in 0..n {
                    args.push(self.ast()?);
                }
                Ast::App(f, args, self.pos()?)
            }
            14 => {
                let bs = self.bindings()?;
                let body = self.boxed()?;
                Ast::Let(bs, body, self.pos()?)
            }
            15 => {
                let bs = self.bindings()?;
                Ast::LegacyLet(bs, self.pos()?)
            }
            16 => {
                let a = self.boxed()?;
                let b = self.boxed()?;
                Ast::With(a, b, self.pos()?)
            }
            17 => {
                let c = self.boxed()?;
                let t = self.boxed()?;
                let e = self.boxed()?;
                Ast::If(c, t, e, self.pos()?)
            }
            18 => {
                let c = self.boxed()?;
                let b = self.boxed()?;
                Ast::Assert(c, b, self.pos()?)
            }
            19 => {
                let op = *BINOPS.get(self.b()? as usize)?;
                let l = self.boxed()?;
                let r = self.boxed()?;
                Ast::BinOp(op, l, r, self.pos()?)
            }
            20 => {
                let e = self.boxed()?;
                Ast::Not(e, self.pos()?)
            }
            21 => {
                let e = self.boxed()?;
                Ast::Neg(e, self.pos()?)
            }
            _ => return None,
        })
    }
}

/// Decodes an entry, giving its positions the file index `file`. Returns
/// `None` for a damaged or foreign entry.
pub fn decode(data: &[u8], file: u32) -> D<Ast> {
    let rest = data.strip_prefix(MAGIC.as_slice())?;
    let mut d = Dec { data: rest, at: 0, file, strs: Vec::new(), syms: Vec::new() };
    let n = d.len()?;
    let table_len = d.len()?;
    let table_end = d.at + table_len;
    let mut strs = Vec::with_capacity(n);
    for _ in 0..n {
        let l = d.len()?;
        let s = std::str::from_utf8(rest.get(d.at..d.at + l)?).ok()?;
        d.at += l;
        strs.push(s);
    }
    if d.at != table_end {
        return None;
    }
    d.strs = strs;
    d.syms = vec![None; n];
    let a = d.ast()?;
    (d.at == rest.len()).then_some(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;

    fn roundtrip(src: &str) {
        let a = Parser::new(src, 3, "/base").parse_file().ok().unwrap();
        let enc = encode(&a);
        let b = decode(&enc, 3).unwrap();
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
        assert_eq!(encode(&b), enc);
    }

    #[test]
    fn roundtrips_every_construct() {
        roundtrip(
            r#"let x = 1; inherit (y) a b; in rec { a.b.${"c"} = -2.5e3; s = "a${x}b"; p = ./x/${y}; q = <nixpkgs>;
               f = { a ? 1, b, ... }@args: x: a + b * 3 - 4 / 2; g = h 1 2; l = [ 1 "x" ] ++ [ ];
               w = with x; assert !true -> false; if a == b && c != d || e < f then g // { } else e.f or z;
               n = x ? a.b; c = __curPos; i = ''multi ${x} line''; u = http://example.org; }"#,
        );
        roundtrip("let { body = 1; }");
    }

    #[test]
    fn rejects_damaged_entries() {
        let a = Parser::new("{ a = [ 1 2 3 ]; }", 0, "/").parse_file().ok().unwrap();
        let enc = encode(&a);
        for n in 0..enc.len() {
            assert!(decode(&enc[..n], 0).is_none());
        }
    }
}
