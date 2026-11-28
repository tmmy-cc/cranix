//! TOML 1.0 parser for `builtins.fromTOML`.
//!
//! Follows Nix 2.24 where it differs from the specification's choices:
//! dates and times are rejected, integers outside the 64-bit range
//! saturate, and strings end at their first NUL character.

use std::collections::BTreeMap;

use crate::error::{err, R};
use crate::value::{Attrs, Sym, Value};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Created as the parent of a table header; may be defined later.
    Implicit,
    /// Defined by a `[header]`.
    Header,
    /// Created by a dotted key; extendable by dotted keys only.
    Dotted,
    /// An inline table or one inside it; immutable once parsed.
    Inline,
}

struct Table {
    map: BTreeMap<String, Node>,
    kind: Kind,
}

enum Node {
    Value(Value),
    Table(Table),
    Array(Vec<Node>),
    /// An array of tables defined by `[[header]]`s.
    Tables(Vec<Table>),
}

impl Table {
    fn new(kind: Kind) -> Table {
        Table { map: BTreeMap::new(), kind }
    }

    fn seal(&mut self) {
        self.kind = Kind::Inline;
        for n in self.map.values_mut() {
            n.seal();
        }
    }

    fn into_value(self) -> Value {
        let entries = self.map.into_iter().map(|(k, n)| (Sym::new(&k), n.into_value())).collect();
        Value::attrs(Attrs::from_sorted(entries))
    }
}

impl Node {
    fn seal(&mut self) {
        match self {
            Node::Table(t) => t.seal(),
            Node::Array(a) => a.iter_mut().for_each(Node::seal),
            _ => {}
        }
    }

    fn into_value(self) -> Value {
        match self {
            Node::Value(v) => v,
            Node::Table(t) => t.into_value(),
            Node::Array(a) => Value::list(a.into_iter().map(Node::into_value).collect()),
            Node::Tables(ts) => Value::list(ts.into_iter().map(Table::into_value).collect()),
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    /// Dates and times become `{ _type = "timestamp"; value = …; }`, as
    /// with Nix's `parse-toml-timestamps` experimental feature.
    timestamps: bool,
}

pub fn from_toml(src: &str) -> R<Value> {
    from_toml_with(src, false)
}

pub fn from_toml_with(src: &str, timestamps: bool) -> R<Value> {
    let mut p = Parser { s: src.as_bytes(), i: 0, timestamps };
    p.document().map_err(|e| {
        let (line, col) = p.line_col();
        Box::new(crate::error::EvalError::new(
            crate::error::ErrKind::Other,
            format!("while parsing TOML: {} at line {line}, column {col}", e.msg),
        ))
    })
}

impl<'a> Parser<'a> {
    fn line_col(&self) -> (usize, usize) {
        let upto = &self.s[..self.i.min(self.s.len())];
        let line = upto.iter().filter(|&&c| c == b'\n').count() + 1;
        let col = upto.len() - upto.iter().rposition(|&c| c == b'\n').map_or(0, |p| p + 1) + 1;
        (line, col)
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn at(&self, lit: &str) -> bool {
        self.s[self.i..].starts_with(lit.as_bytes())
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, c: u8, what: &str) -> R<()> {
        if self.eat(c) {
            Ok(())
        } else {
            err(format!("expected {what}"))
        }
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }

    fn comment(&mut self) {
        if self.peek() == Some(b'#') {
            while !matches!(self.peek(), None | Some(b'\n')) {
                self.i += 1;
            }
        }
    }

    fn newline(&mut self) -> bool {
        if self.at("\r\n") {
            self.i += 2;
            true
        } else {
            self.eat(b'\n')
        }
    }

    /// Whitespace, comments and newlines, as allowed inside arrays.
    fn ws_nl(&mut self) {
        loop {
            self.ws();
            self.comment();
            if !self.newline() {
                return;
            }
        }
    }

    /// The rest of a line after an expression: only a comment may follow.
    fn end_of_line(&mut self) -> R<()> {
        self.ws();
        self.comment();
        if self.peek().is_none() || self.newline() {
            Ok(())
        } else {
            err("expected a newline or the end of the document after an expression")
        }
    }

    fn document(&mut self) -> R<Value> {
        let mut root = Table::new(Kind::Header);
        // Path of the table that key/value pairs currently go into.
        let mut current: Vec<String> = Vec::new();
        loop {
            self.ws_nl();
            match self.peek() {
                None => break,
                Some(b'[') => {
                    let array = self.at("[[");
                    self.i += if array { 2 } else { 1 };
                    self.ws();
                    let key = self.key()?;
                    self.ws();
                    if array {
                        if !self.at("]]") {
                            return err("expected ']]' to close the array of tables header");
                        }
                        self.i += 2;
                    } else {
                        self.expect(b']', "']' to close the table header")?;
                    }
                    self.end_of_line()?;
                    define_table(&mut root, &key, array)?;
                    current = key;
                }
                Some(_) => {
                    let table = table_at(&mut root, &current);
                    self.key_value(table)?;
                    self.end_of_line()?;
                }
            }
        }
        Ok(root.into_value())
    }

    fn key_value(&mut self, table: &mut Table) -> R<()> {
        let key = self.key()?;
        self.ws();
        self.expect(b'=', "'=' after a key")?;
        self.ws();
        let v = self.value()?;
        insert_dotted(table, &key, v)
    }

    /// A possibly dotted key.
    fn key(&mut self) -> R<Vec<String>> {
        let mut parts = vec![self.simple_key()?];
        loop {
            let save = self.i;
            self.ws();
            if self.eat(b'.') {
                self.ws();
                parts.push(self.simple_key()?);
            } else {
                self.i = save;
                return Ok(parts);
            }
        }
    }

    fn simple_key(&mut self) -> R<String> {
        match self.peek() {
            Some(b'"') => {
                self.i += 1;
                self.basic_string()
            }
            Some(b'\'') => {
                self.i += 1;
                self.literal_string()
            }
            _ => {
                let start = self.i;
                while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
                    self.i += 1;
                }
                if start == self.i {
                    return err("expected a key");
                }
                Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
            }
        }
    }

    fn value(&mut self) -> R<Node> {
        match self.peek() {
            None | Some(b'\n' | b'\r' | b'#') => err("expected a value after '='"),
            Some(b'"') => {
                let s = if self.at("\"\"\"") {
                    self.i += 3;
                    self.ml_basic_string()?
                } else {
                    self.i += 1;
                    self.basic_string()?
                };
                Ok(Node::Value(nix_string(s)))
            }
            Some(b'\'') => {
                let s = if self.at("'''") {
                    self.i += 3;
                    self.ml_literal_string()?
                } else {
                    self.i += 1;
                    self.literal_string()?
                };
                Ok(Node::Value(nix_string(s)))
            }
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                loop {
                    self.ws_nl();
                    if self.eat(b']') {
                        break;
                    }
                    items.push(self.value()?);
                    self.ws_nl();
                    if self.eat(b',') {
                        continue;
                    }
                    self.expect(b']', "',' or ']' in an array")?;
                    break;
                }
                Ok(Node::Array(items))
            }
            Some(b'{') => {
                self.i += 1;
                let mut t = Table::new(Kind::Dotted);
                self.ws();
                if !self.eat(b'}') {
                    loop {
                        self.ws();
                        self.key_value(&mut t)?;
                        self.ws();
                        if self.eat(b',') {
                            self.ws();
                            if self.peek() == Some(b'}') {
                                return err("trailing comma in an inline table");
                            }
                            continue;
                        }
                        self.expect(b'}', "',' or '}' in an inline table")?;
                        break;
                    }
                }
                t.seal();
                Ok(Node::Table(t))
            }
            Some(b't') if self.at("true") => {
                self.i += 4;
                Ok(Node::Value(Value::Bool(true)))
            }
            Some(b'f') if self.at("false") => {
                self.i += 5;
                Ok(Node::Value(Value::Bool(false)))
            }
            Some(_) => self.number(),
        }
    }

    fn number(&mut self) -> R<Node> {
        let start = self.i;
        if self.is_datetime() {
            if !self.timestamps {
                return err("Dates and times are not supported");
            }
            return Ok(Node::Value(self.datetime()));
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'+' | b'-')) {
            // A sign only belongs to the number after an exponent marker.
            if matches!(self.peek(), Some(b'+' | b'-')) && self.i > start && !matches!(self.s[self.i - 1], b'e' | b'E') {
                break;
            }
            self.i += 1;
        }
        let tok = std::str::from_utf8(&self.s[start..self.i]).unwrap_or("");
        if tok.is_empty() {
            return err("expected a value after '='");
        }
        parse_number(tok).map(|v| Node::Value(v)).or_else(|_| err(format!("invalid value '{tok}'")))
    }

    /// Whether a date (`1979-05-27`) or time (`07:32:00`) starts here.
    /// A date, time or date-time, in the form Nix prints it: `T` between
    /// date and time, upper-case `T` and `Z`.
    fn datetime(&mut self) -> Value {
        let start = self.i;
        while let Some(c) = self.peek() {
            let space_sep = c == b' ' && self.s.get(self.i + 1).is_some_and(u8::is_ascii_digit) && self.i - start == 10;
            if c.is_ascii_digit() || matches!(c, b'-' | b':' | b'.' | b'+' | b'T' | b't' | b'Z' | b'z') || space_sep {
                self.i += 1;
            } else {
                break;
            }
        }
        let text: String = std::str::from_utf8(&self.s[start..self.i])
            .unwrap_or("")
            .chars()
            .map(|c| match c {
                ' ' | 't' => 'T',
                'z' => 'Z',
                c => c,
            })
            .collect();
        Value::attrs(crate::value::Attrs::from_unsorted(vec![
            (crate::value::Sym::new("_type"), Value::str("timestamp")),
            (crate::value::Sym::new("value"), Value::str(text)),
        ]))
    }

    fn is_datetime(&self) -> bool {
        let rest = &self.s[self.i..];
        let digits = |n: usize| rest.len() > n && rest[..n].iter().all(u8::is_ascii_digit);
        (digits(4) && rest[4] == b'-') || (digits(2) && rest[2] == b':')
    }

    fn basic_string(&mut self) -> R<String> {
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None | Some(b'\n') => return err("unterminated string"),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(utf8(out));
                }
                Some(b'\\') => {
                    self.i += 1;
                    self.escape(&mut out)?;
                }
                Some(c) => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }

    fn escape(&mut self, out: &mut Vec<u8>) -> R<()> {
        let Some(c) = self.peek() else { return err("unterminated string") };
        self.i += 1;
        let simple = match c {
            b'b' => Some(b'\x08'),
            b't' => Some(b'\t'),
            b'n' => Some(b'\n'),
            b'f' => Some(b'\x0c'),
            b'r' => Some(b'\r'),
            b'"' => Some(b'"'),
            b'\\' => Some(b'\\'),
            _ => None,
        };
        if let Some(b) = simple {
            out.push(b);
            return Ok(());
        }
        let n = match c {
            b'u' => 4,
            b'U' => 8,
            c => return err(format!("invalid escape sequence '\\{}'", c as char)),
        };
        let hex = self.s.get(self.i..self.i + n).and_then(|h| std::str::from_utf8(h).ok());
        let ch = hex.and_then(|h| u32::from_str_radix(h, 16).ok()).and_then(char::from_u32);
        let Some(ch) = ch else { return err("invalid unicode escape") };
        self.i += n;
        let mut buf = [0; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        Ok(())
    }

    fn ml_basic_string(&mut self) -> R<String> {
        self.newline();
        let mut out = Vec::new();
        loop {
            if self.at("\"\"\"") {
                return Ok(utf8(self.close_ml(b'"', out)));
            }
            match self.peek() {
                None => return err("unterminated multi-line string"),
                Some(b'\\') => {
                    self.i += 1;
                    // A backslash at the end of a line trims the line break
                    // and the whitespace that follows.
                    let save = self.i;
                    self.ws();
                    if self.newline() {
                        loop {
                            self.ws();
                            if !self.newline() {
                                break;
                            }
                        }
                    } else {
                        self.i = save;
                        self.escape(&mut out)?;
                    }
                }
                Some(c) => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }

    fn literal_string(&mut self) -> R<String> {
        let start = self.i;
        loop {
            match self.peek() {
                None | Some(b'\n') => return err("unterminated string"),
                Some(b'\'') => {
                    self.i += 1;
                    return Ok(utf8(self.s[start..self.i - 1].to_vec()));
                }
                Some(_) => self.i += 1,
            }
        }
    }

    fn ml_literal_string(&mut self) -> R<String> {
        self.newline();
        let mut out = Vec::new();
        loop {
            if self.at("'''") {
                return Ok(utf8(self.close_ml(b'\'', out)));
            }
            match self.peek() {
                None => return err("unterminated multi-line string"),
                Some(c) => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }

    /// Consumes the closing delimiter of a multi-line string. Up to two
    /// quotes directly before it belong to the content.
    fn close_ml(&mut self, q: u8, mut out: Vec<u8>) -> Vec<u8> {
        let mut n = 0;
        while self.peek() == Some(q) && n < 5 {
            self.i += 1;
            n += 1;
        }
        out.extend(std::iter::repeat(q).take(n - 3));
        out
    }
}

fn utf8(b: Vec<u8>) -> String {
    String::from_utf8(b).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Nix strings end at a NUL character.
fn nix_string(mut s: String) -> Value {
    if let Some(i) = s.find('\0') {
        s.truncate(i);
    }
    Value::str(s)
}

/// Digits with single underscores between them.
fn digits(s: &str, ok: impl Fn(u8) -> bool) -> Option<String> {
    let b = s.as_bytes();
    if b.is_empty() || b[0] == b'_' || b[b.len() - 1] == b'_' || s.contains("__") {
        return None;
    }
    b.iter().all(|&c| c == b'_' || ok(c)).then(|| s.replace('_', ""))
}

fn parse_number(tok: &str) -> Result<Value, ()> {
    let (sign, body) = match tok.as_bytes()[0] {
        b'+' => ("", &tok[1..]),
        b'-' => ("-", &tok[1..]),
        _ => ("", tok),
    };
    match body {
        "inf" => return Ok(Value::Float(if sign == "-" { f64::NEG_INFINITY } else { f64::INFINITY })),
        "nan" => return Ok(Value::Float(f64::NAN)),
        _ => {}
    }
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(d) = tok.strip_prefix(prefix) {
            let d = digits(d, |c| (c as char).is_digit(radix)).ok_or(())?;
            return Ok(Value::Int(u64::from_str_radix(&d, radix).map_err(|_| ())?.min(i64::MAX as u64) as i64));
        }
    }
    let no_leading_zero = |d: &str| !(d.len() > 1 && d.starts_with('0'));
    let (mantissa, exp) = match body.find(['e', 'E']) {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    };
    let (int, frac) = match mantissa.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (mantissa, None),
    };
    let int = digits(int, |c| c.is_ascii_digit()).filter(|d| no_leading_zero(d)).ok_or(())?;
    if frac.is_none() && exp.is_none() {
        let n = format!("{sign}{int}").parse::<i128>().map_err(|_| ())?;
        return Ok(Value::Int(n.clamp(i64::MIN as i128, i64::MAX as i128) as i64));
    }
    let mut f = format!("{sign}{int}");
    if let Some(frac) = frac {
        f.push('.');
        f.push_str(&digits(frac, |c| c.is_ascii_digit()).ok_or(())?);
    }
    if let Some(exp) = exp {
        let (esign, e) = match exp.as_bytes().first() {
            Some(b'+') => ("", &exp[1..]),
            Some(b'-') => ("-", &exp[1..]),
            _ => ("", exp),
        };
        f.push('e');
        f.push_str(esign);
        f.push_str(&digits(e, |c| c.is_ascii_digit()).ok_or(())?);
    }
    f.parse::<f64>().map(Value::Float).map_err(|_| ())
}

/// Descends to the table at `path`, entering the last table of arrays
/// of tables. The path was validated when its header was defined.
fn table_at<'t>(mut t: &'t mut Table, path: &[String]) -> &'t mut Table {
    for k in path {
        t = match t.map.get_mut(k) {
            Some(Node::Table(sub)) => sub,
            Some(Node::Tables(ts)) => ts.last_mut().unwrap(),
            _ => unreachable!("table header path not defined"),
        };
    }
    t
}

fn define_table(root: &mut Table, key: &[String], array: bool) -> R<()> {
    let (last, parents) = key.split_last().unwrap();
    let mut t = root;
    for k in parents {
        let n = t.map.entry(k.clone()).or_insert_with(|| Node::Table(Table::new(Kind::Implicit)));
        t = match n {
            Node::Table(sub) if sub.kind != Kind::Inline => sub,
            Node::Tables(ts) => ts.last_mut().unwrap(),
            _ => return err(format!("key '{k}' is already defined and is not a table")),
        };
    }
    match (t.map.get_mut(last), array) {
        (None, false) => {
            t.map.insert(last.clone(), Node::Table(Table::new(Kind::Header)));
        }
        (None, true) => {
            t.map.insert(last.clone(), Node::Tables(vec![Table::new(Kind::Header)]));
        }
        (Some(Node::Table(sub)), false) if sub.kind == Kind::Implicit => sub.kind = Kind::Header,
        (Some(Node::Tables(ts)), true) => ts.push(Table::new(Kind::Header)),
        _ => return err(format!("table '{}' is already defined", key.join("."))),
    }
    Ok(())
}

fn insert_dotted(t: &mut Table, key: &[String], v: Node) -> R<()> {
    let (last, parents) = key.split_last().unwrap();
    let mut t = t;
    for k in parents {
        let n = t.map.entry(k.clone()).or_insert_with(|| Node::Table(Table::new(Kind::Dotted)));
        t = match n {
            Node::Table(sub) if sub.kind == Kind::Dotted => sub,
            _ => return err(format!("key '{k}' is already defined and cannot be extended with dotted keys")),
        };
    }
    if t.map.contains_key(last) {
        return err(format!("key '{}' is already defined", key.join(".")));
    }
    t.map.insert(last.clone(), v);
    Ok(())
}
