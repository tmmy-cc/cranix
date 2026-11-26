//! `builtins.toXML`: the XML form of a value, in the exact layout Nix
//! writes.

use std::collections::HashSet;
use std::fmt::Write as _;

use crate::eval::{Eval, R};
use crate::print::fmt_float;
use crate::value::*;

struct Writer<'a> {
    ev: &'a Eval,
    out: String,
    depth: usize,
    ctx: Context,
    /// `.drv` paths already written; repeats print as `<repeated />`.
    drvs_seen: HashSet<String>,
}

/// The XML document for `v`, forcing it deeply, and the union of the
/// contexts of all strings in it.
pub fn to_xml(ev: &Eval, v: &Value) -> R<(String, Context)> {
    let mut w = Writer { ev, out: String::new(), depth: 0, ctx: Context::new(), drvs_seen: HashSet::new() };
    w.out.push_str("<?xml version='1.0' encoding='utf-8'?>\n");
    w.open("expr", &[]);
    w.value(v)?;
    w.close("expr");
    Ok((w.out, w.ctx))
}

fn escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#xA;"),
            c => out.push(c),
        }
    }
}

impl Writer<'_> {
    fn start_tag(&mut self, name: &str, attrs: &[(&str, &str)]) {
        for _ in 0..self.depth {
            self.out.push_str("  ");
        }
        self.out.push('<');
        self.out.push_str(name);
        for (k, v) in attrs {
            write!(self.out, " {k}=\"").unwrap();
            escape(v, &mut self.out);
            self.out.push('"');
        }
    }

    /// `attrs` must be sorted by name, as Nix writes them.
    fn open(&mut self, name: &str, attrs: &[(&str, &str)]) {
        self.start_tag(name, attrs);
        self.out.push_str(">\n");
        self.depth += 1;
    }

    fn close(&mut self, name: &str) {
        self.depth -= 1;
        for _ in 0..self.depth {
            self.out.push_str("  ");
        }
        writeln!(self.out, "</{name}>").unwrap();
    }

    fn empty(&mut self, name: &str, attrs: &[(&str, &str)]) {
        self.start_tag(name, attrs);
        self.out.push_str(" />\n");
    }

    fn value(&mut self, v: &Value) -> R<()> {
        let v = self.ev.force(v)?;
        match &v {
            Value::Int(n) => self.empty("int", &[("value", &n.to_string())]),
            Value::Bool(b) => self.empty("bool", &[("value", if *b { "true" } else { "false" })]),
            Value::Str(s) => {
                self.ctx.extend(s.ctx.iter().cloned());
                self.empty("string", &[("value", &s.s)]);
            }
            Value::Path(p) => self.empty("path", &[("value", p)]),
            Value::Null => self.empty("null", &[]),
            Value::Float(f) => self.empty("float", &[("value", &fmt_float(*f))]),
            Value::List(l) => {
                self.open("list", &[]);
                for x in l.iter() {
                    self.value(x)?;
                }
                self.close("list");
            }
            Value::Attrs(a) if self.ev.is_derivation(a)? => {
                let drv_path = self.string_attr(a, &self.ev.syms.drv_path.clone())?;
                let out_path = self.string_attr(a, &self.ev.syms.out_path.clone())?;
                let mut attrs = Vec::new();
                if let Some(p) = &drv_path {
                    attrs.push(("drvPath", p.as_str()));
                }
                if let Some(p) = &out_path {
                    attrs.push(("outPath", p.as_str()));
                }
                self.open("derivation", &attrs);
                let first = matches!(&drv_path, Some(p) if !p.is_empty() && self.drvs_seen.insert(p.clone()));
                if first {
                    self.attrs(a)?;
                } else {
                    self.empty("repeated", &[]);
                }
                self.close("derivation");
            }
            Value::Attrs(a) => {
                self.open("attrs", &[]);
                self.attrs(a)?;
                self.close("attrs");
            }
            Value::Lambda(c) => {
                self.open("function", &[]);
                match &c.def.formals {
                    Some(f) => {
                        let mut attrs = Vec::new();
                        if f.ellipsis {
                            attrs.push(("ellipsis", "1"));
                        }
                        if let Some(n) = &c.def.arg {
                            attrs.push(("name", n.as_str()));
                        }
                        self.open("attrspat", &attrs);
                        let mut names: Vec<&str> = f.entries.iter().map(|(n, _)| n.as_str()).collect();
                        names.sort_unstable();
                        for n in names {
                            self.empty("attr", &[("name", n)]);
                        }
                        self.close("attrspat");
                    }
                    None => {
                        let arg = c.def.arg.as_ref().map_or("", |a| a.as_str());
                        self.empty("varpat", &[("name", arg)]);
                    }
                }
                self.close("function");
            }
            Value::PrimOp(_) | Value::Thunk(_) => self.empty("unevaluated", &[]),
        }
        Ok(())
    }

    /// The value of a derivation's `drvPath` or `outPath`, if it is a
    /// string. Its context is collected when the attribute itself is written.
    fn string_attr(&mut self, a: &Attrs, k: &Sym) -> R<Option<String>> {
        let Some(v) = a.get(k) else { return Ok(None) };
        Ok(match self.ev.force(v)? {
            Value::Str(s) => Some(s.s.clone()),
            _ => None,
        })
    }

    fn attrs(&mut self, a: &Attrs) -> R<()> {
        for (k, x) in a.iter() {
            self.open("attr", &[("name", k.as_str())]);
            self.value(x)?;
            self.close("attr");
        }
        Ok(())
    }
}
