//! Rendering values as Nix syntax and JSON, and parsing JSON.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::rc::Rc;

use crate::eval::{err, CoerceOpts, Eval, R};
use crate::value::*;

/// `%g` with six significant digits, as Nix prints floats.
pub fn fmt_float(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0".into() } else { "0".into() };
    }
    let exp = f.abs().log10().floor() as i32;
    let sci = format!("{:.5e}", f);
    let (mant, e) = sci.split_once('e').unwrap();
    let e: i32 = e.parse().unwrap();
    let exp = if (exp - e).abs() <= 1 { e } else { exp };
    if !(-4..6).contains(&exp) {
        let m = trim_zeros(mant);
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{m}e{sign}{:02}", exp.abs())
    } else {
        let decimals = (5 - exp).max(0) as usize;
        trim_zeros(&format!("{:.*}", decimals, f)).to_string()
    }
}

fn trim_zeros(s: &str) -> &str {
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.')
    } else {
        s
    }
}

pub fn is_ident(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'\'' || c == b'-')
        && !matches!(s, "if" | "then" | "else" | "assert" | "with" | "let" | "in" | "rec" | "inherit" | "or")
}

pub fn nix_string(s: &str, out: &mut String) {
    out.push('"');
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '$' if chars.peek() == Some(&'{') => out.push_str("\\$"),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Prints a value in Nix syntax. With `strict`, nested values are forced;
/// otherwise unevaluated parts print as `«thunk»`.
pub fn print_value(ev: &Eval, v: &Value, strict: bool) -> R<String> {
    let mut out = String::new();
    let mut seen = HashSet::new();
    print_inner(ev, v, strict, &mut out, &mut seen)?;
    Ok(out)
}

fn print_inner(ev: &Eval, v: &Value, strict: bool, out: &mut String, seen: &mut HashSet<usize>) -> R<()> {
    let v = if strict {
        ev.force(v)?
    } else {
        match v {
            Value::Thunk(t) => match t.peek() {
                Some(v) => v,
                _ => {
                    out.push_str("«thunk»");
                    return Ok(());
                }
            },
            v => v.clone(),
        }
    };
    match &v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(n) => write!(out, "{n}").unwrap(),
        Value::Float(f) => out.push_str(&fmt_float(*f)),
        Value::Str(s) => nix_string(&s.s, out),
        Value::Path(p) => out.push_str(p),
        Value::Lambda(_) => out.push_str("«lambda»"),
        Value::PrimOp(p) if p.args.is_empty() => write!(out, "«primop {}»", p.op.name).unwrap(),
        Value::PrimOp(p) => write!(out, "«partially applied primop {}»", p.op.name).unwrap(),
        Value::Thunk(_) => out.push_str("«thunk»"),
        Value::List(l) => {
            let id = Rc::as_ptr(l) as usize;
            if !seen.insert(id) {
                out.push_str("«repeated»");
                return Ok(());
            }
            out.push('[');
            for x in l.iter() {
                out.push(' ');
                print_inner(ev, x, strict, out, seen)?;
            }
            out.push_str(" ]");
            seen.remove(&id);
        }
        Value::Attrs(a) => {
            if ev.is_derivation(a)? {
                if let Some(p) = a.get(&ev.syms.drv_path) {
                    let p = ev.force_str(p)?;
                    write!(out, "«derivation {}»", p.s).unwrap();
                    return Ok(());
                }
            }
            let id = Rc::as_ptr(a) as usize;
            if !seen.insert(id) {
                out.push_str("«repeated»");
                return Ok(());
            }
            out.push('{');
            for (k, x) in a.iter() {
                out.push(' ');
                if is_ident(k.as_str()) {
                    out.push_str(k.as_str());
                } else {
                    nix_string(k.as_str(), out);
                }
                out.push_str(" = ");
                print_inner(ev, x, strict, out, seen)?;
                out.push(';');
            }
            out.push_str(" }");
            seen.remove(&id);
        }
    }
    Ok(())
}

pub fn json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => write!(out, "\\u{:04x}", c as u32).unwrap(),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A float as nlohmann/json writes it, which Nix uses: the shortest
/// digits that round-trip, in fixed notation for decimal exponents from
/// -4 to 15 and in exponent notation otherwise; `null` if not finite.
fn json_float(f: f64) -> String {
    if !f.is_finite() {
        return "null".into();
    }
    let sci = format!("{:e}", f.abs());
    let (mant, exp) = sci.split_once('e').unwrap();
    let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    let k = digits.len() as i32;
    // The value is 0.DIGITS × 10^n.
    let n = exp.parse::<i32>().unwrap() + 1;
    let sign = if f.is_sign_negative() { "-" } else { "" };
    let body = if k <= n && n <= 15 {
        format!("{digits}{}.0", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 15 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -4 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let m = if k == 1 { digits.clone() } else { format!("{}.{}", &digits[..1], &digits[1..]) };
        let e = n - 1;
        format!("{m}e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs())
    };
    format!("{sign}{body}")
}

/// `builtins.toJSON`; path values are copied to the store.
pub fn to_json(ev: &Eval, v: &Value, out: &mut String, ctx: &mut Context) -> R<()> {
    let v = ev.force(v)?;
    match &v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(n) => write!(out, "{n}").unwrap(),
        Value::Float(f) => out.push_str(&json_float(*f)),
        Value::Str(s) => {
            ctx.extend(s.ctx.iter().cloned());
            json_string(&s.s, out);
        }
        Value::Path(_) => {
            let s = ev.coerce_to_string(&v, &CoerceOpts { more: false, copy: true }, ctx)?;
            json_string(&s, out);
        }
        Value::List(l) => {
            out.push('[');
            for (i, x) in l.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                to_json(ev, x, out, ctx)?;
            }
            out.push(']');
        }
        Value::Attrs(a) => {
            if a.get(&ev.syms.to_string).is_some() {
                let s = ev.coerce_to_string(&v, &CoerceOpts { more: false, copy: true }, ctx)?;
                json_string(&s, out);
                return Ok(());
            }
            if let Some(p) = a.get(&ev.syms.out_path) {
                return to_json(ev, p, out, ctx);
            }
            out.push('{');
            for (i, (k, x)) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_string(k.as_str(), out);
                out.push(':');
                to_json(ev, x, out, ctx).map_err(|mut e| {
                    e.trace.push(format!("while evaluating attribute '{k}'"));
                    e
                })?;
            }
            out.push('}');
        }
        v => return err(format!("cannot convert {} to JSON", v.describe())),
    }
    Ok(())
}

pub fn from_json(s: &str) -> R<Value> {
    let j: serde_json::Value = serde_json::from_str(s).or_else(|e| err(format!("invalid JSON: {e}")))?;
    Ok(convert(j))
}

fn convert(j: serde_json::Value) -> Value {
    match j {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i),
            None => Value::Float(n.as_f64().unwrap_or(0.0)),
        },
        serde_json::Value::String(s) => Value::str(s),
        serde_json::Value::Array(a) => Value::list(a.into_iter().map(convert).collect()),
        serde_json::Value::Object(o) => {
            Value::attrs(Attrs::from_unsorted(o.into_iter().map(|(k, v)| (Sym::new(&k), convert(v))).collect()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fmt_float;

    #[test]
    fn floats_like_printf_g() {
        assert_eq!(fmt_float(0.1), "0.1");
        assert_eq!(fmt_float(1.0), "1");
        assert_eq!(fmt_float(3.14159265), "3.14159");
        assert_eq!(fmt_float(1e20), "1e+20");
        assert_eq!(fmt_float(123456.0), "123456");
        assert_eq!(fmt_float(1234567.0), "1.23457e+06");
        assert_eq!(fmt_float(0.0001), "0.0001");
        assert_eq!(fmt_float(0.00001), "1e-05");
    }

    #[test]
    fn json_floats_like_nlohmann() {
        use super::json_float;
        assert_eq!(json_float(1000.0), "1000.0");
        assert_eq!(json_float(-0.0), "-0.0");
        assert_eq!(json_float(0.1), "0.1");
        assert_eq!(json_float(3.14), "3.14");
        assert_eq!(json_float(1e100), "1e+100");
        assert_eq!(json_float(1e-7), "1e-07");
        assert_eq!(json_float(1.5e-7), "1.5e-07");
        assert_eq!(json_float(0.0001), "0.0001");
        assert_eq!(json_float(123456789.0), "123456789.0");
        assert_eq!(json_float(1e15), "1e+15");
        assert_eq!(json_float(1e14), "100000000000000.0");
        assert_eq!(json_float(1e16), "1e+16");
        assert_eq!(json_float(f64::INFINITY), "null");
        assert_eq!(json_float(f64::NAN), "null");
    }
}
