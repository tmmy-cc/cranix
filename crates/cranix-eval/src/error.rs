//! Evaluation errors: their source positions, the trace of frames that
//! were active when they were raised, and rendering them for the terminal
//! with code snippets, in the layout Nix uses.

use std::collections::{HashSet, VecDeque};
use std::fmt::{self, Write as _};

use crate::ast::Pos;
use crate::eval::Eval;
use crate::print::{fmt_float, is_ident, nix_string};
use crate::value::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrKind {
    /// `throw`; catchable by `tryEval`.
    Throw,
    /// Failed `assert`; catchable by `tryEval`.
    Assert,
    Abort,
    Other,
}

/// One step of the evaluation that was in progress when an error was
/// raised ("while calling the 'map' builtin").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Frame {
    pub msg: String,
    pub pos: Option<Pos>,
    /// Shown only with `--show-trace`: frames that every function call or
    /// branch adds and that rarely help locating the problem.
    pub detail: bool,
}

impl Frame {
    pub fn new(msg: impl Into<String>, pos: Option<Pos>) -> Frame {
        Frame { msg: msg.into(), pos, detail: false }
    }

    pub fn detail(msg: impl Into<String>, pos: Option<Pos>) -> Frame {
        Frame { msg: msg.into(), pos, detail: true }
    }
}

impl From<String> for Frame {
    fn from(msg: String) -> Frame {
        Frame::new(msg, None)
    }
}

impl From<&str> for Frame {
    fn from(msg: &str) -> Frame {
        Frame::new(msg, None)
    }
}

/// Frames in the order they were added, innermost first. Deep recursion
/// can add an unbounded number of frames, so only the innermost and the
/// outermost `KEEP` are stored.
#[derive(Debug, Clone, Default)]
pub struct Trace {
    inner: Vec<Frame>,
    outer: VecDeque<Frame>,
    dropped: usize,
}

const KEEP: usize = 256;

impl Trace {
    pub fn push(&mut self, f: impl Into<Frame>) {
        if self.inner.len() < KEEP {
            self.inner.push(f.into());
            return;
        }
        if self.outer.len() == KEEP {
            self.outer.pop_front();
            self.dropped += 1;
        }
        self.outer.push_back(f.into());
    }

    pub fn len(&self) -> usize {
        self.inner.len() + self.outer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Frames innermost first.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Frame> {
        self.inner.iter().chain(self.outer.iter())
    }

    /// Number of frames between the stored innermost and outermost ones
    /// that were discarded.
    pub fn dropped(&self) -> usize {
        self.dropped
    }
}

#[derive(Debug, Clone)]
pub struct EvalError {
    pub kind: ErrKind,
    pub msg: String,
    /// Where the error was raised, when that is known.
    pub pos: Option<Pos>,
    /// Advice printed after the message ("Did you mean foo?").
    pub hint: Option<String>,
    pub trace: Trace,
}

impl EvalError {
    pub fn new(kind: ErrKind, msg: impl Into<String>) -> EvalError {
        EvalError { kind, msg: msg.into(), pos: None, hint: None, trace: Trace::default() }
    }
}

/// Plain one-line-per-frame rendering for contexts without access to the
/// sources; `Eval::render_error` is the full form.
impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for t in self.trace.iter().rev() {
            writeln!(f, "       … {}", t.msg)?;
        }
        write!(f, "error: {}", self.msg)?;
        if let Some(h) = &self.hint {
            write!(f, "\n       {h}")?;
        }
        Ok(())
    }
}

pub type R<T> = Result<T, Box<EvalError>>;

pub fn err<T>(msg: impl Into<String>) -> R<T> {
    Err(Box::new(EvalError::new(ErrKind::Other, msg)))
}

pub fn err_kind<T>(kind: ErrKind, msg: impl Into<String>) -> R<T> {
    Err(Box::new(EvalError::new(kind, msg)))
}

/// An error raised at `pos`.
pub fn err_at<T>(pos: Pos, msg: impl Into<String>) -> R<T> {
    let mut e = EvalError::new(ErrKind::Other, msg);
    e.pos = Some(pos);
    Err(Box::new(e))
}

/// An error with advice for fixing it.
pub fn err_hint<T>(pos: Option<Pos>, msg: impl Into<String>, hint: Option<String>) -> R<T> {
    let mut e = EvalError::new(ErrKind::Other, msg);
    e.pos = pos;
    e.hint = hint;
    Err(Box::new(e))
}

// ---- suggestions ----

pub fn levenshtein(a: &str, b: &str) -> usize {
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

/// Up to three of `candidates` that are plausible misspellings of `name`,
/// closest first. The allowed edit distance grows with the name's length
/// so that one-letter names do not match every other one-letter name.
pub fn close_matches<'a>(name: &str, candidates: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let max = (name.chars().count() + 1) / 3;
    let mut found: Vec<(usize, &str)> = candidates
        .into_iter()
        .filter(|c| *c != name)
        .map(|c| (levenshtein(name, c), c))
        .filter(|(d, _)| *d <= max.max(1))
        .collect();
    found.sort();
    found.dedup();
    found.into_iter().take(3).map(|(_, c)| c).collect()
}

/// "a", "a or b", "a, b or c".
pub fn or_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [a] => a.to_string(),
        [init @ .., last] => format!("{} or {last}", init.join(", ")),
    }
}

/// "a", "a and b", "a, b and c"; long lists are cut after ten items.
pub fn and_list(items: &[&str]) -> String {
    let shown: Vec<String> = items.iter().take(10).map(|s| format!("'{s}'")).collect();
    match (shown.as_slice(), items.len()) {
        ([], _) => String::new(),
        ([a], _) => a.clone(),
        (s, n) if n > 10 => format!("{} and {} more", s.join(", "), n - 10),
        ([init @ .., last], _) => format!("{} and {last}", init.join(", ")),
    }
}

/// "Did you mean foo?" for the close matches, if there are any.
pub fn did_you_mean<'a>(name: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let close = close_matches(name, candidates);
    match close.len() {
        0 => None,
        1 => Some(format!("Did you mean {}?", close[0])),
        _ => Some(format!("Did you mean one of {}?", or_list(&close))),
    }
}

// ---- rendering ----

pub struct RenderOptions {
    /// Show every frame, detail frames included.
    pub show_trace: bool,
    pub color: bool,
}

/// Frames shown from each end of the trace without `--show-trace`.
const SHORT_TRACE_ENDS: usize = 2;

const INDENT: &str = "       ";

struct Style {
    on: bool,
}

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn red(&self, s: &str) -> String {
        self.paint("31;1", s)
    }
    fn magenta(&self, s: &str) -> String {
        self.paint("35;1", s)
    }
    fn blue(&self, s: &str) -> String {
        self.paint("34;1", s)
    }
    fn yellow(&self, s: &str) -> String {
        self.paint("33;1", s)
    }
    fn faint(&self, s: &str) -> String {
        self.paint("2", s)
    }
}

enum Item<'a> {
    Frame(&'a Frame),
    /// Repeats of frames that were already shown.
    Duplicates(usize),
    /// Frames left out of a short trace.
    Truncated(usize),
}

impl Eval {
    /// Renders an error as Nix does: the trace from the outermost frame
    /// inwards, then the message, each with the source line it refers to.
    pub fn render_error(&self, e: &EvalError, o: &RenderOptions) -> String {
        let st = Style { on: o.color };
        let items = select_frames(e, o.show_trace);
        let mut out = String::new();
        if items.is_empty() {
            write!(out, "{} {}", st.red("error:"), indent_rest(&e.msg)).unwrap();
            self.render_pos(&mut out, e.pos, INDENT, &st);
        } else {
            writeln!(out, "{}", st.red("error:")).unwrap();
            for it in items {
                match it {
                    Item::Frame(f) => {
                        write!(out, "{INDENT}{} {}", st.faint("…"), indent_rest(&f.msg)).unwrap();
                        self.render_pos(&mut out, f.pos, "         ", &st);
                        out.push_str("\n\n");
                    }
                    Item::Duplicates(n) => {
                        let s = format!("({n} duplicate frame{} omitted)", if n == 1 { "" } else { "s" });
                        write!(out, "{INDENT}{}\n\n", st.yellow(&s)).unwrap();
                    }
                    Item::Truncated(n) => {
                        let s = format!(
                            "({n} frame{} omitted; use '--show-trace' to show the full, detailed trace)",
                            if n == 1 { "" } else { "s" }
                        );
                        write!(out, "{INDENT}{}\n\n", st.yellow(&s)).unwrap();
                    }
                }
            }
            write!(out, "{INDENT}{} {}", st.red("error:"), indent_rest(&e.msg)).unwrap();
            self.render_pos(&mut out, e.pos, INDENT, &st);
        }
        if let Some(h) = &e.hint {
            write!(out, "\n{INDENT}{}", indent_rest(h)).unwrap();
        }
        out
    }

    /// Appends `at FILE:LINE:COL:` and the lines around it, with a caret
    /// under the column.
    fn render_pos(&self, out: &mut String, pos: Option<Pos>, at_indent: &str, st: &Style) {
        let Some(pos) = pos else { return };
        let files = self.files.borrow();
        let Some((name, src)) = files.get(pos.file as usize) else { return };
        let (_, line, col) = self.pos_info(pos);
        write!(out, "\n{at_indent}at {}:", st.magenta(&format!("{name}:{line}:{col}"))).unwrap();
        let lines: Vec<&str> = src.split('\n').collect();
        let gutter = |n: usize| format!("{n:>13}|");
        let first = line.saturating_sub(1).max(1);
        let last = (line + 1).min(lines.len());
        for n in first..=last {
            let text = lines[n - 1].trim_end_matches('\r');
            write!(out, "\n{} {text}", st.blue(&gutter(n))).unwrap();
            if n == line {
                // Tabs keep their width so the caret lines up.
                let pad: String = text.chars().take(col - 1).map(|c| if c == '\t' { '\t' } else { ' ' }).collect();
                write!(out, "\n{} {pad}{}", st.blue(&format!("{:>14}", "|")), st.red("^")).unwrap();
            }
        }
    }

    /// A short rendering of a value for error messages. Nothing is forced:
    /// unevaluated parts print as `«thunk»`, and long strings, lists and
    /// sets are cut short.
    pub fn preview(&self, v: &Value) -> String {
        let mut out = String::new();
        self.preview_inner(v, 0, &mut out);
        out
    }

    fn preview_inner(&self, v: &Value, depth: usize, out: &mut String) {
        const MAX_DEPTH: usize = 3;
        const MAX_ITEMS: usize = 10;
        const MAX_STRING: usize = 1024;
        let v = match v {
            Value::Thunk(t) => match t.peek() {
                Some(v) => v,
                None => {
                    out.push_str("«thunk»");
                    return;
                }
            },
            v => v.clone(),
        };
        match &v {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Int(n) => write!(out, "{n}").unwrap(),
            Value::Float(f) => out.push_str(&fmt_float(*f)),
            Value::Str(s) if s.s.len() > MAX_STRING => {
                let mut cut = MAX_STRING;
                while !s.s.is_char_boundary(cut) {
                    cut -= 1;
                }
                nix_string(&s.s[..cut], out);
                write!(out, "«{} bytes elided»", s.s.len() - cut).unwrap();
            }
            Value::Str(s) => nix_string(&s.s, out),
            Value::Path(p) => out.push_str(p),
            Value::Lambda(c) => {
                out.push_str("«lambda ");
                if let Some(n) = &c.def.name {
                    write!(out, "{n} ").unwrap();
                }
                write!(out, "@ {}»", self.fmt_pos(c.def.pos)).unwrap();
            }
            Value::PrimOp(p) if p.args.is_empty() => write!(out, "«primop {}»", p.op.name).unwrap(),
            Value::PrimOp(p) => write!(out, "«partially applied primop {}»", p.op.name).unwrap(),
            Value::Thunk(_) => out.push_str("«thunk»"),
            Value::List(l) if l.is_empty() => out.push_str("[ ]"),
            Value::List(_) if depth >= MAX_DEPTH => out.push_str("[ … ]"),
            Value::List(l) => {
                out.push('[');
                for x in l.iter().take(MAX_ITEMS) {
                    out.push(' ');
                    self.preview_inner(x, depth + 1, out);
                }
                if l.len() > MAX_ITEMS {
                    write!(out, " «{} items elided»", l.len() - MAX_ITEMS).unwrap();
                }
                out.push_str(" ]");
            }
            Value::Attrs(a) => {
                let is_drv = a.get(&self.syms.ty).and_then(|t| match t {
                    Value::Thunk(t) => t.peek(),
                    v => Some(v.clone()),
                });
                if matches!(is_drv, Some(Value::Str(s)) if s.s == "derivation") {
                    out.push_str("«derivation»");
                    return;
                }
                if a.is_empty() {
                    out.push_str("{ }");
                    return;
                }
                if depth >= MAX_DEPTH {
                    out.push_str("{ … }");
                    return;
                }
                out.push('{');
                for (k, x) in a.iter().take(MAX_ITEMS) {
                    out.push(' ');
                    if is_ident(k.as_str()) {
                        out.push_str(k.as_str());
                    } else {
                        nix_string(k.as_str(), out);
                    }
                    out.push_str(" = ");
                    self.preview_inner(x, depth + 1, out);
                    out.push(';');
                }
                if a.len() > MAX_ITEMS {
                    write!(out, " «{} attributes elided»", a.len() - MAX_ITEMS).unwrap();
                }
                out.push_str(" }");
            }
        }
    }

    /// "expected a list but found an integer: 5".
    pub fn type_error<T>(&self, expected: &str, v: &Value) -> R<T> {
        err(format!("expected {expected} but found {}: {}", v.describe(), self.preview(v)))
    }
}

/// Continuation lines of a multi-line message line up with its first line.
fn indent_rest(s: &str) -> String {
    s.replace('\n', &format!("\n{INDENT}"))
}

/// The frames to print, outermost first. Frames repeating one already shown
/// are collapsed into a count. Without `show_trace`, detail frames are
/// left out and only the ends of a long trace are kept.
fn select_frames(e: &EvalError, show_trace: bool) -> Vec<Item<'_>> {
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    let mut dups = 0;
    let n_outer = e.trace.len() - e.trace.inner.len();
    for (i, f) in e.trace.iter().rev().enumerate() {
        if show_trace && i == n_outer && e.trace.dropped() > 0 {
            items.push(Item::Truncated(e.trace.dropped()));
        }
        if f.msg.is_empty() || (!show_trace && f.detail) {
            continue;
        }
        if !seen.insert((&f.msg, f.pos)) {
            dups += 1;
            continue;
        }
        if dups > 0 {
            items.push(Item::Duplicates(dups));
            dups = 0;
        }
        items.push(Item::Frame(f));
    }
    if dups > 0 {
        items.push(Item::Duplicates(dups));
    }
    if !show_trace {
        let frames: Vec<usize> = (0..items.len()).filter(|&i| matches!(items[i], Item::Frame(_))).collect();
        if frames.len() > 2 * SHORT_TRACE_ENDS + 1 {
            let cut_from = frames[SHORT_TRACE_ENDS];
            let cut_to = frames[frames.len() - SHORT_TRACE_ENDS];
            let mut omitted = 0;
            for it in &items[cut_from..cut_to] {
                match it {
                    Item::Frame(_) => omitted += 1,
                    Item::Duplicates(n) => omitted += n,
                    Item::Truncated(n) => omitted += n,
                }
            }
            items.splice(cut_from..cut_to, [Item::Truncated(omitted)]);
        }
    }
    items
}
