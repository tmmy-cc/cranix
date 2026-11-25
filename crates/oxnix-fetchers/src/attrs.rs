//! Input attributes: the string, integer and Boolean map that describes a
//! fetcher input, as stored in lock files and the fetcher cache.

use std::collections::BTreeMap;

use serde_json::Value as Json;

use crate::Result;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attr {
    Str(String),
    Int(u64),
    Bool(bool),
}

impl From<&str> for Attr {
    fn from(s: &str) -> Attr {
        Attr::Str(s.to_string())
    }
}
impl From<String> for Attr {
    fn from(s: String) -> Attr {
        Attr::Str(s)
    }
}
impl From<u64> for Attr {
    fn from(n: u64) -> Attr {
        Attr::Int(n)
    }
}
impl From<bool> for Attr {
    fn from(b: bool) -> Attr {
        Attr::Bool(b)
    }
}

pub type Attrs = BTreeMap<String, Attr>;

pub fn to_json(a: &Attrs) -> Json {
    let mut m = serde_json::Map::new();
    for (k, v) in a {
        let j = match v {
            Attr::Str(s) => Json::String(s.clone()),
            Attr::Int(n) => Json::from(*n),
            Attr::Bool(b) => Json::Bool(*b),
        };
        m.insert(k.clone(), j);
    }
    Json::Object(m)
}

pub fn to_json_string(a: &Attrs) -> String {
    to_json(a).to_string()
}

pub fn from_json(j: &Json) -> Result<Attrs> {
    let obj = j.as_object().ok_or("input attributes must be an object")?;
    let mut a = Attrs::new();
    for (k, v) in obj {
        let x = match v {
            Json::String(s) => Attr::Str(s.clone()),
            Json::Bool(b) => Attr::Bool(*b),
            Json::Number(n) => Attr::Int(n.as_u64().or_else(|| n.as_f64().map(|f| f as u64)).unwrap_or(0)),
            _ => return Err("unsupported input attribute type in lock file".into()),
        };
        a.insert(k.clone(), x);
    }
    Ok(a)
}

pub fn get_str(a: &Attrs, k: &str) -> Result<Option<String>> {
    match a.get(k) {
        None => Ok(None),
        Some(Attr::Str(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("input attribute '{k}' is not a string {}", to_json_string(a))),
    }
}

pub fn req_str(a: &Attrs, k: &str) -> Result<String> {
    get_str(a, k)?.ok_or_else(|| format!("input attribute '{k}' is missing"))
}

pub fn get_int(a: &Attrs, k: &str) -> Result<Option<u64>> {
    match a.get(k) {
        None => Ok(None),
        Some(Attr::Int(n)) => Ok(Some(*n)),
        Some(_) => Err(format!("input attribute '{k}' is not an integer")),
    }
}

pub fn get_bool(a: &Attrs, k: &str) -> Result<Option<bool>> {
    match a.get(k) {
        None => Ok(None),
        Some(Attr::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(format!("input attribute '{k}' is not a Boolean")),
    }
}

/// Query parameters for an input's URL form; Booleans become `0`/`1`.
pub fn to_query(a: &Attrs) -> BTreeMap<String, String> {
    a.iter()
        .map(|(k, v)| {
            let s = match v {
                Attr::Str(s) => s.clone(),
                Attr::Int(n) => n.to_string(),
                Attr::Bool(b) => (if *b { "1" } else { "0" }).to_string(),
            };
            (k.clone(), s)
        })
        .collect()
}
