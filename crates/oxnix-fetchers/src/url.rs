//! URL parsing and printing with Nix's grammar and percent-encoding rules,
//! so that inputs print to the same strings as in Nix (`flake metadata`,
//! the `url` attribute of tarball and Git inputs).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::Result;

pub const PCT_ENCODED: &str = "(?:%[0-9a-fA-F][0-9a-fA-F])";
pub const SCHEME_NAME: &str = "(?:[a-z][a-z0-9+.-]*)";
const UNRESERVED: &str = "(?:[a-zA-Z0-9-._~])";
const SUBDELIMS: &str = "(?:[!$&'\"()*+,;=])";
pub const REF_REGEX: &str = r"[a-zA-Z0-9@][a-zA-Z0-9_.\/@+-]*";
pub const REV_REGEX: &str = "[0-9a-fA-F]{40}";
pub const FLAKE_ID_REGEX: &str = "[a-zA-Z][a-zA-Z0-9_-]*";

fn pchar() -> String {
    format!("(?:{UNRESERVED}|{PCT_ENCODED}|{SUBDELIMS}|[:@])")
}

pub fn query_regex() -> String {
    format!("(?:{}|[/? \"])*", pchar())
}

pub fn fragment_regex() -> String {
    format!("(?:{}|[/? \"^])*", pchar())
}

fn anchored(s: &str) -> Regex {
    Regex::new(&format!("^(?:{s})$")).expect("valid regex")
}

pub fn ref_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| anchored(REF_REGEX))
}

pub fn rev_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| anchored(REV_REGEX))
}

pub fn flake_id_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| anchored(FLAKE_ID_REGEX))
}

/// Git ref names that `git check-ref-format` would reject.
pub fn is_bad_git_ref(r: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    let re = R.get_or_init(|| {
        Regex::new(r"//|^[./]|/\.|\.\.|[[:cntrl:][:space:]:?^~\[]|\\|\*|\.lock$|\.lock/|@\{|[/.]$|^@$|^$").expect("valid regex")
    });
    re.is_match(r)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedUrl {
    pub url: String,
    /// The URL without query and fragment, as written.
    pub base: String,
    pub scheme: String,
    pub authority: Option<String>,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub fragment: String,
}

fn uri_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        let ipv6_seg = r"[0-9a-fA-F:]+(?:%\w+)?";
        let ipv6 = format!(r"(?:\[{ipv6_seg}\]|{ipv6_seg})");
        let hostname = format!("(?:(?:{UNRESERVED}|{PCT_ENCODED}|{SUBDELIMS})*)");
        let host = format!("(?:{ipv6}|{hostname})");
        let user = format!("(?:(?:{UNRESERVED}|{PCT_ENCODED}|{SUBDELIMS}|:)*)");
        let authority = format!("(?:{user}@)?{host}(?::[0-9]+)?");
        let segment = format!("(?:{}*)", pchar());
        let abs_path = format!("(?:(?:/{segment})*/?)");
        let path = format!("(?:{segment}(?:/{segment})*/?)");
        anchored(&format!(
            "(({SCHEME_NAME}):(?://({authority})({abs_path})|(/?{path})))(?:\\?({}))?(?:#({}))?",
            query_regex(),
            fragment_regex()
        ))
    })
}

/// Splits `tarball+https` into the application and transport schemes.
pub fn split_scheme(scheme: &str) -> (Option<&str>, &str) {
    match scheme.split_once('+') {
        Some((a, t)) => (Some(a), t),
        None => (None, scheme),
    }
}

pub fn parse_url(url: &str) -> Result<ParsedUrl> {
    let m = uri_regex().captures(url).ok_or_else(|| format!("'{url}' is not a valid URL"))?;
    let scheme = m[2].to_string();
    let authority = m.get(3).map(|a| a.as_str().to_string());
    let mut path = m.get(4).or(m.get(5)).map_or("", |p| p.as_str()).to_string();
    let transport_is_file = split_scheme(&scheme).1 == "file";
    if let Some(a) = &authority {
        if !a.is_empty() && transport_is_file {
            return Err(format!("file:// URL '{url}' has unexpected authority '{a}'"));
        }
    }
    if transport_is_file && path.is_empty() {
        path = "/".into();
    }
    Ok(ParsedUrl {
        url: url.to_string(),
        base: m[1].to_string(),
        scheme,
        authority,
        path: percent_decode(&path)?,
        query: decode_query(m.get(6).map_or("", |q| q.as_str()))?,
        fragment: percent_decode(m.get(7).map_or("", |f| f.as_str()))?,
    })
}

pub fn percent_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = s.get(i + 1..i + 3).filter(|_| i + 2 < b.len());
            match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                Some(c) => out.push(c),
                None => return Err(format!("invalid URI parameter '{s}'")),
            }
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("invalid URI parameter '{s}'"))
}

pub fn decode_query(q: &str) -> Result<BTreeMap<String, String>> {
    let mut m = BTreeMap::new();
    for s in q.split('&').filter(|s| !s.is_empty()) {
        if let Some((k, v)) = s.split_once('=') {
            m.entry(k.to_string()).or_insert(percent_decode(v)?);
        }
    }
    Ok(m)
}

pub fn percent_encode(s: &str, keep: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric() || b"-._~".contains(&c) || keep.as_bytes().contains(&c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

pub fn encode_query(q: &BTreeMap<String, String>) -> String {
    q.iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k, ":@/?"), percent_encode(v, ":@/?")))
        .collect::<Vec<_>>()
        .join("&")
}

impl ParsedUrl {
    pub fn new(scheme: &str, authority: Option<&str>, path: &str) -> ParsedUrl {
        ParsedUrl {
            scheme: scheme.into(),
            authority: authority.map(Into::into),
            path: path.into(),
            ..Default::default()
        }
    }

    /// `scheme:[//authority]path[?query][#fragment]`, percent-encoding the
    /// path, query and fragment.
    pub fn to_url_string(&self) -> String {
        let mut s = format!("{}:", self.scheme);
        if let Some(a) = &self.authority {
            s.push_str("//");
            s.push_str(a);
        }
        s.push_str(&percent_encode(&self.path, ":@/"));
        if !self.query.is_empty() {
            s.push('?');
            s.push_str(&encode_query(&self.query));
        }
        if !self.fragment.is_empty() {
            s.push('#');
            s.push_str(&percent_encode(&self.fragment, ""));
        }
        s
    }
}

/// Normalises scp-style (`git@host:path`) and plain-path Git URLs.
pub fn fix_git_url(url: &str) -> String {
    static SCP: OnceLock<Regex> = OnceLock::new();
    let scp = SCP.get_or_init(|| Regex::new("^([^/]*)@(.*):(.*)$").expect("valid regex"));
    if !url.starts_with('/') {
        if let Some(c) = scp.captures(url) {
            return format!("ssh://{}@{}/{}", &c[1], &c[2], &c[3]);
        }
    }
    if url.starts_with("file:") {
        return url.to_string();
    }
    if !url.contains("://") {
        return ParsedUrl::new("file", Some(""), url).to_url_string();
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let u = parse_url("git+https://example.org/a%20b.git?ref=main&rev=x#frag").unwrap();
        assert_eq!(u.scheme, "git+https");
        assert_eq!(u.authority.as_deref(), Some("example.org"));
        assert_eq!(u.path, "/a b.git");
        assert_eq!(u.query["ref"], "main");
        assert_eq!(u.fragment, "frag");
        assert_eq!(u.base, "git+https://example.org/a%20b.git");
        assert_eq!(u.to_url_string(), "git+https://example.org/a%20b.git?ref=main&rev=x#frag");
        let p = parse_url("github:NixOS/nixpkgs/nixos-24.05").unwrap();
        assert_eq!(p.path, "NixOS/nixpkgs/nixos-24.05");
        assert!(p.authority.is_none());
        let q = parse_url("path:/nix/store/x-source?narHash=sha256-VIA%3D").unwrap();
        assert_eq!(q.query["narHash"], "sha256-VIA=");
        assert_eq!(q.to_url_string(), "path:/nix/store/x-source?narHash=sha256-VIA%3D");
    }

    #[test]
    fn git_urls() {
        assert_eq!(fix_git_url("git@github.com:o/r.git"), "ssh://git@github.com/o/r.git");
        assert_eq!(fix_git_url("/tmp/repo"), "file:///tmp/repo");
        assert_eq!(fix_git_url("https://x/y"), "https://x/y");
        assert!(is_bad_git_ref("a..b"));
        assert!(!is_bad_git_ref("refs/heads/main"));
    }
}
