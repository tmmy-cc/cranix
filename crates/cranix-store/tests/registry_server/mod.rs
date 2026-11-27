//! A fake package registry for tests. It answers the GitLab generic
//! package API under `/api/v4/projects/<id>/packages/generic/` and the
//! OCI distribution API under `/v2/`, with a token endpoint at `/token`.
//!
//! GitLab requests carry `PRIVATE-TOKEN`; reads need the read or the write
//! token, uploads the write token. The token endpoint hands out bearer
//! tokens for `pull` to either token and for `pull,push` to the write
//! token, given as the password of basic authentication. Names are checked
//! the way the real services check them, and every request is logged.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use cranix_core::hash::{base64_decode, Hash};

#[derive(Default)]
pub struct State {
    pub read_token: Option<String>,
    pub write_token: Option<String>,
    /// GitLab files by `<project>/<package>/<version>/<file>`.
    pub generic: BTreeMap<String, Vec<u8>>,
    /// OCI blobs by `<repository>@<digest>`.
    pub blobs: BTreeMap<String, Vec<u8>>,
    /// OCI manifests by `<repository>:<tag>`.
    pub manifests: BTreeMap<String, Vec<u8>>,
    uploads: BTreeMap<String, String>,
    next: usize,
    /// `METHOD /path STATUS` of each request handled.
    pub log: Vec<String>,
}

pub struct RegistryServer {
    /// `127.0.0.1:<port>`.
    pub addr: String,
    pub state: Arc<Mutex<State>>,
}

impl RegistryServer {
    pub fn start(read_token: Option<&str>, write_token: Option<&str>) -> RegistryServer {
        RegistryServer::start_on(0, read_token, write_token)
    }

    pub fn start_on(port: u16, read_token: Option<&str>, write_token: Option<&str>) -> RegistryServer {
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let state = Arc::new(Mutex::new(State {
            read_token: read_token.map(str::to_string),
            write_token: write_token.map(str::to_string),
            ..State::default()
        }));
        let s = state.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let s = s.clone();
                std::thread::spawn(move || {
                    let _ = handle(conn, &s);
                });
            }
        });
        RegistryServer { addr, state }
    }

    pub fn log(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }
}

struct Request {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn reply(status: u16) -> Reply {
    Reply { status, headers: Vec::new(), body: Vec::new() }
}

fn oci_error(status: u16, code: &str) -> Reply {
    let body = format!(r#"{{"errors":[{{"code":"{code}","message":"{}"}}]}}"#, code.to_lowercase().replace('_', " "));
    Reply { status, headers: vec![("Content-Type".into(), "application/json".into())], body: body.into_bytes() }
}

fn read_request(conn: &mut TcpStream) -> std::io::Result<Request> {
    let mut rd = BufReader::new(conn.try_clone()?);
    let mut line = String::new();
    rd.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut headers = BTreeMap::new();
    loop {
        let mut h = String::new();
        if rd.read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    if headers.get("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
        conn.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    }
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = vec![0; len];
    rd.read_exact(&mut body)?;
    let (path, q) = target.split_once('?').unwrap_or((&target, ""));
    let query = q
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (k.to_string(), v.to_string())
        })
        .collect();
    Ok(Request { method, path: path.to_string(), query, headers, body })
}

fn handle(mut conn: TcpStream, state: &Mutex<State>) -> std::io::Result<()> {
    let req = read_request(&mut conn)?;
    let rep = {
        let mut st = state.lock().unwrap();
        let rep = if let Some(rest) = req.path.strip_prefix("/api/v4/projects/") {
            gitlab(&mut st, &req, rest)
        } else if req.path == "/token" {
            token(&st, &req)
        } else if let Some(rest) = req.path.strip_prefix("/v2/") {
            oci(&mut st, &req, rest)
        } else {
            reply(404)
        };
        st.log.push(format!("{} {} {}", req.method, req.path, rep.status));
        rep
    };
    let mut head = format!("HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n", rep.status, rep.body.len());
    for (k, v) in &rep.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    conn.write_all(head.as_bytes())?;
    if req.method != "HEAD" {
        conn.write_all(&rep.body)?;
    }
    conn.flush()
}

/// GitLab's rules for generic package names, versions and file names.
fn gitlab_name_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '~')) && s != "." && s != ".."
}

fn gitlab(st: &mut State, req: &Request, rest: &str) -> Reply {
    let Some((project, rest)) = rest.split_once("/packages/generic/") else { return reply(404) };
    if project.contains('/') {
        return reply(404);
    }
    let parts: Vec<&str> = rest.split('/').collect();
    let [package, version, file] = parts.as_slice() else { return reply(400) };
    if !parts.iter().all(|p| gitlab_name_ok(p)) {
        return reply(400);
    }
    let token = req.headers.get("private-token").map(String::as_str);
    let is = |t: &Option<String>| t.is_none() || t.as_deref() == token;
    let key = format!("{project}/{package}/{version}/{file}");
    match req.method.as_str() {
        "GET" | "HEAD" => {
            if !(is(&st.read_token) || is(&st.write_token)) {
                return reply(if token.is_some() { 403 } else { 401 });
            }
            match st.generic.get(&key) {
                Some(d) => Reply { status: 200, headers: Vec::new(), body: d.clone() },
                None => reply(404),
            }
        }
        "PUT" => {
            if !is(&st.write_token) {
                return reply(if token.is_some() { 403 } else { 401 });
            }
            st.generic.insert(key, req.body.clone());
            Reply { status: 201, headers: Vec::new(), body: br#"{"message":"201 Created"}"#.to_vec() }
        }
        _ => reply(405),
    }
}

fn token(st: &State, req: &Request) -> Reply {
    let scope = req.query.get("scope").cloned().unwrap_or_default();
    let push = scope.ends_with(":pull,push") || scope.ends_with(":push");
    let password = req
        .headers
        .get("authorization")
        .and_then(|a| a.strip_prefix("Basic "))
        .and_then(base64_decode)
        .and_then(|d| String::from_utf8(d).ok())
        .and_then(|up| up.split_once(':').map(|(_, p)| p.to_string()));
    let is = |t: &Option<String>| t.is_none() || t.as_deref() == password.as_deref();
    let allowed = if push { is(&st.write_token) } else { is(&st.read_token) || is(&st.write_token) };
    if !allowed {
        return oci_error(401, "UNAUTHORIZED");
    }
    let repo = scope.strip_prefix("repository:").and_then(|s| s.rsplit_once(':')).map_or("", |(r, _)| r);
    let bearer = format!("{}.{repo}", if push { "push" } else { "pull" });
    Reply { status: 200, headers: Vec::new(), body: serde_json::json!({ "token": bearer }).to_string().into_bytes() }
}

/// Whether the bearer token of `req` allows `push` (or only pull) on `repo`.
fn bearer_ok(req: &Request, repo: &str, push: bool) -> bool {
    let Some(t) = req.headers.get("authorization").and_then(|a| a.strip_prefix("Bearer ")) else { return false };
    t == format!("push.{repo}") || !push && t == format!("pull.{repo}")
}

fn oci_repo_ok(r: &str) -> bool {
    r.split('/').all(|c| !c.is_empty() && c.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-')))
}

fn oci_tag_ok(t: &str) -> bool {
    t.len() <= 128
        && t.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        && t.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn digest(data: &[u8]) -> String {
    format!("sha256:{}", Hash::sha256(data).to_base16())
}

fn oci(st: &mut State, req: &Request, rest: &str) -> Reply {
    let (repo, kind, arg) = if let Some((r, a)) = rest.split_once("/blobs/uploads/") {
        (r, "upload", a)
    } else if let Some((r, a)) = rest.split_once("/blobs/") {
        (r, "blob", a)
    } else if let Some((r, a)) = rest.split_once("/manifests/") {
        (r, "manifest", a)
    } else {
        return reply(404);
    };
    if !oci_repo_ok(repo) {
        return oci_error(400, "NAME_INVALID");
    }
    let push = !matches!(req.method.as_str(), "GET" | "HEAD");
    if !bearer_ok(req, repo, push) {
        return oci_error(401, "UNAUTHORIZED");
    }
    match (kind, req.method.as_str()) {
        ("blob", "GET" | "HEAD") => match st.blobs.get(&format!("{repo}@{arg}")) {
            Some(d) => Reply { status: 200, headers: vec![("Docker-Content-Digest".into(), arg.into())], body: d.clone() },
            None => oci_error(404, "BLOB_UNKNOWN"),
        },
        ("upload", "POST") if arg.is_empty() => {
            st.next += 1;
            let id = format!("u{}", st.next);
            st.uploads.insert(id.clone(), repo.to_string());
            Reply { status: 202, headers: vec![("Location".into(), format!("/v2/{repo}/blobs/uploads/{id}"))], body: Vec::new() }
        }
        ("upload", "PUT") => {
            if st.uploads.remove(arg).as_deref() != Some(repo) {
                return oci_error(404, "BLOB_UPLOAD_UNKNOWN");
            }
            let want = req.query.get("digest").cloned().unwrap_or_default();
            if digest(&req.body) != want {
                return oci_error(400, "DIGEST_INVALID");
            }
            st.blobs.insert(format!("{repo}@{want}"), req.body.clone());
            Reply { status: 201, headers: vec![("Location".into(), format!("/v2/{repo}/blobs/{want}"))], body: Vec::new() }
        }
        ("manifest", "GET" | "HEAD") => match st.manifests.get(&format!("{repo}:{arg}")) {
            Some(d) => Reply {
                status: 200,
                headers: vec![("Content-Type".into(), "application/vnd.oci.image.manifest.v1+json".into())],
                body: d.clone(),
            },
            None => oci_error(404, "MANIFEST_UNKNOWN"),
        },
        ("manifest", "PUT") => {
            if !oci_tag_ok(arg) {
                return oci_error(400, "TAG_INVALID");
            }
            let Ok(m) = serde_json::from_slice::<serde_json::Value>(&req.body) else { return oci_error(400, "MANIFEST_INVALID") };
            let mut refs = vec![m["config"]["digest"].as_str().unwrap_or("").to_string()];
            refs.extend(m["layers"].as_array().into_iter().flatten().map(|l| l["digest"].as_str().unwrap_or("").to_string()));
            if refs.iter().any(|d| !st.blobs.contains_key(&format!("{repo}@{d}"))) {
                return oci_error(400, "MANIFEST_BLOB_UNKNOWN");
            }
            st.manifests.insert(format!("{repo}:{arg}"), req.body.clone());
            reply(201)
        }
        _ => oci_error(405, "UNSUPPORTED"),
    }
}
