//! A fake S3 service for tests. It answers path-style requests
//! (`/BUCKET/KEY`) for `GET`, `HEAD` and `PUT` of objects and for
//! multipart uploads, and checks the AWS signature version 4 of every
//! request against one access key. Every request is logged.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use cranix_store::s3::{authorization, sha256_hex, Credentials, Request};

pub const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
pub const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

#[derive(Default)]
pub struct State {
    pub bucket: String,
    /// Objects by key.
    pub objects: BTreeMap<String, Vec<u8>>,
    /// Parts of unfinished multipart uploads, by upload ID and part number.
    uploads: BTreeMap<String, (String, BTreeMap<u32, Vec<u8>>)>,
    next: usize,
    /// `METHOD /path?query STATUS` of each request.
    pub log: Vec<String>,
}

pub struct S3Server {
    /// `127.0.0.1:<port>`.
    pub addr: String,
    pub state: Arc<Mutex<State>>,
}

impl S3Server {
    pub fn start(bucket: &str) -> S3Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let state = Arc::new(Mutex::new(State { bucket: bucket.into(), ..State::default() }));
        let s = state.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let s = s.clone();
                std::thread::spawn(move || {
                    let _ = handle(conn, &s);
                });
            }
        });
        S3Server { addr, state }
    }

    pub fn log(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }
}

struct Req {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    raw_query: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_request(conn: &mut TcpStream) -> std::io::Result<Req> {
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
            (unescape(k), unescape(v))
        })
        .collect();
    Ok(Req { method, path: path.to_string(), query, raw_query: q.to_string(), headers, body })
}

/// Whether `req` carries a valid signature by the test key.
fn signed(req: &Req) -> bool {
    let Some(auth) = req.headers.get("authorization") else { return false };
    let Some(date) = req.headers.get("x-amz-date") else { return false };
    let Some(payload) = req.headers.get("x-amz-content-sha256") else { return false };
    if *payload != sha256_hex(&req.body) {
        return false;
    }
    let Some(names) = auth.split("SignedHeaders=").nth(1).and_then(|s| s.split(',').next()) else { return false };
    let headers: Vec<(&str, &str)> = names.split(';').map(|n| (n, req.headers.get(n).map_or("", String::as_str))).collect();
    let query: Vec<(&str, &str)> = req.query.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let creds = Credentials { access_key: ACCESS_KEY.into(), secret_key: SECRET_KEY.into(), session_token: None };
    let want = authorization(&creds, "us-east-1", "s3", date, &Request { method: &req.method, path: &req.path, query: &query, headers: &headers, payload_hash: payload });
    *auth == want
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn reply(status: u16) -> Reply {
    Reply { status, headers: Vec::new(), body: Vec::new() }
}

fn error(status: u16, code: &str) -> Reply {
    Reply { status, headers: Vec::new(), body: format!("<Error><Code>{code}</Code></Error>").into_bytes() }
}

fn etag(data: &[u8]) -> String {
    format!("\"{}\"", &sha256_hex(data)[..32])
}

fn s3(st: &mut State, req: &Req) -> Reply {
    if !signed(req) {
        return error(403, "SignatureDoesNotMatch");
    }
    let rest = req.path.strip_prefix('/').unwrap_or("");
    let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
    if bucket != st.bucket {
        return error(404, "NoSuchBucket");
    }
    let key = unescape(key);
    let q = |n: &str| req.query.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    match (req.method.as_str(), q("uploads"), q("uploadId")) {
        ("GET" | "HEAD", None, None) => match st.objects.get(&key) {
            Some(d) => Reply { status: 200, headers: vec![("ETag".into(), etag(d))], body: d.clone() },
            None => error(404, "NoSuchKey"),
        },
        ("PUT", None, None) => {
            st.objects.insert(key, req.body.clone());
            Reply { status: 200, headers: vec![("ETag".into(), etag(&req.body))], body: Vec::new() }
        }
        ("POST", Some(_), None) => {
            st.next += 1;
            let id = format!("upload/{}", st.next);
            st.uploads.insert(id.clone(), (key, BTreeMap::new()));
            Reply { status: 200, headers: Vec::new(), body: format!("<InitiateMultipartUploadResult><UploadId>{id}</UploadId></InitiateMultipartUploadResult>").into_bytes() }
        }
        ("PUT", None, Some(id)) => {
            let n: u32 = q("partNumber").and_then(|n| n.parse().ok()).unwrap_or(0);
            let Some((_, parts)) = st.uploads.get_mut(&id) else { return error(404, "NoSuchUpload") };
            parts.insert(n, req.body.clone());
            Reply { status: 200, headers: vec![("ETag".into(), etag(&req.body))], body: Vec::new() }
        }
        ("POST", None, Some(id)) => {
            let Some((k, parts)) = st.uploads.remove(&id) else { return error(404, "NoSuchUpload") };
            let body = String::from_utf8_lossy(&req.body);
            let listed: Vec<String> = body.split("<ETag>").skip(1).map(|s| s.split("</ETag>").next().unwrap_or("").replace("&quot;", "\"")).collect();
            let want: Vec<String> = parts.values().map(|p| etag(p)).collect();
            if listed != want || parts.values().rev().skip(1).any(|p| p.len() < 5 << 20) {
                // Like S3, a failure after the request was accepted.
                return Reply { status: 200, headers: Vec::new(), body: b"<Error><Code>InvalidPart</Code></Error>".to_vec() };
            }
            st.objects.insert(k, parts.into_values().flatten().collect());
            Reply { status: 200, headers: Vec::new(), body: b"<CompleteMultipartUploadResult/>".to_vec() }
        }
        ("DELETE", None, Some(id)) => {
            st.uploads.remove(&id);
            reply(204)
        }
        _ => error(405, "MethodNotAllowed"),
    }
}

fn handle(mut conn: TcpStream, state: &Mutex<State>) -> std::io::Result<()> {
    let req = read_request(&mut conn)?;
    let rep = {
        let mut st = state.lock().unwrap();
        let rep = s3(&mut st, &req);
        let q = if req.raw_query.is_empty() { String::new() } else { format!("?{}", req.raw_query) };
        st.log.push(format!("{} {}{q} {}", req.method, req.path, rep.status));
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
