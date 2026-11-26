//! A small HTTP binary cache for tests: it serves the files under a
//! directory with `GET` and `HEAD` and stores `PUT` bodies there.
//!
//! It can require a bearer token, answer `503` to a number of requests
//! to exercise retries, refuse uploads whose path contains a given text,
//! and it records every request it handles.

#![allow(dead_code)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct Behaviour {
    /// Requests without `Authorization: Bearer <token>` get `401`.
    pub token: Option<String>,
    /// Answer `503` to this many of the next requests.
    pub unavailable: usize,
    /// Answer `500` to uploads whose path contains this text.
    pub fail_puts: Option<String>,
    /// `METHOD /path STATUS` of each request handled.
    pub log: Vec<String>,
}

pub struct CacheServer {
    pub url: String,
    pub root: PathBuf,
    pub state: Arc<Mutex<Behaviour>>,
}

impl CacheServer {
    /// Serves `root` on a free port of 127.0.0.1 from a background thread.
    pub fn start(root: &Path) -> CacheServer {
        CacheServer::start_on(root, 0)
    }

    pub fn start_on(root: &Path, port: u16) -> CacheServer {
        fs::create_dir_all(root).unwrap();
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(Behaviour::default()));
        let (r, s) = (root.to_path_buf(), state.clone());
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let (r, s) = (r.clone(), s.clone());
                std::thread::spawn(move || {
                    let _ = handle(conn, &r, &s);
                });
            }
        });
        CacheServer { url, root: root.to_path_buf(), state }
    }

    pub fn log(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }

    pub fn clear_log(&self) {
        self.state.lock().unwrap().log.clear();
    }
}

fn respond(conn: &mut TcpStream, status: u16, body: &[u8], head_only: bool) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
    write!(conn, "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
    if !head_only {
        conn.write_all(body)?;
    }
    conn.flush()
}

fn handle(mut conn: TcpStream, root: &Path, state: &Mutex<Behaviour>) -> std::io::Result<()> {
    let mut rd = BufReader::new(conn.try_clone()?);
    let mut line = String::new();
    rd.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("/").to_string());
    let mut len = 0usize;
    let mut auth = None;
    let mut expect_continue = false;
    loop {
        let mut h = String::new();
        if rd.read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        let (k, v) = h.split_once(':').unwrap_or((&h, ""));
        let v = v.trim();
        match k.to_ascii_lowercase().as_str() {
            "content-length" => len = v.parse().unwrap_or(0),
            "authorization" => auth = Some(v.to_string()),
            "expect" => expect_continue = v.eq_ignore_ascii_case("100-continue"),
            _ => {}
        }
    }
    let path = target.split('?').next().unwrap_or("/").to_string();
    let status = {
        let mut st = state.lock().unwrap();
        if st.unavailable > 0 {
            st.unavailable -= 1;
            Some(503)
        } else if st.token.as_ref().is_some_and(|t| auth.as_deref() != Some(&format!("Bearer {t}"))) {
            Some(401)
        } else if method == "PUT" && st.fail_puts.as_ref().is_some_and(|f| path.contains(f.as_str())) {
            Some(500)
        } else {
            None
        }
    };
    let rel = path.trim_start_matches('/');
    let bad = rel.split('/').any(|c| c == ".." || c.is_empty() && !rel.is_empty());
    let file = root.join(rel);
    let (status, body) = match (status, method.as_str()) {
        (Some(s), _) => (s, Vec::new()),
        _ if bad => (400, Vec::new()),
        (None, "GET" | "HEAD") => match fs::read(&file) {
            Ok(d) if file.is_file() => (200, d),
            _ => (404, Vec::new()),
        },
        (None, "PUT") => {
            if expect_continue {
                conn.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            }
            let mut data = vec![0; len];
            rd.read_exact(&mut data)?;
            fs::create_dir_all(file.parent().unwrap())?;
            let tmp = file.with_extension("upload-tmp");
            fs::write(&tmp, &data)?;
            fs::rename(&tmp, &file)?;
            (201, Vec::new())
        }
        _ => (405, Vec::new()),
    };
    // Drain an upload that was refused, so curl sees the answer.
    if method == "PUT" && status != 201 && !expect_continue {
        let _ = std::io::copy(&mut rd.by_ref().take(len as u64), &mut std::io::sink());
    }
    state.lock().unwrap().log.push(format!("{method} {path} {status}"));
    respond(&mut conn, status, &body, method == "HEAD")
}
