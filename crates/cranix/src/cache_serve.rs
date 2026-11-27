//! `cache serve`: answers `GET` and `HEAD` requests for the files of a
//! binary cache, so that clients that speak only HTTP, such as Nix, read
//! a registry cache.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use cranix_store::binary_cache::BinaryCache;
use cranix_store::registry::validate_rel;
use cranix_store::settings::Settings;
use cranix_store::substitute::open_cache;

const USAGE: &str = "usage: cranix cache serve [--listen ADDR:PORT] URL";

pub fn cmd_cache(settings: &Settings, args: &[String]) -> Result<(), String> {
    let Some((sub, rest)) = args.split_first() else { return Err(USAGE.into()) };
    if sub != "serve" {
        return Err(USAGE.into());
    }
    let mut listen = "127.0.0.1:5000".to_string();
    let mut url = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => listen = it.next().ok_or("--listen requires an argument")?.clone(),
            f if f.starts_with('-') => return Err(format!("cache serve: unknown flag '{f}'\n{USAGE}")),
            u if url.is_none() => url = Some(u.to_string()),
            _ => return Err(USAGE.into()),
        }
    }
    let url = url.ok_or(USAGE)?;
    let cache = Arc::new(open_cache(&url, settings)?);
    let listener = TcpListener::bind(&listen).map_err(|e| format!("listening on '{listen}': {e}"))?;
    let addr = listener.local_addr().map_err(|e| format!("listening on '{listen}': {e}"))?;
    println!("http://{addr}");
    let _ = std::io::stdout().flush();
    eprintln!("serving '{}' on http://{addr}", cache.shown());
    for conn in listener.incoming().flatten() {
        let cache = cache.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle(conn, &cache) {
                eprintln!("warning: {e}");
            }
        });
    }
    Ok(())
}

fn content_type(rel: &str) -> &'static str {
    if rel == "nix-cache-info" {
        "text/x-nix-cache-info"
    } else if rel.ends_with(".narinfo") {
        "text/x-nix-narinfo"
    } else if rel.starts_with("nar/") {
        "application/x-nix-nar"
    } else {
        "application/octet-stream"
    }
}

fn status_line(conn: &mut TcpStream, status: u16, reason: &str, extra: &str) -> std::io::Result<()> {
    write!(conn, "HTTP/1.1 {status} {reason}\r\nConnection: close\r\n{extra}\r\n")
}

fn handle(mut conn: TcpStream, cache: &BinaryCache) -> Result<(), String> {
    let io = |e: std::io::Error| format!("serving a request: {e}");
    let mut rd = BufReader::new(conn.try_clone().map_err(io)?);
    let mut line = String::new();
    rd.read_line(&mut line).map_err(io)?;
    loop {
        let mut h = String::new();
        if rd.read_line(&mut h).map_err(io)? == 0 || h.trim().is_empty() {
            break;
        }
    }
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
    let rel = target.split('?').next().unwrap_or("").trim_start_matches('/');
    if method != "GET" && method != "HEAD" {
        return status_line(&mut conn, 405, "Method Not Allowed", "Content-Length: 0\r\nAllow: GET, HEAD\r\n").map_err(io);
    }
    if validate_rel(rel).is_err() {
        return status_line(&mut conn, 400, "Bad Request", "Content-Length: 0\r\n").map_err(io);
    }
    let ct = format!("Content-Type: {}\r\n", content_type(rel));
    let fail = |conn: &mut TcpStream, e: String| {
        eprintln!("warning: {e}");
        status_line(conn, 502, "Bad Gateway", "Content-Length: 0\r\n").map_err(io)
    };
    if method == "HEAD" {
        return match cache.file_exists(rel) {
            Ok(true) => status_line(&mut conn, 200, "OK", &ct).map_err(io),
            Ok(false) => status_line(&mut conn, 404, "Not Found", "Content-Length: 0\r\n").map_err(io),
            Err(e) => fail(&mut conn, e),
        };
    }
    // NARs are streamed; small files are read first, so that a missing
    // one gets 404.
    if rel.starts_with("nar/") {
        if !matches!(cache.file_exists(rel), Ok(true)) {
            return status_line(&mut conn, 404, "Not Found", "Content-Length: 0\r\n").map_err(io);
        }
        let mut body = match cache.open_file(rel) {
            Ok(b) => b,
            Err(e) => return fail(&mut conn, e),
        };
        status_line(&mut conn, 200, "OK", &ct).map_err(io)?;
        std::io::copy(&mut body, &mut conn).map_err(io)?;
        return Ok(());
    }
    match cache.get_file(rel) {
        Ok(Some(d)) => {
            status_line(&mut conn, 200, "OK", &format!("{ct}Content-Length: {}\r\n", d.len())).map_err(io)?;
            conn.write_all(&d).map_err(io)
        }
        Ok(None) => status_line(&mut conn, 404, "Not Found", "Content-Length: 0\r\n").map_err(io),
        Err(e) => fail(&mut conn, e),
    }
}
