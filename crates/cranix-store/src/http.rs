//! HTTP requests for binary caches, made by running curl.
//!
//! A [`HttpClient`] carries what every request to one cache shares: extra
//! headers (for example `Authorization`), a netrc file and how often a
//! request that failed in a transient way is retried. Headers are passed
//! to curl on its standard input, so tokens never show up in the process
//! list.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::Duration;

use crate::binary_cache::redact_url;
use crate::Result;

#[derive(Clone, Debug)]
pub struct HttpClient {
    headers: Vec<(String, String)>,
    netrc_file: Option<PathBuf>,
    /// How many times a request is tried in all.
    attempts: u32,
    /// Delay before the first retry; it doubles with each further one.
    retry_delay: Duration,
}

impl Default for HttpClient {
    fn default() -> Self {
        HttpClient { headers: Vec::new(), netrc_file: None, attempts: 5, retry_delay: Duration::from_millis(250) }
    }
}

/// The status, headers and body of a finished request.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    /// The headers of the last response, by lower-case name.
    pub headers: BTreeMap<String, Vec<String>>,
}

impl Response {
    /// The first value of the header `name` (lower case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.first()).map(String::as_str)
    }
}

/// Separates the body, the headers and the status in curl's output.
const SEP: u8 = 0x1f;

/// Whether a request that ended with `status` may succeed when repeated.
/// Status 0 stands for a failure to connect or a connection that broke.
pub fn is_transient(status: u16) -> bool {
    matches!(status, 0 | 408 | 429 | 500..=599)
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\n' | '\r' => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl HttpClient {
    pub fn new() -> HttpClient {
        HttpClient::default()
    }

    /// Sends `name: value` with every request.
    pub fn header(mut self, name: &str, value: &str) -> HttpClient {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn bearer_token(self, token: &str) -> HttpClient {
        self.header("Authorization", &format!("Bearer {token}"))
    }

    /// Takes credentials from `path` when it exists, like Nix's
    /// `netrc-file`.
    pub fn netrc_file(mut self, path: Option<PathBuf>) -> HttpClient {
        self.netrc_file = path;
        self
    }

    pub fn attempts(mut self, n: u32) -> HttpClient {
        self.attempts = n.max(1);
        self
    }

    pub fn retry_delay(mut self, d: Duration) -> HttpClient {
        self.retry_delay = d;
        self
    }

    /// curl's options for this client, in its config file syntax.
    fn config(&self) -> String {
        let mut c = String::from("silent\nshow-error\nlocation\n");
        for (n, v) in &self.headers {
            c.push_str(&format!("header = {}\n", quote(&format!("{n}: {v}"))));
        }
        if let Some(f) = self.netrc_file.as_deref().filter(|f| f.exists()) {
            c.push_str(&format!("netrc-optional\nnetrc-file = {}\n", quote(&f.to_string_lossy())));
        }
        c
    }

    fn command(&self) -> Command {
        let mut c = Command::new("curl");
        c.args(["--config", "-"]).stdin(Stdio::piped());
        c
    }

    fn spawn(&self, mut cmd: Command) -> Result<Child> {
        let mut child = cmd.spawn().map_err(|e| format!("running curl: {e}"))?;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(self.config().as_bytes()).map_err(|e| format!("running curl: {e}"))?;
        Ok(child)
    }

    /// Runs one request; the body comes back on curl's standard output,
    /// followed by the headers as JSON and the status, each after a `SEP`.
    fn run_once(&self, args: &[&str], url: &str) -> Result<(Response, String)> {
        let mut cmd = self.command();
        cmd.args(args).args(["--write-out", "\u{1f}%{header_json}\u{1f}%{http_code}"]).arg(url);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let out = self.spawn(cmd)?.wait_with_output().map_err(|e| format!("running curl: {e}"))?;
        let mut body = out.stdout;
        let status_at = body.iter().rposition(|&b| b == SEP).unwrap_or(0);
        let status = String::from_utf8_lossy(&body[status_at..]).trim_matches(|c: char| c == SEP as char || c.is_whitespace()).parse().unwrap_or(0);
        let headers_at = body[..status_at].iter().rposition(|&b| b == SEP).unwrap_or(status_at);
        let headers = parse_header_json(&body[(headers_at + 1).min(status_at)..status_at]);
        body.truncate(headers_at);
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Ok((Response { status, body, headers }, err))
    }

    /// Runs a request, repeating it while it fails in a transient way.
    fn run(&self, what: &str, args: &[&str], url: &str) -> Result<Response> {
        let mut delay = self.retry_delay;
        for attempt in 1..=self.attempts {
            let (resp, err) = self.run_once(args, url)?;
            if !is_transient(resp.status) {
                return Ok(resp);
            }
            // curl may quote the URL in its own message.
            let why = if resp.status == 0 { err.replace(url, &redact_url(url)) } else { format!("HTTP status {}", resp.status) };
            if attempt == self.attempts {
                return Err(format!("{what} '{}': {why}", redact_url(url)));
            }
            eprintln!("warning: {what} '{}': {why}; retrying in {} ms", redact_url(url), delay.as_millis());
            std::thread::sleep(delay);
            delay *= 2;
        }
        unreachable!()
    }

    pub fn get(&self, url: &str) -> Result<Response> {
        self.run("downloading", &[], url)
    }

    /// The status a `HEAD` request for `url` gets.
    pub fn head(&self, url: &str) -> Result<u16> {
        Ok(self.run("querying", &["--head", "--output", "/dev/null"], url)?.status)
    }

    /// Uploads the file at `src` with `PUT`.
    pub fn put_file(&self, url: &str, src: &Path, content_type: &str) -> Result<()> {
        let src = src.to_str().ok_or_else(|| format!("cannot upload '{}': its name is not UTF-8", src.display()))?;
        let ct = format!("Content-Type: {content_type}");
        let resp = self.run("uploading to", &["--upload-file", src, "--header", &ct, "--output", "/dev/null"], url)?;
        match resp.status {
            200..=299 => Ok(()),
            s => Err(format!("uploading to '{}': HTTP status {s}", redact_url(url))),
        }
    }

    /// Sends a `method` request with `headers` added and, when given, the
    /// file `body` as its body; any status comes back as a response.
    pub fn send(&self, method: &str, url: &str, headers: &[(&str, &str)], body: Option<&Path>) -> Result<Response> {
        let mut client = self.clone();
        for (n, v) in headers {
            client = client.header(n, v);
        }
        let src = match body {
            Some(b) => Some(b.to_str().ok_or_else(|| format!("cannot upload '{}': its name is not UTF-8", b.display()))?),
            None => None,
        };
        let mut args = match method {
            "HEAD" => vec!["--head", "--output", "/dev/null"],
            m => vec!["--request", m],
        };
        if let Some(src) = src {
            args.extend(["--upload-file", src]);
        }
        client.run(if body.is_some() { "uploading to" } else { "requesting" }, &args, url)
    }

    /// Streams the body of `url`, which must exist. curl itself retries
    /// transient failures that happen before the body starts.
    pub fn open(&self, url: &str) -> Result<Download> {
        let mut cmd = self.command();
        let retries = (self.attempts - 1).to_string();
        cmd.args(["--fail", "--retry", &retries]).arg(url);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = self.spawn(cmd)?;
        let stdout = child.stdout.take().unwrap();
        Ok(Download { child, stdout, url: url.to_string() })
    }
}

/// Parses curl's `%{header_json}`: an object of lower-case names to lists
/// of values.
fn parse_header_json(data: &[u8]) -> BTreeMap<String, Vec<String>> {
    let Ok(serde_json::Value::Object(m)) = serde_json::from_slice(data) else { return BTreeMap::new() };
    m.into_iter()
        .map(|(k, v)| {
            let vals = match v {
                serde_json::Value::Array(a) => a.into_iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
                serde_json::Value::String(s) => vec![s],
                _ => Vec::new(),
            };
            (k.to_ascii_lowercase(), vals)
        })
        .collect()
}

/// The body of a download; reports curl's failure once the stream ends.
pub struct Download {
    child: Child,
    stdout: ChildStdout,
    url: String,
}

impl Read for Download {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.stdout.read(buf)?;
        if n == 0 && !buf.is_empty() {
            let mut msg = String::new();
            if let Some(e) = self.child.stderr.as_mut() {
                let _ = e.read_to_string(&mut msg);
            }
            let st = self.child.wait()?;
            if !st.success() {
                return Err(io::Error::other(format!("downloading '{}': {}", redact_url(&self.url), msg.trim().replace(&self.url, &redact_url(&self.url)))));
            }
        }
        Ok(n)
    }
}

impl Drop for Download {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_quotes_headers() {
        let c = HttpClient::new().bearer_token("a\"b\\c").header("authorization", "Basic x").config();
        assert!(c.contains("header = \"authorization: Basic x\"\n"));
        assert!(!c.contains("Bearer"));
        let c = HttpClient::new().header("X-Token", "a\"b\\c\nd").config();
        assert!(c.contains(r#"header = "X-Token: a\"b\\cd""#));
        assert!(is_transient(503) && is_transient(0) && !is_transient(404));
    }
}
