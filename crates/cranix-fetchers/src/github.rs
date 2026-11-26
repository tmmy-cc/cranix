//! `github:`, `gitlab:` and `sourcehut:` inputs: refs are resolved through
//! the forge's API and revisions are fetched as tarball archives.

use cranix_store::Store;

use crate::attrs::{get_int, get_str, req_str, Attr, Attrs};
use crate::input::{parse_rev, Input, Tree};
use crate::url::{self, ParsedUrl};
use crate::{cache, storeutil, Result, TempDir};

pub fn from_url(u: &ParsedUrl) -> Result<Input> {
    let parts: Vec<&str> = u.path.split('/').filter(|s| !s.is_empty()).collect();
    let (mut r, mut rev) = (None, None);
    match parts.len() {
        0 | 1 => return Err(format!("URL '{}' is invalid", u.url)),
        2 => {}
        3 => {
            if url::rev_regex().is_match(parts[2]) {
                rev = Some(parse_rev(parts[2])?);
            } else if url::ref_regex().is_match(parts[2]) {
                r = Some(parts[2].to_string());
            } else {
                return Err(format!("in URL '{}', '{}' is not a commit hash or branch/tag name", u.url, parts[2]));
            }
        }
        _ => {
            let rs = parts[2..].join("/");
            if !url::ref_regex().is_match(&rs) {
                return Err(format!("in URL '{}', '{rs}' is not a branch/tag name", u.url));
            }
            r = Some(rs);
        }
    }
    let mut host = None;
    for (k, v) in &u.query {
        match k.as_str() {
            "rev" => {
                if rev.is_some() {
                    return Err(format!("URL '{}' contains multiple commit hashes", u.url));
                }
                rev = Some(parse_rev(v)?);
            }
            "ref" => {
                if !url::ref_regex().is_match(v) {
                    return Err(format!("URL '{}' contains an invalid branch/tag name", u.url));
                }
                if r.is_some() {
                    return Err(format!("URL '{}' contains multiple branch/tag names", u.url));
                }
                r = Some(v.clone());
            }
            "host" => host = Some(v.clone()),
            _ => {}
        }
    }
    if let (Some(r), Some(rev)) = (&r, &rev) {
        return Err(format!("URL '{}' contains both a commit hash and a branch/tag name {r} {rev}", u.url));
    }
    let mut i = Input::default();
    i.set("type", u.scheme.clone());
    i.set("owner", parts[0]);
    i.set("repo", parts[1]);
    if let Some(rev) = rev {
        i.set("rev", rev);
    }
    if let Some(r) = r {
        i.set("ref", r);
    }
    if let Some(h) = host {
        i.set("host", h);
    }
    if let Some(h) = u.query.get("narHash") {
        i.set("narHash", h.clone());
    }
    Ok(i)
}

fn host(i: &Input) -> String {
    let default = match i.ty().as_str() {
        "gitlab" => "gitlab.com",
        "sourcehut" => "git.sr.ht",
        _ => "github.com",
    };
    get_str(&i.attrs, "host").ok().flatten().unwrap_or_else(|| default.into())
}

fn auth_headers(i: &Input, host: &str) -> Vec<(String, String)> {
    let Some(tok) = crate::settings().access_tokens.get(host).cloned() else { return Vec::new() };
    match i.ty().as_str() {
        "github" => vec![("Authorization".into(), format!("token {tok}"))],
        "gitlab" => match tok.split_once(':') {
            Some(("OAuth2", t)) => vec![("Authorization".into(), format!("Bearer {t}"))],
            Some(("PAT", t)) => vec![("PRIVATE-TOKEN".into(), t.to_string())],
            _ => {
                crate::warn(format!("Unrecognized access token for host '{host}'"));
                Vec::new()
            }
        },
        _ => vec![("Authorization".into(), format!("Bearer {tok}"))],
    }
}

fn read_json(store: &Store, url: &str, headers: &[(String, String)]) -> Result<serde_json::Value> {
    let f = crate::download::download_file(store, url, "source", &headers.to_vec())?;
    let text = std::fs::read_to_string(storeutil::real_path(store, &f.store_path)).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("parsing response of '{url}': {e}"))
}

fn rev_from_ref(store: &Store, i: &Input) -> Result<String> {
    let h = host(i);
    let owner = req_str(&i.attrs, "owner")?;
    let repo = req_str(&i.attrs, "repo")?;
    let r = i.get_ref()?.unwrap_or_else(|| "HEAD".into());
    let headers = auth_headers(i, &h);
    match i.ty().as_str() {
        "github" => {
            let u = if h == "github.com" {
                format!("https://api.{h}/repos/{owner}/{repo}/commits/{r}")
            } else {
                format!("https://{h}/api/v3/repos/{owner}/{repo}/commits/{r}")
            };
            let j = read_json(store, &u, &headers)?;
            let sha = j.get("sha").and_then(|s| s.as_str()).ok_or_else(|| format!("unexpected response from '{u}'"))?;
            parse_rev(sha)
        }
        "gitlab" => {
            let u = format!("https://{h}/api/v4/projects/{owner}%2F{repo}/repository/commits?ref_name={r}");
            let j = read_json(store, &u, &headers)?;
            let sha = j.get(0).and_then(|c| c.get("id")).and_then(|s| s.as_str()).ok_or_else(|| format!("No commits returned by GitLab API -- '{u}'"))?;
            parse_rev(sha)
        }
        _ => {
            let base = format!("https://{h}/{owner}/{repo}");
            let mut r = r;
            if r == "HEAD" {
                let f = crate::download::download_file(store, &format!("{base}/HEAD"), "source", &headers)?;
                let s = std::fs::read_to_string(storeutil::real_path(store, &f.store_path)).map_err(|e| e.to_string())?;
                let line = s.lines().next().unwrap_or("");
                r = line.strip_prefix("ref: ").ok_or_else(|| format!("unable to resolve HEAD ref for SourceHut repo '{base}'"))?.trim().to_string();
            }
            let f = crate::download::download_file(store, &format!("{base}/info/refs"), "source", &headers)?;
            let s = std::fs::read_to_string(storeutil::real_path(store, &f.store_path)).map_err(|e| e.to_string())?;
            let want: Vec<String> = if r.starts_with("refs/") { vec![r.clone()] } else { vec![format!("refs/heads/{r}"), format!("refs/tags/{r}")] };
            for line in s.lines() {
                if let Some((sha, name)) = line.split_once('\t') {
                    if want.iter().any(|w| w == name) {
                        return parse_rev(sha);
                    }
                }
            }
            Err(format!("unable to resolve ref '{r}' for SourceHut repo '{base}'"))
        }
    }
}

fn archive_url(i: &Input, rev: &str) -> Result<(String, Vec<(String, String)>)> {
    let h = host(i);
    let owner = req_str(&i.attrs, "owner")?;
    let repo = req_str(&i.attrs, "repo")?;
    let headers = auth_headers(i, &h);
    let u = match i.ty().as_str() {
        "github" if h != "github.com" => format!("https://{h}/api/v3/repos/{owner}/{repo}/tarball/{rev}"),
        "github" if headers.is_empty() => format!("https://{h}/{owner}/{repo}/archive/{rev}.tar.gz"),
        "github" => format!("https://api.{h}/repos/{owner}/{repo}/tarball/{rev}"),
        "gitlab" => format!("https://{h}/api/v4/projects/{owner}%2F{repo}/repository/archive.tar.gz?sha={rev}"),
        _ => format!("https://{h}/{owner}/{repo}/archive/{rev}.tar.gz"),
    };
    Ok((u, headers))
}

pub fn fetch(store: &Store, input: &Input) -> Result<(Tree, Input)> {
    let mut i = input.clone();
    if i.get_ref()?.is_none() {
        i.set("ref", "HEAD");
    }
    let rev = match i.get_rev()? {
        Some(r) => r,
        None => rev_from_ref(store, &i)?,
    };
    i.attrs.remove("ref");
    i.set("rev", rev.clone());
    let key: Attrs = [("rev".to_string(), Attr::Str(rev.clone()))].into();
    if let Some((v, sp, _)) = cache::lookup_path(store, "gitRevToSource", &key) {
        if let Ok(Some(lm)) = get_int(&v, "lastModified") {
            i.set("lastModified", lm);
            return Ok((Tree::Store(sp), i));
        }
    }
    let (u, headers) = archive_url(&i, &rev)?;
    eprintln!("downloading '{u}'");
    let tmp = TempDir::new_in(&store.state_dir().join("tmp"), "forge")?;
    let file = tmp.path().join("archive");
    crate::download::download(&u, &headers, None, &file)?;
    let dest = tmp.path().join("unpacked");
    std::fs::create_dir(&dest).map_err(|e| e.to_string())?;
    let lm = crate::tar::unpack(&file, &dest)?;
    let root = crate::tar::singleton_root(&dest);
    let (sp, _) = storeutil::add_to_store(store, &root, "source")?;
    cache::upsert_path(store, "gitRevToSource", &key, &[("lastModified".to_string(), Attr::Int(lm))].into(), &sp);
    i.set("lastModified", lm);
    Ok((Tree::Store(sp), i))
}
