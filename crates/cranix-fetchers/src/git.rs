//! Git inputs through the `git` command line tool: local working trees
//! (including uncommitted changes to tracked files), commits of local
//! repositories, and remote repositories mirrored into bare clones in the
//! store's state directory.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use cranix_core::hash::Hash;
use cranix_store::Store;

use crate::attrs::{get_bool, req_str, Attr, Attrs};
use crate::input::{Input, Tree};
use crate::url::parse_url;
use crate::{cache, Result, TempDir};

const NULL_REV: &str = "0000000000000000000000000000000000000000";

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("running git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "program 'git' failed ({}): {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn git_ok(dir: &Path, args: &[&str]) -> Option<String> {
    git(dir, args).ok()
}

struct RepoInfo {
    is_local: bool,
    /// The working tree path for local repositories, the URL otherwise.
    url: String,
}

fn repo_info(input: &Input) -> Result<RepoInfo> {
    let u = parse_url(&req_str(&input.attrs, "url")?)?;
    let force_http = std::env::var("_NIX_FORCE_HTTP").as_deref() == Ok("1");
    let is_bare = u.scheme == "file" && !Path::new(&u.path).join(".git").exists();
    let is_local = u.scheme == "file" && !force_http && !is_bare;
    Ok(RepoInfo { is_local, url: if is_local { u.path } else { u.base } })
}

pub fn local_path(input: &Input) -> Option<String> {
    repo_info(input).ok().filter(|r| r.is_local).map(|r| r.url)
}

pub fn put_file(input: &Input, rel: &str, contents: &str) -> Result<()> {
    let r = repo_info(input)?;
    if !r.is_local {
        return Err(format!("cannot commit '{rel}' to Git repository '{}' because it's not a working tree", input.to_string()));
    }
    let dir = Path::new(&r.url);
    let p = dir.join(rel);
    fs::write(&p, contents).map_err(|e| format!("writing '{}': {e}", p.display()))?;
    let ignored = Command::new("git").arg("-C").arg(dir).args(["check-ignore", "--quiet", rel]).status().map(|s| s.success()).unwrap_or(false);
    if !ignored {
        git(dir, &["add", "--intent-to-add", "--", rel])?;
    }
    Ok(())
}

fn flag(input: &Input, k: &str) -> Result<bool> {
    Ok(get_bool(&input.attrs, k)?.unwrap_or(false))
}

fn cache_path(store: &Store, url: &str, shallow: bool) -> PathBuf {
    let h = Hash::sha256(url.as_bytes()).to_nix32();
    store.state_dir().join("gitv3").join(if shallow { format!("{h}-shallow") } else { h })
}

fn read_head(url_or_path: &str) -> Option<String> {
    let out = Command::new("git").args(["ls-remote", "--symref", url_or_path]).stdin(Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().next()?;
    if let Some(rest) = line.strip_prefix("ref: ") {
        return rest.split('\t').next().map(|s| s.trim().to_string());
    }
    line.split('\t').next().map(|s| s.trim().to_string())
}

fn within_ttl(p: &Path) -> bool {
    let Ok(md) = fs::metadata(p) else { return false };
    let mtime = md.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs());
    mtime + crate::settings().tarball_ttl > crate::now()
}

fn read_head_cached(store: &Store, url: &str) -> Option<String> {
    let dir = cache_path(store, url, false);
    let head = dir.join("HEAD");
    let mut cached = None;
    if head.exists() {
        cached = read_head(&dir.to_string_lossy());
        if let Some(c) = &cached {
            if c != "__nix_dummy_branch" && !c.ends_with("/__nix_dummy_branch") && within_ttl(&head) {
                return cached;
            }
        }
    }
    if let Some(r) = read_head(url) {
        return Some(r);
    }
    if let Some(c) = &cached {
        crate::warn(format!("could not get HEAD ref for repository '{url}'; using expired cached ref '{c}'"));
    }
    cached
}

fn workdir_ref(dir: &Path) -> Option<String> {
    git_ok(dir, &["symbolic-ref", "-q", "HEAD"]).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn last_modified(store: &Store, dir: &Path, rev: &str) -> Result<u64> {
    let key: Attrs = [("rev".to_string(), Attr::from(rev))].into();
    if let Some((v, _)) = cache::lookup(store, "gitLastModified", &key) {
        if let Ok(Some(n)) = crate::attrs::get_int(&v, "lastModified") {
            return Ok(n);
        }
    }
    let n: u64 = git(dir, &["log", "-1", "--format=%ct", rev])?.trim().parse().map_err(|_| "cannot parse commit time")?;
    cache::upsert(store, "gitLastModified", &key, &[("lastModified".to_string(), Attr::Int(n))].into());
    Ok(n)
}

fn rev_count(store: &Store, dir: &Path, rev: &str) -> Result<u64> {
    let key: Attrs = [("rev".to_string(), Attr::from(rev))].into();
    if let Some((v, _)) = cache::lookup(store, "gitRevCount", &key) {
        if let Ok(Some(n)) = crate::attrs::get_int(&v, "revCount") {
            return Ok(n);
        }
    }
    let n: u64 = git(dir, &["rev-list", "--count", rev])?.trim().parse().map_err(|_| "cannot parse revision count")?;
    cache::upsert(store, "gitRevCount", &key, &[("revCount".to_string(), Attr::Int(n))].into());
    Ok(n)
}

fn has_object(dir: &Path, rev: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["cat-file", "-e", &format!("{rev}^{{commit}}")])
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn resolve_ref(dir: &Path, r: &str) -> Result<String> {
    git(dir, &["rev-parse", "--verify", "--quiet", r])
        .map(|s| s.trim().to_string())
        .map_err(|_| format!("resolving Git reference '{r}': reference not found"))
}

pub fn fetch(store: &Store, input: &Input) -> Result<(Tree, Input)> {
    let info = repo_info(input)?;
    if flag(input, "exportIgnore")? && flag(input, "submodules")? {
        return Err("exportIgnore and submodules are not supported together yet".into());
    }
    if input.get_ref()?.is_some() || input.get_rev()?.is_some() || !info.is_local {
        from_commit(store, &info, input.clone())
    } else {
        from_workdir(store, &info, input.clone())
    }
}

fn from_commit(store: &Store, info: &RepoInfo, mut input: Input) -> Result<(Tree, Input)> {
    let orig_ref = input.get_ref()?;
    let shallow = flag(&input, "shallow")?;
    let all_refs = flag(&input, "allRefs")?;
    let r = match &orig_ref {
        Some(r) => r.clone(),
        None => {
            let head = if info.is_local { workdir_ref(Path::new(&info.url)) } else { read_head_cached(store, &info.url) };
            head.unwrap_or_else(|| {
                crate::warn(format!("could not read HEAD ref from repo at '{}', using 'master'", info.url));
                "master".into()
            })
        }
    };
    input.set("ref", r.clone());
    let repo_dir: PathBuf;
    if info.is_local {
        repo_dir = PathBuf::from(&info.url);
        if input.get_rev()?.is_none() {
            input.set("rev", resolve_ref(&repo_dir, &r)?);
        }
    } else {
        repo_dir = cache_path(store, &info.url, shallow);
        if !repo_dir.join("HEAD").exists() {
            fs::create_dir_all(&repo_dir).map_err(|e| e.to_string())?;
            git(&repo_dir, &["-c", "init.defaultBranch=__nix_dummy_branch", "init", "--bare", "--quiet"])?;
        }
        git(&repo_dir, &["config", "remote.origin.url", &info.url])?;
        let local_ref = if r.starts_with("refs/") { repo_dir.join(&r) } else { repo_dir.join("refs/heads").join(&r) };
        let do_fetch = match input.get_rev()? {
            Some(rev) => !has_object(&repo_dir, &rev),
            None => all_refs || !within_ttl(&local_ref),
        };
        if do_fetch {
            let fetch_ref = if all_refs {
                "refs/*".to_string()
            } else if let Some(rev) = input.get_rev()? {
                rev
            } else if r.starts_with("refs/") || r == "HEAD" {
                r.clone()
            } else {
                format!("refs/heads/{r}")
            };
            let refspec = if input.get_rev()?.is_some() && !all_refs { fetch_ref.clone() } else { format!("{fetch_ref}:{fetch_ref}") };
            let mut args = vec!["fetch", "--quiet", "--force"];
            if shallow {
                args.push("--depth=1");
            }
            args.extend(["--", info.url.as_str(), refspec.as_str()]);
            eprintln!("fetching Git repository '{}'", info.url);
            if let Err(e) = git(&repo_dir, &args) {
                if !local_ref.exists() {
                    return Err(e);
                }
                eprintln!("error: {e}");
                crate::warn(format!("could not update local clone of Git repository '{}'; continuing with the most recent version", info.url));
            }
            if input.get_rev()?.is_none() {
                if let Ok(f) = fs::File::options().write(true).open(&local_ref) {
                    let _ = f.set_modified(std::time::SystemTime::now());
                }
            }
            if orig_ref.is_none() && git(&repo_dir, &["symbolic-ref", "--", "HEAD", &r]).is_err() {
                crate::warn(format!("could not update cached head '{r}' for '{}'", info.url));
            }
        }
        match input.get_rev()? {
            Some(rev) => {
                if !has_object(&repo_dir, &rev) {
                    return Err(format!(
                        "Cannot find Git revision '{rev}' in ref '{r}' of repository '{}'! Please make sure that the rev exists on the ref you've specified or add allRefs = true; to fetchGit.",
                        info.url
                    ));
                }
            }
            None => input.set("rev", resolve_ref(&repo_dir, &r)?),
        }
    }
    let is_shallow = git(&repo_dir, &["rev-parse", "--is-shallow-repository"]).map(|s| s.trim() == "true").unwrap_or(false);
    if is_shallow && !shallow {
        return Err(format!(
            "'{}' is a shallow Git repository, but shallow repositories are only allowed when `shallow = true;` is specified",
            info.url
        ));
    }
    let rev = input.get_rev()?.unwrap();
    let lm = last_modified(store, &repo_dir, &rev)?;
    if !shallow {
        input.set("revCount", rev_count(store, &repo_dir, &rev)?);
    }
    input.set("lastModified", lm);

    // A tree already copied for this revision needs no export.
    let tmp = TempDir::new_in(&store.state_dir().join("tmp"), "git")?;
    let dest = tmp.path().join("tree");
    let export_ignore = flag(&input, "exportIgnore")?;
    let subs = flag(&input, "submodules")?;
    let fp = format!("{rev}{}{}", if subs { ";s" } else { "" }, if export_ignore { ";e" } else { "" });
    let key: Attrs = [
        ("name".to_string(), Attr::Str(input.get_name())),
        ("fingerprint".to_string(), Attr::Str(fp)),
        ("method".to_string(), Attr::from("nar")),
        ("path".to_string(), Attr::from("/")),
    ]
    .into();
    if let Some((_, sp, _)) = cache::lookup_path(store, "fetchToStore", &key) {
        return Ok((Tree::Store(sp), input));
    }
    export_commit(store, &repo_dir, &rev, &dest, export_ignore, subs)?;
    Ok((Tree::Dir { path: dest, keep: None, tmp: Some(tmp) }, input))
}

struct Entry {
    mode: String,
    sha: String,
    path: String,
}

fn ls_tree(dir: &Path, rev: &str) -> Result<Vec<Entry>> {
    let out = git(dir, &["ls-tree", "-r", "-z", "--full-tree", rev])?;
    let mut v = Vec::new();
    for rec in out.split('\0').filter(|s| !s.is_empty()) {
        let Some((meta, path)) = rec.split_once('\t') else { continue };
        let mut it = meta.split(' ');
        let mode = it.next().unwrap_or("").to_string();
        let _ty = it.next();
        let sha = it.next().unwrap_or("").to_string();
        v.push(Entry { mode, sha, path: path.to_string() });
    }
    Ok(v)
}

/// Paths (files and their ancestor directories) carrying the
/// `export-ignore` attribute, read from `rev` or from the working tree.
fn export_ignored(dir: &Path, rev: Option<&str>, files: &[String]) -> Result<BTreeSet<String>> {
    let mut all: BTreeSet<String> = BTreeSet::new();
    for f in files {
        let mut p = f.as_str();
        all.insert(p.to_string());
        while let Some(i) = p.rfind('/') {
            p = &p[..i];
            all.insert(p.to_string());
        }
    }
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir).arg("check-attr").arg("-z").arg("--stdin");
    if let Some(r) = rev {
        cmd.arg(format!("--source={r}"));
    }
    cmd.arg("export-ignore");
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
    let mut stdin = child.stdin.take().unwrap();
    let input: Vec<u8> = all.iter().flat_map(|p| p.bytes().chain([0])).collect();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let _ = writer.join();
    if !out.status.success() {
        return Err(format!("git check-attr failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let f: Vec<&str> = s.split('\0').collect();
    let mut set = BTreeSet::new();
    for c in f.chunks(3) {
        if c.len() == 3 && c[2] == "set" {
            set.insert(c[0].to_string());
        }
    }
    Ok(set)
}

fn is_ignored(ignored: &BTreeSet<String>, path: &str) -> bool {
    if ignored.is_empty() {
        return false;
    }
    let mut p = path;
    loop {
        if ignored.contains(p) {
            return true;
        }
        match p.rfind('/') {
            Some(i) => p = &p[..i],
            None => return false,
        }
    }
}

/// Writes the tree of `rev` into `dest` from the raw blobs.
fn export_commit(store: &Store, dir: &Path, rev: &str, dest: &Path, export_ignore: bool, submodules: bool) -> Result<()> {
    fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    let entries = ls_tree(dir, rev)?;
    let ignored = if export_ignore {
        export_ignored(dir, Some(rev), &entries.iter().map(|e| e.path.clone()).collect::<Vec<_>>())?
    } else {
        BTreeSet::new()
    };
    let entries: Vec<Entry> = entries.into_iter().filter(|e| !is_ignored(&ignored, &e.path)).collect();
    let mut blobs = Vec::new();
    let mut gitlinks = BTreeMap::new();
    for e in &entries {
        let p = dest.join(&e.path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if e.mode == "160000" {
            // Submodules appear as empty directories unless fetched.
            fs::create_dir_all(&p).map_err(|e| e.to_string())?;
            gitlinks.insert(e.path.clone(), e.sha.clone());
        } else {
            blobs.push(e);
        }
    }
    write_blobs(dir, &blobs, dest)?;
    if submodules && !gitlinks.is_empty() {
        let modules = dest.join(".gitmodules");
        if modules.exists() {
            let base_url = git_ok(dir, &["config", "remote.origin.url"]).map(|s| s.trim().to_string()).unwrap_or_else(|| dir.to_string_lossy().into_owned());
            for sm in parse_gitmodules(&modules)? {
                let Some(sub_rev) = gitlinks.get(&sm.path) else { continue };
                let resolved = resolve_submodule_url(&base_url, &sm.url);
                let mut a: Attrs = Attrs::new();
                a.insert("type".into(), "git".into());
                a.insert("url".into(), Attr::Str(resolved));
                if !sm.branch.is_empty() {
                    a.insert("ref".into(), Attr::Str(sm.branch.clone()));
                }
                a.insert("rev".into(), Attr::Str(sub_rev.clone()));
                a.insert("exportIgnore".into(), Attr::Bool(export_ignore));
                a.insert("submodules".into(), Attr::Bool(true));
                a.insert("allRefs".into(), Attr::Bool(true));
                let sub = Input::from_attrs(a)?;
                let (tree, _) = sub.fetch_checked(store)?;
                let target = dest.join(&sm.path);
                crate::storeutil::remove_tree(&target);
                copy_tree_out(store, tree, &target)?;
            }
        }
    }
    Ok(())
}

fn copy_tree_out(store: &Store, tree: Tree, target: &Path) -> Result<()> {
    let (src, keep) = match &tree {
        Tree::Dir { path, keep, .. } => (path.clone(), keep.as_deref()),
        Tree::Store(sp) => (crate::storeutil::real_path(store, sp), None),
    };
    copy_filtered(&src, target, &src, keep)
}

fn copy_filtered(src: &Path, dst: &Path, root: &Path, keep: Option<&dyn Fn(&str) -> bool>) -> Result<()> {
    let err = |e: std::io::Error| format!("copying '{}': {e}", src.display());
    let md = fs::symlink_metadata(src).map_err(err)?;
    if md.is_symlink() {
        std::os::unix::fs::symlink(fs::read_link(src).map_err(err)?, dst).map_err(err)?;
    } else if md.is_dir() {
        fs::create_dir_all(dst).map_err(err)?;
        for e in fs::read_dir(src).map_err(err)? {
            let e = e.map_err(err)?;
            let child = e.path();
            if let Some(k) = keep {
                let rel = child.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                if !k(&rel) {
                    continue;
                }
            }
            copy_filtered(&child, &dst.join(e.file_name()), root, keep)?;
        }
    } else {
        fs::copy(src, dst).map_err(err)?;
        let exec = md.permissions().mode() & 0o100 != 0;
        fs::set_permissions(dst, fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 })).map_err(err)?;
    }
    Ok(())
}

fn write_blobs(dir: &Path, blobs: &[&Entry], dest: &Path) -> Result<()> {
    if blobs.is_empty() {
        return Ok(());
    }
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("running git: {e}"))?;
    let mut stdin = child.stdin.take().unwrap();
    let shas: Vec<u8> = blobs.iter().flat_map(|e| e.sha.bytes().chain([b'\n'])).collect();
    let writer = std::thread::spawn(move || stdin.write_all(&shas));
    let mut out = BufReader::with_capacity(1 << 20, child.stdout.take().unwrap());
    for e in blobs {
        let mut line = String::new();
        out.read_line(&mut line).map_err(|e| e.to_string())?;
        let size: u64 = line.trim_end().rsplit(' ').next().and_then(|s| s.parse().ok()).ok_or_else(|| format!("unexpected git cat-file output '{line}'"))?;
        let p = dest.join(&e.path);
        if e.mode == "120000" {
            let mut t = vec![0u8; size as usize];
            out.read_exact(&mut t).map_err(|e| e.to_string())?;
            std::os::unix::fs::symlink(String::from_utf8_lossy(&t).as_ref(), &p).map_err(|e| e.to_string())?;
        } else {
            let mut f = fs::File::create(&p).map_err(|er| format!("creating '{}': {er}", p.display()))?;
            std::io::copy(&mut (&mut out).take(size), &mut f).map_err(|e| e.to_string())?;
            let mode = if e.mode == "100755" { 0o755 } else { 0o644 };
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
        }
        let mut nl = [0u8; 1];
        out.read_exact(&mut nl).map_err(|e| e.to_string())?;
    }
    let _ = writer.join();
    let st = child.wait().map_err(|e| e.to_string())?;
    if !st.success() {
        return Err("git cat-file failed".into());
    }
    Ok(())
}

struct Submodule {
    path: String,
    url: String,
    branch: String,
}

fn parse_gitmodules(file: &Path) -> Result<Vec<Submodule>> {
    let out = Command::new("git")
        .arg("config")
        .arg("--file")
        .arg(file)
        .args(["--get-regexp", r"^submodule\..*\.(path|url|branch)$"])
        .output()
        .map_err(|e| e.to_string())?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut m: BTreeMap<String, Submodule> = BTreeMap::new();
    for line in s.lines() {
        let Some((k, v)) = line.split_once(' ') else { continue };
        let Some(rest) = k.strip_prefix("submodule.") else { continue };
        let Some((name, key)) = rest.rsplit_once('.') else { continue };
        let e = m.entry(name.to_string()).or_insert(Submodule { path: String::new(), url: String::new(), branch: String::new() });
        match key {
            "path" => e.path = v.to_string(),
            "url" => e.url = v.to_string(),
            "branch" => e.branch = v.to_string(),
            _ => {}
        }
    }
    Ok(m.into_values().filter(|s| !s.path.is_empty() && !s.url.is_empty()).collect())
}

/// Resolves `./` and `../` submodule URLs against the parent's URL.
fn resolve_submodule_url(base: &str, url: &str) -> String {
    if !(url.starts_with("./") || url.starts_with("../")) {
        return url.to_string();
    }
    let mut base = base.trim_end_matches('/').to_string();
    let mut rest = url;
    loop {
        if let Some(r) = rest.strip_prefix("./") {
            rest = r;
        } else if let Some(r) = rest.strip_prefix("../") {
            if let Some(i) = base.rfind('/') {
                base.truncate(i);
            }
            rest = r;
        } else {
            break;
        }
    }
    format!("{base}/{rest}")
}

fn from_workdir(store: &Store, info: &RepoInfo, mut input: Input) -> Result<(Tree, Input)> {
    let dir = PathBuf::from(&info.url);
    let head = git_ok(&dir, &["rev-parse", "--verify", "--quiet", "HEAD"]).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let status = git(&dir, &["status", "--porcelain=v1", "-z", "--untracked-files=no", "--ignore-submodules=all"])?;
    let mut dirty = !status.is_empty();
    let staged = git(&dir, &["ls-files", "-z", "--cached", "--stage"])?;
    let deleted: BTreeSet<String> = git(&dir, &["ls-files", "-z", "--deleted"])?.split('\0').filter(|s| !s.is_empty()).map(String::from).collect();
    let mut files = Vec::new();
    let mut sub_paths = Vec::new();
    for rec in staged.split('\0').filter(|s| !s.is_empty()) {
        let Some((meta, path)) = rec.split_once('\t') else { continue };
        if meta.starts_with("160000") {
            sub_paths.push(path.to_string());
            continue;
        }
        if !deleted.contains(path) {
            files.push(path.to_string());
        }
    }
    files.dedup();
    let export_ignore = flag(&input, "exportIgnore")?;
    if export_ignore && !files.is_empty() {
        let ign = export_ignored(&dir, None, &files)?;
        files.retain(|f| !is_ignored(&ign, f));
    }
    let mut keep_set: BTreeSet<String> = BTreeSet::new();
    for f in &files {
        let mut p = f.as_str();
        keep_set.insert(p.to_string());
        while let Some(i) = p.rfind('/') {
            p = &p[..i];
            keep_set.insert(p.to_string());
        }
    }
    let submodules = flag(&input, "submodules")?;
    let tree = if submodules && !sub_paths.is_empty() {
        let tmp = TempDir::new_in(&store.state_dir().join("tmp"), "git-wd")?;
        let dest = tmp.path().join("tree");
        let ks = keep_set.clone();
        copy_filtered(&dir, &dest, &dir, Some(&move |r: &str| ks.contains(r)))?;
        for sp in &sub_paths {
            let mut a = Attrs::new();
            a.insert("type".into(), "git".into());
            a.insert("url".into(), Attr::Str(format!("{}/{sp}", info.url)));
            a.insert("exportIgnore".into(), Attr::Bool(export_ignore));
            a.insert("submodules".into(), Attr::Bool(true));
            let sub = Input::from_attrs(a)?;
            let (t, si) = sub.fetch_checked(store)?;
            if si.get_rev()?.is_none() {
                dirty = true;
            }
            let target = dest.join(sp);
            crate::storeutil::remove_tree(&target);
            copy_tree_out(store, t, &target)?;
        }
        Tree::Dir { path: dest, keep: None, tmp: Some(tmp) }
    } else {
        Tree::Dir { path: dir.clone(), keep: Some(Box::new(move |r: &str| keep_set.contains(r))), tmp: None }
    };
    let s = crate::settings();
    if !dirty {
        if let Some(r) = workdir_ref(&dir) {
            input.set("ref", r);
        }
        let rev = head.clone().unwrap_or_else(|| NULL_REV.to_string());
        input.set("rev", rev.clone());
        let rc = if rev == NULL_REV { 0 } else { rev_count(store, &dir, &rev)? };
        input.set("revCount", rc);
    } else {
        if !s.allow_dirty {
            return Err(format!("Git tree '{}' is dirty", info.url));
        }
        if s.warn_dirty {
            crate::warn(format!("Git tree '{}' is dirty", info.url));
        }
        if let Some(h) = &head {
            input.set("dirtyRev", format!("{h}-dirty"));
            input.set("dirtyShortRev", format!("{}-dirty", &h[..7]));
        }
    }
    let lm = match &head {
        Some(h) => last_modified(store, &dir, h)?,
        None => 0,
    };
    input.set("lastModified", lm);
    Ok((tree, input))
}
