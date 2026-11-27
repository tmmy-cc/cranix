//! Uploading to and substituting from GitLab and OCI registry caches,
//! against the fake registry in `registry_server`.

mod registry_server;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use cranix_core::signing::SecretKey;
use cranix_core::StorePath;
use cranix_store::binary_cache::BinaryCache;
use cranix_store::http::HttpClient;
use cranix_store::realisation::{DrvOutput, Realisation};
use cranix_store::substitute::Substituters;
use cranix_store::{PathInfo, Store};
use registry_server::RegistryServer;

const READ: &str = "glpat-TESTREAD0123456789";
const WRITE: &str = "glpat-TESTTOKEN0123456789";

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("cranix-registry-{name}-{}", std::process::id()));
    remove(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn remove(d: &Path) {
    if d.exists() {
        let _ = std::process::Command::new("chmod").args(["-R", "u+w"]).arg(d).status();
        let _ = std::fs::remove_dir_all(d);
    }
}

fn open(url: &str) -> BinaryCache {
    BinaryCache::open(url).unwrap().with_http(HttpClient::new().retry_delay(Duration::from_millis(10)))
}

fn upload(cache: &BinaryCache, store: &Store, p: &StorePath, key: &SecretKey) -> Result<String, String> {
    let info = store.query_info(p).unwrap().unwrap();
    let info = PathInfo { ca: None, ..info };
    cache.add_path(&store.dir, &store.real_path(p), &info, &[], std::slice::from_ref(key)).map(|ni| ni.url)
}

/// Writes the read and write tokens to files and returns the URL
/// parameters naming them.
fn token_params(root: &Path) -> String {
    std::fs::write(root.join("read"), format!("{READ}\n")).unwrap();
    std::fs::write(root.join("write"), WRITE).unwrap();
    format!("read-token-file={}&write-token-file={}", root.join("read").display(), root.join("write").display())
}

/// Uploads a closure of two paths and a realisation to `url`, then
/// substitutes the closure into a fresh store and reads the realisation.
fn round_trip(root: &Path, url: &str) -> (StorePath, StorePath, Vec<String>) {
    let key = SecretKey::from_seed("test-1", &[5; 32]);
    let src = Store::open_chroot(&root.join("src")).unwrap();
    let a = src.add_text("a", b"leaf", &BTreeSet::new()).unwrap();
    let b = src.add_text("hello-2.12", src.dir.print(&a).as_bytes(), &[a.clone()].into()).unwrap();

    let cache = open(url);
    cache.init_for_writing(&src.dir).unwrap();
    let mut nar_urls = Vec::new();
    for p in [&a, &b] {
        nar_urls.push(upload(&cache, &src, p, &key).unwrap());
    }
    assert!(cache.file_exists(&format!("{}.narinfo", b.hash_part())).unwrap());
    assert!(!cache.file_exists("00000000000000000000000000000000.narinfo").unwrap());
    let info = String::from_utf8(cache.get_file("nix-cache-info").unwrap().unwrap()).unwrap();
    assert!(info.contains("StoreDir: /nix/store"), "{info}");

    let id = DrvOutput::parse(&format!("sha256:{}!out", "ab".repeat(32))).unwrap();
    let r = Realisation { id: id.clone(), out_path: b.clone(), signatures: BTreeSet::new(), dependent_realisations: BTreeMap::new() };
    cache.add_realisation(&r, std::slice::from_ref(&key)).unwrap();
    assert_eq!(cache.query_realisation(&id).unwrap().unwrap().out_path, b);

    let mut dst = Store::open_chroot(&root.join("dst")).unwrap();
    dst.set_substituters(Substituters::new(vec![open(url)], vec![key.to_public()], true, 4));
    assert!(dst.substitute_paths(std::slice::from_ref(&b)).unwrap().is_empty());
    assert!(dst.is_valid(&a) && dst.verify(&b).unwrap());
    assert_eq!(std::fs::read(dst.real_path(&a)).unwrap(), b"leaf");
    (a, b, nar_urls)
}

#[test]
fn gitlab_round_trip_with_tokens() {
    let root = scratch("gitlab");
    let server = RegistryServer::start(Some(READ), Some(WRITE));
    let base = format!("gitlab://{}/group/project?scheme=http", server.addr);
    let url = format!("{base}&{}", token_params(&root));
    let (a, b, nar_urls) = round_trip(&root, &url);
    assert!(nar_urls.iter().all(|u| u.starts_with("nar/") && u.matches('/').count() == 1), "{nar_urls:?}");

    let st = server.state.lock().unwrap();
    let keys: Vec<&String> = st.generic.keys().collect();
    let pkg = |h: &str| format!("group%2Fproject/nix-{}/v1/{h}.narinfo", &h[..2]);
    assert!(st.generic.contains_key(&pkg(a.hash_part())), "{keys:?}");
    assert!(st.generic.contains_key(&pkg(b.hash_part())), "{keys:?}");
    assert!(keys.iter().any(|k| k.starts_with("group%2Fproject/nix-meta/v1/realisations+2Fsha256+3A")), "{keys:?}");
    assert!(!keys.iter().any(|k| k.contains("nix-cache-info")), "{keys:?}");
    // NARs go up before the narinfo that names them.
    let puts: Vec<&String> = st.log.iter().filter(|l| l.starts_with("PUT")).collect();
    assert!(puts[0].contains(".nar.xz") && puts[1].ends_with(".narinfo 201"), "{puts:?}");
    drop(st);

    // Reading needs the read token, writing the write token.
    let anon = open(&base);
    let err = anon.get_file(&format!("{}.narinfo", a.hash_part())).unwrap_err();
    assert!(err.contains("401") && err.contains("read token"), "{err}");
    let read_only = open(&format!("{base}&token-file={}", root.join("read").display()));
    assert!(read_only.get_file(&format!("{}.narinfo", a.hash_part())).unwrap().is_some());
    let err = read_only.put_file("log/x", &root.join("read"), "text/plain").unwrap_err();
    assert!(err.contains("403") && err.contains("write token"), "{err}");
    assert!(!err.contains(READ) && !err.contains(WRITE), "{err}");

    // `access-tokens` supplies a token where the URL names none.
    let tokens: BTreeMap<String, String> = [(server.addr.clone(), WRITE.to_string())].into();
    let by_host = open(&base).with_access_tokens(&tokens);
    by_host.put_file("log/y", &root.join("read"), "text/plain").unwrap();
    remove(&root);
}

#[test]
fn github_round_trip_with_layouts() {
    let root = scratch("github");
    let server = RegistryServer::start(Some(READ), Some(WRITE));
    let base = format!("github://Owner/Repo?registry=http://{}", server.addr);
    let url = format!("{base}&layout=name&{}", token_params(&root));
    let (_, b, nar_urls) = round_trip(&root, &url);
    assert!(nar_urls[1].starts_with("nar/hello/"), "{nar_urls:?}");

    let st = server.state.lock().unwrap();
    let tags: Vec<&String> = st.manifests.keys().collect();
    assert!(st.manifests.contains_key(&format!("owner/repo/nix-{}:v1.{}.narinfo", &b.hash_part()[..2], b.hash_part())), "{tags:?}");
    assert!(tags.iter().any(|t| t.starts_with("owner/repo/hello:v1.") && t.ends_with(".nar.xz")), "{tags:?}");
    assert!(tags.iter().any(|t| t.starts_with("owner/repo/nix-meta:v1.realisations_2Fsha256_3A")), "{tags:?}");
    drop(st);

    // A group layout puts every NAR in one package.
    let grouped = scratch("github-group");
    let url = format!("{base}&group=release-1.0&version=r1&{}", token_params(&grouped));
    let (_, _, nar_urls) = round_trip(&grouped, &url);
    assert!(nar_urls.iter().all(|u| u.starts_with("nar/release-1.0/")), "{nar_urls:?}");
    assert!(server.state.lock().unwrap().manifests.keys().filter(|k| k.starts_with("owner/repo/release-1.0:r1.")).count() == 2);

    // Without a token the token endpoint refuses pushes.
    let anon = open(&base);
    let err = anon.put_file("log/x", &grouped.join("read"), "text/plain").unwrap_err();
    assert!(err.contains("401"), "{err}");
    assert!(!err.contains(READ) && !err.contains(WRITE), "{err}");
    remove(&root);
    remove(&grouped);
}

#[test]
fn file_names_are_checked_before_sending() {
    let server = RegistryServer::start(None, None);
    for url in [format!("gitlab://{}/g/p?scheme=http", server.addr), format!("github://o/r?registry=http://{}", server.addr)] {
        let cache = open(&url);
        for bad in ["../x", "nar/../../x", "a//b", "./x", "x?y", "a b", "nar/UP/x"] {
            assert!(cache.get_file(bad).is_err(), "{bad}");
            assert!(cache.file_exists(bad).is_err(), "{bad}");
        }
    }
    assert!(server.log().is_empty(), "{:?}", server.log());
}
