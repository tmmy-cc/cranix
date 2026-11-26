//! Uploading to and substituting from an HTTP binary cache.

mod cache_server;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cache_server::CacheServer;
use oxnix_core::signing::SecretKey;
use oxnix_core::StorePath;
use oxnix_store::binary_cache::BinaryCache;
use oxnix_store::http::HttpClient;
use oxnix_store::substitute::Substituters;
use oxnix_store::{PathInfo, Store};

const TOKEN: &str = "s3cr\"t";

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("oxnix-http-{name}-{}", std::process::id()));
    remove(&d);
    d
}

/// Store objects are read-only, so make them writable before removing.
fn remove(d: &Path) {
    if d.exists() {
        let _ = std::process::Command::new("chmod").args(["-R", "u+w"]).arg(d).status();
        let _ = std::fs::remove_dir_all(d);
    }
}

fn client() -> HttpClient {
    HttpClient::new().bearer_token(TOKEN).retry_delay(Duration::from_millis(10))
}

/// Uploads `p` the way `oxnix copy --to` does.
fn upload(cache: &BinaryCache, store: &Store, p: &StorePath, key: &SecretKey) -> Result<(), String> {
    let info = store.query_info(p).unwrap().unwrap();
    // Text paths are content-addressed; drop CA so the signature matters.
    let info = PathInfo { ca: None, ..info };
    cache.add_path(&store.dir, &store.real_path(p), &info, &[], std::slice::from_ref(key)).map(|_| ())
}

fn substituters(server: &CacheServer, key: &SecretKey) -> Substituters {
    let cache = BinaryCache::open(&server.url).unwrap().with_http(client());
    Substituters::new(vec![cache], vec![key.to_public()], true, 4)
}

fn count(log: &[String], prefix: &str) -> usize {
    log.iter().filter(|l| l.starts_with(prefix)).count()
}

#[test]
fn upload_and_substitute_over_http() {
    let root = scratch("main");
    let server = CacheServer::start(&root.join("served"));
    server.state.lock().unwrap().token = Some(TOKEN.into());
    let key = SecretKey::from_seed("test-1", &[5; 32]);

    let src = Store::open_chroot(&root.join("src")).unwrap();
    let a = src.add_text("a", b"leaf", &BTreeSet::new()).unwrap();
    let b = src.add_text("b", src.dir.print(&a).as_bytes(), &[a.clone()].into()).unwrap();

    // Without the token nothing gets in.
    let anon = BinaryCache::open(&server.url).unwrap();
    let err = anon.init_for_writing(&src.dir).unwrap_err();
    assert!(err.contains("401"), "{err}");

    let cache = BinaryCache::open(&format!("{}?compression=zstd", server.url)).unwrap().with_http(client());
    cache.init_for_writing(&src.dir).unwrap();
    server.clear_log();
    for p in [&a, &b] {
        upload(&cache, &src, p, &key).unwrap();
    }
    // Each NAR goes up before the narinfo that names it.
    let puts: Vec<String> = server.log().into_iter().filter(|l| l.starts_with("PUT")).collect();
    assert_eq!(puts.len(), 4, "{puts:?}");
    assert!(puts[0].starts_with("PUT /nar/") && puts[0].ends_with(".nar.zst 201"));
    assert_eq!(puts[1], format!("PUT /{}.narinfo 201", a.hash_part()));
    assert!(puts[2].starts_with("PUT /nar/"));
    assert_eq!(puts[3], format!("PUT /{}.narinfo 201", b.hash_part()));

    // A failed NAR upload leaves no narinfo behind.
    let c = src.add_text("c", b"never uploaded", &BTreeSet::new()).unwrap();
    server.state.lock().unwrap().fail_puts = Some("/nar/".into());
    let err = upload(&cache, &src, &c, &key).unwrap_err();
    assert!(err.contains("HTTP status 500"), "{err}");
    assert!(!root.join("served").join(format!("{}.narinfo", c.hash_part())).exists());
    server.state.lock().unwrap().fail_puts = None;

    // Transient failures are retried.
    server.state.lock().unwrap().unavailable = 2;
    assert!(cache.get_file("nix-cache-info").unwrap().is_some());
    server.state.lock().unwrap().unavailable = 10;
    let err = cache.get_file("nix-cache-info").unwrap_err();
    assert!(err.contains("HTTP status 503"), "{err}");
    server.state.lock().unwrap().unavailable = 0;

    // Substitute the closure of `b` into a fresh store.
    server.clear_log();
    let mut dst = Store::open_chroot(&root.join("dst")).unwrap();
    dst.set_substituters(substituters(&server, &key));
    assert!(dst.substitute_paths(std::slice::from_ref(&b)).unwrap().is_empty());
    assert!(dst.is_valid(&a) && dst.verify(&b).unwrap());
    assert_eq!(std::fs::read(dst.real_path(&a)).unwrap(), b"leaf");
    assert!(!dst.substitutable(std::slice::from_ref(&c)));
    let log = server.log();
    assert_eq!(count(&log, "GET /nix-cache-info"), 1, "{log:?}");
    assert_eq!(count(&log, &format!("GET /{}.narinfo 404", c.hash_part())), 1, "{log:?}");

    // A second handle on the same store answers from its narinfo cache,
    // the missing path included.
    server.clear_log();
    let mut again = Store::open_chroot(&root.join("dst")).unwrap();
    again.set_substituters(substituters(&server, &key));
    assert!(!again.substitutable(std::slice::from_ref(&c)));
    assert_eq!(server.log(), Vec::<String>::new());

    // Expired answers are asked again.
    let mut fresh = Store::open_chroot(&root.join("dst")).unwrap();
    fresh.set_substituters(substituters(&server, &key).narinfo_ttls(0, 0));
    assert!(!fresh.substitutable(std::slice::from_ref(&c)));
    assert_eq!(count(&server.log(), &format!("GET /{}.narinfo", c.hash_part())), 1);

    remove(&root);
}
