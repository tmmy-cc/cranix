//! Uploading to and substituting from S3 caches, against the fake S3
//! service in `s3_server`, which checks every signature. Only the
//! example keys of the AWS documentation are used.

mod s3_server;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::Duration;

use cranix_core::signing::SecretKey;
use cranix_store::binary_cache::BinaryCache;
use cranix_store::http::HttpClient;
use cranix_store::realisation::{DrvOutput, Realisation};
use cranix_store::substitute::Substituters;
use cranix_store::{PathInfo, Store};
use s3_server::{S3Server, ACCESS_KEY, SECRET_KEY};

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("cranix-s3-{name}-{}", std::process::id()));
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

/// Credentials in the environment, and a shared credentials file with a
/// profile whose secret is wrong.
fn setup_env() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let f = std::env::temp_dir().join(format!("cranix-s3-credentials-{}", std::process::id()));
        std::fs::write(&f, format!("[good]\naws_access_key_id = {ACCESS_KEY}\naws_secret_access_key = {SECRET_KEY}\n\n[wrong]\naws_access_key_id = {ACCESS_KEY}\naws_secret_access_key = not-the-secret-key\n")).unwrap();
        std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &f);
        std::env::set_var("AWS_CONFIG_FILE", "/nonexistent");
        std::env::set_var("AWS_ACCESS_KEY_ID", ACCESS_KEY);
        std::env::set_var("AWS_SECRET_ACCESS_KEY", SECRET_KEY);
        std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    });
}

fn open(url: &str) -> BinaryCache {
    BinaryCache::open(url).unwrap().with_http(HttpClient::new().attempts(2).retry_delay(Duration::from_millis(10)))
}

#[test]
fn s3_round_trip() {
    setup_env();
    let root = scratch("round-trip");
    let server = S3Server::start("cache");
    let url = format!("s3://cache?endpoint={}&scheme=http&region=us-east-1", server.addr);
    let key = SecretKey::from_seed("test-1", &[5; 32]);
    let src = Store::open_chroot(&root.join("src")).unwrap();
    let a = src.add_text("a", b"leaf", &BTreeSet::new()).unwrap();
    let b = src.add_text("hello-2.12", src.dir.print(&a).as_bytes(), &[a.clone()].into()).unwrap();

    let cache = open(&url);
    cache.init_for_writing(&src.dir).unwrap();
    for p in [&a, &b] {
        let info = PathInfo { ca: None, ..src.query_info(p).unwrap().unwrap() };
        cache.add_path(&src.dir, &src.real_path(p), &info, &[], std::slice::from_ref(&key)).unwrap();
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
    dst.set_substituters(Substituters::new(vec![open(&url)], vec![key.to_public()], true, 4));
    assert!(dst.substitute_paths(std::slice::from_ref(&b)).unwrap().is_empty());
    assert!(dst.is_valid(&a) && dst.verify(&b).unwrap());

    let st = server.state.lock().unwrap();
    let keys: Vec<&String> = st.objects.keys().collect();
    assert!(st.objects.contains_key(&format!("{}.narinfo", b.hash_part())), "{keys:?}");
    assert!(keys.iter().any(|k| k.starts_with("nar/") && k.ends_with(".nar.xz")), "{keys:?}");
    assert!(st.objects.contains_key(&format!("realisations/{id}.doi")), "{keys:?}");
    assert!(st.log.iter().all(|l| !l.ends_with(" 403") || l.contains(".narinfo") || l.contains("nix-cache-info")), "{:?}", st.log);
    drop(st);

    // A profile picks other credentials; S3's refusal reads as missing,
    // and the secret never shows.
    let wrong = open(&format!("{url}&profile=wrong"));
    assert!(wrong.get_file("nix-cache-info").unwrap().is_none());
    let err = wrong.put_bytes("log/x", b"x", "text/plain").unwrap_err();
    assert!(err.contains("403") && err.contains("SignatureDoesNotMatch"), "{err}");
    assert!(!err.contains(SECRET_KEY) && !err.contains("not-the-secret-key"), "{err}");
    assert!(open(&format!("{url}&profile=good")).get_file("nix-cache-info").unwrap().is_some());
    remove(&root);
}

#[test]
fn s3_multipart_upload() {
    setup_env();
    let root = scratch("multipart");
    let server = S3Server::start("big");
    let url = format!("s3://big/prefix?endpoint=http://{}&compression=none&multipart-threshold=1&buffer-size=5242880", server.addr);
    let src = Store::open_chroot(&root.join("src")).unwrap();
    // 12 MiB that compress badly, so the NAR has three parts.
    let mut data = Vec::with_capacity(12 << 20);
    let mut x: u32 = 1;
    while data.len() < 12 << 20 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        data.extend_from_slice(&x.to_le_bytes());
    }
    let p = src.add_text("big", &data, &BTreeSet::new()).unwrap();
    let cache = open(&url);
    cache.init_for_writing(&src.dir).unwrap();
    let info = PathInfo { ca: None, ..src.query_info(&p).unwrap().unwrap() };
    let ni = cache.add_path(&src.dir, &src.real_path(&p), &info, &[], &[]).unwrap();

    let log = server.log();
    let parts: Vec<&String> = log.iter().filter(|l| l.contains("partNumber=")).collect();
    assert_eq!(parts.len(), 3, "{log:?}");
    assert!(log.iter().any(|l| l.starts_with("POST /big/prefix/nar/") && l.contains("?uploads ")), "{log:?}");
    let st = server.state.lock().unwrap();
    assert!(st.objects.contains_key(&format!("prefix/{}", ni.url)), "{:?}", st.objects.keys());
    drop(st);

    let mut dst = Store::open_chroot(&root.join("dst")).unwrap();
    dst.set_substituters(Substituters::new(vec![open(&url)], Vec::new(), false, 4));
    assert!(dst.substitute_paths(std::slice::from_ref(&p)).unwrap().is_empty());
    assert_eq!(std::fs::read(dst.real_path(&p)).unwrap(), data);
    remove(&root);
}

#[test]
fn s3_names_are_checked_before_sending() {
    setup_env();
    let server = S3Server::start("c");
    let cache = open(&format!("s3://c?endpoint={}&scheme=http", server.addr));
    for bad in ["../x", "nar/../../x", "a//b", "x?y", "a b"] {
        assert!(cache.get_file(bad).is_err(), "{bad}");
        assert!(cache.file_exists(bad).is_err(), "{bad}");
    }
    assert!(server.log().is_empty(), "{:?}", server.log());
}
