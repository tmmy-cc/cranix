//! Client and daemon talking to each other in-process.

use std::collections::BTreeSet;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cranix_core::{nar, Derivation, Output, StoreDir, StorePath};
use cranix_core::signing::SecretKey;
use cranix_daemon::client::{ClientOptions, Connection};
use cranix_daemon::proto::DerivedPath;
use cranix_daemon::machines;
use cranix_daemon::remote_build::RemoteBuilders;
use cranix_daemon::server::{Daemon, DaemonConfig};
use cranix_store::build::{host_system, BuildOptions};
use cranix_store::binary_cache::BinaryCache;
use cranix_store::settings::Settings;
use cranix_store::substitute::Substituters;
use cranix_store::upload::UploadTarget;
use cranix_store::{PathInfo, Store};

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("cranix-daemon-test-{name}-{}", std::process::id()));
    let _ = std::process::Command::new("chmod").arg("-R").arg("u+w").arg(&p).status();
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p.canonicalize().unwrap()
}

fn connect(d: &Arc<Daemon>, trusted: bool) -> Connection {
    let (a, b) = UnixStream::pair().unwrap();
    let sd: StoreDir = d.store.dir.clone();
    let d = Arc::clone(d);
    let b2 = b.try_clone().unwrap();
    std::thread::spawn(move || d.serve(Box::new(b), Box::new(b2), trusted));
    let a2 = a.try_clone().unwrap();
    Connection::from_streams(Box::new(a), Box::new(a2), sd).unwrap()
}

fn nar_of(s: &Store) -> impl Fn(&PathInfo, &mut dyn Write) -> std::io::Result<()> + Sync + '_ {
    move |i, w| nar::dump(&s.real_path(&i.path), w)
}

#[test]
fn copy_query_and_temp_roots() {
    let root = scratch("copy");
    let src = Store::open_at(&root.join("src")).unwrap();
    let sd = src.dir.clone();
    let dst = Store::open(sd.clone(), root.join("dst/store"), root.join("dst/var")).unwrap();
    let daemon = Arc::new(Daemon::new(dst, DaemonConfig::default()));

    let a = src.add_text("a", b"alpha", &BTreeSet::new()).unwrap();
    let b = src.add_text("b", format!("refers to {}", sd.print(&a)).as_bytes(), &[a.clone()].into()).unwrap();
    std::fs::create_dir_all(root.join("tree/sub")).unwrap();
    std::fs::write(root.join("tree/sub/f"), "x").unwrap();
    let t = src.add_path(&root.join("tree"), "tree", cranix_core::FileIngestion::Recursive, None).unwrap();

    let mut c = connect(&daemon, true);
    assert_eq!(c.version, cranix_daemon::proto::PROTOCOL_VERSION);
    assert_eq!(c.trusted, Some(true));
    c.set_options(&Default::default()).unwrap();
    let all: BTreeSet<StorePath> = [a.clone(), b.clone(), t.clone()].into();
    assert!(c.query_valid_paths(&all).unwrap().is_empty());

    let order = src.topo_sort(&all).unwrap();
    assert!(order.iter().position(|p| *p == a) < order.iter().position(|p| *p == b));
    let infos: Vec<PathInfo> = order.iter().map(|p| src.query_info(p).unwrap().unwrap()).collect();
    c.add_multiple_to_store(&infos, &nar_of(&src), true).unwrap();
    assert_eq!(c.query_valid_paths(&all).unwrap(), all);
    for i in &infos {
        assert_eq!(c.query_path_info(&i.path).unwrap().as_ref(), Some(i));
        let mut got = Vec::new();
        c.nar_from_path(&i.path, &mut got).unwrap();
        let mut want = Vec::new();
        nar::dump(&src.real_path(&i.path), &mut want).unwrap();
        assert_eq!(got, want);
    }
    assert_eq!(c.query_referrers(&a).unwrap(), [b.clone()].into());
    let missing = StorePath::from_base_name("00000000000000000000000000000000-nope").unwrap();
    assert_eq!(c.query_path_info(&missing).unwrap(), None);
    assert!(c.ensure_path(&missing).unwrap_err().contains("does not exist and cannot be created"));

    // The first connection's temporary roots keep its paths alive.
    let mut gc = connect(&daemon, true);
    let (deleted, _) = gc.collect_garbage(2, &BTreeSet::new(), u64::MAX).unwrap();
    assert!(deleted.is_empty(), "deleted {deleted:?}");
    assert!(gc.find_roots().unwrap().iter().any(|(l, p)| l.starts_with("{temp:") && *p == b));
    drop(c);
    // The daemon drops a connection's roots once it has seen it close.
    let mut deleted = Vec::new();
    for _ in 0..100 {
        deleted = gc.collect_garbage(2, &BTreeSet::new(), u64::MAX).unwrap().0;
        if !deleted.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(deleted.len(), 3);
    assert!(!daemon.store.is_valid(&b));
}

#[test]
fn untrusted_clients_need_content_addresses() {
    let root = scratch("untrusted");
    let src = Store::open_at(&root.join("src")).unwrap();
    let dst = Store::open(src.dir.clone(), root.join("dst/store"), root.join("dst/var")).unwrap();
    let daemon = Arc::new(Daemon::new(dst, DaemonConfig::default()));
    let mut c = connect(&daemon, false);
    assert_eq!(c.trusted, Some(false));

    let a = src.add_text("a", b"alpha", &BTreeSet::new()).unwrap();
    let mut info = src.query_info(&a).unwrap().unwrap();
    // A content-addressed path is accepted from anyone.
    c.add_multiple_to_store(&[info.clone()], &nar_of(&src), true).unwrap();
    assert!(daemon.store.is_valid(&a));

    // The same contents claimed as an input-addressed path are not.
    info.path = StorePath::from_base_name(&format!("{}-a", "1".repeat(32))).unwrap();
    info.ca = None;
    let nar_bytes = {
        let mut v = Vec::new();
        nar::dump(&src.real_path(&a), &mut v).unwrap();
        v
    };
    let e = c.add_to_store_nar(&info, &mut &nar_bytes[..], true).unwrap_err();
    assert!(e.contains("lacks a signature"), "{e}");
    // A false content address is caught too.
    info.ca = src.query_info(&a).unwrap().unwrap().ca;
    let e = c.add_to_store_nar(&info, &mut &nar_bytes[..], true).unwrap_err();
    assert!(e.contains("does not match"), "{e}");
    assert!(!daemon.store.is_valid(&info.path));
    // The connection is still usable after errors.
    assert!(c.is_valid_path(&a).unwrap());
}

fn write_drv(store: &Store, name: &str, script: &str, inputs: &[(StorePath, &str)]) -> StorePath {
    write_drv_env(store, name, script, inputs, &[])
}

/// Writes a `/bin/sh -c script` derivation; the outputs of the inputs are
/// in `$dep`, `$dep1`, `$dep2`, ….
fn write_drv_env(store: &Store, name: &str, script: &str, inputs: &[(StorePath, &str)], env: &[(&str, &str)]) -> StorePath {
    let sd = store.dir.clone();
    let mut d = Derivation {
        name: name.into(),
        platform: host_system(),
        builder: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        ..Default::default()
    };
    d.outputs.insert("out".into(), Output::default());
    d.env.insert("name".into(), name.into());
    for (i, (p, o)) in inputs.iter().enumerate() {
        d.input_drvs.entry(p.clone()).or_default().insert(o.to_string());
        let dep = store.read_derivation(p).unwrap();
        let var = if i == 0 { "dep".to_string() } else { format!("dep{i}") };
        d.env.insert(var, sd.print(dep.outputs["out"].path.as_ref().unwrap()));
    }
    for (k, v) in env {
        d.env.insert(k.to_string(), v.to_string());
    }
    let mut hashes = std::collections::HashMap::new();
    d.fill_output_paths(&sd, &mut |p| cranix_daemon::server::drv_hash(store, p, &mut hashes)).unwrap();
    store.add_text(&format!("{name}.drv"), d.to_aterm(&sd).as_bytes(), &d.references()).unwrap()
}

#[test]
fn remote_build_through_cranix_daemon() {
    let root = scratch("remote");
    // The builder's store can run builds; the local one shares its store
    // directory but keeps its objects elsewhere, so it can only build
    // remotely.
    let remote = Store::open_at(&root.join("remote")).unwrap();
    let sd = remote.dir.clone();
    let local = Store::open(sd.clone(), root.join("local/store"), root.join("local/var")).unwrap();
    assert!(!local.can_build());

    let sock: PathBuf = format!("/tmp/cranix-test-{}.sock", std::process::id()).into();
    let daemon = Arc::new(Daemon::new(remote, DaemonConfig::default()));
    {
        let d = Arc::clone(&daemon);
        let s = sock.clone();
        std::thread::spawn(move || d.serve_socket(&s));
    }
    for _ in 0..100 {
        if Path::new(&sock).exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let dep = write_drv(&local, "dep", "echo dep > $out", &[]);
    let top = write_drv(&local, "top", "read x < $dep; echo \"$x and top\" > $out; echo $dep >> $out", &[(dep.clone(), "out")]);

    let spec = format!("unix://{} {} - 2", sock.display(), host_system());
    let hook = RemoteBuilders::new(machines::parse(&spec, &host_system()).unwrap(), 1);
    let opts = BuildOptions { jobs: hook.total_slots(), hook: Some(Arc::new(hook)), ..Default::default() };
    let res = local.realise(&[top.clone()], &opts).unwrap();
    let out = &res[&top]["out"];
    let text = std::fs::read_to_string(local.real_path(out)).unwrap();
    let dep_out = local.read_derivation(&dep).unwrap().outputs["out"].path.clone().unwrap();
    assert_eq!(text, format!("dep and top\n{}\n", sd.print(&dep_out)));
    let info = local.query_info(out).unwrap().unwrap();
    assert_eq!(info.references, [dep_out].into());
    assert_eq!(info.deriver.as_ref(), Some(&top));
    assert!(local.verify(out).unwrap());

    // With no machine able to take it and no local slot, building fails
    // with an explanation.
    let other = write_drv(&local, "other", "echo > $out", &[]);
    let hook = RemoteBuilders::new(machines::parse("unix:///nonexistent riscv64-linux", &host_system()).unwrap(), 0);
    let opts = BuildOptions { jobs: 1, hook: Some(Arc::new(hook)), ..Default::default() };
    let e = local.realise(&[other], &opts).unwrap_err();
    assert!(e.contains("max-jobs = 0"), "{e}");
    let _ = std::fs::remove_file(&sock);
}

/// The narinfo names (`<hash>.narinfo`) in the file cache `dir`.
fn narinfos(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".narinfo")).collect()
}

fn upload_to(dir: &Path) -> Option<Arc<UploadTarget>> {
    let cache = BinaryCache::open(&format!("file://{}", dir.display())).unwrap();
    Some(Arc::new(UploadTarget::new(cache, vec![SecretKey::from_seed("up-1", &[7; 32])], 2, true)))
}

#[test]
fn daemon_and_remote_builds_upload_their_outputs() {
    let root = scratch("upload");
    let remote = Store::open_at(&root.join("remote")).unwrap();
    let sd = remote.dir.clone();
    let local = Store::open(sd.clone(), root.join("local/store"), root.join("local/var")).unwrap();

    // The daemon uploads what it builds for its clients.
    let sock: PathBuf = format!("/tmp/cranix-test-up-{}.sock", std::process::id()).into();
    let config = DaemonConfig { build: BuildOptions { upload: upload_to(&root.join("daemon-cache")), ..Default::default() }, ..Default::default() };
    let daemon = Arc::new(Daemon::new(remote, config));
    {
        let d = Arc::clone(&daemon);
        let s = sock.clone();
        std::thread::spawn(move || d.serve_socket(&s));
    }
    for _ in 0..100 {
        if Path::new(&sock).exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let dep = write_drv(&local, "dep", "echo dep > $out", &[]);
    let top = write_drv(&local, "top", "echo $dep > $out", &[(dep.clone(), "out")]);
    let spec = format!("unix://{} {} - 2", sock.display(), host_system());
    let hook = RemoteBuilders::new(machines::parse(&spec, &host_system()).unwrap(), 1);
    // The local store uploads the outputs remote builders return.
    let opts = BuildOptions { jobs: hook.total_slots(), hook: Some(Arc::new(hook)), upload: upload_to(&root.join("local-cache")), ..Default::default() };
    let res = local.realise(&[top.clone()], &opts).unwrap();
    let out = res[&top]["out"].clone();
    let dep_out = local.read_derivation(&dep).unwrap().outputs["out"].path.clone().unwrap();
    let want: BTreeSet<String> = [&out, &dep_out].iter().map(|p| format!("{}.narinfo", p.hash_part())).collect();
    assert_eq!(narinfos(&root.join("local-cache")), want);
    assert_eq!(narinfos(&root.join("daemon-cache")), want);
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn concurrent_clients_build_shared_derivations_once() {
    let root = scratch("concurrent");
    let store = Store::open_at(&root.join("s")).unwrap();
    let counter = root.join("builds");
    let c = counter.to_string_lossy().into_owned();
    let script = "echo $name >> $counter; /bin/sleep 0.3; echo $name > $out";
    let env = [("counter", c.as_str())];
    let leaf = write_drv_env(&store, "leaf", script, &[], &env);
    let a = write_drv_env(&store, "a", script, &[(leaf.clone(), "out")], &env);
    let b = write_drv_env(&store, "b", script, &[(leaf.clone(), "out")], &env);
    let top = write_drv_env(&store, "top", script, &[(a.clone(), "out"), (b.clone(), "out")], &env);
    let daemon = Arc::new(Daemon::new(store, DaemonConfig::default()));

    let requests = [vec![a.clone()], vec![b.clone()], vec![top.clone()], vec![top.clone(), a.clone()], vec![leaf.clone()]];
    let handles: Vec<_> = requests
        .into_iter()
        .map(|drvs| {
            let mut c = connect(&daemon, true);
            std::thread::spawn(move || {
                let targets: Vec<DerivedPath> = drvs.iter().map(|d| DerivedPath::Built { drv: d.clone(), outputs: None }).collect();
                c.build_paths_with_results(&targets).unwrap()
            })
        })
        .collect();
    for h in handles {
        for (t, res) in h.join().unwrap() {
            assert!(res.status.success(), "{t:?}: {}", res.error_msg);
            assert_eq!(res.built_outputs.len(), 1);
        }
    }
    let mut built: Vec<String> = std::fs::read_to_string(&counter).unwrap().lines().map(String::from).collect();
    built.sort();
    assert_eq!(built, ["a", "b", "leaf", "top"], "every derivation is built exactly once");
}

fn serve_client(store: Arc<Store>, write: bool) -> cranix_daemon::serve::ServeConnection {
    let (a, b) = UnixStream::pair().unwrap();
    let sd = store.dir.clone();
    let b2 = b.try_clone().unwrap();
    std::thread::spawn(move || cranix_daemon::serve::serve(&store, b, b2, write, &BuildOptions::default()));
    let a2 = a.try_clone().unwrap();
    let mut c = cranix_daemon::serve::ServeConnection::from_streams(Box::new(a), Box::new(a2), sd, None, "test".into());
    c.handshake().unwrap();
    c
}

#[test]
fn serve_protocol_roundtrip() {
    let root = scratch("serve");
    let src = Store::open_at(&root.join("src")).unwrap();
    let dst = Arc::new(Store::open(src.dir.clone(), root.join("dst/store"), root.join("dst/var")).unwrap());
    let a = src.add_text("a", b"alpha", &BTreeSet::new()).unwrap();
    let b = src.add_text("b", format!("{}", src.dir.print(&a)).as_bytes(), &[a.clone()].into()).unwrap();
    let infos: Vec<PathInfo> = [&a, &b].iter().map(|p| src.query_info(p).unwrap().unwrap()).collect();

    let mut ro = serve_client(Arc::clone(&dst), false);
    assert_eq!(ro.version, cranix_daemon::serve::SERVE_PROTOCOL_VERSION);
    assert!(ro.add_paths(&infos, &nar_of(&src)).is_err(), "writing needs --write");

    let mut c = serve_client(Arc::clone(&dst), true);
    let all: BTreeSet<StorePath> = [a.clone(), b.clone()].into();
    assert!(c.query_valid_paths(&all).unwrap().is_empty());
    c.add_paths(&infos, &nar_of(&src)).unwrap();
    assert_eq!(c.query_valid_paths(&all).unwrap(), all);
    for i in &infos {
        assert_eq!(c.query_path_info(&i.path).unwrap().as_ref(), Some(i));
        let mut got = Vec::new();
        c.nar_from_path(&i.path, &mut got).unwrap();
        let mut want = Vec::new();
        nar::dump(&src.real_path(&i.path), &mut want).unwrap();
        assert_eq!(got, want);
    }
    assert_eq!(c.query_closure(&[b.clone()].into(), false).unwrap(), all);
    let missing = StorePath::from_base_name(&format!("{}-x", "0".repeat(32))).unwrap();
    assert_eq!(c.query_path_info(&missing).unwrap(), None);

    // Builds: a derivation with its .drv in the store (BuildPaths) and one
    // sent in full (BuildDerivation).
    let bs = Arc::new(Store::open_at(&root.join("build")).unwrap());
    let d1 = write_drv(&bs, "one", "echo one > $out", &[]);
    let d2 = write_drv(&bs, "two", "echo two > $out", &[]);
    let mut c = serve_client(Arc::clone(&bs), true);
    let res = c.build_paths(&[DerivedPath::Built { drv: d1.clone(), outputs: None }]).unwrap();
    assert!(res[0].1.status.success(), "{}", res[0].1.error_msg);
    let out1 = bs.read_derivation(&d1).unwrap().outputs["out"].path.clone().unwrap();
    assert!(bs.is_valid(&out1));
    let drv2 = bs.read_derivation(&d2).unwrap();
    let res = c.build_derivation(&d2, &drv2).unwrap();
    assert!(res.status.success(), "{}", res.error_msg);
    assert_eq!(res.built_outputs["out"].out_path, drv2.outputs["out"].path.clone().unwrap());
    let bad = write_drv(&bs, "bad", "exit 3", &[]);
    let res = c.build_paths(&[DerivedPath::Built { drv: bad, outputs: None }]).unwrap();
    assert!(!res[0].1.status.success());
    assert!(res[0].1.error_msg.contains("failed"), "{}", res[0].1.error_msg);
}

#[path = "../../cranix-store/tests/cache_server/mod.rs"]
mod cache_server;

/// A store that substitutes from `url`, trusting only `key`, whose objects
/// live apart from the store directory so that it cannot build.
fn substituting_store(root: &Path, sd: &StoreDir, url: &str, key: &SecretKey) -> Store {
    let mut s = Store::open(sd.clone(), root.join("store"), root.join("var")).unwrap();
    let mut settings = Settings::default();
    settings.set("substituters", url).unwrap();
    settings.set("trusted-public-keys", &key.to_public().to_string()).unwrap();
    settings.set("narinfo-cache-negative-ttl", "0").unwrap();
    s.set_substituters(Substituters::from_settings(&settings).unwrap());
    s
}

#[test]
fn daemon_substitutes_signed_paths() {
    let root = scratch("subst");
    let src = Store::open_at(&root.join("src")).unwrap();
    let sd = src.dir.clone();
    let key = SecretKey::from_seed("test-1", &[7; 32]);
    let stranger = SecretKey::from_seed("stranger-1", &[9; 32]);

    let a = src.add_text("a", b"alpha", &BTreeSet::new()).unwrap();
    let b = src.add_text("b", format!("refers to {}", sd.print(&a)).as_bytes(), &[a.clone()].into()).unwrap();
    let drv = write_drv(&src, "cached", "echo cached > $out", &[]);
    let out = src.realise(&[drv.clone()], &BuildOptions::default()).unwrap()[&drv]["out"].clone();
    // Input-addressed, so only a signature makes it trusted.
    let fdrv = write_drv(&src, "foreign", "echo signed by someone else > $out", &[]);
    let foreign = src.realise(&[fdrv.clone()], &BuildOptions::default()).unwrap()[&fdrv]["out"].clone();

    let server = cache_server::CacheServer::start(&root.join("cache"));
    let cache = BinaryCache::open(&server.url).unwrap();
    cache.init_for_writing(&sd).unwrap();
    for (p, k) in [(&a, &key), (&b, &key), (&out, &key), (&foreign, &stranger)] {
        cache.add_path(&sd, &src.real_path(p), &src.query_info(p).unwrap().unwrap(), &[], &[k.clone()]).unwrap();
    }

    let dst = substituting_store(&root.join("dst"), &sd, &server.url, &key);
    assert!(!dst.can_build());
    let daemon = Arc::new(Daemon::new(dst, DaemonConfig::default()));
    let mut c = connect(&daemon, true);
    c.set_options(&Default::default()).unwrap();

    let (build, subst, unknown, download, nar) = c.query_missing(&[DerivedPath::Opaque(b.clone())]).unwrap();
    assert!(build.is_empty() && unknown.is_empty());
    assert_eq!(subst, [a.clone(), b.clone()].into());
    assert!(download > 0 && nar > 0);
    let (_, subst, unknown, _, _) = c.query_missing(&[DerivedPath::Opaque(foreign.clone())]).unwrap();
    assert!(subst.is_empty(), "{subst:?}");
    assert_eq!(unknown, [foreign.clone()].into());

    c.ensure_path(&b).unwrap();
    assert!(daemon.store.is_valid(&a) && daemon.store.is_valid(&b));
    // Paths without a signature by a trusted key are not substituted.
    let e = c.ensure_path(&foreign).unwrap_err();
    assert!(e.contains("does not exist and cannot be created"), "{e}");
    assert!(!daemon.store.is_valid(&foreign));

    // A derivation whose output is in the cache is substituted, although
    // this store cannot build.
    let drv_info = src.query_info(&drv).unwrap().unwrap();
    c.add_multiple_to_store(&[drv_info], &nar_of(&src), true).unwrap();
    let target = DerivedPath::Built { drv: drv.clone(), outputs: None };
    let (build, subst, _, _, _) = c.query_missing(&[target.clone()]).unwrap();
    assert!(build.is_empty());
    assert_eq!(subst, [out.clone()].into());
    let res = c.build_paths_with_results(&[target]).unwrap();
    assert_eq!(res[0].1.status, cranix_daemon::proto::BuildStatus::Substituted, "{}", res[0].1.error_msg);
    assert_eq!(res[0].1.built_outputs["out"].out_path, out);
    assert_eq!(std::fs::read_to_string(daemon.store.real_path(&out)).unwrap(), "cached\n");
    assert_eq!(daemon.store.query_sigs(&out).unwrap().len(), 1);

    // A cache marked `trusted=true` needs no signature by a trusted key.
    let trusting = substituting_store(&root.join("trusting"), &sd, &format!("{}?trusted=true", server.url), &key);
    let trusting = Arc::new(Daemon::new(trusting, DaemonConfig::default()));
    let mut t = connect(&trusting, true);
    t.set_options(&Default::default()).unwrap();
    t.ensure_path(&foreign).unwrap();
    assert!(trusting.store.is_valid(&foreign));

    // Clients that turn substitution off get nothing from the caches.
    let mut c = connect(&daemon, true);
    c.set_options(&ClientOptions { use_substitutes: false, ..Default::default() }).unwrap();
    let (_, _, unknown, _, _) = c.query_missing(&[DerivedPath::Opaque(foreign)]).unwrap();
    assert_eq!(unknown.len(), 1);
}
