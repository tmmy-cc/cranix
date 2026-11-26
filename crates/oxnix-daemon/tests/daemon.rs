//! Client and daemon talking to each other in-process.

use std::collections::BTreeSet;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oxnix_core::{nar, Derivation, Output, StoreDir, StorePath};
use oxnix_daemon::client::Connection;
use oxnix_daemon::machines;
use oxnix_daemon::remote_build::RemoteBuilders;
use oxnix_daemon::server::{Daemon, DaemonConfig};
use oxnix_store::build::{host_system, BuildOptions};
use oxnix_store::{PathInfo, Store};

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("oxnix-daemon-test-{name}-{}", std::process::id()));
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
    let t = src.add_path(&root.join("tree"), "tree", oxnix_core::FileIngestion::Recursive, None).unwrap();

    let mut c = connect(&daemon, true);
    assert_eq!(c.version, oxnix_daemon::proto::PROTOCOL_VERSION);
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
    assert!(c.ensure_path(&missing).unwrap_err().contains("is not valid"));

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
    let sd = store.dir.clone();
    let mut d = Derivation {
        name: name.into(),
        platform: host_system(),
        builder: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        ..Default::default()
    };
    d.outputs.insert("out".into(), Output::default());
    for (p, o) in inputs {
        d.input_drvs.entry(p.clone()).or_default().insert(o.to_string());
        let dep = store.read_derivation(p).unwrap();
        d.env.insert("dep".into(), sd.print(dep.outputs["out"].path.as_ref().unwrap()));
    }
    let mut hashes = std::collections::HashMap::new();
    d.fill_output_paths(&sd, &mut |p| oxnix_daemon::server::drv_hash(store, p, &mut hashes)).unwrap();
    store.add_text(&format!("{name}.drv"), d.to_aterm(&sd).as_bytes(), &d.references()).unwrap()
}

#[test]
fn remote_build_through_oxnix_daemon() {
    let root = scratch("remote");
    // The builder's store can run builds; the local one shares its store
    // directory but keeps its objects elsewhere, so it can only build
    // remotely.
    let remote = Store::open_at(&root.join("remote")).unwrap();
    let sd = remote.dir.clone();
    let local = Store::open(sd.clone(), root.join("local/store"), root.join("local/var")).unwrap();
    assert!(!local.can_build());

    let sock: PathBuf = format!("/tmp/oxnix-test-{}.sock", std::process::id()).into();
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
