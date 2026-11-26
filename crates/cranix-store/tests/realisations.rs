//! Signed realisations: a content-addressed build signs its realisation,
//! uploading carries it to a binary cache, and substitution checks its
//! signature before using it.

use std::path::{Path, PathBuf};

use cranix_core::signing::SecretKey;
use cranix_core::{Derivation, Output, StorePath};
use cranix_store::binary_cache::BinaryCache;
use cranix_store::build::{host_system, BuildOptions};
use cranix_store::settings::Settings;
use cranix_store::substitute::Substituters;
use cranix_store::Store;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().canonicalize().unwrap().join(format!("cranix-realisations-{name}-{}", std::process::id()));
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

/// Writes a floating content-addressed derivation into `store`.
fn ca_drv(store: &Store) -> (StorePath, Derivation) {
    let mut d = Derivation {
        name: "floating".into(),
        platform: host_system(),
        builder: "/bin/sh".into(),
        args: vec!["-c".into(), "echo content-addressed > $out".into()],
        ..Default::default()
    };
    d.outputs.insert("out".into(), Output { path: None, hash_algo: "r:sha256".into(), hash: String::new() });
    d.env.insert("name".into(), "floating".into());
    d.env.insert("out".into(), cranix_core::derivation::hash_placeholder("out"));
    let text = d.to_aterm(&store.dir);
    let p = store.add_text("floating.drv", text.as_bytes(), &d.references()).unwrap();
    (p, d)
}

/// A store that cannot build, substituting from `url` and trusting `key`.
fn substituting(root: &Path, src: &Store, url: &str, key: &SecretKey) -> Store {
    let mut s = Store::open(src.dir.clone(), root.join("store"), root.join("var")).unwrap();
    let mut settings = Settings::default();
    settings.set("substituters", url).unwrap();
    settings.set("trusted-public-keys", &key.to_public().to_string()).unwrap();
    s.set_substituters(Substituters::from_settings(&settings).unwrap());
    s
}

#[test]
fn realisations_are_signed_uploaded_and_checked() {
    let root = scratch("signed");
    let key = SecretKey::from_seed("builder-1", &[3; 32]);
    let stranger = SecretKey::from_seed("stranger-1", &[4; 32]);
    let mut src = Store::open_at(&root.join("src")).unwrap();
    src.set_signing_keys(vec![key.clone()]);
    let (drv_path, drv) = ca_drv(&src);
    let opts = BuildOptions { ca_derivations: true, ..Default::default() };
    let out = src.realise(&[drv_path.clone()], &opts).unwrap()[&drv_path]["out"].clone();

    // The local build signs its realisation.
    let r = src.query_output_realisation(&drv, "out").unwrap().unwrap();
    assert_eq!(r.out_path, out);
    assert!(r.is_signed_by(&[key.to_public()]));
    assert!(!r.is_signed_by(&[stranger.to_public()]));

    // Uploading: the path, and its realisation signed once more.
    for (name, signer) in [("good", &key), ("bad", &stranger)] {
        let cache = BinaryCache::open(&format!("file://{}", root.join(name).display())).unwrap();
        cache.init_for_writing(&src.dir).unwrap();
        let info = src.query_info(&out).unwrap().unwrap();
        cache.add_path(&src.dir, &src.real_path(&out), &info, &[], &[]).unwrap();
        let mut unsigned = r.clone();
        unsigned.signatures.clear();
        cache.add_realisation(&unsigned, &[signer.clone()]).unwrap();
    }
    assert_eq!(src.realisations_of(&[out.clone()].into()).unwrap(), vec![r.clone()]);

    // A store that cannot build gets the output from the realisation.
    let good = format!("file://{}", root.join("good").display());
    let dst = substituting(&root.join("dst"), &src, &good, &key);
    dst.add_text("floating.drv", drv.to_aterm(&src.dir).as_bytes(), &drv.references()).unwrap();
    let got = dst.realise(&[drv_path.clone()], &opts).unwrap();
    assert_eq!(got[&drv_path]["out"], out);
    assert!(dst.is_valid(&out));
    assert!(dst.query_output_realisation(&drv, "out").unwrap().unwrap().is_signed_by(&[key.to_public()]));

    // Signed by a key it does not trust: not used, and the store cannot
    // build it instead.
    let bad = format!("file://{}", root.join("bad").display());
    let other = substituting(&root.join("other"), &src, &bad, &key);
    other.add_text("floating.drv", drv.to_aterm(&src.dir).as_bytes(), &drv.references()).unwrap();
    let e = other.realise(&[drv_path.clone()], &opts).unwrap_err();
    assert!(e.contains("cannot build"), "{e}");
    assert!(other.query_output_realisation(&drv, "out").unwrap().is_none());
    remove(&root);
}
