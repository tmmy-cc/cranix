//! `provenance`: in-toto statements with SLSA provenance for the outputs
//! of an installable, signed as DSSE envelopes and stored in binary
//! caches, and their verification.

use std::io::Read;

use cranix_core::signing::PublicKey;
use cranix_core::StorePath;
use cranix_sbom::{dsse, provenance};
use cranix_store::binary_cache::read_secret_keys;
use cranix_store::substitute::{open_cache, trusted_keys};
use serde_json::Value;

use crate::{build_options, collect_drvs, eval_target, flake_cmd, new_eval, parse_target, render_error, Cli};

const USAGE: &str = "usage: cranix provenance [FILE | --expr E | INSTALLABLE] [-A ATTR] [-o FILE] [--sign] [--to URL]
       cranix provenance verify [FILE | --from URL PATH...] [--public-key KEY]...";

pub fn cmd_provenance(cli: &Cli, args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("verify") {
        return cmd_verify(cli, &args[1..]);
    }
    let mut file = None;
    let mut sign = false;
    let mut to = None;
    let mut rest = Vec::new();
    let mut it = args.iter().cloned();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-o" | "--output" => file = Some(it.next().ok_or("-o requires an argument")?),
            "--sign" => sign = true,
            "--to" => to = Some(it.next().ok_or("--to requires an argument")?),
            _ => rest.push(a),
        }
    }
    let flags = flake_cmd::take_flake_flags(&mut rest)?;
    let t = parse_target(&rest, &[])?;
    if let Some(f) = t.flags.iter().next() {
        return Err(format!("provenance: unknown flag '{f}'\n{USAGE}"));
    }
    let installable = t.file.clone().filter(|f| t.expr.is_none() && flake_cmd::is_installable(f));
    let ev = match &installable {
        Some(_) => flake_cmd::new_eval(cli, flags.impure)?,
        None => new_eval(cli)?,
    };
    let value = match &installable {
        Some(spec) => flake_cmd::eval_installable(&ev, cli, &flags, spec, flake_cmd::Kind::Build).map(|s| s.value),
        None => eval_target(&ev, cli, &t),
    }
    .map_err(|e| render_error(&ev, cli, &e))?;
    let mut drvs = Vec::new();
    collect_drvs(&ev, &value, &mut drvs).map_err(|e| render_error(&ev, cli, &e))?;
    if drvs.is_empty() {
        return Err("provenance: the expression names no derivation".into());
    }
    flake_cmd::realise(&ev, cli, &drvs)?;

    let keys = if sign || to.is_some() {
        let keys = read_secret_keys(cli.settings.secret_key_files.iter().map(String::as_str))?;
        if keys.is_empty() {
            return Err("provenance: signing needs a key in 'secret-key-files'".into());
        }
        keys
    } else {
        Vec::new()
    };
    let cache = to.as_deref().map(|u| open_cache(u, &cli.settings)).transpose()?;
    let opts = build_options(cli);
    let mut seen = std::collections::BTreeSet::new();
    let mut text = String::new();
    for (d, _) in &drvs {
        if !seen.insert(d.clone()) {
            continue;
        }
        for (_, p, st) in provenance::statements(&ev.store, d, &opts)? {
            let payload = serde_json::to_string(&st).unwrap();
            let line = if keys.is_empty() {
                payload
            } else {
                serde_json::to_string(&dsse::sign(dsse::IN_TOTO_PAYLOAD_TYPE, payload.as_bytes(), &keys)).unwrap()
            };
            if let Some(c) = &cache {
                let tmp = std::env::temp_dir().join(format!("cranix-provenance-{}-{}", std::process::id(), p.hash_part()));
                std::fs::write(&tmp, &line).map_err(|e| format!("writing '{}': {e}", tmp.display()))?;
                let r = c.put_file(&provenance::cache_file(&p), &tmp, "application/json");
                let _ = std::fs::remove_file(&tmp);
                r?;
            }
            text.push_str(&line);
            text.push('\n');
        }
    }
    match file {
        Some(f) => std::fs::write(&f, text).map_err(|e| format!("writing '{f}': {e}")),
        None => {
            print!("{text}");
            Ok(())
        }
    }
}

fn read_key(s: &str) -> Result<PublicKey, String> {
    let text = match std::fs::read_to_string(s) {
        Ok(t) => t,
        Err(_) => s.to_string(),
    };
    PublicKey::parse(&text)
}

/// Checks each envelope: a valid signature by a trusted key, an in-toto
/// statement as payload, and subjects whose digests match the store
/// paths this store holds.
fn cmd_verify(cli: &Cli, args: &[String]) -> Result<(), String> {
    let mut keys = trusted_keys(&cli.settings.trusted_public_keys);
    let mut file = None;
    let mut from = None;
    let mut paths = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--public-key" => keys.push(read_key(it.next().ok_or("--public-key requires an argument")?)?),
            "--from" => from = Some(it.next().ok_or("--from requires an argument")?.clone()),
            f if f.starts_with('-') && f != "-" => return Err(format!("provenance verify: unknown flag '{f}'\n{USAGE}")),
            f if from.is_some() => paths.push(f.to_string()),
            f => file = Some(f.to_string()),
        }
    }
    let store = crate::open_local_store(cli).ok();
    let mut docs: Vec<(String, Option<String>)> = Vec::new();
    match &from {
        Some(url) => {
            if paths.is_empty() {
                return Err(format!("provenance verify --from needs store paths\n{USAGE}"));
            }
            let cache = open_cache(url, &cli.settings)?;
            let dir = &store.as_ref().map(|s| s.dir.clone()).unwrap_or_default();
            for p in &paths {
                let sp = dir.parse(p).or_else(|_| StorePath::from_base_name(p.rsplit('/').next().unwrap_or(p)))?;
                let full = dir.print(&sp);
                let data = cache
                    .get_file(&provenance::cache_file(&sp))?
                    .ok_or_else(|| format!("the cache has no provenance for '{full}'"))?;
                docs.push((String::from_utf8_lossy(&data).into_owned(), Some(full)));
            }
        }
        None => {
            let mut text = String::new();
            match file.as_deref() {
                None | Some("-") => std::io::stdin().read_to_string(&mut text).map_err(|e| format!("reading stdin: {e}"))?,
                Some(f) => {
                    text = std::fs::read_to_string(f).map_err(|e| format!("reading '{f}': {e}"))?;
                    0
                }
            };
            docs.extend(text.lines().filter(|l| !l.trim().is_empty()).map(|l| (l.to_string(), None)));
        }
    }
    if docs.is_empty() {
        return Err("provenance verify: no envelopes to verify".into());
    }
    let mut failed = 0;
    for (i, (doc, want)) in docs.iter().enumerate() {
        let what = want.clone().unwrap_or_else(|| format!("envelope {}", i + 1));
        match verify_one(doc, want.as_deref(), &keys, store.as_ref()) {
            Ok(line) => println!("{line}"),
            Err(e) => {
                eprintln!("error: {what}: {e}");
                failed += 1;
            }
        }
    }
    if failed > 0 {
        return Err(format!("{failed} of {} statements failed verification", docs.len()));
    }
    Ok(())
}

fn verify_one(doc: &str, want: Option<&str>, keys: &[PublicKey], store: Option<&cranix_store::Store>) -> Result<String, String> {
    let env: Value = serde_json::from_str(doc).map_err(|e| format!("not JSON: {e}"))?;
    let v = dsse::verify(&env, keys)?;
    if v.payload_type != dsse::IN_TOTO_PAYLOAD_TYPE {
        return Err(format!("payload type '{}' is not an in-toto statement", v.payload_type));
    }
    let st: Value = serde_json::from_slice(&v.payload).map_err(|e| format!("the payload is not JSON: {e}"))?;
    if st["_type"] != provenance::STATEMENT_TYPE {
        return Err("the payload is not an in-toto Statement v1".into());
    }
    let subjects = st["subject"].as_array().ok_or("the statement has no subjects")?;
    let mut names = Vec::new();
    for s in subjects {
        let name = s["name"].as_str().ok_or("a subject has no name")?;
        let sha = s["digest"]["sha256"].as_str().ok_or_else(|| format!("subject '{name}' has no sha256 digest"))?;
        if let Some(store) = store {
            if let Ok(p) = store.dir.parse(name) {
                if let Some(info) = store.query_info(&p)? {
                    if info.nar_hash.to_base16() != sha {
                        return Err(format!("subject '{name}' has digest {sha}, but the store holds {}", info.nar_hash.to_base16()));
                    }
                }
            }
        }
        names.push(name.to_string());
    }
    if let Some(w) = want {
        if !names.iter().any(|n| n == w) {
            return Err(format!("the statement is about {}", names.join(", ")));
        }
    }
    Ok(format!("{}: signed by {}", names.join(", "), v.keys.join(", ")))
}
