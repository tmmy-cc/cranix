//! `copy`: uploads closures to a binary cache or a directory of NARs, with
//! the filters of `cranix_store::select`, and substitutes closures from a
//! cache.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use cranix_core::nar;
use cranix_core::StorePath;
use cranix_store::binary_cache::{read_secret_keys, redact_url};
use cranix_store::select::{Filter, Reason, Selection, Selector};
use cranix_store::substitute::{open_cache, trusted_keys, Substituters};
use cranix_store::Store;

use crate::{open_local_store, parse_store_path, Cli};

const USAGE: &str = "usage: cranix copy (--to URL | --to-nars DIR) [--dry-run] [--type TYPES] [--exclude-host GLOB]...
                   [--exclude-name GLOB]... [--exclude-class system|test] [--exclude-local] PATH...
       cranix copy --from URL [--no-check-sigs] PATH...";

pub fn cmd_copy(cli: &Cli, args: &[String]) -> Result<(), String> {
    let mut to = None;
    let mut to_nars = None;
    let mut from = None;
    let mut dry_run = false;
    let mut filter = Filter::default();
    let mut check_sigs = cli.settings.require_sigs;
    let mut paths = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().cloned().ok_or_else(|| format!("{flag} requires an argument"));
        match a.as_str() {
            "--to" => to = Some(value("--to")?),
            "--to-nars" => to_nars = Some(PathBuf::from(value("--to-nars")?)),
            "--from" => from = Some(value("--from")?),
            "--no-check-sigs" => check_sigs = false,
            "--dry-run" => dry_run = true,
            "--type" => filter.add_types(&value("--type")?)?,
            "--exclude-host" => filter.hosts.push(value("--exclude-host")?),
            "--exclude-name" => filter.names.push(value("--exclude-name")?),
            "--exclude-class" => filter.add_classes(&value("--exclude-class")?)?,
            "--exclude-local" => filter.local = true,
            f if f.starts_with('-') => return Err(format!("copy: unknown flag '{f}'\n{USAGE}")),
            p => paths.push(p.to_string()),
        }
    }
    let mut store = open_local_store(cli)?;
    let roots: Vec<StorePath> = paths.iter().map(|p| parse_store_path(&store.dir, p)).collect::<Result<_, _>>()?;
    match (to, to_nars, from) {
        (Some(_), Some(_), _) => Err(format!("copy: --to and --to-nars exclude each other\n{USAGE}")),
        (to, nars, None) if to.is_some() || nars.is_some() => {
            let sel = Selector::new(&store, filter).select(&roots)?;
            report(&store, &sel, dry_run);
            if dry_run {
                return Ok(());
            }
            match (to, nars) {
                (Some(url), _) => upload(cli, &store, &sel, &url),
                (_, Some(dir)) => export_nars(&store, &sel, &dir),
                _ => unreachable!(),
            }
        }
        (None, None, Some(from)) if filter.is_empty() && !dry_run => {
            let s = &cli.settings;
            let cache = open_cache(&from, s)?;
            let keys = trusted_keys(&s.trusted_public_keys);
            store.set_substituters(
                Substituters::new(vec![cache], keys, check_sigs, s.max_substitution_jobs)
                    .narinfo_ttls(s.narinfo_cache_positive_ttl, s.narinfo_cache_negative_ttl),
            );
            let failed = store.substitute_paths(&roots)?;
            if let Some(p) = failed.first() {
                return Err(format!("path '{}' is not available from '{}'", store.dir.print(p), redact_url(&from)));
            }
            Ok(())
        }
        (None, None, Some(_)) => Err(format!("copy: filters and --dry-run apply to --to and --to-nars\n{USAGE}")),
        _ => Err(USAGE.into()),
    }
}

/// Prints what a selection left out, and with `dry_run` what it takes,
/// one path per line on standard output.
fn report(store: &Store, sel: &Selection, dry_run: bool) {
    let missing: Vec<&StorePath> = sel.left_out.iter().filter(|(_, r)| **r == Reason::Missing).map(|(p, _)| p).collect();
    if !missing.is_empty() {
        eprintln!("warning: leaving out {} paths that are not in the local store:", missing.len());
        for p in &missing {
            eprintln!("  {}", store.dir.print(p));
        }
    }
    if !dry_run {
        return;
    }
    let mut out = std::io::stdout().lock();
    for (p, ty) in &sel.take {
        let why = ty.map_or("reference".to_string(), |t| t.name().to_string());
        writeln!(out, "copy {} ({why})", store.dir.print(p)).ok();
    }
    for (p, r) in &sel.left_out {
        writeln!(out, "skip {}: {r}", store.dir.print(p)).ok();
    }
}

pub fn upload(cli: &Cli, store: &Store, sel: &Selection, url: &str) -> Result<(), String> {
    let s = &cli.settings;
    let cache = open_cache(url, s)?;
    // Uploads replace what the store remembers about this cache.
    let disk = store.narinfo_cache(&cache.url, s.narinfo_cache_positive_ttl, s.narinfo_cache_negative_ttl);
    let cache = cache.with_narinfo_cache(disk);
    cache.init_for_writing(&store.dir)?;
    let mut key_files: Vec<&str> = s.secret_key_files.iter().map(String::as_str).collect();
    key_files.extend(cache.param("secret-key"));
    let keys = read_secret_keys(key_files)?;
    let mut copied = 0;
    let mut taken = BTreeSet::new();
    // References come before the paths that refer to them.
    for (p, _) in &sel.take {
        taken.insert(p.clone());
        if cache.file_exists(&format!("{}.narinfo", p.hash_part()))? {
            continue;
        }
        eprintln!("copying path '{}' to '{}'...", store.dir.print(p), cache.shown());
        let info = store.query_info(p)?.ok_or_else(|| format!("path '{}' is not valid", store.dir.print(p)))?;
        cache.add_path(&store.dir, &store.real_path(p), &info, &store.query_sigs(p)?, &keys)?;
        copied += 1;
    }
    // Realisations of the copied outputs follow their paths.
    for r in store.realisations_of(&taken)? {
        cache.add_realisation(&r, &keys)?;
    }
    eprintln!("copied {copied} paths");
    Ok(())
}

/// Writes each selected path as `DIR/<name>.nar`, with `DIR/index.json`
/// listing their metadata in upload order.
fn export_nars(store: &Store, sel: &Selection, dir: &std::path::Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("creating '{}': {e}", dir.display()))?;
    let mut index = Vec::new();
    for (p, _) in &sel.take {
        let info = store.query_info(p)?.ok_or_else(|| format!("path '{}' is not valid", store.dir.print(p)))?;
        let file = dir.join(format!("{p}.nar"));
        let f = fs::File::create(&file).map_err(|e| format!("creating '{}': {e}", file.display()))?;
        let mut w = std::io::BufWriter::new(f);
        nar::dump(&store.real_path(p), &mut w).and_then(|_| w.flush()).map_err(|e| format!("writing '{}': {e}", file.display()))?;
        index.push(serde_json::json!({
            "path": store.dir.print(p),
            "nar": format!("{p}.nar"),
            "narHash": info.nar_hash.to_sri(),
            "narSize": info.nar_size,
            "references": info.references.iter().map(|r| store.dir.print(r)).collect::<Vec<_>>(),
            "deriver": info.deriver.as_ref().map(|d| store.dir.print(d)),
            "ca": info.ca,
            "signatures": store.query_sigs(p)?,
        }));
    }
    let idx = dir.join("index.json");
    fs::write(&idx, serde_json::to_string_pretty(&index).unwrap() + "\n").map_err(|e| format!("writing '{}': {e}", idx.display()))?;
    eprintln!("exported {} paths to '{}'", index.len(), dir.display());
    Ok(())
}
