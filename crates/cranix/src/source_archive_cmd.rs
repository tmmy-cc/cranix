//! `source-archive`: bundles every source of an installable's build graph
//! (fetched downloads and local source paths, optionally the derivations
//! naming them) as a binary cache in a directory, a tarball or any cache
//! `copy --to` takes, with an index of source, URL, hash and licence.
//! Only fixed-output derivations are substituted or built.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cranix_core::StorePath;
use cranix_sbom::release::{self, Kind};
use cranix_store::binary_cache::redact_url;
use cranix_store::select::{Filter, Selector};
use cranix_store::substitute::open_cache;

use crate::{collect_drvs, copy_cmd, eval_target, flake_cmd, new_eval, parse_target, render_error, sbom_cmd, Cli};

const USAGE: &str = "usage: cranix source-archive [FILE | --expr E | INSTALLABLE] [-A ATTR]
                             (-o DIR | --tarball FILE | --to URL) [--drvs] [--no-fetch]
                             [--exclude-host GLOB]... [--exclude-name GLOB]... [--exclude-class system|test] [--exclude-local]";

enum Dest {
    Dir(PathBuf),
    Tarball(PathBuf),
    Url(String),
}

pub fn cmd_source_archive(cli: &Cli, args: &[String]) -> Result<(), String> {
    let mut dest = Vec::new();
    let mut fetch = true;
    let mut with_drvs = false;
    let mut filter = Filter::default();
    let mut rest = Vec::new();
    let mut it = args.iter().cloned();
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or_else(|| format!("{flag} requires an argument"));
        match a.as_str() {
            "-o" | "--output" => dest.push(Dest::Dir(value("-o")?.into())),
            "--tarball" => dest.push(Dest::Tarball(value("--tarball")?.into())),
            "--to" => dest.push(Dest::Url(value("--to")?)),
            "--drvs" => with_drvs = true,
            "--no-fetch" => fetch = false,
            "--exclude-host" => filter.hosts.push(value("--exclude-host")?),
            "--exclude-name" => filter.names.push(value("--exclude-name")?),
            "--exclude-class" => filter.add_classes(&value("--exclude-class")?)?,
            "--exclude-local" => filter.local = true,
            _ => rest.push(a),
        }
    }
    let dest = match dest.len() {
        1 => dest.pop().unwrap(),
        _ => return Err(format!("source-archive: give one of -o, --tarball and --to\n{USAGE}")),
    };
    let flags = flake_cmd::take_flake_flags(&mut rest)?;
    let t = parse_target(&rest, &[])?;
    if let Some(f) = t.flags.iter().next() {
        return Err(format!("source-archive: unknown flag '{f}'\n{USAGE}"));
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
        return Err("source-archive: the expression names no derivation".into());
    }
    let meta = sbom_cmd::package_meta(&ev, &value);
    let roots: Vec<StorePath> = drvs.iter().map(|(d, _)| d.clone()).collect();
    let graph = release::graph(&ev.store, &roots)?;
    let failed = if fetch { fetch_sources(&ev, cli, &graph) } else { Default::default() };

    let mut entries = release::collect(&ev.store, &graph, &meta);
    if !with_drvs {
        entries.retain(|e| e.kind != Kind::Derivation);
    }
    for e in entries.iter_mut().filter(|e| !e.available) {
        let why = e.fetcher.as_ref().and_then(|f| failed.get(f));
        e.reason = Some(why.cloned().unwrap_or_else(|| "not fetched".into()));
    }

    // The selection applies the filters of `copy` and orders references
    // first.
    let sel = Selector::new(&ev.store, filter).select(&entries.iter().filter(|e| e.available).map(|e| e.path.clone()).collect::<Vec<_>>())?;
    for e in entries.iter_mut() {
        if let Some(r) = sel.left_out.get(&e.path) {
            e.reason = Some(format!("left out: {r}"));
        }
    }
    let missing: Vec<_> = entries.iter().filter(|e| !e.available).collect();
    if !missing.is_empty() {
        eprintln!("warning: {} sources are not available and are listed as missing:", missing.len());
        for e in &missing {
            let urls = if e.urls.is_empty() { String::new() } else { format!(" ({})", e.urls.iter().map(|u| redact_url(u)).collect::<Vec<_>>().join(" ")) };
            eprintln!("  {}{urls}: {}", ev.store.dir.print(&e.path), e.reason.as_deref().unwrap_or_default());
        }
    }

    let s = &cli.settings;
    let write = |url: &str| -> Result<(), String> {
        copy_cmd::upload(cli, &ev.store, &sel, url)?;
        release::write_index(&ev.store, &entries, &open_cache(url, s)?)
    };
    match &dest {
        Dest::Dir(dir) => write(&file_url(dir)?)?,
        Dest::Url(url) => write(url)?,
        Dest::Tarball(file) => {
            let tmp = std::env::temp_dir().join(format!("cranix-source-archive-{}", std::process::id()));
            let r = (|| {
                write(&file_url(&tmp)?)?;
                let f = fs::File::create(file).map_err(|e| format!("creating '{}': {e}", file.display()))?;
                release::write_tar_gz(&tmp, std::io::BufWriter::new(f)).map_err(|e| format!("writing '{}': {e}", file.display()))
            })();
            let _ = fs::remove_dir_all(&tmp);
            r?
        }
    }
    let count = |k: Kind| entries.iter().filter(|e| e.kind == k && e.available && e.reason.is_none()).count();
    let shown = match &dest {
        Dest::Dir(d) | Dest::Tarball(d) => d.display().to_string(),
        Dest::Url(u) => redact_url(u),
    };
    eprintln!(
        "archived {} fetched and {} local sources and {} derivations to '{shown}'",
        count(Kind::Fetched),
        count(Kind::Local),
        count(Kind::Derivation)
    );
    match missing.len() {
        0 => Ok(()),
        n => Err(format!("source-archive: {n} sources could not be fetched; the index lists them")),
    }
}

/// Substitutes or builds the missing fixed-output derivations of `graph`,
/// one at a time and inputs first, and builds nothing else. Returns why
/// each one that is still missing failed.
fn fetch_sources(ev: &cranix_eval::Eval, cli: &Cli, graph: &BTreeMap<StorePath, cranix_core::Derivation>) -> BTreeMap<StorePath, String> {
    let mut failed = BTreeMap::new();
    let outs: Vec<StorePath> = release::missing_fetches(&ev.store, graph).iter().filter_map(|d| graph[d].outputs["out"].path.clone()).collect();
    if let Err(e) = ev.store.substitute_paths(&outs) {
        cranix_fetchers::warn(format!("substituting sources: {e}"));
    }
    let mut todo = release::missing_fetches(&ev.store, graph);
    while let Some(d) = todo.pop() {
        if failed.contains_key(&d) || !release::missing_fetches(&ev.store, graph).contains(&d) {
            continue;
        }
        let why = match release::blocker(&ev.store, graph, &d) {
            Ok(()) => match flake_cmd::realise(ev, cli, &[(d.clone(), "out".into())]) {
                Ok(_) => continue,
                Err(e) => e,
            },
            Err(Ok(input)) if !failed.contains_key(&input) => {
                todo.retain(|x| *x != input);
                todo.push(d);
                todo.push(input);
                continue;
            }
            Err(Ok(input)) => format!("its input '{}' cannot be fetched", ev.store.dir.print(&input)),
            Err(Err(msg)) => msg,
        };
        cranix_fetchers::warn(format!("cannot fetch '{}': {why}", ev.store.dir.print(&d)));
        failed.insert(d, why);
    }
    failed
}

fn file_url(dir: &Path) -> Result<String, String> {
    fs::create_dir_all(dir).map_err(|e| format!("creating '{}': {e}", dir.display()))?;
    let abs = fs::canonicalize(dir).map_err(|e| format!("'{}': {e}", dir.display()))?;
    Ok(format!("file://{}", abs.display()))
}
