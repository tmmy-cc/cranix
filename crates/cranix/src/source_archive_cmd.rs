//! `source-archive`: bundles every source of an installable's build graph
//! (fetched downloads, local source paths and the derivations naming
//! them) as a binary cache in a directory, a tarball or at a cache URL,
//! with an index of source, URL, hash and licence.

use std::fs;
use std::path::{Path, PathBuf};

use cranix_core::StorePath;
use cranix_sbom::release::{self, Kind};
use cranix_store::binary_cache::redact_url;
use cranix_store::substitute::open_cache;

use crate::{collect_drvs, eval_target, flake_cmd, new_eval, parse_target, render_error, sbom_cmd, Cli};

const USAGE: &str = "usage: cranix source-archive [FILE | --expr E | INSTALLABLE] [-A ATTR]
                             (-o DIR | --tarball FILE | --to URL) [--no-fetch]";

enum Dest {
    Dir(PathBuf),
    Tarball(PathBuf),
    Url(String),
}

pub fn cmd_source_archive(cli: &Cli, args: &[String]) -> Result<(), String> {
    let mut dest = Vec::new();
    let mut fetch = true;
    let mut rest = Vec::new();
    let mut it = args.iter().cloned();
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or_else(|| format!("{flag} requires an argument"));
        match a.as_str() {
            "-o" | "--output" => dest.push(Dest::Dir(value("-o")?.into())),
            "--tarball" => dest.push(Dest::Tarball(value("--tarball")?.into())),
            "--to" => dest.push(Dest::Url(value("--to")?)),
            "--no-fetch" => fetch = false,
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

    // Each download is fetched on its own, so that one that is gone
    // leaves the others.
    if fetch {
        for d in release::missing_fetches(&ev.store, &graph) {
            if let Err(e) = flake_cmd::realise(&ev, cli, &[(d.clone(), "out".into())]) {
                cranix_fetchers::warn(format!("cannot fetch '{}': {e}", ev.store.dir.print(&d)));
            }
        }
    }
    let entries = release::collect(&ev.store, &graph, &meta);
    let missing: Vec<_> = entries.iter().filter(|e| !e.available).collect();
    if !missing.is_empty() {
        eprintln!("warning: {} sources are not available and are listed as missing:", missing.len());
        for e in &missing {
            let urls = if e.urls.is_empty() { String::new() } else { format!(" ({})", e.urls.iter().map(|u| redact_url(u)).collect::<Vec<_>>().join(" ")) };
            eprintln!("  {}{urls}", ev.store.dir.print(&e.path));
        }
    }

    let s = &cli.settings;
    let copied = match &dest {
        Dest::Dir(dir) => release::write_cache(&ev.store, &entries, &open_cache(&file_url(dir)?, s)?)?,
        Dest::Url(url) => release::write_cache(&ev.store, &entries, &open_cache(url, s)?)?,
        Dest::Tarball(file) => {
            let tmp = std::env::temp_dir().join(format!("cranix-source-archive-{}", std::process::id()));
            let r = (|| {
                let n = release::write_cache(&ev.store, &entries, &open_cache(&file_url(&tmp)?, s)?)?;
                let f = fs::File::create(file).map_err(|e| format!("creating '{}': {e}", file.display()))?;
                release::write_tar_gz(&tmp, std::io::BufWriter::new(f)).map_err(|e| format!("writing '{}': {e}", file.display()))?;
                Ok::<_, String>(n)
            })();
            let _ = fs::remove_dir_all(&tmp);
            r?
        }
    };
    let count = |k: Kind| entries.iter().filter(|e| e.kind == k && e.available).count();
    let shown = match &dest {
        Dest::Dir(d) | Dest::Tarball(d) => d.display().to_string(),
        Dest::Url(u) => redact_url(u),
    };
    eprintln!(
        "archived {} fetched and {} local sources and {} derivations ({copied} new paths) to '{shown}'",
        count(Kind::Fetched),
        count(Kind::Local),
        count(Kind::Derivation)
    );
    Ok(())
}

fn file_url(dir: &Path) -> Result<String, String> {
    fs::create_dir_all(dir).map_err(|e| format!("creating '{}': {e}", dir.display()))?;
    let abs = fs::canonicalize(dir).map_err(|e| format!("'{}': {e}", dir.display()))?;
    Ok(format!("file://{}", abs.display()))
}
