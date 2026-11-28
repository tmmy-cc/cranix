//! `cranix`: command line front end.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;

use cranix_core::hash::{Encoding, Hash, HashAlgo, HashSink};
use cranix_core::{nar, FileIngestion, OutputKind, StorePath};
use cranix_eval::value::{Attrs, Sym};
use cranix_eval::{print, Eval, Options, RenderOptions, Value};
use cranix_store::binary_cache::{read_secret_keys, redact_url, BinaryCache};
use cranix_store::build::{default_root, BuildOptions};
use cranix_store::settings::{Kind, Settings};
use cranix_store::substitute::{open_cache, Substituters};
use cranix_store::Store;

mod cache_serve;
mod copy_cmd;
mod provenance_cmd;
mod sbom_cmd;
mod source_archive_cmd;
mod vuln_cmd;
mod remote;
mod flake_cmd;
mod eval_cache;
mod nix_env_cmd;
mod profile_cmd;
mod profiles;

#[cfg(not(feature = "dhat-heap"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static GLOBAL: dhat::Alloc = dhat::Alloc;

const USAGE: &str = "\
usage: cranix [global options] <command> [args]

commands:
  eval [FILE | --expr E | INSTALLABLE] [-A ATTR] [--json | --raw] [--lazy]
  instantiate [FILE | --expr E] [-A ATTR]       write .drv files, print their paths
  build [FILE | --expr E | INSTALLABLE] [-A ATTR] [-o LINK | --no-link] [-j N] [-L] [--keep-failed] [--check]
        [--upload-to URL [--upload-jobs N] [--upload-required]]   upload outputs as they are built
  run INSTALLABLE [-- ARGS]                      build and run a flake app or package
  shell INSTALLABLE... [-c CMD ARGS]             shell with the packages on PATH
  develop [INSTALLABLE] [-c CMD ARGS]            shell with a derivation's build environment
  flake metadata|show|lock|update|check|init|new [FLAKE] [--json]
  show-derivation DRV                            print a derivation as JSON
  realisation info [FILE | --expr E | DRV^OUT...] [-A ATTR] [--json]
  hash path|file PATH [--type ALGO] [--base16|--base32|--sri]
  hash convert HASH [--to base16|nix32|base64|sri]
  nar dump PATH > out.nar | nar restore DEST < in.nar
  store add PATH | closure PATH... | verify | gc [--dry-run] | ls
  store path-info [--json] [-r] [-S | --closure-size] PATH...
  store sign -k KEYFILE [-r] PATH...            add signatures to local paths
  copy --to URL PATH... | copy --from URL PATH...   copy closures to or from a binary cache
        [--to-nars DIR] [--dry-run] [--type TYPES] [--exclude-host GLOB] [--exclude-name GLOB]
        [--exclude-class system|test] [--exclude-local]   choose what is copied
  cache serve [--listen ADDR:PORT] URL           serve a binary cache (e.g. s3://, gitlab://) over HTTP
  sbom [FILE | --expr E | INSTALLABLE] [-A ATTR] [--format cyclonedx|spdx] [-o FILE]
        [--build-time] [--scan-binaries] [--scan-sources] [--merge DOC]   SBOM of a package or NixOS system
  sbom lock Cargo.lock|package-lock.json        SBOM of a lock file
  provenance [FILE | --expr E | INSTALLABLE] [-A ATTR] [-o FILE] [--sign] [--to URL]
                                                 SLSA provenance of the outputs, optionally signed
  provenance verify [FILE | --from URL PATH...] [--public-key KEY]   check signed provenance
  source-archive [FILE | --expr E | INSTALLABLE] [-A ATTR] (-o DIR | --tarball FILE | --to URL)
        [--drvs] [--no-fetch] [--exclude-host GLOB] ...   bundle every source of a release with an index
  vuln-db update [--db DIR] | vuln-db import [--osv FILE] [--nvd FEED]   vulnerability database
  vuln-scan SBOM [--vex FILE] [--fail-on LEVEL] [--max-db-age 7d] [--report FILE]
                                                 check an SBOM; exits 2 on findings, 3 on an old database
  key generate-secret --key-name NAME | key convert-secret-to-public < KEY
  config show [--show-secrets] [NAME]            print the settings in effect
  store serve [--write]                          serve the store to ssh:// clients (also: --serve)
  nix-env [-p PROFILE] [-f FILE] -i [-A] NAME... | -e NAME... | -u [NAME...] | -q [-a] [-P] [--out-path]
        | --rollback | --list-generations | --switch-generation N | --delete-generations old|Nd|+N|N...
                                                 manage a profile with manifest.nix, as nix-env does
  profile install|remove|upgrade|list|rollback|history|wipe-history [--profile PATH] ...
                                                 manage a profile with manifest.json, as nix profile does
  daemon [--stdio] [--socket PATH] [--force-trusted|--force-untrusted]
                                                 serve the store to Nix clients

global options:
  --store DIR       use a store rooted at DIR whose store directory is DIR/store
                    (required for building); default: chroot store at ~/.local/share/cranix
  --store daemon | unix://SOCKET[?store=DIR] | ssh-ng://[USER@]HOST | ssh://[USER@]HOST
                    build through a Nix daemon (evaluation still writes to the default store)
  --builders SPEC   remote builders in Nix's machines format, or @FILE
                    (the `builders` setting; default @/etc/nix/machines)
  -I [PREFIX=]PATH  add to the search path (also read from $NIX_PATH)
  --arg NAME EXPR, --argstr NAME STRING   arguments for auto-called functions
  --system SYSTEM   value of builtins.currentSystem
  --pure            restrict impure builtins
  --show-trace      show the full trace of evaluation errors
  --option NAME VALUE   set a setting; every setting NAME also has the flags
                    --NAME VALUE, --extra-NAME VALUE (lists) or --NAME/--no-NAME
                    (Booleans), e.g. --sandbox, --timeout N, --substituters URLS,
                    --extra-experimental-features ca-derivations, --trusted-users U
                    settings are read, later ones winning, from $NIX_CONF_DIR/nix.conf
                    (/etc/nix), ~/.config/nix/nix.conf ($XDG_CONFIG_HOME,
                    $NIX_USER_CONF_FILES), ~/.config/cranix/cranix.conf,
                    $CRANIX_CONFIG, $NIX_CONFIG and then the command line
  --store URL       for 'store path-info', read a binary cache (file://, https://, s3://BUCKET,
                    gitlab://HOST/GROUP/PROJECT or github://OWNER/REPO)

flake options (eval, build, run, shell, develop, flake):
  --impure, --no-write-lock-file, --no-update-lock-file, --recreate-lock-file,
  --commit-lock-file, --update-input PATH, --override-input PATH REF,
  --override-flake FROM TO, --no-registries, --refresh

installables are flake references with an optional attribute path, e.g.
  .#hello, nixpkgs#hello, github:NixOS/nixpkgs/nixos-24.05#hello
";

struct Cli {
    store: Option<PathBuf>,
    remote: Option<cranix_daemon::client::StoreUri>,
    search: Vec<(String, String)>,
    /// `prefix=flake:ref` search path entries, resolved when evaluating.
    flake_search: Vec<(String, String)>,
    args: Vec<(String, ArgVal)>,
    pure: bool,
    show_trace: bool,
    /// The configuration files, the environment and the command line's
    /// settings, in that order of precedence.
    settings: Settings,
    rest: Vec<String>,
}

enum ArgVal {
    Expr(String),
    Str(String),
}

fn parse_search(s: &str) -> Option<(String, String)> {
    let (prefix, path) = match s.split_once('=') {
        Some((p, v)) => (p.to_string(), v.to_string()),
        None => (String::new(), s.to_string()),
    };
    // Relative entries resolve against the working directory when looked up.
    (!path.is_empty()).then_some((prefix, path))
}

/// Splits `NIX_PATH` at colons that do not belong to a `flake:` or URL
/// scheme.
fn split_nix_path(np: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in np.split(':') {
        match out.last_mut() {
            Some(last) if last.ends_with("flake") || last.ends_with("https") || last.ends_with("http") || part.starts_with("//") => {
                last.push(':');
                last.push_str(part);
            }
            _ => out.push(part.to_string()),
        }
    }
    out.into_iter().filter(|s| !s.is_empty()).collect()
}

impl Cli {
    /// The system that builds run on and `builtins.currentSystem`.
    fn system(&self) -> &str {
        &self.settings.build.system
    }

    fn add_search(&mut self, s: &str) {
        let (prefix, path) = s.split_once('=').unwrap_or(("", s));
        if path.starts_with("flake:") {
            self.flake_search.push((prefix.to_string(), path.to_string()));
        } else {
            self.search.extend(parse_search(s));
        }
    }
}

fn parse_cli() -> Result<Cli, String> {
    let mut cli = Cli {
        store: None,
        remote: None,
        search: Vec::new(),
        flake_search: Vec::new(),
        args: Vec::new(),
        pure: false,
        show_trace: false,
        settings: Settings::load()?,
        rest: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| format!("{name} requires an argument"));
        match a.as_str() {
            // What follows belongs to the program being run.
            "--" | "-c" | "--command" if !cli.rest.is_empty() => {
                cli.rest.push(a);
                cli.rest.extend(it.by_ref());
            }
            "--store" => {
                let v = val("--store")?;
                match cranix_daemon::client::StoreUri::parse(&v) {
                    Some(u) => cli.remote = Some(u),
                    None => cli.store = Some(PathBuf::from(v)),
                }
            }
            "-I" => {
                let v = val("-I")?;
                cli.add_search(&v);
            }
            "--arg" => {
                let n = val("--arg")?;
                let e = val("--arg")?;
                cli.args.push((n, ArgVal::Expr(e)));
            }
            "--argstr" => {
                let n = val("--argstr")?;
                let s = val("--argstr")?;
                cli.args.push((n, ArgVal::Str(s)));
            }
            "--pure" => cli.pure = true,
            "--show-trace" => cli.show_trace = true,
            "--option" => {
                let n = val("--option")?;
                let v = val("--option")?;
                cli.settings.set(&n, &v)?;
            }
            "--relaxed-sandbox" => cli.settings.set("sandbox", "relaxed")?,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            f => match setting_flag(f) {
                Some((name, None)) => cli.settings.set(&name, if f.starts_with("--no-") { "false" } else { "true" })?,
                Some((name, Some(()))) => {
                    let v = val(f)?;
                    cli.settings.set(&name, &v)?;
                }
                None => cli.rest.push(a),
            },
        }
    }
    if let Ok(np) = std::env::var("NIX_PATH") {
        for e in split_nix_path(&np) {
            cli.add_search(&e);
        }
    }
    cranix_fetchers::set_settings(|f| *f = cli.settings.fetch.clone());
    Ok(cli)
}

/// The setting a command line flag sets, as Nix derives flags from
/// settings: `--NAME`/`--no-NAME` for Booleans (no value follows),
/// `--NAME VALUE` for the others and `--extra-NAME VALUE` for lists.
fn setting_flag(flag: &str) -> Option<(String, Option<()>)> {
    let n = flag.strip_prefix("--")?;
    if let Some(base) = n.strip_prefix("extra-") {
        if Settings::kind(base) == Some(Kind::List) {
            return Some((n.to_string(), Some(())));
        }
    }
    match Settings::kind(n) {
        Some(Kind::Bool) => return Some((n.to_string(), None)),
        Some(_) => return Some((n.to_string(), Some(()))),
        None => {}
    }
    let base = n.strip_prefix("no-")?;
    (Settings::kind(base) == Some(Kind::Bool)).then(|| (base.to_string(), None))
}

fn store_url(cli: &Cli) -> Option<String> {
    let s = cli.store.as_ref()?.to_string_lossy().into_owned();
    s.contains("://").then_some(s)
}

/// Opens the local store without substituters.
fn open_local_store(cli: &Cli) -> Result<Store, String> {
    if let Some(u) = &cli.remote {
        return remote::eval_store(u);
    }
    if let Some(u) = store_url(cli) {
        return Err(format!("binary cache '{}' can only be used with 'store path-info'", redact_url(&u)));
    }
    match &cli.store {
        Some(d) => Store::open_at(d),
        None => Store::open_chroot(&default_root()),
    }
}

fn open_store(cli: &Cli) -> Result<Store, String> {
    let mut store = open_local_store(cli)?;
    store.set_substituters(Substituters::from_settings(&cli.settings)?);
    store.set_signing_keys(read_secret_keys(cli.settings.secret_key_files.iter().map(String::as_str))?);
    Ok(store)
}

fn main() -> ExitCode {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();
    // Deeply recursive Nix code (nixpkgs fixpoints) needs a large stack.
    let child = std::thread::Builder::new().stack_size(1 << 30).spawn(run).expect("spawning main thread");
    let result = child.join();
    cranix_eval::astcache::flush();
    match result {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(e)) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
        Err(_) => ExitCode::from(101),
    }
}

fn run() -> Result<(), String> {
    let cli = parse_cli()?;
    let Some(cmd) = cli.rest.first().cloned() else {
        return Err(USAGE.to_string());
    };
    let args: Vec<String> = cli.rest[1..].to_vec();
    match cmd.as_str() {
        "eval" => cmd_eval(&cli, &args),
        "instantiate" => cmd_instantiate(&cli, &args, false),
        "build" => cmd_instantiate(&cli, &args, true),
        "show-derivation" => cmd_show_derivation(&cli, &args),
        "realisation" => cmd_realisation(&cli, &args),
        "hash" => cmd_hash(&args),
        "nar" => cmd_nar(&args),
        "store" if args.first().map(String::as_str) == Some("serve") => serve(&cli, &args[1..]),
        "--serve" => serve(&cli, &args),
        "store" => cmd_store(&cli, &args),
        "copy" => copy_cmd::cmd_copy(&cli, &args),
        "sbom" => sbom_cmd::cmd_sbom(&cli, &args),
        "provenance" => provenance_cmd::cmd_provenance(&cli, &args),
        "source-archive" => source_archive_cmd::cmd_source_archive(&cli, &args),
        "vuln-db" => vuln_cmd::cmd_vuln_db(&cli, &args),
        "vuln-scan" => vuln_cmd::cmd_vuln_scan(&args),
        "cache" => cache_serve::cmd_cache(&cli.settings, &args),
        "key" => cmd_key(&args),
        "config" => cmd_config(&cli, &args),
        "daemon" => {
            if cli.remote.is_some() {
                return Err("cranix daemon serves a local store; pass --store DIR".into());
            }
            remote::cmd_daemon(open_store(&cli)?, &args, &cli.settings)
        }
        "flake" => flake_cmd::cmd_flake(&cli, &args),
        "nix-env" | "env" => nix_env_cmd::cmd_nix_env(&cli, &args),
        "profile" => profile_cmd::cmd_profile(&cli, &args),
        "run" | "shell" | "develop" => flake_cmd::cmd_run_like(&cli, &cmd, &args),
        c => Err(format!("unknown command '{c}'\n{USAGE}")),
    }
}

fn serve(cli: &Cli, args: &[String]) -> Result<(), String> {
    if cli.remote.is_some() {
        return Err("serving needs a local store; pass --store DIR".into());
    }
    remote::cmd_serve(open_store(cli)?, args, &cli.settings)
}

struct Target {
    file: Option<String>,
    expr: Option<String>,
    attr: Option<String>,
    flags: BTreeSet<String>,
    opts: Vec<(String, String)>,
}

fn parse_target(args: &[String], value_flags: &[&str]) -> Result<Target, String> {
    let mut t = Target { file: None, expr: None, attr: None, flags: BTreeSet::new(), opts: Vec::new() };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--expr" | "-E" => t.expr = Some(it.next().ok_or("--expr requires an argument")?.clone()),
            "-A" | "--attr" => t.attr = Some(it.next().ok_or("-A requires an argument")?.clone()),
            f if value_flags.contains(&f) => {
                t.opts.push((f.to_string(), it.next().ok_or_else(|| format!("{f} requires an argument"))?.clone()))
            }
            f if f.starts_with('-') => {
                t.flags.insert(f.to_string());
            }
            f => t.file = Some(f.to_string()),
        }
    }
    Ok(t)
}

fn new_eval(cli: &Cli) -> Result<Rc<Eval>, String> {
    let mut search_path = cli.search.clone();
    search_path.extend(cli.flake_search.iter().cloned());
    let store = open_store(cli)?;
    let opts = Options {
        search_path,
        system: cli.system().to_string(),
        pure: cli.pure,
        trace_verbose: false,
        experimental_features: cli.settings.experimental_features.clone(),
        resolve_search: Some(Box::new(flake_cmd::resolve_search_entry)),
    };
    Ok(Eval::new(store, opts))
}

/// Renders an evaluation error for stderr, in colour when stderr is a
/// terminal and `NO_COLOR` is unset.
fn render_error(ev: &Eval, cli: &Cli, e: &cranix_eval::EvalError) -> String {
    use std::io::IsTerminal;
    let color = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").map_or(true, |v| v.is_empty());
    ev.render_error(e, &RenderOptions { show_trace: cli.show_trace, color })
}

fn build_options(cli: &Cli) -> BuildOptions {
    cli.settings.build_options()
}

fn cwd() -> String {
    std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "/".into())
}

/// Evaluates the target, auto-calls functions and selects `-A`.
fn eval_target(ev: &Eval, cli: &Cli, t: &Target) -> cranix_eval::R<Value> {
    let mut v = match (&t.expr, &t.file) {
        (Some(e), _) => ev.eval_string(e, &cwd())?,
        (None, Some(f)) => {
            let p = if f.starts_with('/') { f.clone() } else { format!("{}/{f}", cwd()) };
            ev.import(&p)?
        }
        (None, None) => ev.import(&format!("{}/default.nix", cwd()))?,
    };
    v = auto_call(ev, cli, v)?;
    if let Some(path) = &t.attr {
        for k in path.split('.').filter(|k| !k.is_empty()) {
            // Numeric components index into lists, as in nix-instantiate.
            v = match (ev.force(&v)?, k.parse::<usize>()) {
                (Value::List(l), Ok(i)) => match l.get(i) {
                    Some(x) => ev.force(x)?,
                    None => return cranix_eval::eval::err(format!("list index {i} in selection path '{path}' is out of bounds")),
                },
                (v, _) => match ev.force_attrs(&v)?.get(&Sym::new(k)) {
                    Some(x) => ev.force(x)?,
                    None => return cranix_eval::eval::err(format!("attribute '{k}' in selection path '{path}' not found")),
                },
            };
            v = auto_call(ev, cli, v)?;
        }
    }
    Ok(v)
}

fn auto_call(ev: &Eval, cli: &Cli, v: Value) -> cranix_eval::R<Value> {
    let v = ev.force(&v)?;
    let Value::Lambda(c) = &v else { return Ok(v) };
    let Some(formals) = &c.def.formals else { return Ok(v) };
    let mut entries = Vec::new();
    for (name, a) in &cli.args {
        if !formals.ellipsis && !formals.entries.iter().any(|(s, _)| s.as_str() == name) {
            continue;
        }
        let val = match a {
            ArgVal::Expr(e) => ev.eval_string(e, &cwd())?,
            ArgVal::Str(s) => Value::str(s.as_str()),
        };
        entries.push((Sym::new(name), val));
    }
    let r = ev.call(&v, Value::attrs(Attrs::from_unsorted(entries)))?;
    ev.force(&r)
}

fn cmd_eval(cli: &Cli, args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    let flags = flake_cmd::take_flake_flags(&mut args)?;
    let t = parse_target(&args, &[])?;
    if let Some(spec) = t.file.as_deref().filter(|f| t.expr.is_none() && flake_cmd::is_installable(f)) {
        return flake_cmd::cmd_eval(cli, spec, &flags, t.flags.contains("--json"), t.flags.contains("--raw"));
    }
    let ev = new_eval(cli)?;
    let r = (|| {
        let v = eval_target(&ev, cli, &t)?;
        if t.flags.contains("--json") {
            let mut s = String::new();
            print::to_json(&ev, &v, &mut s, &mut Default::default())?;
            Ok(s)
        } else if t.flags.contains("--raw") {
            Ok(ev.force_str(&v)?.s.clone())
        } else {
            let strict = !t.flags.contains("--lazy");
            if strict {
                ev.deep_force(&v)?;
            }
            print::print_value(&ev, &v, strict)
        }
    })();
    match r {
        Ok(s) => {
            println!("{s}");
            Ok(())
        }
        Err(e) => Err(render_error(&ev, cli, &e)),
    }
}

/// Derivations named by a value: one derivation, a list of them, or the
/// derivations among a set's attributes.
fn collect_drvs(ev: &Eval, v: &Value, out: &mut Vec<(StorePath, String)>) -> cranix_eval::R<()> {
    let v = ev.force(v)?;
    match &v {
        Value::Attrs(a) if ev.is_derivation(a)? => {
            let drv = ev.force_str(a.get_str("drvPath").ok_or(()).or_else(|_| cranix_eval::eval::err("derivation without drvPath"))?)?;
            let out_name = match a.get_str("outputName") {
                Some(o) => ev.force_plain_str(o)?,
                None => "out".into(),
            };
            out.push((ev.store.dir.parse(&drv.s).or_else(cranix_eval::eval::err)?, out_name));
        }
        Value::Attrs(a) => {
            for (_, x) in a.iter() {
                let x = ev.force(x)?;
                if let Value::Attrs(b) = &x {
                    if ev.is_derivation(b)? {
                        collect_drvs(ev, &x, out)?;
                    }
                }
            }
        }
        Value::List(l) => {
            for x in l.iter() {
                collect_drvs(ev, x, out)?;
            }
        }
        v => return cranix_eval::eval::err(format!("expected a derivation but found {}", v.describe())),
    }
    Ok(())
}

/// The derivations of a flake installable, from the evaluation cache when
/// it holds them and every one is valid in the store.
fn cached_installable_drvs(ev: &Eval, cli: &Cli, flags: &flake_cmd::FlakeFlags, spec: &str, drvs: &mut Vec<(StorePath, String)>) -> cranix_eval::R<()> {
    let inst = flake_cmd::lock_installable(ev, flags, spec)?;
    let cache = eval_cache::EvalCache::open(cli, ev, flags.impure, &inst.locked, "drvs", &inst.frag);
    if let Some(serde_json::Value::Array(items)) = cache.as_ref().and_then(|c| c.get()) {
        let hit: Option<Vec<(StorePath, String)>> = items
            .iter()
            .map(|i| {
                let d = ev.store.dir.parse(i.get(0)?.as_str()?).ok().filter(|d| ev.store.is_valid(d))?;
                Some((d, i.get(1)?.as_str()?.to_string()))
            })
            .collect();
        if let Some(hit) = hit.filter(|h| !h.is_empty()) {
            *drvs = hit;
            return Ok(());
        }
    }
    let sel = flake_cmd::eval_locked(ev, cli, &inst, flake_cmd::Kind::Build)?;
    collect_drvs(ev, &sel.value, drvs)?;
    if let Some(c) = &cache {
        c.put(drvs.iter().map(|(d, o)| serde_json::json!([ev.store.dir.print(d), o])).collect());
    }
    Ok(())
}

fn cmd_instantiate(cli: &Cli, args: &[String], build: bool) -> Result<(), String> {
    let mut args = args.to_vec();
    let flags = flake_cmd::take_flake_flags(&mut args)?;
    let t = parse_target(&args, &["-o", "--out-link", "-j", "--max-jobs", "--cores"])?;
    let installable = t.file.clone().filter(|f| t.expr.is_none() && flake_cmd::is_installable(f));
    let ev = match &installable {
        Some(_) => flake_cmd::new_eval(cli, flags.impure)?,
        None => new_eval(cli)?,
    };
    let mut drvs = Vec::new();
    let r = match &installable {
        Some(spec) => cached_installable_drvs(&ev, cli, &flags, spec, &mut drvs),
        None => eval_target(&ev, cli, &t).and_then(|v| collect_drvs(&ev, &v, &mut drvs)),
    };
    r.map_err(|e| render_error(&ev, cli, &e))?;
    if !build {
        for (d, _) in &drvs {
            println!("{}", ev.store.dir.print(d));
        }
        return Ok(());
    }
    let mut opts = build_options(cli);
    for (k, v) in &t.opts {
        match k.as_str() {
            "-j" | "--max-jobs" => opts.jobs = v.parse().map_err(|_| "invalid -j value")?,
            "--cores" => opts.cores = v.parse().map_err(|_| "invalid --cores value")?,
            _ => {}
        }
    }
    opts.print_logs = t.flags.contains("-L") || t.flags.contains("--print-build-logs");
    opts.keep_failed |= t.flags.contains("-K") || t.flags.contains("--keep-failed");
    let paths: Vec<StorePath> = drvs.iter().map(|(d, _)| d.clone()).collect();
    let check = t.flags.contains("--check") || t.flags.contains("--rebuild");
    if check && cli.remote.is_some() {
        return Err("build --check rebuilds in a local store; pass --store DIR".into());
    }
    let (res, mut session) = match installable.as_ref().and_then(|_| flake_cmd::present_outputs(&ev, &paths)) {
        Some(r) => (r, None),
        None => match &cli.remote {
            Some(u) => {
                let mut s = remote::Session::open(u)?;
                (s.realise(&ev.store, &paths, &opts)?, Some(s))
            }
            None => {
                remote::configure_builders(&mut opts, &cli.settings.builders)?;
                (ev.store.realise(&paths, &opts)?, None)
            }
        },
    };
    if check {
        check_reproducible(&ev.store, &paths, &opts)?;
    }
    let link_base = t.opts.iter().find(|(k, _)| k == "-o" || k == "--out-link").map(|(_, v)| v.clone()).unwrap_or("result".into());
    let no_link = t.flags.contains("--no-link");
    for (i, (d, out)) in drvs.iter().enumerate() {
        let p = res[d].get(out).ok_or_else(|| format!("derivation has no output '{out}'"))?;
        let s = ev.store.dir.print(p);
        println!("{s}");
        if !no_link {
            let mut link = if i == 0 { link_base.clone() } else { format!("{link_base}-{}", i + 1) };
            if out != "out" {
                link = format!("{link}-{out}");
            }
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&s, &link).map_err(|e| format!("creating '{link}': {e}"))?;
            match &mut session {
                Some(sess) => sess.add_indirect_root(Path::new(&link))?,
                None => ev.store.add_indirect_root(Path::new(&link))?,
            }
        }
    }
    Ok(())
}

/// Rebuilds each of `drvs` and fails with the files that differ from the
/// existing outputs.
fn check_reproducible(store: &Store, drvs: &[StorePath], opts: &BuildOptions) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    let mut failures = Vec::new();
    for d in drvs.iter().filter(|d| seen.insert((*d).clone())) {
        for diff in store.check_derivation(d, opts)? {
            let mut msg = format!(
                "output '{}' of '{}' differs from its rebuild:",
                store.dir.print(&diff.path),
                store.dir.print(d)
            );
            for line in &diff.differences {
                msg.push_str("\n  ");
                msg.push_str(line);
            }
            if let Some(k) = &diff.kept {
                msg.push_str(&format!("\nthe rebuild is kept at '{}'", k.display()));
            }
            failures.push(msg);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

fn cmd_show_derivation(cli: &Cli, args: &[String]) -> Result<(), String> {
    let store = open_store(cli)?;
    let mut out = String::from("{");
    for (n, a) in args.iter().enumerate() {
        let p = store.dir.parse(a)?;
        let d = store.read_derivation(&p)?;
        let mut s = String::new();
        let js = |x: &str, s: &mut String| print::json_string(x, s);
        if n > 0 {
            out.push(',');
        }
        js(a, &mut out);
        s.push_str("{\"args\":[");
        for (i, x) in d.args.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            js(x, &mut s);
        }
        s.push_str("],\"builder\":");
        js(&d.builder, &mut s);
        s.push_str(",\"env\":{");
        for (i, (k, v)) in d.env.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            js(k, &mut s);
            s.push(':');
            js(v, &mut s);
        }
        s.push_str("},\"inputDrvs\":{");
        for (i, (k, outs)) in d.input_drvs.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            js(&store.dir.print(k), &mut s);
            s.push_str(":{\"dynamicOutputs\":{},\"outputs\":[");
            for (j, o) in outs.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                js(o, &mut s);
            }
            s.push_str("]}");
        }
        s.push_str("},\"inputSrcs\":[");
        for (i, p) in d.input_srcs.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            js(&store.dir.print(p), &mut s);
        }
        s.push_str("],\"name\":");
        js(&d.name, &mut s);
        s.push_str(",\"outputs\":{");
        for (i, (k, o)) in d.outputs.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            js(k, &mut s);
            s.push_str(":{");
            let mut fields = Vec::new();
            let kind = o.kind();
            if kind == OutputKind::Fixed {
                fields.push(format!("\"hash\":\"{}\"", o.hash));
            }
            if let Some((method, algo)) = o.method_algo() {
                let m = method.name();
                fields.push(format!("\"hashAlgo\":\"{algo}\""));
                if kind == OutputKind::Impure {
                    fields.push("\"impure\":true".into());
                }
                fields.push(format!("\"method\":\"{m}\""));
            }
            if let Some(p) = &o.path {
                let mut ps = String::new();
                js(&store.dir.print(p), &mut ps);
                fields.push(format!("\"path\":{ps}"));
            }
            s.push_str(&fields.join(","));
            s.push('}');
        }
        s.push_str("},\"system\":");
        js(&d.platform, &mut s);
        s.push('}');
        out.push(':');
        out.push_str(&s);
    }
    out.push('}');
    println!("{out}");
    Ok(())
}

/// `realisation info`: builds the given derivation outputs if needed and
/// prints their realisations (or, without `ca-derivations`, their paths).
fn cmd_realisation(cli: &Cli, args: &[String]) -> Result<(), String> {
    let usage = "usage: cranix realisation info [FILE | --expr E | DRV^OUT...] [-A ATTR] [--json]";
    let Some((sub, rest)) = args.split_first() else { return Err(usage.into()) };
    if sub != "info" {
        return Err(usage.into());
    }
    let ev = new_eval(cli)?;
    let mut wanted: Vec<(StorePath, String)> = Vec::new();
    let mut eval_args = Vec::new();
    for a in rest {
        match a.split_once('^') {
            Some((d, outs)) => {
                let p = ev.store.dir.parse(d)?;
                let names: Vec<String> = if outs == "*" {
                    ev.store.read_derivation(&p)?.outputs.keys().cloned().collect()
                } else {
                    outs.split(',').map(String::from).collect()
                };
                wanted.extend(names.into_iter().map(|o| (p.clone(), o)));
            }
            None => eval_args.push(a.clone()),
        }
    }
    let t = parse_target(&eval_args, &[])?;
    if wanted.is_empty() || t.file.is_some() || t.expr.is_some() {
        let r = eval_target(&ev, cli, &t).and_then(|v| collect_drvs(&ev, &v, &mut wanted));
        r.map_err(|e| e.to_string())?;
    }
    let paths: Vec<StorePath> = wanted.iter().map(|(d, _)| d.clone()).collect();
    let built = ev.store.realise(&paths, &build_options(cli))?;
    let ca = cli.settings.experimental_features.contains("ca-derivations");
    let mut json = Vec::new();
    let mut out = std::io::stdout().lock();
    for (d, o) in &wanted {
        let path = built[d].get(o).ok_or_else(|| format!("derivation '{}' has no output '{o}'", ev.store.dir.print(d)))?;
        if !ca {
            json.push(serde_json::json!({ "opaquePath": ev.store.dir.print(path) }));
            if !t.flags.contains("--json") {
                writeln!(out, "{}", ev.store.dir.print(path)).ok();
            }
            continue;
        }
        let drv = ev.store.read_derivation(d)?;
        let r = ev.store.query_output_realisation(&drv, o)?.ok_or_else(|| {
            format!("cannot operate on output '{o}' of the unbuilt derivation '{}'", ev.store.dir.print(d))
        })?;
        if !t.flags.contains("--json") {
            writeln!(out, "{} {}", r.id, ev.store.dir.print(&r.out_path)).ok();
        }
        json.push(r.to_json());
    }
    if t.flags.contains("--json") {
        writeln!(out, "{}", serde_json::Value::Array(json)).ok();
    }
    Ok(())
}

fn cmd_hash(args: &[String]) -> Result<(), String> {
    let mut algo = HashAlgo::Sha256;
    let mut enc = Encoding::Sri;
    let mut pos = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--type" => algo = HashAlgo::parse(it.next().ok_or("--type requires an argument")?).ok_or("unknown hash type")?,
            "--base16" => enc = Encoding::Base16,
            "--base32" | "--nix32" => enc = Encoding::Nix32,
            "--base64" => enc = Encoding::Base64,
            "--sri" => enc = Encoding::Sri,
            "--to" => {
                enc = match it.next().map(String::as_str) {
                    Some("base16") => Encoding::Base16,
                    Some("nix32") | Some("base32") => Encoding::Nix32,
                    Some("base64") => Encoding::Base64,
                    Some("sri") => Encoding::Sri,
                    _ => return Err("--to expects base16, nix32, base64 or sri".into()),
                }
            }
            p => pos.push(p.to_string()),
        }
    }
    let (mode, items) = pos.split_first().ok_or("hash: missing mode")?;
    for it in items {
        let h = match mode.as_str() {
            "path" => {
                let mut sink = HashSink::new(algo);
                nar::dump(Path::new(it), &mut sink).map_err(|e| format!("{it}: {e}"))?;
                sink.finish().0
            }
            "file" => Hash::digest(algo, &std::fs::read(it).map_err(|e| format!("{it}: {e}"))?),
            "convert" => Hash::parse(it, None)?,
            m => return Err(format!("unknown hash mode '{m}'")),
        };
        println!("{}", h.encode(enc, false));
    }
    Ok(())
}

fn cmd_nar(args: &[String]) -> Result<(), String> {
    match args {
        [m, p] if m == "dump" => {
            let stdout = std::io::stdout().lock();
            nar::dump(Path::new(p), stdout).map_err(|e| format!("{p}: {e}"))
        }
        [m, p] if m == "restore" => nar::restore(std::io::stdin().lock(), Path::new(p)).map_err(|e| format!("{p}: {e}")),
        _ => Err("usage: cranix nar dump PATH | nar restore DEST".into()),
    }
}

fn cmd_store(cli: &Cli, args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("path-info") {
        if let Some(u) = store_url(cli) {
            return cmd_cache_path_info(cli, &u, &args[1..]);
        }
    }
    let store = open_store(cli)?;
    let parse = |s: &String| parse_store_path(&store.dir, s);
    let mut out = std::io::stdout().lock();
    match args.first().map(String::as_str) {
        Some("add") => {
            for p in &args[1..] {
                let path = Path::new(p);
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or("source".into());
                let sp = store.add_path(path, &name, FileIngestion::Recursive, None)?;
                writeln!(out, "{}", store.dir.print(&sp)).ok();
            }
        }
        Some("path-info") => return cmd_path_info(cli, &store, &args[1..]),
        Some("sign") => {
            let mut keys = Vec::new();
            let mut recursive = false;
            let mut paths = Vec::new();
            let mut it = args[1..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "-k" | "--key-file" => keys.push(it.next().ok_or("--key-file requires an argument")?.clone()),
                    "-r" | "--recursive" => recursive = true,
                    _ => paths.push(parse(a)?),
                }
            }
            if keys.is_empty() {
                return Err("store sign: pass the secret key file with --key-file".into());
            }
            let keys = read_secret_keys(keys.iter().map(String::as_str))?;
            let paths = if recursive { store.closure(paths)?.into_iter().collect() } else { paths };
            for p in &paths {
                store.sign_path(p, &keys)?;
            }
            eprintln!("added {} signatures", paths.len() * keys.len());
        }
        Some("closure") => {
            let roots: Vec<StorePath> = args[1..].iter().map(parse).collect::<Result<_, _>>()?;
            for p in store.closure(roots)? {
                writeln!(out, "{}", store.dir.print(&p)).ok();
            }
        }
        Some("ls") => {
            for p in store.valid_paths()? {
                writeln!(out, "{}", store.dir.print(&p)).ok();
            }
        }
        Some("verify") => {
            let mut bad = 0;
            for p in store.valid_paths()? {
                if !store.verify(&p)? {
                    eprintln!("path '{}' was modified! expected hash differs", store.dir.print(&p));
                    bad += 1;
                }
            }
            if bad > 0 {
                return Err(format!("{bad} paths failed verification"));
            }
        }
        Some("gc") => {
            let dry = args.iter().any(|a| a == "--dry-run");
            let (dead, freed) = store.collect_garbage(dry)?;
            for p in &dead {
                writeln!(out, "{}", store.dir.print(p)).ok();
            }
            eprintln!(
                "{} {} store paths, {:.2} MiB",
                if dry { "would delete" } else { "deleted" },
                dead.len(),
                freed as f64 / (1024.0 * 1024.0)
            );
        }
        _ => return Err("usage: cranix store add|path-info|sign|closure|ls|verify|gc".into()),
    }
    Ok(())
}

/// Parses a store path given in full, as a base name, or as a symlink into
/// the store such as `result`.
fn parse_store_path(dir: &cranix_core::StoreDir, s: &str) -> Result<StorePath, String> {
    let target = match std::fs::read_link(s) {
        Ok(t) if !dir.is_in_store(s) => t.to_string_lossy().into_owned(),
        _ => s.to_string(),
    };
    match dir.to_store_path(&target) {
        Some((p, _)) => Ok(p),
        None => StorePath::from_base_name(&target),
    }
}

struct PathInfoArgs {
    json: bool,
    recursive: bool,
    closure_size: bool,
    paths: Vec<String>,
}

fn parse_path_info_args(args: &[String]) -> Result<PathInfoArgs, String> {
    let mut a = PathInfoArgs { json: false, recursive: false, closure_size: false, paths: Vec::new() };
    for x in args {
        match x.as_str() {
            "--json" => a.json = true,
            "-r" | "--recursive" => a.recursive = true,
            "-S" | "--closure-size" => a.closure_size = true,
            f if f.starts_with('-') => return Err(format!("path-info: unknown flag '{f}'")),
            p => a.paths.push(p.to_string()),
        }
    }
    Ok(a)
}

/// The fields `nix path-info --json` prints for every store.
fn path_info_json(
    dir: &cranix_core::StoreDir,
    info: &cranix_store::PathInfo,
    sigs: &[String],
) -> serde_json::Map<String, serde_json::Value> {
    use serde_json::Value as J;
    let mut m = serde_json::Map::new();
    m.insert("ca".into(), info.ca.clone().map_or(J::Null, J::String));
    m.insert("deriver".into(), info.deriver.as_ref().map_or(J::Null, |d| J::String(dir.print(d))));
    m.insert("narHash".into(), J::String(info.nar_hash.to_sri()));
    m.insert("narSize".into(), J::from(info.nar_size));
    m.insert("references".into(), J::Array(info.references.iter().map(|r| J::String(dir.print(r))).collect()));
    m.insert("signatures".into(), J::Array(sigs.iter().cloned().map(J::String).collect()));
    m
}

fn print_path_info_text(
    out: &mut impl Write,
    dir: &cranix_core::StoreDir,
    info: &cranix_store::PathInfo,
    sigs: &[String],
    closure_size: Option<u64>,
) {
    writeln!(out, "{}", dir.print(&info.path)).ok();
    writeln!(out, "  NarHash: {}", info.nar_hash.to_sri()).ok();
    writeln!(out, "  NarSize: {}", info.nar_size).ok();
    if let Some(n) = closure_size {
        writeln!(out, "  ClosureSize: {n}").ok();
    }
    for r in &info.references {
        writeln!(out, "  Reference: {}", dir.print(r)).ok();
    }
    if let Some(d) = &info.deriver {
        writeln!(out, "  Deriver: {}", dir.print(d)).ok();
    }
    if let Some(ca) = &info.ca {
        writeln!(out, "  CA: {ca}").ok();
    }
    for s in sigs {
        writeln!(out, "  Signature: {s}").ok();
    }
}

fn cmd_path_info(_cli: &Cli, store: &Store, args: &[String]) -> Result<(), String> {
    let a = parse_path_info_args(args)?;
    let mut roots = Vec::new();
    for p in &a.paths {
        let sp = parse_store_path(&store.dir, p)?;
        if !store.is_valid(&sp) {
            return Err(format!("path '{}' is not valid", store.dir.print(&sp)));
        }
        roots.push(sp);
    }
    let paths: Vec<StorePath> = if a.recursive { store.closure(roots)?.into_iter().collect() } else { roots };
    let mut json = serde_json::Map::new();
    let mut out = std::io::stdout().lock();
    for p in &paths {
        let info = store.query_info(p)?.ok_or_else(|| format!("path '{}' is not valid", store.dir.print(p)))?;
        let sigs = store.query_sigs(p)?;
        let closure_size = if a.closure_size {
            let mut n = 0;
            for q in store.closure([p.clone()])? {
                n += store.query_info(&q)?.map_or(0, |i| i.nar_size);
            }
            Some(n)
        } else {
            None
        };
        if a.json {
            let mut m = path_info_json(&store.dir, &info, &sigs);
            if let Some(n) = closure_size {
                m.insert("closureSize".into(), n.into());
            }
            m.insert("registrationTime".into(), store.registration_time(p).map_or(serde_json::Value::Null, Into::into));
            m.insert("ultimate".into(), store.is_ultimate(p)?.into());
            json.insert(store.dir.print(p), m.into());
        } else {
            print_path_info_text(&mut out, &store.dir, &info, &sigs, closure_size);
        }
    }
    if a.json {
        writeln!(out, "{}", serde_json::Value::Object(json)).ok();
    }
    Ok(())
}

type NarInfos = std::collections::BTreeMap<StorePath, cranix_core::NarInfo>;

fn cache_info(cache: &BinaryCache, dir: &cranix_core::StoreDir, p: &StorePath, infos: &mut NarInfos) -> Result<(), String> {
    if !infos.contains_key(p) {
        let ni = cache
            .query_narinfo(dir, p.hash_part())?
            .filter(|ni| ni.path == *p)
            .ok_or_else(|| format!("path '{}' is not valid", dir.print(p)))?;
        infos.insert(p.clone(), ni);
    }
    Ok(())
}

fn cache_closure(cache: &BinaryCache, dir: &cranix_core::StoreDir, root: &StorePath, infos: &mut NarInfos) -> Result<BTreeSet<StorePath>, String> {
    let mut seen = BTreeSet::new();
    let mut todo = vec![root.clone()];
    while let Some(p) = todo.pop() {
        if seen.insert(p.clone()) {
            cache_info(cache, dir, &p, infos)?;
            todo.extend(infos[&p].references.iter().filter(|r| !seen.contains(*r)).cloned());
        }
    }
    Ok(seen)
}

/// `store path-info --store URL`: reads narinfos from a binary cache.
fn cmd_cache_path_info(cli: &Cli, url: &str, args: &[String]) -> Result<(), String> {
    let a = parse_path_info_args(args)?;
    let cache = open_cache(url, &cli.settings)?;
    let dir = cranix_core::StoreDir::new(cache.info()?.store_dir);
    let mut infos = NarInfos::new();
    let mut roots = Vec::new();
    for p in &a.paths {
        let sp = match dir.to_store_path(p) {
            Some((sp, _)) => sp,
            None => StorePath::from_base_name(p)?,
        };
        cache_info(&cache, &dir, &sp, &mut infos)?;
        roots.push(sp);
    }
    let paths: Vec<StorePath> = if a.recursive {
        let mut all = BTreeSet::new();
        for r in &roots {
            all.extend(cache_closure(&cache, &dir, r, &mut infos)?);
        }
        all.into_iter().collect()
    } else {
        roots
    };
    let mut json = serde_json::Map::new();
    let mut out = std::io::stdout().lock();
    for p in &paths {
        let sizes = if a.closure_size {
            let c = cache_closure(&cache, &dir, p, &mut infos)?;
            Some((c.iter().map(|q| infos[q].nar_size).sum::<u64>(), c.iter().map(|q| infos[q].file_size.unwrap_or(0)).sum::<u64>()))
        } else {
            None
        };
        let ni = &infos[p];
        let info = cranix_store::PathInfo {
            path: ni.path.clone(),
            nar_hash: ni.nar_hash.clone(),
            nar_size: ni.nar_size,
            references: ni.references.clone(),
            deriver: ni.deriver.clone(),
            ca: ni.ca.clone(),
        };
        if a.json {
            use serde_json::Value as J;
            let mut m = path_info_json(&dir, &info, &ni.sigs);
            if let Some((n, d)) = sizes {
                m.insert("closureSize".into(), n.into());
                m.insert("closureDownloadSize".into(), d.into());
            }
            m.insert("compression".into(), J::String(ni.compression.clone()));
            m.insert("downloadHash".into(), ni.file_hash.as_ref().map_or(J::Null, |h| J::String(h.to_sri())));
            m.insert("downloadSize".into(), ni.file_size.map_or(J::Null, Into::into));
            m.insert("registrationTime".into(), J::Null);
            m.insert("ultimate".into(), false.into());
            m.insert("url".into(), J::String(ni.url.clone()));
            json.insert(dir.print(p), m.into());
        } else {
            print_path_info_text(&mut out, &dir, &info, &ni.sigs, sizes.map(|s| s.0));
        }
    }
    if a.json {
        writeln!(out, "{}", serde_json::Value::Object(json)).ok();
    }
    Ok(())
}

/// `config show [--show-secrets] [NAME]`: the settings in effect, as
/// `name = value` lines. Secrets in substituter URLs and access tokens are
/// hidden unless `--show-secrets` is given.
fn cmd_config(cli: &Cli, args: &[String]) -> Result<(), String> {
    let secrets = args.iter().any(|a| a == "--show-secrets");
    let rest: Vec<&String> = args.iter().filter(|a| *a != "--show-secrets").collect();
    let value = |n: &str| if secrets { cli.settings.get(n) } else { cli.settings.get_shown(n) };
    match rest.as_slice() {
        [c] if *c == "show" => {
            for n in Settings::names() {
                println!("{n} = {}", value(n).unwrap_or_default());
            }
            Ok(())
        }
        [c, name] if *c == "show" => {
            let v = value(name).ok_or_else(|| format!("could not find setting '{name}'"))?;
            println!("{v}");
            Ok(())
        }
        _ => Err("usage: cranix config show [--show-secrets] [NAME]".into()),
    }
}

fn cmd_key(args: &[String]) -> Result<(), String> {
    use cranix_core::signing::SecretKey;
    match args.first().map(String::as_str) {
        Some("generate-secret") => {
            let name = match &args[1..] {
                [f, n] if f == "--key-name" => n,
                _ => return Err("usage: cranix key generate-secret --key-name NAME".into()),
            };
            println!("{}", SecretKey::generate(name)?);
            Ok(())
        }
        Some("convert-secret-to-public") => {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut s).map_err(|e| format!("reading the secret key: {e}"))?;
            println!("{}", SecretKey::parse(&s)?.to_public());
            Ok(())
        }
        _ => Err("usage: cranix key generate-secret --key-name NAME | key convert-secret-to-public < KEY".into()),
    }
}
