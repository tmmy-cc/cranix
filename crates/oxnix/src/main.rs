//! `oxnix`: command line front end.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;

use oxnix_core::hash::{Encoding, Hash, HashAlgo, HashSink};
use oxnix_core::{nar, FileIngestion, StorePath};
use oxnix_eval::value::{Attrs, Sym};
use oxnix_eval::{print, Eval, Options, RenderOptions, Value};
use oxnix_store::binary_cache::{read_secret_keys, BinaryCache};
use oxnix_store::build::{default_root, host_system, BuildOptions};
use oxnix_store::config::Settings;
use oxnix_store::substitute::{http_client, trusted_keys, Substituters};
use oxnix_store::Store;

mod remote;

#[cfg(not(feature = "dhat-heap"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static GLOBAL: dhat::Alloc = dhat::Alloc;

const USAGE: &str = "\
usage: oxnix [global options] <command> [args]

commands:
  eval [FILE | --expr E] [-A ATTR] [--json | --raw] [--lazy]
  instantiate [FILE | --expr E] [-A ATTR]       write .drv files, print their paths
  build [FILE | --expr E] [-A ATTR] [-o LINK | --no-link] [-j N] [-L] [--keep-failed]
  show-derivation DRV                            print a derivation as JSON
  hash path|file PATH [--type ALGO] [--base16|--base32|--sri]
  hash convert HASH [--to base16|nix32|base64|sri]
  nar dump PATH > out.nar | nar restore DEST < in.nar
  store add PATH | closure PATH... | verify | gc [--dry-run] | ls
  store path-info [--json] [-r] [-S | --closure-size] PATH...
  store sign -k KEYFILE [-r] PATH...            add signatures to local paths
  copy --to URL PATH... | copy --from URL PATH...   copy closures to or from a binary cache
  key generate-secret --key-name NAME | key convert-secret-to-public < KEY
  store serve [--write]                          serve the store to ssh:// clients (also: --serve)
  daemon [--stdio] [--socket PATH] [--trusted-users U] [--allowed-users U] [--force-trusted|--force-untrusted]
                                                 serve the store to Nix clients

global options:
  --store DIR       use a store rooted at DIR whose store directory is DIR/store
                    (required for building); default: chroot store at ~/.local/share/oxnix
  --store daemon | unix://SOCKET[?store=DIR] | ssh-ng://[USER@]HOST | ssh://[USER@]HOST
                    build through a Nix daemon (evaluation still writes to the default store)
  --builders SPEC   remote builders in Nix's machines format, or @FILE
                    (default: `builders` from nix.conf, else @/etc/nix/machines)
  -I [PREFIX=]PATH  add to the search path (also read from $NIX_PATH)
  --arg NAME EXPR, --argstr NAME STRING   arguments for auto-called functions
  --system SYSTEM   value of builtins.currentSystem
  --pure            restrict impure builtins
  --show-trace      show the full trace of evaluation errors
  --option NAME VALUE   set a configuration setting (also --NAME VALUE, --[no-]NAME)
                    settings: substituters, trusted-public-keys, require-sigs,
                    substitute, secret-key-files, max-substitution-jobs
                    (and extra-*), read from ~/.config/oxnix/oxnix.conf and $OXNIX_CONFIG
  --store URL       for 'store path-info', read a binary cache (file:// or https://)
  --sandbox, --no-sandbox, --timeout N, --max-silent-time N
                    shorthands for the build settings sandbox (true|false|relaxed),
                    timeout and max-silent-time; sandbox-paths via --option
  --experimental-features FEATURES, --extra-experimental-features FEATURES
                    set or extend the enabled experimental features (also read
                    from nix.conf and $NIX_CONFIG), e.g. ca-derivations
";

struct Cli {
    store: Option<PathBuf>,
    remote: Option<oxnix_daemon::client::StoreUri>,
    builders: Option<String>,
    search: Vec<(String, String)>,
    args: Vec<(String, ArgVal)>,
    system: String,
    pure: bool,
    show_trace: bool,
    settings: Settings,
    /// Build settings from `NIX_CONFIG` and `--option`, in order of precedence.
    options: Vec<(String, String)>,
    features: BTreeSet<String>,
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
    path.starts_with('/').then_some((prefix, path))
}

fn parse_cli() -> Result<Cli, String> {
    let mut cli = Cli {
        store: None,
        remote: None,
        builders: None,
        search: Vec::new(),
        args: Vec::new(),
        system: host_system(),
        pure: false,
        show_trace: false,
        settings: Settings::load()?,
        features: configured_features(),
        options: Vec::new(),
        rest: Vec::new(),
    };
    if let Ok(conf) = std::env::var("NIX_CONFIG") {
        for (k, v) in parse_conf(&conf) {
            // configured_features has read the experimental features.
            if k.ends_with("experimental-features") {
                continue;
            } else if Settings::is_known(&k) {
                cli.settings.set(&k, &v)?;
            } else {
                cli.options.push((k, v));
            }
        }
    }
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| format!("{name} requires an argument"));
        match a.as_str() {
            "--store" => {
                let v = val("--store")?;
                match oxnix_daemon::client::StoreUri::parse(&v) {
                    Some(u) => cli.remote = Some(u),
                    None => cli.store = Some(PathBuf::from(v)),
                }
            }
            "--builders" => cli.builders = Some(val("--builders")?),
            "-I" => {
                let v = val("-I")?;
                cli.search.extend(parse_search(&v));
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
            "--system" => cli.system = val("--system")?,
            "--pure" => cli.pure = true,
            "--show-trace" => cli.show_trace = true,
            "--option" => {
                let n = val("--option")?;
                let v = val("--option")?;
                if n == "experimental-features" {
                    cli.features = v.split_whitespace().map(String::from).collect();
                } else if n == "extra-experimental-features" {
                    cli.features.extend(v.split_whitespace().map(String::from));
                } else if Settings::is_known(&n) {
                    cli.settings.set(&n, &v)?;
                } else {
                    cli.options.push((n, v));
                }
            }
            "--sandbox" => cli.options.push(("sandbox".into(), "true".into())),
            "--no-sandbox" => cli.options.push(("sandbox".into(), "false".into())),
            f if f.strip_prefix("--").is_some_and(|n| Settings::is_known(n) && !Settings::is_bool(n)) => {
                let v = val(f)?;
                cli.settings.set(&f[2..], &v)?;
            }
            f if f.strip_prefix("--").is_some_and(Settings::is_bool) => cli.settings.set(&f[2..], "true")?,
            f if f.strip_prefix("--no-").is_some_and(Settings::is_bool) => cli.settings.set(&f[5..], "false")?,
            "--timeout" => {
                let v = val("--timeout")?;
                cli.options.push(("timeout".into(), v));
            }
            "--max-silent-time" => {
                let v = val("--max-silent-time")?;
                cli.options.push(("max-silent-time".into(), v));
            }
            "--experimental-features" => cli.features = val(&a)?.split_whitespace().map(String::from).collect(),
            "--extra-experimental-features" => cli.features.extend(val(&a)?.split_whitespace().map(String::from)),
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            _ => cli.rest.push(a),
        }
    }
    if let Ok(np) = std::env::var("NIX_PATH") {
        cli.search.extend(np.split(':').filter(|s| !s.is_empty()).filter_map(parse_search));
    }
    Ok(cli)
}

/// Experimental features enabled by the Nix configuration files and
/// `$NIX_CONFIG`, applied in that order.
fn configured_features() -> BTreeSet<String> {
    let mut texts = vec![std::fs::read_to_string("/etc/nix/nix.conf").unwrap_or_default()];
    let user_conf = match std::env::var("XDG_CONFIG_HOME") {
        Ok(d) => PathBuf::from(d).join("nix/nix.conf"),
        Err(_) => PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config/nix/nix.conf"),
    };
    texts.push(std::fs::read_to_string(user_conf).unwrap_or_default());
    texts.push(std::env::var("NIX_CONFIG").unwrap_or_default());
    let mut features = BTreeSet::new();
    for line in texts.iter().flat_map(|t| t.lines()) {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.split('#').next().unwrap_or("").split_whitespace().map(String::from);
        match k.trim() {
            "experimental-features" => features = v.collect(),
            "extra-experimental-features" => features.extend(v),
            _ => {}
        }
    }
    features
}

/// Parses `nix.conf` syntax: `name = value` lines, `#` comments.
fn parse_conf(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let l = l.split('#').next().unwrap_or("");
            let (k, v) = l.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .filter(|(k, _)| !k.is_empty())
        .collect()
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
        return Err(format!("binary cache '{u}' can only be used with 'store path-info'"));
    }
    match &cli.store {
        Some(d) => Store::open_at(d),
        None => Store::open_chroot(&default_root()),
    }
}

fn open_store(cli: &Cli) -> Result<Store, String> {
    let mut store = open_local_store(cli)?;
    store.set_substituters(Substituters::from_settings(&cli.settings)?);
    Ok(store)
}

fn main() -> ExitCode {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();
    // Deeply recursive Nix code (nixpkgs fixpoints) needs a large stack.
    let child = std::thread::Builder::new().stack_size(1 << 30).spawn(run).expect("spawning main thread");
    match child.join() {
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
        "hash" => cmd_hash(&args),
        "nar" => cmd_nar(&args),
        "store" if args.first().map(String::as_str) == Some("serve") => serve(&cli, &args[1..]),
        "--serve" => serve(&cli, &args),
        "store" => cmd_store(&cli, &args),
        "copy" => cmd_copy(&cli, &args),
        "key" => cmd_key(&args),
        "daemon" => {
            if cli.remote.is_some() {
                return Err("oxnix daemon serves a local store; pass --store DIR".into());
            }
            let builders = cli.builders.clone().unwrap_or_else(remote::default_builders);
            remote::cmd_daemon(open_store(&cli)?, &args, BuildOptions { system: cli.system.clone(), ..Default::default() }, &builders)
        }
        c => Err(format!("unknown command '{c}'\n{USAGE}")),
    }
}

fn serve(cli: &Cli, args: &[String]) -> Result<(), String> {
    if cli.remote.is_some() {
        return Err("serving needs a local store; pass --store DIR".into());
    }
    let builders = cli.builders.clone().unwrap_or_else(remote::default_builders);
    remote::cmd_serve(open_store(cli)?, args, BuildOptions { system: cli.system.clone(), ..Default::default() }, &builders)
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
    let store = open_store(cli)?;
    let opts = Options {
        search_path: cli.search.clone(),
        system: cli.system.clone(),
        pure: cli.pure,
        trace_verbose: false,
        experimental_features: cli.features.clone(),
    };
    Ok(Eval::new(store, opts))
}

/// Renders an evaluation error for stderr, in colour when stderr is a
/// terminal and `NO_COLOR` is unset.
fn render_error(ev: &Eval, cli: &Cli, e: &oxnix_eval::EvalError) -> String {
    use std::io::IsTerminal;
    let color = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").map_or(true, |v| v.is_empty());
    ev.render_error(e, &RenderOptions { show_trace: cli.show_trace, color })
}

fn cwd() -> String {
    std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "/".into())
}

/// Evaluates the target, auto-calls functions and selects `-A`.
fn eval_target(ev: &Eval, cli: &Cli, t: &Target) -> oxnix_eval::R<Value> {
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
                    None => return oxnix_eval::eval::err(format!("list index {i} in selection path '{path}' is out of bounds")),
                },
                (v, _) => match ev.force_attrs(&v)?.get(&Sym::new(k)) {
                    Some(x) => ev.force(x)?,
                    None => return oxnix_eval::eval::err(format!("attribute '{k}' in selection path '{path}' not found")),
                },
            };
            v = auto_call(ev, cli, v)?;
        }
    }
    Ok(v)
}

fn auto_call(ev: &Eval, cli: &Cli, v: Value) -> oxnix_eval::R<Value> {
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
    let t = parse_target(args, &[])?;
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
fn collect_drvs(ev: &Eval, v: &Value, out: &mut Vec<(StorePath, String)>) -> oxnix_eval::R<()> {
    let v = ev.force(v)?;
    match &v {
        Value::Attrs(a) if ev.is_derivation(a)? => {
            let drv = ev.force_str(a.get_str("drvPath").ok_or(()).or_else(|_| oxnix_eval::eval::err("derivation without drvPath"))?)?;
            let out_name = match a.get_str("outputName") {
                Some(o) => ev.force_plain_str(o)?,
                None => "out".into(),
            };
            out.push((ev.store.dir.parse(&drv.s).or_else(oxnix_eval::eval::err)?, out_name));
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
        v => return oxnix_eval::eval::err(format!("expected a derivation but found {}", v.describe())),
    }
    Ok(())
}

fn cmd_instantiate(cli: &Cli, args: &[String], build: bool) -> Result<(), String> {
    let t = parse_target(args, &["-o", "--out-link", "-j", "--max-jobs", "--cores"])?;
    let ev = new_eval(cli)?;
    let mut drvs = Vec::new();
    let r = eval_target(&ev, cli, &t).and_then(|v| collect_drvs(&ev, &v, &mut drvs));
    r.map_err(|e| render_error(&ev, cli, &e))?;
    if !build {
        for (d, _) in &drvs {
            println!("{}", ev.store.dir.print(d));
        }
        return Ok(());
    }
    let mut opts = BuildOptions { system: cli.system.clone(), ..Default::default() };
    for (k, v) in &cli.options {
        if !opts.set(k, v)? {
            eprintln!("warning: unknown setting '{k}'");
        }
    }
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
    let (res, mut session) = match &cli.remote {
        Some(u) => {
            let mut s = remote::Session::open(u)?;
            (s.realise(&ev.store, &paths, &opts)?, Some(s))
        }
        None => {
            remote::configure_builders(&mut opts, &cli.builders.clone().unwrap_or_else(remote::default_builders))?;
            (ev.store.realise(&paths, &opts)?, None)
        }
    };
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
            if !o.hash.is_empty() {
                fields.push(format!("\"hash\":\"{}\"", o.hash));
                let (m, a) = match o.hash_algo.strip_prefix("r:") {
                    Some(a) => ("nar", a),
                    None => ("flat", o.hash_algo.as_str()),
                };
                fields.push(format!("\"hashAlgo\":\"{a}\""));
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
        _ => Err("usage: oxnix nar dump PATH | nar restore DEST".into()),
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
        _ => return Err("usage: oxnix store add|path-info|sign|closure|ls|verify|gc".into()),
    }
    Ok(())
}

/// Parses a store path given in full, as a base name, or as a symlink into
/// the store such as `result`.
fn parse_store_path(dir: &oxnix_core::StoreDir, s: &str) -> Result<StorePath, String> {
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
    dir: &oxnix_core::StoreDir,
    info: &oxnix_store::PathInfo,
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
    dir: &oxnix_core::StoreDir,
    info: &oxnix_store::PathInfo,
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

type NarInfos = std::collections::BTreeMap<StorePath, oxnix_core::NarInfo>;

fn cache_info(cache: &BinaryCache, dir: &oxnix_core::StoreDir, p: &StorePath, infos: &mut NarInfos) -> Result<(), String> {
    if !infos.contains_key(p) {
        let ni = cache
            .query_narinfo(dir, p.hash_part())?
            .filter(|ni| ni.path == *p)
            .ok_or_else(|| format!("path '{}' is not valid", dir.print(p)))?;
        infos.insert(p.clone(), ni);
    }
    Ok(())
}

fn cache_closure(cache: &BinaryCache, dir: &oxnix_core::StoreDir, root: &StorePath, infos: &mut NarInfos) -> Result<BTreeSet<StorePath>, String> {
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
    let cache = BinaryCache::open(url)?.with_http(http_client(&cli.settings));
    let dir = oxnix_core::StoreDir::new(cache.info()?.store_dir);
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
        let info = oxnix_store::PathInfo {
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

/// `copy --to URL` uploads closures from the local store; `copy --from
/// URL` substitutes closures from a cache into it.
fn cmd_copy(cli: &Cli, args: &[String]) -> Result<(), String> {
    let mut to = None;
    let mut from = None;
    let mut check_sigs = cli.settings.require_sigs;
    let mut paths = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--to" => to = Some(it.next().ok_or("--to requires an argument")?.clone()),
            "--from" => from = Some(it.next().ok_or("--from requires an argument")?.clone()),
            "--no-check-sigs" => check_sigs = false,
            f if f.starts_with('-') => return Err(format!("copy: unknown flag '{f}'")),
            p => paths.push(p.to_string()),
        }
    }
    let mut store = open_local_store(cli)?;
    let roots: Vec<StorePath> = paths.iter().map(|p| parse_store_path(&store.dir, p)).collect::<Result<_, _>>()?;
    match (to, from) {
        (Some(to), None) => {
            let s = &cli.settings;
            let cache = BinaryCache::open(&to)?.with_http(http_client(s));
            // Uploads replace what the store remembers about this cache.
            let disk = store.narinfo_cache(&cache.url, s.narinfo_cache_positive_ttl, s.narinfo_cache_negative_ttl);
            let cache = cache.with_narinfo_cache(disk);
            cache.init_for_writing(&store.dir)?;
            let mut key_files: Vec<&str> = cli.settings.secret_key_files.iter().map(String::as_str).collect();
            key_files.extend(cache.param("secret-key"));
            let keys = read_secret_keys(key_files)?;
            for r in &roots {
                if !store.is_valid(r) {
                    return Err(format!("path '{}' is not valid", store.dir.print(r)));
                }
            }
            // References are uploaded before the paths that refer to them.
            let mut order = Vec::new();
            let mut seen = BTreeSet::new();
            fn visit(store: &Store, p: &StorePath, seen: &mut BTreeSet<StorePath>, order: &mut Vec<StorePath>) -> Result<(), String> {
                if !seen.insert(p.clone()) {
                    return Ok(());
                }
                let info = store.query_info(p)?.ok_or_else(|| format!("path '{}' is not valid", store.dir.print(p)))?;
                for r in info.references.iter().filter(|r| *r != p) {
                    visit(store, r, seen, order)?;
                }
                order.push(p.clone());
                Ok(())
            }
            for r in &roots {
                visit(&store, r, &mut seen, &mut order)?;
            }
            let mut copied = 0;
            for p in &order {
                if cache.file_exists(&format!("{}.narinfo", p.hash_part()))? {
                    continue;
                }
                eprintln!("copying path '{}' to '{}'...", store.dir.print(p), cache.url);
                let info = store.query_info(p)?.ok_or_else(|| format!("path '{}' is not valid", store.dir.print(p)))?;
                cache.add_path(&store.dir, &store.real_path(p), &info, &store.query_sigs(p)?, &keys)?;
                copied += 1;
            }
            eprintln!("copied {copied} paths");
            Ok(())
        }
        (None, Some(from)) => {
            let s = &cli.settings;
            let cache = BinaryCache::open(&from)?.with_http(http_client(s));
            let keys = trusted_keys(&s.trusted_public_keys);
            store.set_substituters(
                Substituters::new(vec![cache], keys, check_sigs, s.max_substitution_jobs)
                    .narinfo_ttls(s.narinfo_cache_positive_ttl, s.narinfo_cache_negative_ttl),
            );
            let failed = store.substitute_paths(&roots)?;
            if let Some(p) = failed.first() {
                return Err(format!("path '{}' is not available from '{from}'", store.dir.print(p)));
            }
            Ok(())
        }
        _ => Err("usage: oxnix copy --to URL PATH... | copy --from URL PATH...".into()),
    }
}

fn cmd_key(args: &[String]) -> Result<(), String> {
    use oxnix_core::signing::SecretKey;
    match args.first().map(String::as_str) {
        Some("generate-secret") => {
            let name = match &args[1..] {
                [f, n] if f == "--key-name" => n,
                _ => return Err("usage: oxnix key generate-secret --key-name NAME".into()),
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
        _ => Err("usage: oxnix key generate-secret --key-name NAME | key convert-secret-to-public < KEY".into()),
    }
}
