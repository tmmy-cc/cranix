//! `oxnix`: command line front end.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;

use oxnix_core::hash::{Encoding, Hash, HashAlgo, HashSink};
use oxnix_core::{nar, FileIngestion, StorePath};
use oxnix_eval::value::{Attrs, Sym};
use oxnix_eval::{print, Eval, Options, Value};
use oxnix_store::build::{default_root, host_system, BuildOptions};
use oxnix_store::Store;

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
  store add PATH | path-info PATH... | closure PATH... | verify | gc [--dry-run] | ls

global options:
  --store DIR       use a store rooted at DIR whose store directory is DIR/store
                    (required for building); default: chroot store at ~/.local/share/oxnix
  -I [PREFIX=]PATH  add to the search path (also read from $NIX_PATH)
  --arg NAME EXPR, --argstr NAME STRING   arguments for auto-called functions
  --system SYSTEM   value of builtins.currentSystem
  --pure            restrict impure builtins
";

struct Cli {
    store: Option<PathBuf>,
    search: Vec<(String, String)>,
    args: Vec<(String, ArgVal)>,
    system: String,
    pure: bool,
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
    let mut cli = Cli { store: None, search: Vec::new(), args: Vec::new(), system: host_system(), pure: false, rest: Vec::new() };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| format!("{name} requires an argument"));
        match a.as_str() {
            "--store" => cli.store = Some(PathBuf::from(val("--store")?)),
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

fn open_store(cli: &Cli) -> Result<Store, String> {
    match &cli.store {
        Some(d) => Store::open_at(d),
        None => Store::open_chroot(&default_root()),
    }
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
        "store" => cmd_store(&cli, &args),
        c => Err(format!("unknown command '{c}'\n{USAGE}")),
    }
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
    Ok(Eval::new(store, Options { search_path: cli.search.clone(), system: cli.system.clone(), pure: cli.pure, trace_verbose: false }))
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
            let a = ev.force_attrs(&v)?;
            v = match k.parse::<usize>() {
                Ok(i) if a.is_empty() => return oxnix_eval::eval::err(format!("index {i} into a set")),
                _ => match a.get(&Sym::new(k)) {
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
        Err(e) => Err(e.to_string()),
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
    r.map_err(|e| e.to_string())?;
    if !build {
        for (d, _) in &drvs {
            println!("{}", ev.store.dir.print(d));
        }
        return Ok(());
    }
    let mut opts = BuildOptions { system: cli.system.clone(), ..Default::default() };
    for (k, v) in &t.opts {
        match k.as_str() {
            "-j" | "--max-jobs" => opts.jobs = v.parse().map_err(|_| "invalid -j value")?,
            "--cores" => opts.cores = v.parse().map_err(|_| "invalid --cores value")?,
            _ => {}
        }
    }
    opts.print_logs = t.flags.contains("-L") || t.flags.contains("--print-build-logs");
    opts.keep_failed = t.flags.contains("-K") || t.flags.contains("--keep-failed");
    let paths: Vec<StorePath> = drvs.iter().map(|(d, _)| d.clone()).collect();
    let res = ev.store.realise(&paths, &opts)?;
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
            ev.store.add_indirect_root(Path::new(&link))?;
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
    let store = open_store(cli)?;
    let parse = |s: &String| -> Result<StorePath, String> {
        match store.dir.to_store_path(s) {
            Some((p, _)) => Ok(p),
            None => StorePath::from_base_name(s),
        }
    };
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
        Some("path-info") => {
            for p in &args[1..] {
                let sp = parse(p)?;
                let info = store.query_info(&sp)?.ok_or_else(|| format!("path '{p}' is not valid"))?;
                writeln!(out, "{}", store.dir.print(&sp)).ok();
                writeln!(out, "  NarHash: {}", info.nar_hash.to_sri()).ok();
                writeln!(out, "  NarSize: {}", info.nar_size).ok();
                for r in &info.references {
                    writeln!(out, "  Reference: {}", store.dir.print(r)).ok();
                }
                if let Some(d) = &info.deriver {
                    writeln!(out, "  Deriver: {}", store.dir.print(d)).ok();
                }
                if let Some(ca) = &info.ca {
                    writeln!(out, "  CA: {ca}").ok();
                }
            }
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
        _ => return Err("usage: oxnix store add|path-info|closure|ls|verify|gc".into()),
    }
    Ok(())
}
