#!/usr/bin/env python3
"""Compares cranix's fetchers and flakes with real Nix.

Builds local fixtures (a Git repository with an export-ignore attribute,
symlinks and an executable, a dirty working tree, a tarball with a single
top-level directory and an empty directory) and checks that

* fetchGit, fetchTree, fetchTarball and fetchurl return the same store
  paths and attributes as `nix eval --impure`,
* a flake with a `follows` input locks to the same flake.lock as
  `nix flake lock`, which `nix flake metadata` then leaves unchanged,
* flake outputs, `self` and `getFlake` attributes and `flake metadata
  --json` agree, and `flake show` (text and JSON, with `--all-systems` and
  `--legacy`) and the `flake metadata` text (in several time zones) print
  the same output,
* `eval nixpkgs#hello.drvPath` agrees.

With --network it also fetches from GitHub (remote Git, shallow Git,
github: inputs, archive tarballs) and locks a flake with GitHub inputs.

Set CRANIX to the cranix binary (default: target/release/cranix).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

here = os.path.dirname(os.path.abspath(__file__))
cranix = os.environ.get("CRANIX", os.path.join(here, "..", "target", "release", "cranix"))
network = "--network" in sys.argv
failures = 0
passed = 0

GIT_ENV = dict(
    os.environ,
    GIT_AUTHOR_NAME="t",
    GIT_AUTHOR_EMAIL="t@example.org",
    GIT_COMMITTER_NAME="t",
    GIT_COMMITTER_EMAIL="t@example.org",
    GIT_AUTHOR_DATE="2024-01-02T03:04:05Z",
    GIT_COMMITTER_DATE="2024-01-02T03:04:05Z",
)


def sh(cmd, cwd=None, env=None):
    subprocess.run(cmd, cwd=cwd, env=env or GIT_ENV, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None, p


def check(name, want, got, detail=""):
    global failures, passed
    if want == got and want is not None:
        passed += 1
    else:
        failures += 1
        print(f"FAIL {name}{detail}\n  nix:   {want}\n  cranix: {got}")


def compare_eval(name, expr_file, cwd):
    nix, np = run(["nix", "eval", "--impure", "--json", "-f", expr_file], cwd)
    ox, op = run([cranix, "eval", "--json", expr_file], cwd)
    if nix is None or ox is None:
        check(name, nix, ox, f"\n  nix stderr: {np.stderr[-400:]}\n  cranix stderr: {op.stderr[-400:]}")
        return
    a, b = json.loads(nix), json.loads(ox)
    for k in a:
        check(f"{name}.{k}", a[k], b.get(k))


def git_repo(path, files, commits=1):
    os.makedirs(path)
    sh(["git", "init", "-q", "-b", "main"], path)
    for rel, content in files.items():
        p = os.path.join(path, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if isinstance(content, tuple):
            os.symlink(content[1], p)
            continue
        with open(p, "w") as f:
            f.write(content)
        if rel.endswith(".sh"):
            os.chmod(p, 0o755)
    sh(["git", "add", "."], path)
    sh(["git", "commit", "-qm", "one"], path)
    for i in range(1, commits):
        with open(os.path.join(path, "a.txt"), "a") as f:
            f.write(f"{i}\n")
        env = dict(GIT_ENV, GIT_COMMITTER_DATE=f"2024-02-0{i}T00:00:00Z")
        sh(["git", "commit", "-qam", f"c{i}"], path, env)


def fetcher_tests(tmp):
    repo = os.path.join(tmp, "repo")
    git_repo(repo, {
        "a.txt": "hello\n",
        "run.sh": "#!/bin/sh\n",
        "link": ("symlink", "a.txt"),
        "sub/b": "x\n",
        ".gitattributes": "ign export-ignore\n",
        "ign": "ignored\n",
    }, commits=3)
    tb = os.path.join(tmp, "tb")
    os.makedirs(os.path.join(tb, "top", "d", "empty"))
    with open(os.path.join(tb, "top", "f"), "w") as f:
        f.write("1\n")
    os.chmod(os.path.join(tb, "top", "f"), 0o755)
    os.symlink("f", os.path.join(tb, "top", "l"))
    os.utime(os.path.join(tb, "top", "f"), (1672531200, 1672531200))
    sh(["tar", "-C", tb, "-czf", os.path.join(tmp, "t.tar.gz"), "top"])
    sh(["tar", "-C", tb, "-cJf", os.path.join(tmp, "t.tar.xz"), "top"])
    expr = os.path.join(tmp, "fetch.nix")
    with open(expr, "w") as f:
        f.write(f"""
let r = {repo}; t = "file://{tmp}/t.tar.gz"; f = x: builtins.removeAttrs x [ "outPath" ] // {{ o = x.outPath; }}; in {{
  gitWorkdir = f (builtins.fetchGit r);
  gitRef = f (builtins.fetchGit {{ url = r; ref = "main"; }});
  gitRev = f (builtins.fetchGit {{ url = r; rev = (builtins.fetchGit r).rev; ref = "main"; name = "named"; }});
  gitTree = f (builtins.fetchTree {{ type = "git"; url = "file://${{toString r}}"; }});
  gitNoIgnore = f (builtins.fetchGit {{ url = r; exportIgnore = false; }});
  tarball = builtins.fetchTarball t;
  tarballNamed = builtins.fetchTarball {{ url = t; name = "x"; }};
  tarballXz = builtins.fetchTarball "file://{tmp}/t.tar.xz";
  treeTarball = f (builtins.fetchTree t);
  file = builtins.fetchurl t;
  treeFile = f (builtins.fetchTree {{ type = "file"; url = t; }});
  path = f (builtins.fetchTree {{ type = "path"; path = "{tb}"; }});
}}
""")
    compare_eval("fetch", expr, tmp)
    with open(os.path.join(repo, "a.txt"), "a") as fh:
        fh.write("dirty\n")
    dirty = os.path.join(tmp, "dirty.nix")
    with open(dirty, "w") as f:
        f.write(f"""
let r = {repo}; f = x: builtins.removeAttrs x [ "outPath" ] // {{ o = x.outPath; }}; in {{
  dirty = f (builtins.fetchGit r);
  dirtyTree = f (builtins.fetchTree {{ type = "git"; url = "file://${{toString r}}"; }});
}}
""")
    compare_eval("dirty", dirty, tmp)
    sh(["git", "checkout", "-q", "a.txt"], repo)


def write_flake(path, text):
    with open(os.path.join(path, "flake.nix"), "w") as f:
        f.write(text)


def flake_tests(tmp):
    dep = os.path.join(tmp, "dep")
    git_repo(dep, {"flake.nix": """{
  description = "dep";
  inputs.nixpkgs.url = "path:%s";
  outputs = { self, nixpkgs }: { greeting = "hi from dep"; v = nixpkgs.value; src = self.outPath; };
}
""" % os.path.join(tmp, "pkgs")})
    pkgs = os.path.join(tmp, "pkgs")
    os.makedirs(pkgs)
    write_flake(pkgs, '{ outputs = { self }: { value = 42; }; }\n')
    other = os.path.join(tmp, "other-pkgs")
    os.makedirs(other)
    write_flake(other, '{ outputs = { self }: { value = 7; }; }\n')
    data = os.path.join(tmp, "data")
    os.makedirs(data)
    with open(os.path.join(data, "x"), "w") as f:
        f.write("data\n")
    top = os.path.join(tmp, "top")
    git_repo(top, {"flake.nix": f"""{{
  description = "top";
  inputs.nixpkgs.url = "path:{other}";
  inputs.dep.url = "git+file://{dep}";
  inputs.dep.inputs.nixpkgs.follows = "nixpkgs";
  inputs.data = {{ url = "path:{data}"; flake = false; }};
  nixConfig.bash-prompt = "x";
  outputs = {{ self, nixpkgs, dep, data }}: {{
    msg = dep.greeting;
    v = dep.v;
    x = builtins.readFile "${{data}}/x";
    selfInfo = {{ inherit (self) lastModified narHash; }};
    names = builtins.attrNames self;
  }};
}}
"""})
    copy = os.path.join(tmp, "top-nix")
    shutil.copytree(top, copy, symlinks=True)
    _, p = run([cranix, "flake", "lock"], top)
    if p.returncode != 0:
        check("flake lock", "ok", p.stderr)
        return
    run(["nix", "flake", "lock"], copy)
    with open(os.path.join(top, "flake.lock")) as f:
        ox_lock = f.read()
    with open(os.path.join(copy, "flake.lock")) as f:
        nix_lock = f.read().replace(copy, top)
    check("flake.lock matches nix flake lock", nix_lock, ox_lock)
    run(["nix", "flake", "metadata"], top)
    with open(os.path.join(top, "flake.lock")) as f:
        check("nix flake metadata keeps the lock", ox_lock, f.read())
    sh(["git", "add", "flake.lock"], top)
    sh(["git", "commit", "-qm", "lock"], top)
    for attr in [".#msg", ".#v", ".#x", ".#selfInfo", ".#names"]:
        nix, _ = run(["nix", "eval", "--json", attr], top)
        ox, _ = run([cranix, "eval", "--json", attr], top)
        check(f"eval {attr}", nix, ox)
    nm, _ = run(["nix", "flake", "metadata", "--json"], top)
    om, _ = run([cranix, "flake", "metadata", "--json"], top)
    check("flake metadata --json", nm and json.loads(nm), om and json.loads(om))
    e = (f'let f = builtins.getFlake "git+file://{top}"; in '
         '{ inherit (f) rev revCount lastModified lastModifiedDate narHash shortRev submodules msg; '
         'o = f.outPath; si = builtins.attrNames f.sourceInfo; d = f.inputs.dep.outPath; }')
    nix, _ = run(["nix", "eval", "--impure", "--json", "--expr", e], top)
    ox, _ = run([cranix, "eval", "--json", "--expr", e], top)
    check("getFlake", nix and json.loads(nix), ox and json.loads(ox))


SHOW_FLAKE = """{
  description = "show test";
  outputs = { self }: let
    drv = system: name: derivation { inherit name system; builder = "/bin/sh"; args = [ "-c" "echo > $out" ]; }
      // { meta.description = "the ${name}"; };
  in {
    lib.add = a: b: a + b;
    lib.nested.x = 1;
    overlays.default = final: prev: { };
    overlays.empty = { };
    overlay = final: prev: { };
    nixosModules.foo = { ... }: { };
    nixosModule = { ... }: { };
    nixosConfigurations.box = { config = { }; };
    custom = { a = 1; b = "x"; };
    answer = 42;
    packages.SYS.default = drv "SYS" "hello";
    packages.SYS.other = drv "SYS" "other";
    packages.x86_64-linux.default = drv "x86_64-linux" "hello";
    packages.riscv64-linux = { };
    devShells.SYS.default = drv "SYS" "shell";
    checks.SYS.t = drv "SYS" "check";
    apps.SYS.default = { type = "app"; program = "/bin/sh"; };
    formatter.SYS = drv "SYS" "fmt";
    legacyPackages.SYS = { hello = drv "SYS" "lhello"; sub.x = drv "SYS" "x"; broken = throw "no"; };
    templates.default = { path = ./.; description = "a template"; };
    defaultTemplate = { path = ./.; description = "old template"; };
    hydraJobs.build.SYS = drv "SYS" "job";
    defaultPackage.SYS = drv "SYS" "dp";
    devShell.SYS = drv "SYS" "ds";
  };
}
"""


def strip_ansi(s):
    import re
    return re.sub(r"\x1b\[[0-9;]*[mK]", "", s)


def show_tests(tmp):
    system = subprocess.run(["nix", "eval", "--impure", "--raw", "--expr", "builtins.currentSystem"],
                            capture_output=True, text=True).stdout
    d = os.path.join(tmp, "show")
    os.makedirs(d)
    write_flake(d, SHOW_FLAKE.replace("SYS", system))
    ref = f"path:{d}"
    flags = [[], ["--all-systems"], ["--legacy"], ["--legacy", "--all-systems"],
             ["--json"], ["--json", "--all-systems"], ["--json", "--legacy", "--all-systems"]]
    for f in flags:
        n = subprocess.run(["nix", "flake", "show", ref] + f, capture_output=True, text=True, cwd=tmp)
        o = subprocess.run([cranix, "flake", "show", ref] + f, capture_output=True, text=True, cwd=tmp)
        nerr = [l for l in strip_ansi(n.stderr).splitlines() if l.strip() and not l.startswith("evaluating")]
        oerr = [l for l in strip_ansi(o.stderr).splitlines() if l.strip()]
        name = "flake show " + " ".join(f)
        check(name + " (stdout)", n.stdout, o.stdout)
        check(name + " (stderr)", nerr, oerr)
        check(name + " (status)", n.returncode, o.returncode)
    for tz in ["UTC", "Asia/Tokyo", "America/New_York"]:
        env = dict(os.environ, TZ=tz)
        n = subprocess.run(["nix", "flake", "metadata", ref], capture_output=True, text=True, env=env)
        o = subprocess.run([cranix, "flake", "metadata", ref], capture_output=True, text=True, env=env)
        check(f"flake metadata TZ={tz}", n.stdout, o.stdout)


CHECK_FLAKES = {
    "ok": """{
  outputs = { self }: let
    drv = name: derivation { inherit name; system = "SYS"; builder = "/bin/sh"; args = [ "-c" "echo > $out" ]; };
  in {
    packages.SYS.default = drv "p";
    checks.SYS.t = drv "c";
    nixosConfigurations.box.config.system.build.toplevel = drv "toplevel";
  };
}
""",
    "no-toplevel": """{
  outputs = { self }: { nixosConfigurations.box = { config = { }; }; };
}
""",
    "toplevel-not-drv": """{
  outputs = { self }: { nixosConfigurations.box.config.system.build.toplevel = 1; };
}
""",
    "bad-package": """{
  outputs = { self }: { packages.SYS.default = derivation { name = "x"; system = "SYS"; builder = throw "no builder"; }; };
}
""",
}


def check_tests(tmp):
    system = subprocess.run(["nix", "eval", "--impure", "--raw", "--expr", "builtins.currentSystem"],
                            capture_output=True, text=True).stdout
    for name, text in CHECK_FLAKES.items():
        d = os.path.join(tmp, "check-" + name)
        git_repo(d, {"flake.nix": text.replace("SYS", system)})
        n = subprocess.run(["nix", "flake", "check", "--no-build", f"git+file://{d}"], capture_output=True, text=True, cwd=tmp)
        # The second run reads the evaluation cache.
        for run_ in ["", " (cached)"]:
            o = subprocess.run([cranix, "flake", "check", "--no-build", f"git+file://{d}"], capture_output=True, text=True, cwd=tmp)
            check(f"flake check {name}{run_} (status)", n.returncode, o.returncode, f"\n  {o.stderr[-400:]}")


def nixpkgs_tests(tmp):
    nix, _ = run(["nix", "eval", "nixpkgs#hello.drvPath"], tmp)
    if nix is None:
        print("skipping nixpkgs#hello: nix cannot resolve nixpkgs")
        return
    ox, p = run([cranix, "eval", "nixpkgs#hello.drvPath"], tmp)
    check("eval nixpkgs#hello.drvPath", nix, ox, f"\n  {p.stderr[-400:]}")


def network_tests(tmp):
    rev = "02fe640c9e117dd9d6a34efc7bcb8bd09c08111d"
    expr = os.path.join(tmp, "net.nix")
    with open(expr, "w") as f:
        f.write(f"""
let f = x: builtins.removeAttrs x [ "outPath" ] // {{ o = x.outPath; }}; in {{
  remote = f (builtins.fetchGit {{ url = "https://github.com/NixOS/flake-registry"; rev = "{rev}"; }});
  shallow = f (builtins.fetchTree {{ type = "git"; url = "https://github.com/NixOS/flake-registry"; ref = "master"; rev = "{rev}"; }});
  github = f (builtins.fetchTree "github:NixOS/flake-registry/{rev}");
  archive = builtins.fetchTarball "https://github.com/NixOS/flake-registry/archive/{rev}.tar.gz";
  githubRef = f (builtins.fetchTree {{ type = "github"; owner = "NixOS"; repo = "flake-registry"; ref = "master"; }});
  gitlab = f (builtins.fetchTree "gitlab:pages/plain-html");
  gitlabRev = f (builtins.fetchTree {{ type = "gitlab"; owner = "pages"; repo = "plain-html"; rev = (builtins.fetchTree "gitlab:pages/plain-html").rev; }});
  sourcehut = f (builtins.fetchTree "sourcehut:~sircmpwn/scdoc");
  tarball = f (builtins.fetchTree "https://github.com/NixOS/flake-registry/archive/{rev}.tar.gz");
  lockable = f (builtins.fetchTree "https://channels.nixos.org/nixpkgs-unstable/nixexprs.tar.zst");
  remoteHead = f (builtins.fetchGit "https://github.com/NixOS/flake-registry");
}}
""")
    compare_eval("network", expr, tmp)
    fl = os.path.join(tmp, "netflake")
    os.makedirs(fl)
    write_flake(fl, """{
  inputs.utils.url = "github:numtide/flake-utils/cd489559845d81f673a12885576016c65cbe9363";
  inputs.other.url = "github:numtide/flake-utils";
  inputs.other.inputs.systems.follows = "utils/systems";
  inputs.reg = { url = "github:NixOS/flake-registry/%s"; flake = false; };
  inputs.gl = { url = "gitlab:pages/plain-html"; flake = false; };
  inputs.tb = { url = "https://channels.nixos.org/nixpkgs-unstable/nixexprs.tar.zst"; flake = false; };
  inputs.gitHead = { url = "git+https://github.com/NixOS/flake-registry"; flake = false; };
  outputs = { self, ... }: { };
}
""" % rev)
    copy = fl + "-nix"
    shutil.copytree(fl, copy)
    run([cranix, "flake", "lock"], fl)
    run(["nix", "flake", "lock"], copy)
    with open(os.path.join(fl, "flake.lock")) as a, open(os.path.join(copy, "flake.lock")) as b:
        check("network flake.lock", b.read().replace(copy, fl), a.read())


def main():
    with tempfile.TemporaryDirectory(prefix="cranix-flaketest-") as tmp:
        tmp = os.path.realpath(tmp)
        fetcher_tests(tmp)
        flake_tests(tmp)
        show_tests(tmp)
        check_tests(tmp)
        nixpkgs_tests(tmp)
        if network:
            network_tests(tmp)
    print(f"passed {passed}, failed {failures}")
    sys.exit(1 if failures else 0)


main()
