#!/usr/bin/env python3
"""Content-addressed derivations test: compares oxnix with Nix on tests/ca.nix.

Checks that drvPaths, `show-derivation` and the output paths and
realisations of a build match `nix build` in a scratch store at the same
location, that changing a CA dependency without changing its output reuses
the realisation of its dependent, and that impure derivations rebuild.
Needs Nix 2.24; nothing outside a temporary directory is changed.
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile

here = os.path.dirname(os.path.abspath(__file__))
oxnix = os.environ.get("OXNIX", os.path.join(here, "..", "target", "debug", "oxnix"))
features = "ca-derivations impure-derivations nix-command"
system = {"arm64": "aarch64", "x86_64": "x86_64"}.get(platform.machine(), platform.machine()) + (
    "-darwin" if sys.platform == "darwin" else "-linux"
)
failures = []


def run(cmd, env=None):
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if p.returncode != 0:
        sys.exit(f"command failed: {' '.join(cmd)}\n{p.stderr}")
    return p.stdout.strip()


def check(what, want, got):
    if want == got:
        print(f"ok: {what}")
    else:
        failures.append(what)
        print(f"FAIL: {what}\n  nix:   {want}\n  oxnix: {got}")


def rmtree(d):
    if os.path.exists(d):
        subprocess.run(["chmod", "-R", "u+w", d])
        shutil.rmtree(d)


def main():
    tmp = os.path.realpath(tempfile.mkdtemp(prefix="oxnix-catest-"))
    nix_env = dict(os.environ, NIX_CONFIG=f"extra-experimental-features = {features}")
    ox_env = dict(os.environ, XDG_DATA_HOME=os.path.join(tmp, "xdg"))
    ox = [oxnix, "--extra-experimental-features", features]
    log = os.path.join(tmp, "b-builds")
    args = ["--argstr", "system", system, "--argstr", "log", log]
    attrs = ["a", "b", "c", "multi", "i"]
    try:
        # Evaluation: Nix writes into a chroot store with /nix/store paths.
        chroot = os.path.join(tmp, "chroot")
        for a in attrs:
            want = run(["nix-instantiate", "--store", chroot, os.path.join(here, "ca.nix"), "-A", a] + args, nix_env)
            got = run(ox + ["instantiate", os.path.join(here, "ca.nix"), "-A", a] + args, ox_env)
            check(f"drvPath of {a}", want, got)
            show = ["derivation", "show", "--store", chroot, want]
            want_json = json.loads(run(["nix"] + show, nix_env))
            got_json = json.loads(run(ox + ["show-derivation", got], ox_env))
            check(f"show-derivation of {a}", want_json, got_json)
        want = run(["nix-instantiate", "--eval", "--store", chroot, "-E", f"(import {here}/ca.nix {{ system = \"{system}\"; log = \"{log}\"; }}).c.outPath"], nix_env)
        got = run(ox + ["eval", "--expr", f"(import {here}/ca.nix {{ system = \"{system}\"; log = \"{log}\"; }}).c.outPath"], ox_env)
        check("placeholder outPath of a deferred derivation", want, got)

        # Building: both stores live at the same location, one after the other.
        store = os.path.join(tmp, "s")
        nix_store = f"local?store={store}/store&state={store}/nix-var&log={store}/nix-log"
        built = ["c", "b", "multi.out", "multi.dev"]
        nix_build = ["nix", "build", "--no-link", "--print-out-paths", "--substituters", "", "--store", nix_store, "-f", os.path.join(here, "ca.nix")] + args
        want_paths = run(nix_build + built, nix_env).split("\n")
        info = ["realisation", "info", "--json"]
        want_real = json.loads(run(["nix"] + info + ["--store", nix_store, "-f", os.path.join(here, "ca.nix")] + args + ["b", "c"], nix_env))
        rmtree(store)
        os.remove(log)
        got_paths = []
        for a in built:
            got_paths.append(run(ox + ["--store", store, "build", os.path.join(here, "ca.nix"), "-A", a, "--no-link"] + args, ox_env))
        check("output paths", sorted(set(want_paths)), sorted(got_paths))
        got_real = []
        for a in ["b", "c"]:
            got_real += json.loads(run(ox + ["--store", store] + info + [os.path.join(here, "ca.nix"), "-A", a] + args, ox_env))
        check("realisations", sorted(want_real, key=lambda r: r["id"]), sorted(got_real, key=lambda r: r["id"]))
        b_out = [p for p in got_paths if p.endswith("-b")][0]
        check("self-reference rewritten", b_out, open(os.path.join(b_out, "self")).read().strip())

        # Early cutoff: a salted `a` builds to the same path, so `b` is not
        # rebuilt and `c` keeps its path.
        c_out = [p for p in got_paths if p.endswith("-c")][0]
        salted = run(ox + ["--store", store, "build", os.path.join(here, "ca.nix"), "-A", "c", "--no-link", "--argstr", "salt", "1"] + args, ox_env)
        check("output of c after changing a", c_out, salted)
        check("builds of b", 1, open(log).read().count("b"))

        # Impure derivations build anew every time.
        impure = [run(ox + ["--store", store, "build", os.path.join(here, "ca.nix"), "-A", "i", "--no-link"] + args, ox_env) for _ in range(2)]
        check("impure rebuilds", True, impure[0] != impure[1])
    finally:
        rmtree(tmp)
    print(f"failed {len(failures)}")
    sys.exit(1 if failures else 0)


main()
