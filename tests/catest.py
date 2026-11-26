#!/usr/bin/env python3
"""Content-addressed derivations test: compares cranix with Nix on tests/ca.nix.

Checks that drvPaths, `show-derivation` and the output paths and
realisations of a build match `nix build` in a scratch store at the same
location, that changing a CA dependency without changing its output reuses
the realisation of its dependent (with the same build and resolution
messages as Nix), that impure derivations rebuild, and that real Nix gets
the same paths, realisations and messages when it builds through
`cranix daemon`.
Needs Nix 2.24; nothing outside a temporary directory is changed.
"""

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

here = os.path.dirname(os.path.abspath(__file__))
cranix = os.environ.get("CRANIX", os.path.join(here, "..", "target", "debug", "cranix"))
features = "ca-derivations dynamic-derivations impure-derivations nix-command"
system = {"arm64": "aarch64", "x86_64": "x86_64"}.get(platform.machine(), platform.machine()) + (
    "-darwin" if sys.platform == "darwin" else "-linux"
)
failures = []


def run(cmd, env=None, stderr=False):
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if p.returncode != 0:
        sys.exit(f"command failed: {' '.join(cmd)}\n{p.stderr}")
    return (p.stdout.strip(), p.stderr) if stderr else p.stdout.strip()


def progress(stderr):
    """The build and resolution messages, without Nix's trailing `...` and
    cranix's `(n/total)` counter."""
    out = []
    for line in stderr.splitlines():
        if line.startswith("building '") or line.startswith("resolved derivation: "):
            out.append(re.sub(r"(\.\.\.| \(\d+/\d+\))+$", "", line))
    return sorted(out)


def check(what, want, got):
    if want == got:
        print(f"ok: {what}")
    else:
        failures.append(what)
        print(f"FAIL: {what}\n  nix:   {want}\n  cranix: {got}")


def rmtree(d):
    if os.path.exists(d):
        subprocess.run(["chmod", "-R", "u+w", d])
        shutil.rmtree(d)


def main():
    tmp = os.path.realpath(tempfile.mkdtemp(prefix="cranix-catest-"))
    nix_env = dict(os.environ, NIX_CONFIG=f"extra-experimental-features = {features}")
    ox_env = dict(os.environ, XDG_DATA_HOME=os.path.join(tmp, "xdg"))
    ox = [cranix, "--extra-experimental-features", features]
    log = os.path.join(tmp, "b-builds")
    args = ["--argstr", "system", system, "--argstr", "log", log]
    attrs = ["a", "b", "c", "multi", "text", "textFixed", "i"]
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
        built = ["c", "b", "multi.out", "multi.dev", "text", "textFixed"]
        nix_build = ["nix", "build", "--no-link", "--print-out-paths", "--substituters", "", "--store", nix_store, "-f", os.path.join(here, "ca.nix")] + args
        want_paths = run(nix_build + built, nix_env).split("\n")
        info = ["realisation", "info", "--json"]
        want_real = json.loads(run(["nix"] + info + ["--store", nix_store, "-f", os.path.join(here, "ca.nix")] + args + ["b", "c", "text"], nix_env))
        # The raw format reports resolutions the way `nix-build` does.
        _, want_msgs = run(nix_build + ["--log-format", "raw", "--argstr", "salt", "1", "c"], nix_env, stderr=True)
        rmtree(store)
        os.remove(log)
        got_paths = []
        for a in built:
            got_paths.append(run(ox + ["--store", store, "build", os.path.join(here, "ca.nix"), "-A", a, "--no-link"] + args, ox_env))
        check("output paths", sorted(set(want_paths)), sorted(got_paths))
        got_real = []
        for a in ["b", "c", "text"]:
            got_real += json.loads(run(ox + ["--store", store] + info + [os.path.join(here, "ca.nix"), "-A", a] + args, ox_env))
        check("realisations", sorted(want_real, key=lambda r: r["id"]), sorted(got_real, key=lambda r: r["id"]))
        b_out = [p for p in got_paths if p.endswith("-b")][0]
        check("self-reference rewritten", b_out, open(os.path.join(b_out, "self")).read().strip())

        # Early cutoff: a salted `a` builds to the same path, so `b` is not
        # rebuilt and `c` keeps its path.
        c_out = [p for p in got_paths if p.endswith("-c")][0]
        salted, got_msgs = run(ox + ["--store", store, "build", os.path.join(here, "ca.nix"), "-A", "c", "--no-link", "--argstr", "salt", "1"] + args, ox_env, stderr=True)
        check("output of c after changing a", c_out, salted)
        check("messages after changing a", progress(want_msgs), progress(got_msgs))
        check("builds of b", 1, open(log).read().count("b"))

        # Impure derivations build anew every time.
        impure = [run(ox + ["--store", store, "build", os.path.join(here, "ca.nix"), "-A", "i", "--no-link"] + args, ox_env) for _ in range(2)]
        check("impure rebuilds", True, impure[0] != impure[1])

        # Through the daemon: real Nix builds in a cranix daemon's store at
        # the same location and gets the same paths and realisations.
        rmtree(store)
        os.remove(log)
        sock = os.path.join(tmp, "daemon.sock")
        daemon = subprocess.Popen(ox + ["--store", store, "daemon", "--socket", sock], env=ox_env, stderr=subprocess.DEVNULL)
        try:
            for _ in range(500):
                if os.path.exists(sock):
                    break
                time.sleep(0.01)
            uri = f"unix://{sock}?store={store}/store"
            via = ["nix", "build", "--no-link", "--print-out-paths", "--store", uri, "-f", os.path.join(here, "ca.nix")] + args
            got_paths, got_msgs = run(via + built, nix_env, stderr=True)
            check("output paths through the daemon", sorted(set(want_paths)), sorted(set(got_paths.split("\n"))))
            got_real = json.loads(run(["nix"] + info + ["--store", uri, "-f", os.path.join(here, "ca.nix")] + args + ["b", "c", "text"], nix_env))
            check("realisations through the daemon", sorted(want_real, key=lambda r: r["id"]), sorted(got_real, key=lambda r: r["id"]))
            _, got_msgs = run(via + ["--log-format", "raw", "--argstr", "salt", "1", "c"], nix_env, stderr=True)
            check("messages through the daemon", progress(want_msgs), progress(got_msgs))
            check("builds of b through the daemon", 1, open(log).read().count("b"))
        finally:
            daemon.kill()
            daemon.wait()
    finally:
        rmtree(tmp)
    print(f"failed {len(failures)}")
    sys.exit(1 if failures else 0)


main()
