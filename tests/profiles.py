#!/usr/bin/env python3
"""Profile interoperability test: cranix and Nix work on the same profiles.

A cranix daemon serves a scratch store to Nix, and cranix uses the same
store directly. Profiles made by `cranix nix-env` and `cranix profile` are
read and changed by `nix-env` and `nix profile`, and the other way round:
installed packages, store paths, generations, rollbacks, upgrades and
history agree, and the user environments that either side builds (with
`builtin:buildenv`) hold the expected programs.
Needs Nix 2.24; nothing outside a temporary directory is changed (HOME
and the XDG directories point into it, and substituters are disabled).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

here = os.path.dirname(os.path.abspath(__file__))
cranix = os.environ.get("CRANIX", os.path.join(here, "..", "target", "debug", "cranix"))
pkgs = os.path.join(here, "profiles.nix")
failures = []


def run(cmd, env):
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if p.returncode != 0:
        sys.exit(f"command failed: {' '.join(cmd)}\n{p.stderr}")
    return p.stdout


def check(what, want, got):
    if want == got:
        print(f"ok: {what}")
    else:
        failures.append(what)
        print(f"FAIL: {what}\n  want: {want}\n  got:  {got}")


def rmtree(d):
    if os.path.exists(d):
        subprocess.run(["chmod", "-R", "u+w", d])
        shutil.rmtree(d)


def plain(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def main():
    tmp = os.path.realpath(tempfile.mkdtemp(prefix="cranix-profiles-"))
    env = dict(os.environ)
    for k in ["NIX_PROFILE", "NIX_PATH", "NIX_REMOTE"]:
        env.pop(k, None)
    env.update(
        HOME=os.path.join(tmp, "home"),
        XDG_DATA_HOME=os.path.join(tmp, "xdg-data"),
        XDG_STATE_HOME=os.path.join(tmp, "xdg-state"),
        XDG_CACHE_HOME=os.path.join(tmp, "xdg-cache"),
        XDG_CONFIG_HOME=os.path.join(tmp, "xdg-config"),
        NIX_CONFIG="substituters =\nexperimental-features = nix-command flakes\nwarn-dirty = false",
    )
    os.makedirs(env["HOME"])
    store = os.path.join(tmp, "root")
    ox = [cranix, "--store", store]
    sock = os.path.join(tmp, "daemon.sock")
    daemon = subprocess.Popen(ox + ["daemon", "--socket", sock], env=env, stderr=subprocess.DEVNULL)
    try:
        for _ in range(500):
            if os.path.exists(sock):
                break
            time.sleep(0.01)
        uri = f"unix://{sock}?store={store}/store"
        nix_env = ["nix-env", "--store", uri]
        nix = ["nix", "--store", uri]
        profiles = os.path.join(tmp, "profiles")

        def q(tool, profile, *extra):
            return run(tool + ["-p", profile, "-q"] + list(extra), env).split("\n")[:-1]

        def gens(tool, profile):
            out = run(tool + ["-p", profile, "--list-generations"], env)
            return [(int(l.split()[0]), "(current)" in l) for l in out.splitlines()]

        def hello(profile):
            return subprocess.run([os.path.join(profile, "bin", "hello")], capture_output=True, text=True).stdout.strip()

        # nix-env: cranix makes the profile, Nix reads and changes it.
        p = os.path.join(profiles, "env")
        run(ox + ["nix-env", "-p", p, "-f", pkgs, "-iA", "hello", "cowsay"], env)
        check("link layout", "env-1-link", os.readlink(p))
        check("nix reads cranix's packages", ["cowsay-1.0", "hello-1.0"], q(nix_env, p))
        check("out paths agree", q(ox + ["nix-env"], p, "--out-path"), q(nix_env, p, "--out-path"))
        run(nix_env + ["-p", p, "-f", pkgs, "-iA", "hello-alt"], env)
        check("cranix reads nix's packages", ["cowsay-1.0", "hello-1.0", "hello-alt-1.0"], q(ox + ["nix-env"], p))
        check("priorities resolve the collision", "hello 1", hello(p))
        check("generations agree", gens(nix_env, p), gens(ox + ["nix-env"], p))
        run(ox + ["nix-env", "-p", p, "-f", pkgs, "--arg", "version", "2", "-u", "hello"], env)
        check("nix sees cranix's upgrade", ["cowsay-1.0", "hello-2.0", "hello-alt-1.0"], q(nix_env, p))
        check("upgraded program", "hello 2", hello(p))
        run(nix_env + ["-p", p, "--rollback"], env)
        check("cranix sees nix's rollback", [(1, False), (2, True), (3, False)], gens(ox + ["nix-env"], p))
        run(ox + ["nix-env", "-p", p, "-e", "cowsay"], env)
        check("nix sees cranix's removal", ["hello-1.0", "hello-alt-1.0"], q(nix_env, p))
        check("new generation after rollback", [(1, False), (2, False), (3, False), (4, True)], gens(nix_env, p))
        run(ox + ["nix-env", "-p", p, "--switch-generation", "3"], env)
        run(nix_env + ["-p", p, "--delete-generations", "old"], env)
        check("cranix after nix deletes old generations", [(3, True)], gens(ox + ["nix-env"], p))

        # nix-env: Nix makes the profile, cranix reads it in both forms.
        p = os.path.join(profiles, "nix-made")
        run(nix_env + ["-p", p, "-f", pkgs, "-iA", "hello"], env)
        check("cranix reads a nix-made profile", ["hello-1.0"], q(ox + ["nix-env"], p))
        listed = json.loads(run(ox + ["profile", "list", "--json", "--profile", p], env))
        check("profile list of a nix-env profile", ["hello"], list(listed["elements"]))

        # nix profile: cranix makes the profile, Nix reads and changes it.
        p = os.path.join(profiles, "new")
        run(ox + ["profile", "install", "--profile", p, "-f", pkgs, "hello"], env)
        mine = json.loads(run(ox + ["profile", "list", "--json", "--profile", p], env))
        theirs = json.loads(run(nix + ["profile", "list", "--json", "--profile", p], env))
        check("nix reads cranix's manifest.json", mine, theirs)
        run(nix + ["profile", "install", "--profile", p, "-f", pkgs, "cowsay"], env)
        listed = json.loads(run(ox + ["profile", "list", "--json", "--profile", p], env))
        check("cranix reads nix's manifest.json", ["cowsay", "hello"], sorted(listed["elements"]))
        check("profile list text", plain(run(nix + ["profile", "list", "--profile", p], env)), run(ox + ["profile", "list", "--profile", p], env))
        run(ox + ["profile", "remove", "--profile", p, "hello"], env)
        theirs = json.loads(run(nix + ["profile", "list", "--json", "--profile", p], env))
        check("nix sees cranix's removal", ["cowsay"], sorted(theirs["elements"]))
        run(nix + ["profile", "rollback", "--profile", p], env)
        check("cranix sees nix's rollback", "new-2-link", os.readlink(p))
        check("history agrees", plain(run(nix + ["profile", "history", "--profile", p], env)), run(ox + ["profile", "history", "--profile", p], env))
        run(ox + ["profile", "wipe-history", "--profile", p], env)
        check("nix history after wipe", ["Version 2"], re.findall(r"Version \d+", plain(run(nix + ["profile", "history", "--profile", p], env))))

        # nix-env refuses profiles with manifest.json, in both tools.
        bad = subprocess.run(ox + ["nix-env", "-p", p, "-q"], capture_output=True, text=True, env=env)
        check("cranix nix-env refuses a manifest.json profile", True, bad.returncode != 0 and "incompatible" in bad.stderr)
    finally:
        daemon.kill()
        daemon.wait()
        rmtree(tmp)
    print(f"failed {len(failures)}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
