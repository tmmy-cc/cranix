#!/usr/bin/env python3
"""Differential test: compares `oxnix eval --json` with
`nix-instantiate --eval --strict --json` for each expression in exprs.nix.

Expressions are separated by lines consisting of `#---`.
"""

import os
import subprocess
import sys

here = os.path.dirname(os.path.abspath(__file__))
oxnix = os.environ.get("OXNIX", os.path.join(here, "..", "target", "debug", "oxnix"))


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, cwd="/tmp")
    return (p.stdout.strip() if p.returncode == 0 else "ERROR") , p


def main():
    with open(os.path.join(here, "exprs.nix")) as f:
        exprs = [e.strip("\n") for e in f.read().split("\n#---\n") if e.strip()]
    passed = failed = 0
    for e in exprs:
        want, wp = run(["nix-instantiate", "--eval", "--strict", "--json", "-E", e])
        got, gp = run([oxnix, "eval", "--json", "--expr", e])
        if want == got:
            passed += 1
        else:
            failed += 1
            print(f"FAIL: {e}")
            print(f"  nix:   {want} {wp.stderr.strip()[:300] if want == 'ERROR' else ''}")
            print(f"  oxnix: {got} {gp.stderr.strip()[:300] if got == 'ERROR' else ''}")
    print(f"passed {passed}, failed {failed}")
    sys.exit(1 if failed else 0)


main()
