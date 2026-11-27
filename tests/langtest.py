#!/usr/bin/env python3
"""Runs the language tests of Nix and Snix against cranix.

    python3 tests/langtest.py --fetch            # clone the pinned test suites once
    python3 tests/langtest.py [-k PATTERN] [-v] [--suite nix|snix] [--update-known]

The suites are cloned at pinned revisions into ~/.cache/cranix/langtests
(--dir DIR); the test files stay there, outside this repository.

- eval-okay-NAME.nix evaluates to NAME.exp (NAME.exp.xml through
  builtins.toXML); its NAME.flags are passed on.
- eval-fail-NAME.nix fails to evaluate.
- parse-okay-NAME.nix parses (cranix has no --parse printer, so its AST is
  not compared); parse-fail-NAME.nix does not.
- identity-NAME.nix (Snix) evaluates to its own text.

A failing test fails the run unless tests/langtest-known.txt lists it; a
listed test that passes is reported so the list can shrink. For failing
cases the first error line is also compared with the expected one, and
the number of matches is reported.

cranix is $CRANIX, by default target/release/cranix.
"""
import argparse
import concurrent.futures
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KNOWN = os.path.join(HERE, "langtest-known.txt")

SUITES = {
    "nix": {
        "url": "https://github.com/NixOS/nix.git",
        "rev": "2.24.10",
        "paths": ["tests/functional/lang"],
        # Tests run from tests/functional, naming files lang/NAME.nix.
        "cwd": "tests/functional",
        "dir": "lang",
    },
    "snix": {
        "url": "https://git.snix.dev/snix/snix.git",
        "rev": "2d4b73622b0d875831e0386631e7b4d904746676",
        "paths": ["snix/eval/src/tests/snix_tests"],
        "cwd": "snix/eval/src/tests",
        "dir": "snix_tests",
    },
}

# First error lines that mean the file did not parse.
PARSE_ERRORS = re.compile(
    r"^error: (syntax error|attribute '.*' already defined|undefined variable|invalid |duplicate |dynamic attributes not allowed|.*not allowed in |.*is not allowed|unexpected|path '.*' has a trailing slash|URL literals are disabled)"
)


def run(cmd, cwd, env, stdin=None, timeout=60):
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, input=stdin, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "error: timed out"


def fetch(base):
    for name, s in SUITES.items():
        dest = os.path.join(base, f"{name}-{s['rev'][:12]}")
        if os.path.isdir(os.path.join(dest, s["paths"][0])):
            print(f"{name}: {dest}")
            continue
        subprocess.run(["git", "init", "-q", dest], check=True)
        subprocess.run(["git", "-C", dest, "remote", "add", "origin", s["url"]], check=True)
        subprocess.run(["git", "-C", dest, "sparse-checkout", "set", "--no-cone", *("/" + p for p in s["paths"])], check=True)
        subprocess.run(["git", "-C", dest, "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", s["rev"]], check=True)
        subprocess.run(["git", "-C", dest, "checkout", "-q", "FETCH_HEAD"], check=True)
        print(f"{name}: {dest}")


def first_error(text):
    """The first line of an error, as Nix prints it first."""
    for line in text.splitlines():
        if line.startswith("error:"):
            return line.strip()
    return ""


def innermost_error(text):
    """The message of the innermost error of a trace, for the report."""
    lines = [l.strip() for l in text.splitlines() if l.strip().startswith("error:") and l.strip() != "error:"]
    return lines[-1] if lines else first_error(text)


def split_flags(flags):
    """nix-instantiate flags as cranix's global options and eval arguments."""
    words = flags.split()
    glob, args = [], []
    i = 0
    while i < len(words):
        w = words[i]
        if w in ("--eval", "--strict", "--show-trace", "--no-show-trace", "--no-location"):
            i += 1
        elif w in ("-A", "--attr"):
            args += [w, words[i + 1]]
            i += 2
        elif w in ("--arg", "--argstr"):
            glob += [w, words[i + 1], words[i + 2]]
            i += 3
        elif w in ("-I", "--extra-experimental-features", "--max-call-depth", "--option"):
            n = 3 if w == "--option" else 2
            glob += words[i : i + n]
            i += n
        else:
            glob.append(w)
            i += 1
    return glob, args


def case(cranix, suite, sdir, name, env):
    """Runs one test; returns (passed, message_matched or None, detail)."""
    cwd, d = sdir
    rel = f"{d}/{name}.nix"
    path = os.path.join(cwd, rel)
    pwd = cwd

    def norm(s):
        return s.replace(os.path.realpath(pwd), "/pwd").replace(pwd, "/pwd")

    def read(ext):
        p = os.path.join(cwd, d, f"{name}.{ext}")
        if not os.path.exists(p):
            return None
        with open(p, errors="replace") as f:
            return f.read()

    flags = read("flags")
    glob, args = split_flags(re.sub(r"#.*", "", flags) if flags else "")
    if name.startswith("parse-"):
        code, out, err = run([cranix, *glob, "eval", "--lazy", rel], cwd, env)
        e = norm(first_error(err))
        parse_error = bool(PARSE_ERRORS.match(e))
        want = read("err.exp")
        matched = None
        if name.startswith("parse-fail") and want is not None:
            matched = e.replace(f"/pwd/{rel}", "«stdin»") == first_error(want).replace(f"/pwd/{rel}", "«stdin»")
        if name.startswith("parse-okay"):
            return (not parse_error, None, e)
        return (code != 0 and parse_error, matched, e or "evaluated")
    if name.startswith("eval-fail"):
        code, out, err = run([cranix, *glob, "eval", *args, rel], cwd, env)
        want = read("err.exp")
        matched = None if want is None else norm(first_error(err)) == first_error(want)
        return (code != 0, matched, norm(innermost_error(err)) or "evaluated")
    if name.startswith("identity-"):
        with open(path) as f:
            src = f.read().strip()
        code, out, err = run([cranix, *glob, "eval", *args, rel], cwd, env)
        return (code == 0 and out.strip() == src, None, norm(innermost_error(err)) or out.strip()[:200])
    # eval-okay
    if read("exp-disabled") is not None:
        return None
    xml = read("exp.xml")
    if xml is not None:
        expr = f"builtins.toXML (import ./{rel})"
        code, out, err = run([cranix, *glob, "eval", "--raw", "--expr", expr], cwd, env)
        return (code == 0 and out.strip() == xml.strip(), None, norm(innermost_error(err)) or "output differs")
    want = read("exp")
    if want is None:
        return None
    code, out, err = run([cranix, *glob, "eval", *args, rel], cwd, env)
    ok = code == 0 and norm(out).strip() == want.strip()
    return (ok, None, norm(innermost_error(err)) if code else f"got {norm(out).strip()[:200]}")


def tests_of(sdir):
    cwd, d = sdir
    names = []
    for f in sorted(os.listdir(os.path.join(cwd, d))):
        if f.endswith(".nix") and re.match(r"^(eval|parse)-(okay|fail)-|^identity-", f):
            names.append(f[:-4])
    return names


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=os.path.join(os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "cranix/langtests"))
    ap.add_argument("--fetch", action="store_true", help="clone the pinned test suites")
    ap.add_argument("--suite", choices=sorted(SUITES), action="append")
    ap.add_argument("-k", help="run only tests whose name contains this")
    ap.add_argument("-v", action="store_true", help="show every failure")
    ap.add_argument("--update-known", action="store_true", help="write the failing tests to langtest-known.txt")
    a = ap.parse_args()
    if a.fetch:
        os.makedirs(a.dir, exist_ok=True)
        fetch(a.dir)
        return 0
    cranix = os.environ.get("CRANIX", os.path.join(ROOT, "target/release/cranix"))
    known = set()
    if os.path.exists(KNOWN):
        with open(KNOWN) as f:
            known = {l.strip() for l in f if l.strip() and not l.startswith("#")}
    tmp = tempfile.mkdtemp(prefix="cranix-langtest-")
    failing, fixed, unexpected = [], [], []
    for suite in a.suite or sorted(SUITES):
        s = SUITES[suite]
        base = os.path.join(a.dir, f"{suite}-{s['rev'][:12]}")
        if not os.path.isdir(os.path.join(base, s["paths"][0])):
            print(f"{suite}: not fetched; run with --fetch")
            return 2
        cwd = os.path.join(base, s["cwd"])
        sdir = (cwd, s["dir"])
        env = dict(
            os.environ,
            NIX_PATH=f"{s['dir']}/dir3:{s['dir']}/dir4",
            HOME="/fake-home",
            TEST_VAR="foo",
            XDG_DATA_HOME=os.path.join(tmp, "data"),
            XDG_CONFIG_HOME=os.path.join(tmp, "config"),
            NIX_CONF_DIR=os.path.join(tmp, "etc"),
        )
        for k in ("NIX_CONFIG", "CRANIX_CONFIG", "NIX_USER_CONF_FILES"):
            env.pop(k, None)
        names = [n for n in tests_of(sdir) if not a.k or a.k in n]
        counts = {}
        msgs = [0, 0]
        with concurrent.futures.ThreadPoolExecutor(os.cpu_count() or 4) as pool:
            results = list(pool.map(lambda n: (n, case(cranix, suite, sdir, n, env)), names))
        for n, r in results:
            if r is None:
                continue
            ok, matched, detail = r
            kind = re.match(r"^(eval-okay|eval-fail|parse-okay|parse-fail|identity)", n).group(1)
            c = counts.setdefault(kind, [0, 0])
            c[1] += 1
            if matched is not None:
                msgs[1] += 1
                msgs[0] += matched
            key = f"{suite}/{n}"
            if ok:
                c[0] += 1
                if key in known:
                    fixed.append(key)
            else:
                failing.append(key)
                if key not in known:
                    unexpected.append((key, detail))
                elif a.v:
                    print(f"  known {key}: {detail}")
        total = sum(c[1] for c in counts.values())
        passed = sum(c[0] for c in counts.values())
        parts = ", ".join(f"{k} {c[0]}/{c[1]}" for k, c in sorted(counts.items()))
        print(f"{suite}: passed {passed}/{total} ({parts}); first error line as expected in {msgs[0]}/{msgs[1]} failing cases")
    for k, d in unexpected:
        print(f"FAIL {k}: {d}")
    for k in fixed:
        print(f"now passing, remove from langtest-known.txt: {k}")
    if a.update_known:
        with open(KNOWN, "w") as f:
            f.write("# Language tests cranix does not pass yet; tests/langtest.py --update-known rewrites this list.\n")
            for k in sorted(failing):
                f.write(k + "\n")
        print(f"wrote {len(failing)} tests to {KNOWN}")
        return 0
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
