#!/usr/bin/env python3
"""Validates provenance written by `cranix provenance` against the in-toto
Statement v1, SLSA Provenance v1 and DSSE envelope schemas in
crates/cranix-sbom/tests/schemas. Needs the `jsonschema` package:

    nix shell nixpkgs#python3Packages.jsonschema -c python3 tests/provenance-schema.py FILE...

Each FILE holds one statement or DSSE envelope per line. Without files it
validates the statements and envelopes that cranix writes for a small
expression ($CRANIX, default target/release/cranix).
"""
import base64
import json
import os
import subprocess
import sys
import tempfile

import jsonschema

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMAS = os.path.join(ROOT, "crates/cranix-sbom/tests/schemas")
STATEMENT = "in-toto-statement-v1.schema.json"
SLSA = "slsa-provenance-v1.schema.json"
DSSE = "dsse-envelope.schema.json"


def load(name):
    with open(os.path.join(SCHEMAS, name)) as f:
        return json.load(f)


def validator(name):
    schema = load(name)
    store = {n: load(n) for n in (STATEMENT, SLSA, DSSE)}
    try:
        from referencing import Registry, Resource

        base = schema["$id"].rsplit("/", 1)[0]
        reg = Registry().with_resources(
            (u, Resource.from_contents(s)) for n, s in store.items() for u in (n, s["$id"], base + "/" + n)
        )
        return jsonschema.Draft7Validator(schema, registry=reg, format_checker=jsonschema.FormatChecker())
    except ImportError:
        resolver = jsonschema.RefResolver.from_schema(schema, store=store)
        return jsonschema.Draft7Validator(schema, resolver=resolver, format_checker=jsonschema.FormatChecker())


def errors(name, doc, where):
    errs = sorted(validator(name).iter_errors(doc), key=lambda e: list(e.path))
    return [f"{where}: {'/'.join(map(str, e.path))}: {e.message[:200]}" for e in errs]


def check_doc(doc, where):
    errs = []
    if "payloadType" in doc:
        errs += errors(DSSE, doc, where + " (envelope)")
        if doc.get("payloadType") != "application/vnd.in-toto+json":
            return errs + [f"{where}: payloadType is not application/vnd.in-toto+json"]
        doc = json.loads(base64.b64decode(doc["payload"]))
    errs += errors(STATEMENT, doc, where)
    if doc.get("predicateType") != "https://slsa.dev/provenance/v1":
        return errs + [f"{where}: predicateType is not https://slsa.dev/provenance/v1"]
    errs += errors(SLSA, doc.get("predicate"), where + " (predicate)")
    return errs


def check(path):
    with open(path) as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    errs = [] if lines else [f"{path}: no statements"]
    for i, line in enumerate(lines, 1):
        errs += check_doc(json.loads(line), f"{path}:{i}")
    for e in errs[:10]:
        print(e)
    print(f"{path}: {len(lines)} statements, {'ok' if not errs else f'{len(errs)} errors'}")
    return not errs


def generated():
    cranix = os.environ.get("CRANIX", os.path.join(ROOT, "target/release/cranix"))
    tmp = tempfile.mkdtemp()
    key = os.path.join(tmp, "key.sec")
    with open(key, "w") as f:
        subprocess.run([cranix, "key", "generate-secret", "--key-name", "test-1"], check=True, stdout=f)
    expr = (
        'let dep = derivation { name = "dep"; system = builtins.currentSystem; builder = "/bin/sh";'
        ' args = [ "-c" "echo dep > $out" ]; }; in derivation { name = "demo-1.0"; system = builtins.currentSystem;'
        ' builder = "/bin/sh"; outputs = [ "out" "doc" ]; src = builtins.toFile "src" "source";'
        ' args = [ "-c" "echo ${dep} $src > $out; echo doc > $doc" ]; }'
    )
    env = dict(os.environ, XDG_DATA_HOME=os.path.join(tmp, "data"))
    base = [cranix, "--store", os.path.join(tmp, "store"), "--option", "substituters", "",
            "--option", "secret-key-files", key, "provenance", "--expr", expr]
    out = []
    for name, extra in (("statements", []), ("signed", ["--sign"])):
        f = os.path.join(tmp, f"{name}.jsonl")
        subprocess.run(base + extra + ["-o", f], check=True, env=env)
        out.append(f)
    return out


def main():
    files = sys.argv[1:] or generated()
    ok = all([check(f) for f in files])
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
