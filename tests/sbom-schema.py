#!/usr/bin/env python3
"""Validates CycloneDX 1.6 and SPDX 2.3 JSON documents against the schemas
in crates/cranix-sbom/tests/schemas. Needs the `jsonschema` package:

    nix shell nixpkgs#python3Packages.jsonschema -c python3 tests/sbom-schema.py FILE...

Without files it validates the golden documents and SBOMs that cranix
writes for a small expression ($CRANIX, default target/release/cranix).
"""
import json
import os
import subprocess
import sys
import tempfile

import jsonschema

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMAS = os.path.join(ROOT, "crates/cranix-sbom/tests/schemas")


def load(name):
    with open(os.path.join(SCHEMAS, name)) as f:
        return json.load(f)


def validator(doc):
    if doc.get("bomFormat") == "CycloneDX":
        schema = load("bom-1.6.schema.json")
        store = {s["$id"]: s for s in (load(n) for n in ("spdx.schema.json", "jsf-0.82.schema.json"))}
        store.update({n: load(n) for n in ("spdx.schema.json", "jsf-0.82.schema.json")})
    elif doc.get("spdxVersion") == "SPDX-2.3":
        schema, store = load("spdx-2.3.schema.json"), {}
    else:
        raise SystemExit("neither CycloneDX nor SPDX 2.3")
    try:
        from referencing import Registry, Resource

        reg = Registry().with_resources((k, Resource.from_contents(v)) for k, v in store.items())
        base = schema.get("$id", "")
        reg = reg.with_resources(
            (base.rsplit("/", 1)[0] + "/" + k, Resource.from_contents(v)) for k, v in store.items() if "/" not in k
        )
        return jsonschema.Draft7Validator(schema, registry=reg, format_checker=jsonschema.FormatChecker())
    except ImportError:
        resolver = jsonschema.RefResolver.from_schema(schema, store=store)
        return jsonschema.Draft7Validator(schema, resolver=resolver, format_checker=jsonschema.FormatChecker())


def check(path):
    with open(path) as f:
        doc = json.load(f)
    errors = sorted(validator(doc).iter_errors(doc), key=lambda e: list(e.path))
    for e in errors[:10]:
        print(f"{path}: {'/'.join(map(str, e.path))}: {e.message[:200]}")
    print(f"{path}: {'ok' if not errors else f'{len(errors)} errors'}")
    return not errors


def generated():
    cranix = os.environ.get("CRANIX", os.path.join(ROOT, "target/release/cranix"))
    tmp = tempfile.mkdtemp()
    expr = (
        'let p = derivation { name = "demo-1.0"; pname = "demo"; version = "1.0"; system = builtins.currentSystem;'
        ' builder = "/bin/sh"; args = [ "-c" "echo > $out" ]; }; in p // { meta.license = { spdxId = "MIT"; }; }'
    )
    out = []
    for fmt in ("cyclonedx", "spdx"):
        f = os.path.join(tmp, f"demo.{fmt}.json")
        env = dict(os.environ, XDG_DATA_HOME=os.path.join(tmp, "data"))
        subprocess.run([cranix, "--store", os.path.join(tmp, "store"), "--option", "substituters", "",
                        "sbom", "--expr", expr, "--format", fmt, "-o", f], check=True, env=env)
        out.append(f)
    return out


def main():
    files = sys.argv[1:]
    if not files:
        golden = os.path.join(ROOT, "crates/cranix-sbom/tests/golden")
        files = [os.path.join(golden, f) for f in sorted(os.listdir(golden))] + generated()
    ok = all([check(f) for f in files])
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
