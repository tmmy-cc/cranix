# Schemas

Copies of the published JSON schemas the SBOM documents are checked
against by `tests/sbom-schema.py`; `known_license` reads the licence list
from `spdx.schema.json`. The in-toto, SLSA and DSSE specifications publish
no JSON schemas; the provenance schemas here are transcribed from their
specifications, and `tests/provenance-schema.py` checks the statements
and envelopes of `cranix provenance` against them.

| File | Source |
|---|---|
| `bom-1.6.schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json` | CycloneDX specification 1.6, <https://github.com/CycloneDX/specification/tree/1.6/schema> (Apache-2.0) |
| `spdx-2.3.schema.json` | SPDX specification 2.3, <https://github.com/spdx/spdx-spec/blob/v2.3/schemas/spdx-schema.json> |
| `in-toto-statement-v1.schema.json` | in-toto Statement v1 and ResourceDescriptor, <https://github.com/in-toto/attestation/tree/main/spec/v1> |
| `slsa-provenance-v1.schema.json` | SLSA Provenance v1 predicate, <https://slsa.dev/spec/v1.0/provenance> |
| `dsse-envelope.schema.json` | DSSE envelope, <https://github.com/secure-systems-lab/dsse/blob/master/envelope.md> |
