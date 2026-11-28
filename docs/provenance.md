# Build provenance

`cranix provenance` writes an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
with a [SLSA Provenance v1](https://slsa.dev/spec/v1.0/provenance) predicate
for each output of a derivation. This page describes the build type those
statements name.

## Build type

`buildType`: `https://github.com/tmmy-cc/cranix/blob/main/docs/provenance.md#build-type`

A Nix derivation realised by cranix. All digests are `sha256` digests of the
NAR serialisation of a store object, in lowercase hex: the `NarHash` of its
narinfo, without the `sha256:` prefix and in base 16.

`subject`: one entry, the output path as `name` and its NAR digest.

`externalParameters`:

| Field | Value |
|---|---|
| `derivation` | The store path of the `.drv` file. |
| `output` | The name of the output the statement is about. |

`internalParameters`:

| Field | Value |
|---|---|
| `system` | The `system` setting of the machine that realised the output. |
| `platform` | The derivation's `system`. |
| `systemFeatures` | The `system-features` setting, sorted. |
| `sandbox.mode` | The `sandbox` setting: `true`, `false` or `relaxed`. |
| `sandbox.paths` | The `sandbox-paths` setting, sorted. |
| `sandbox.fallback` | The `sandbox-fallback` setting. |
| `sandbox.allowedImpureHostDeps` | The `allowed-impure-host-deps` setting, sorted. |
| `timeout` | The `timeout` setting in seconds; 0 for no limit. |
| `maxSilentTime` | The `max-silent-time` setting in seconds; 0 for no limit. |

`resolvedDependencies`: sorted by `uri`, the store path of each entry.
`annotations.role` says what the entry is:

| `role` | Entry |
|---|---|
| `derivation` | The `.drv` file. |
| `source` | An input source of the derivation. |
| `input` | An output of an input derivation, with `annotations.derivation` and `annotations.output` naming it. |

An entry has a `digest` when the path is valid in the store that wrote the
statement.

`runDetails.builder`: `id` is `https://github.com/tmmy-cc/cranix`, and
`version.cranix` the version of cranix. `runDetails.metadata` is absent:
the store records no build times, and statements are the same on every run.

## Signatures and caches

A signed statement is a [DSSE](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md)
envelope with `payloadType` `application/vnd.in-toto+json`. Each signature is
an ed25519 signature of a key from `secret-key-files` over the DSSE
pre-authentication encoding, with the key name as `keyid`; the public key
in `name:base64` form, as in `trusted-public-keys`, verifies it.

In a binary cache the envelope for an output lives at
`<hash>.provenance.json`, beside `<hash>.narinfo`, where `<hash>` is the
hash part of the output path.
