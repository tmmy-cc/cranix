# cranix, Nix, Lix and Snix

Four implementations of the same model: a lazy, pure language that produces
store derivations, and a content-addressed store that realises them. They
agree on the externally visible formats (store path fingerprints, ATerm
`.drv` files, NAR) and differ in architecture, scope and goals.

* **Nix** (CppNix): the reference implementation started by Eelco Dolstra,
  developed by the NixOS project. C++.
* **Lix**: a community fork of CppNix 2.18 started in 2024. C++, governed
  independently, aiming to stay a drop-in replacement while improving
  correctness, error messages and the build system, with Rust adopted
  incrementally.
* **Snix**: a 2025 fork of TVL's Tvix, a from-scratch Rust reimplementation
  split into independent services (evaluator, content-addressed store,
  builder) that talk over gRPC.
* **cranix**: this repository. A from-scratch Rust implementation of the
  evaluator, derivations and a local store with a builder, packaged as one
  CLI over four library crates.

The descriptions of Nix, Lix and Snix reflect their public designs as of
late 2025; they are summaries, not measurements, except where the
benchmark section says otherwise.

## At a glance

|                        | Nix 2.24                    | Lix                          | Snix                                   | cranix                                   |
|------------------------|-----------------------------|------------------------------|----------------------------------------|-----------------------------------------|
| Language               | C++                         | C++, gradual Rust            | Rust                                   | Rust                                    |
| Lineage                | original                    | fork of CppNix 2.18          | fork of Tvix (clean-room)              | clean-room                              |
| Evaluator              | AST interpreter             | AST interpreter (CppNix)     | compiler to bytecode + VM              | compiler to resolved IR + tree walker   |
| Variable binding       | static (level, displacement)| static                       | static, upvalue capture                | static (depth, slot); `with` dynamic    |
| Memory management      | Boehm GC                    | Boehm GC                     | reference counting                     | reference counting, cycles live until exit |
| I/O during evaluation  | synchronous                 | synchronous                  | VM suspends into async I/O             | synchronous                             |
| Store model            | `/nix/store` + SQLite DB    | same as Nix                  | BLAKE3 Merkle DAG (castore) + PathInfo service; NARs computed on demand | `/nix/store` layout + one metadata file per path |
| Store backends         | local, daemon, binary caches, SSH, S3 | same as Nix          | pluggable (memory, files, object storage, gRPC) | local, daemon, `file://`/`http(s)://`/`s3://` binary caches, GitLab and GitHub package registries, SSH |
| Daemon protocol        | yes                         | yes, compatible              | partial (via `nix-compat`)             | yes, compatible (server and client, 1.37) |
| Builder                | goal/worker state machine, sandbox | same, sandbox             | separate build service (OCI / bubblewrap) | thread-pool scheduler, sandbox (macOS `sandbox-exec`, Linux namespaces), remote builders |
| Substituters / caches  | yes, signed                 | yes                          | yes (serves and consumes NAR/narinfo)  | yes, signed                             |
| Profiles               | `nix-env`, `nix profile`    | same as Nix                  | no                                     | `nix-env`, `profile`; profiles shared with Nix |
| Flakes                 | experimental                | experimental                 | no                                     | yes, lock files compatible with Nix     |
| Configuration          | `nix.conf`, `NIX_CONFIG`, flags | same as Nix              | own options                            | Nix's files and flags, then `cranix.conf` and `CRANIX_CONFIG` |
| Drop-in for `nix`      | —                           | yes                          | no (toolkit)                           | no (subset CLI)                         |
| nixpkgs `drvPath` parity | reference                 | yes                          | yes for large parts of nixpkgs         | yes for tested attributes (`hello`, `python3`, `git`) |

## Nix

The reference. One C++ code base holds the language, the store abstraction
with many backends (local SQLite-backed store, daemon, SSH, HTTP/S3 binary
caches), the build loop with platform sandboxes, substitution with
signatures, flakes and the fetchers. The evaluator parses with Bison/Flex
into an AST, binds variables statically and interprets the tree; values are
allocated with the Boehm conservative GC, which makes sharing cheap and frees
cycles, at the cost of a GC that scans the whole heap and global mutable
evaluator state. Its strength is completeness: every feature the ecosystem
relies on exists here first.

## Lix

Lix keeps CppNix's architecture and its compatibility promise (same
daemon protocol, same CLI, same store) and concentrates on the qualities of
that code base: the Meson build, error messages and REPL usability,
removing or deprecating misfeatures, a rewritten parser, test coverage, and
a stated intention to move components to Rust step by step. Choosing Lix is
a governance and quality decision more than a technical one; its evaluator
and store behave like Nix's.

## Snix

Snix is the most radical redesign. Each concern is its own crate and
service:

* `snix-eval` compiles Nix to bytecode for a VM whose execution can suspend,
  so builtins that need I/O (importing, reading files, adding paths) are
  served asynchronously by whatever store sits behind them.
* `snix-castore` stores file trees as a Merkle DAG of BLAKE3-addressed
  blobs and directories, deduplicating across store paths and making the
  store mountable through FUSE or virtiofs.
* `snix-store` maps Nix store paths to castore roots and produces NARs and
  narinfos on demand, so it can sit behind or act as a binary cache.
* `snix-build` runs builds behind a protocol, using OCI runtimes or
  bubblewrap.
* `nix-compat` implements the Nix wire formats (store paths, NAR, narinfo,
  derivations, parts of the daemon protocol) and is usable on its own.

The payoff is composability (an evaluator that can run against a remote
store, a store that is not a directory) and a modern async Rust stack. The
cost is that Snix is a toolkit rather than a replacement for the `nix`
command, and the service boundaries add machinery that a single-machine user
does not need.

## cranix

cranix takes Snix's starting point (a Rust implementation written against
Nix's observable behaviour, with the formats in a reusable crate) but keeps
Nix's single-process, single-machine shape:

* `cranix-core` plays the role of `nix-compat`: hashes, nix-base32, store
  path fingerprints, NAR streaming, ATerm and `hashDerivationModulo`, with no
  file system or evaluator dependencies.
* The evaluator compiles the syntax tree to an IR with resolved slots and
  leaked `&'static` nodes, so thunks are two words and need no reference
  counting of code. It walks that IR directly instead of interpreting
  bytecode, which keeps the implementation short (7.8k lines for parser,
  compiler, evaluator and builtins) and the call stack readable in error
  traces.
* Values are reference counted and 16 bytes wide; a thunk is 40 bytes.
  There is no tracing GC and no global evaluator state; cycles created by
  `rec`/`let` stay alive until the process exits.
* `a // b` with a small `b` on a large `a` is stored as a layer over the
  shared `a`, so overlays and bootstrap stages do not copy the package
  set. `mapAttrs` results are thunks holding the shared function, the
  attribute's interned symbol and its value, with no per-attribute closure
  or name string.
* The store separates the logical store directory from where objects live.
  The default is a chroot-style store in the user's home that produces real
  `/nix/store` paths without root, and that reads objects missing from it
  from the host's `/nix/store`. Metadata is one text file per path written
  with atomic rename, which removes SQLite at the cost of query features
  (no referrers index, no transactional multi-path registration).
* The builder is a ready-queue scheduler over a scoped thread pool; it
  implements the parts of the builder environment that nixpkgs relies on
  (`passAsFile`, structured attributes as JSON, `impureEnvVars`),
  reference scanning, content-addressed and impure derivations, the build
  sandbox and remote builders. A daemon speaks Nix's worker protocol, so
  Nix clients can use a cranix store and cranix can use a Nix daemon. The
  daemon substitutes from its binary caches with signature checks, builds
  under its own sandbox settings, and records and serves realisations, so
  real Nix builds content-addressed derivations through it with the same
  paths as in a Nix store.
* One settings value, read from the same files and in the same order as
  Nix (`nix.conf`, `NIX_CONFIG`, `--option`, `--NAME`/`--no-NAME`/`--extra-NAME`),
  configures the builder, substitution, fetchers, experimental features,
  remote builders and the daemon.
* Substitution fetches whole closures from `file://` and `https://` binary
  caches before building, checking signatures and streaming hashes, and
  remembers lookups on disk with Nix's TTLs (one file per path, where Nix
  uses SQLite); `copy --to` writes caches that Nix reads, over `PUT` for
  HTTP, with NARs compressed like cache.nixos.org's, together with the
  signed realisations of content-addressed outputs, which substitution
  checks against `trusted-public-keys`.
* `s3://` caches read and write AWS S3 and S3 compatible stores with
  Nix's parameters and credential sources, signed with AWS signature
  version 4 by cranix itself instead of the AWS SDK, with multipart uploads
  for large NARs.
* The package registry of a GitLab or GitHub project is a binary cache
  (`gitlab://`, `github://`), with separate read and write tokens and NARs
  grouped into registry packages by hash, by name or by release;
  `cache serve` exposes such a cache over plain HTTP for Nix.
* `upload-to` uploads each output while later builds run, closure by
  closure, so the cache stays complete even when a build stops half way;
  Nix uploads after the build with `nix copy` or a `post-build-hook`.
* `copy` and uploads take filters by path type, download host, name and
  class (`system`, `test`), spreading name matches to everything built
  from them, so a shared cache can hold the generic builds of a system
  image without its configuration; `copy --dry-run` explains each choice.
* `cranix sbom` writes deterministic CycloneDX 1.6 and SPDX 2.3 SBOMs of a
  package or NixOS system from its runtime closure or build graph, with
  licences from `meta`, ecosystem purls, the crates and Go modules its
  derivations vendor, and optionally what Go and Rust binaries record; Nix
  has no SBOM command.
* `cranix vuln-scan` checks such an SBOM against OSV and NVD data cached
  locally, with OpenVEX assessments and exit codes for CI.
* `cranix provenance` writes deterministic in-toto statements with SLSA
  Provenance v1 predicates for the outputs of a build (derivation, inputs by
  NAR hash, builder, sandbox settings, time limits), signs them as DSSE
  envelopes with the keys of `secret-key-files`, stores them beside the
  narinfo in a binary cache and verifies them; Nix has no provenance
  command.
* `cranix source-archive` bundles the downloads and local sources of a
  build graph, and with `--drvs` its derivations, into a directory, a
  tarball or any binary cache (`file://`, `s3://`, `gitlab://`, `github://`), with
  an index of source, URL, hash and licence. It fetches only fixed-output
  derivations, lists sources it cannot fetch and then exits non-zero; the
  bundle restores with `copy --from` and rebuilds offline. Nix has no such
  command; `nix flake archive` copies only flake inputs.
* `cranix build --check` rebuilds present outputs and compares them, as
  `nix build --rebuild` does, and names each differing file with its first
  differing line, where Nix reports only that the output is not
  deterministic.

### Measured against Nix 2.24 and Snix

Evaluation of `(import <nixpkgs> {}).<attr>.drvPath` on an Apple M-series
machine (aarch64-darwin), nixpkgs 24.11pre, `.drv` files already present.
Times are the best of three runs (five for cranix), memory is the peak RSS.
Nix, Snix and cranix (tree walker and VM) print the same paths for all
four rows. Snix is `snix-eval` at the revision whose language tests
`tests/langtest.py` runs, with its default in-memory stores; it reads
nixpkgs into its content-addressed store first, which is part of its time.

| Attribute | Nix 2.24 | Snix | cranix, cache off | cranix, cold cache | cranix, warm cache |
|-----------|---------:|-----:|------------------:|-------------------:|-------------------:|
| `hello`   | 0.54 s, 203 MiB | 0.98 s, 534 MiB | 0.31 s, 158 MiB | 0.34 s | 0.28 s, 158 MiB |
| `python3` | 0.55 s, 205 MiB | 1.00 s, 538 MiB | 0.32 s, 160 MiB | 0.35 s | 0.28 s, 160 MiB |
| `git`     | 0.72 s, 264 MiB | 1.37 s, 705 MiB | 0.43 s, 221 MiB | 0.46 s | 0.39 s, 220 MiB |
| NixOS `toplevel` | 3.36 s, 838 MiB | 9.98 s, 2693 MiB | 2.15 s, 1216 MiB | 2.34 s | 1.85 s, 1226 MiB |

The cache columns refer to the on-disk cache of parsed files
(`CRANIX_AST_CACHE=0` turns it off; a cold run fills it, a warm run reads
it). The NixOS row evaluates `config.system.build.toplevel.drvPath` of a
minimal `x86_64-linux` configuration through `<nixpkgs/nixos>`; it reads
about 2,600 files and fills 27 MB of cache.

cranix is 35–40% faster than Nix here and uses 20–25% less memory on
packages; the NixOS evaluation needs about 45% more memory than Nix, since
reference counting does not reclaim the cycles that the module system's
fixpoints create. Snix is 2–3 times slower than Nix and needs 2.5–3 times
its memory.

**Where the time goes.** Sampling profiles (samply at 4 kHz, CPU time of
all threads, parse cache off), attributed by the innermost cranix function
of each sample:

| Share of CPU time            | `hello` | `python3` | NixOS | `flake check` | NixOS, VM |
|------------------------------|--------:|----------:|------:|--------------:|----------:|
| allocation, copies, freeing  | 38%     | 40%       | 42%   | 43%           | 43%       |
| system calls (file reads, page faults) | 20% | 15% | 11%  | 11%           | 11%       |
| derivation hashing           | 10%     | 11%       | 7%    | 9%            | 7%        |
| parsing                      | 9%      | 9%        | 10%   | 8%            | 9%        |
| dispatch (walker or VM)      | 8%      | 9%        | 13%   | 12%           | 15%       |
| attribute set operations     | 7%      | 7%        | 6%    | 6%            | 4%        |
| thunks and forcing           | 4%      | 5%        | 7%    | 6%            | 6%        |
| compile pass                 | 3%      | 3%        | 3%    | 3%            | 3%        |
| builtins, strings            | 1%      | 1%        | 1%    | 1%            | 1%        |
| building VM chunks           | –       | –         | –     | –             | 0.2%      |

Counting the frames below the parser as well, parsing is 17–19% of every
workload, which is what the warm cache saves. `flake check` is the check
of a flake with `hello`, `python3` and `git` as packages, one check and
one NixOS configuration.

**The bytecode VM.** `CRANIX_EVAL=vm` runs a bytecode VM beside the tree
walker. It compiles each thunk body, lambda body and file on first use into
a flat chunk of ops on a value stack, reuses the tree walker's operations,
and records error frames as regions over the ops, so results, errors and
traces are identical. Attribute selections carry an inline cache: the
index at which the key was found last time, tried before searching. It
hits 58% of lookups for `hello` and 75% for NixOS, but lookups are only a
few percent of the time, so it gains about 1%. With a warm parse cache:

| Attribute        | Tree walker      | VM               |
|------------------|-----------------:|-----------------:|
| `hello`          | 0.28 s, 158 MiB  | 0.29 s, 166 MiB  |
| `python3`        | 0.28 s, 160 MiB  | 0.29 s, 169 MiB  |
| `git`            | 0.39 s, 220 MiB  | 0.40 s, 230 MiB  |
| NixOS `toplevel` | 1.85 s, 1226 MiB | 2.01 s, 1250 MiB |
| `flake check`    | 2.23 s, 1384 MiB | 2.34 s, 1418 MiB |

The VM is 3–9% slower and uses 2–6% more memory, so the tree walker stays
the default. Dispatch is 8–13% of the time, below the 20% at which a VM
would pay off, and the VM moves values through its stack where the walker
returns them in registers, which adds reference-count traffic. Its chunks
are not cached on disk: building them is 0.2% of the time, and they point
into the syntax trees that the parse cache already restores. A JIT is not
planned: the VM's own loop is 7% of the NixOS run, no small set of
functions dominates, and allocation, system calls and hashing, which a
JIT would not change, take two thirds of the time.

**Flake evaluation cache.** Flake installables and `flake check` cache
their results per locked flake. `eval --raw nixpkgs#<attr>.drvPath` and
`flake check --no-build` of the flake above, best of three:

| Command   | Nix 2.24 | cranix, `--no-eval-cache` | cranix, cache hit |
|-----------|---------:|--------------------------:|------------------:|
| `hello`   | 0.72 s, 315 MiB | 0.40 s, 228 MiB    | < 5 ms, 5 MiB     |
| `python3` | 0.74 s, 318 MiB | 0.41 s, 231 MiB    | < 5 ms, 5 MiB     |
| `git`     | 0.86 s, 378 MiB | 0.52 s, 293 MiB    | < 5 ms, 5 MiB     |
| `flake check` | 2.68 s, 992 MiB | 2.25 s, 1385 MiB | 0.03 s, 7 MiB  |

Nix's evaluation cache does not cover the final value of `nix eval` or
`nix flake check`, so its times are the same with and without
`--no-eval-cache`. Unlocked flakes, dirty trees and `--impure` are never
cached. These changes left the uncached path as it was: with the cache
off, the tree walker took 0.31, 0.32, 0.43 and 2.18 s with the same peak
memory before them, and 0.31, 0.32, 0.43 and 2.15 s after.

### Choosing between them

* Running NixOS or a production fleet: Nix or Lix. They have years of
  production use behind the daemon, sandbox, substituters, flakes and remote
  builders, and cover the rest of the surface (S3 stores).
  Pick Lix for its community process and quality focus, Nix for being the
  upstream reference.
* Building infrastructure out of Nix concepts (remote evaluation, alternative
  store backends, a deduplicating content-addressed store, serving caches):
  Snix.
* Embedding Nix evaluation or derivation handling in a Rust program, or
  studying how Nix works in a small code base: cranix. Its crates are small
  enough to read in an afternoon, and its differential test suite pins its
  behaviour to Nix's output.
