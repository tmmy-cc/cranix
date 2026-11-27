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
| Store backends         | local, daemon, binary caches, SSH, S3 | same as Nix          | pluggable (memory, files, object storage, gRPC) | local, daemon, `file://`/`http(s)://` binary caches, GitLab and GitHub package registries, SSH |
| Daemon protocol        | yes                         | yes, compatible              | partial (via `nix-compat`)             | yes, compatible (server and client, 1.37) |
| Builder                | goal/worker state machine, sandbox | same, sandbox             | separate build service (OCI / bubblewrap) | thread-pool scheduler, sandbox (macOS `sandbox-exec`, Linux namespaces), remote builders |
| Substituters / caches  | yes, signed                 | yes                          | yes (serves and consumes NAR/narinfo)  | yes, signed                             |
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
* The package registry of a GitLab or GitHub project is a binary cache
  (`gitlab://`, `github://`), with separate read and write tokens and NARs
  grouped into registry packages by hash, by name or by release;
  `cache serve` exposes such a cache over plain HTTP for Nix.
* `upload-to` uploads each output while later builds run, closure by
  closure, so the cache stays complete even when a build stops half way;
  Nix uploads after the build with `nix copy` or a `post-build-hook`.

### Measured against Nix 2.24

Evaluation of `(import <nixpkgs> {}).<attr>.drvPath` on an Apple M-series
machine (aarch64-darwin), nixpkgs 24.11pre, best of three runs, `.drv` files
already present in both stores. Both tools print the same path.

| Attribute | Nix 2.24 time | cranix time | Nix peak RSS | cranix peak RSS |
|-----------|--------------:|-----------:|-------------:|---------------:|
| `hello`   | 0.29 s        | 0.25 s     | 205 MiB      | 157 MiB        |
| `python3` | 0.29 s        | 0.26 s     | 206 MiB      | 160 MiB        |
| `git`     | 0.36 s        | 0.35 s     | 265 MiB      | 225 MiB        |

cranix (with mimalloc) is on par with or slightly faster than Nix on these
workloads and uses 15–25% less memory. A heap profile of `hello` peaks at
about 140 MB; the largest remaining items are merges of mid-sized sets by
`//` (30%), thunks including `mapAttrs` results (26%), and the compiled
syntax trees of the imported files (8%). Most of
it stays live until exit, because reference counting does not reclaim the
cycles that fixpoints create. Lix and Snix were not installed on the
benchmark machine and are not part of this table.

### Choosing between them

* Running NixOS or a production fleet: Nix or Lix. They have years of
  production use behind the daemon, sandbox, substituters, flakes and remote
  builders, and cover the rest of the surface (S3 stores, profiles,
  `nix-env`, the evaluation cache).
  Pick Lix for its community process and quality focus, Nix for being the
  upstream reference.
* Building infrastructure out of Nix concepts (remote evaluation, alternative
  store backends, a deduplicating content-addressed store, serving caches):
  Snix.
* Embedding Nix evaluation or derivation handling in a Rust program, or
  studying how Nix works in a small code base: cranix. Its crates are small
  enough to read in an afternoon, and its differential test suite pins its
  behaviour to Nix's output.
