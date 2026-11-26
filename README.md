# oxnix

A Rust implementation of the Nix package manager: the Nix language, store
derivations, the NAR format, a local store with garbage collection, and a
parallel derivation builder. It is written from the specification of Nix's
observable behaviour (store path fingerprints, ATerm, NAR, evaluation
semantics) and designed around Rust idioms; it is not a line-by-line
translation of the C++ code base.

Its output is bit-compatible with Nix 2.24: evaluating
`(import <nixpkgs> {}).hello.drvPath` produces the same `.drv` path as
`nix-instantiate`, which means every derivation in the darwin stdenv
bootstrap graph hashes identically.

## Layout

| Crate          | Lines | Contents |
|----------------|------:|----------|
| `oxnix-core`   | 1.2k  | Hashes (md5/sha1/sha256/sha512), nix-base32, SRI, store paths and their fingerprints, streaming NAR writer/reader, derivations (ATerm, `hashDerivationModulo`, output paths) |
| `oxnix-store`  | 1.0k  | Local store, path metadata, `add_text`/`add_path`, reference scanning, closures, GC roots and collection, verification, parallel builder |
| `oxnix-eval`   | 4.6k  | Lexer/parser, scope-resolving compiler, lazy evaluator, ~110 builtins, `derivationStrict`, printing, JSON |
| `oxnix`        | 0.5k  | CLI |

The core crate has no knowledge of the evaluator or the file system layout of
a store, so it can be reused by tools that only need hashing, NAR or
derivation handling.

## Design

**Evaluator.** Source is parsed by a hand-written recursive-descent parser
(string and path bodies are lexed on demand, so interpolation nests without a
lexer state stack). A compile pass lowers the syntax tree to an IR in which
every statically bound variable is a `(depth, slot)` pair; only names that
can only come from `with` are looked up by name at run time. Undefined
variables are reported before evaluation starts. Nested attribute paths
(`a.b.c = 1; a.b.d = 2;`) are merged at compile time.

Compiled expressions are leaked to `&'static`, so a thunk is just
`(&'static Expr, Rc<Env>)`. Values are a 16-byte enum of immediates and `Rc`
pointers; attribute sets are sorted vectors keyed by interned symbols
(pointer equality, string ordering), so `attrNames` needs no sort. Thunks black-hole while being forced (infinite
recursion detection) and restore themselves when forcing fails, which keeps
`tryEval` semantics identical to Nix. `map`, `genList` and friends allocate
dedicated application thunks instead of boxed closures.

Memory is reference counted. Cyclic structures (recursive sets, `let`) are
not reclaimed while an evaluation runs, which suits one-shot CLI evaluation.
To keep that affordable, `a // b` with a small `b` on a large `a` is a layer
over the shared `a` (overlays and bootstrap stages do not copy the package
set), `mapAttrs` results share one function and the attribute's interned
name, and `intersectAttrs` walks its smaller argument. On nixpkgs, peak
memory is 15–25% below Nix 2.24 and evaluation time is on par.

**Store.** A store has a *logical* directory (the one baked into hashes) and
a *physical* one. By default the logical directory is `/nix/store` and
objects live below `~/.local/share/oxnix/nix/store` (a chroot store), so
evaluation results are identical to a regular Nix install without needing
root. `--store DIR` selects a store whose logical and physical directories
coincide, which is what building requires.

Path metadata (NAR hash, size, references, deriver, content address) is one
small text file per path, written atomically with rename. Objects are
canonicalised (read-only, mtime 1) and registered after they are complete.
Store paths that are not in this store are read from the host's `/nix/store`,
so nixpkgs checkouts there can be imported directly.

**Builder.** `realise` loads the derivation graph, prunes everything whose
outputs are valid and runs a ready-queue scheduler over a thread pool (`-j`).
Builders get Nix's environment (`NIX_BUILD_TOP`, `HOME=/homeless-shelter`,
`PATH=/path-not-set`, `passAsFile`, `NIX_ATTRS_JSON_FILE` for structured
attributes, `impureEnvVars` for fixed-output derivations). Outputs are
scanned for references against the input closure with a windowed scanner,
fixed-output hashes are verified, logs are kept per derivation and the tail
is shown on failure. `builtin:fetchurl` is implemented with `curl`.

**Substitution.** Before building, `realise` asks the configured binary
caches (default `https://cache.nixos.org`) for the missing outputs of each
derivation; derivations whose outputs are all available are fetched with
their closures instead of built, and their inputs are skipped. Lookups and
downloads run in parallel (`max-substitution-jobs`). NARs are streamed from
`curl` through the decompressor (xz, zstd, bzip2 or none) into the store
while the file and NAR hashes are checked, and paths are registered in
dependency order once their references are valid. With `require-sigs`, a
narinfo must carry an ed25519 signature by one of `trusted-public-keys` over
Nix's fingerprint, or be content-addressed. `builtins.storePath` substitutes
missing paths the same way. Caches hold `/nix/store` paths, so substitution
applies to the default chroot store.

Settings use `nix.conf` syntax and are read from
`~/.config/oxnix/oxnix.conf`, then `$OXNIX_CONFIG`, then `--option NAME
VALUE` (or `--NAME VALUE`, `--[no-]NAME`): `substituters`,
`trusted-public-keys`, `require-sigs`, `substitute`, `secret-key-files`,
`max-substitution-jobs`, each list also as `extra-NAME`.

## Usage

```bash
cargo build --release
```

```bash
target/release/oxnix eval --expr '(import <nixpkgs> {}).hello.drvPath' -I nixpkgs=/path/to/nixpkgs
```

```bash
target/release/oxnix --store ~/oxstore build tests/build.nix -j 8 -L
```

```bash
target/release/oxnix build --expr '(import <nixpkgs> {}).hello' -I nixpkgs=/path/to/nixpkgs
```

```bash
target/release/oxnix copy --to 'file:///tmp/cache?compression=zstd&secret-key=/path/to/key' ./result
```

Commands: `eval` (`--json`, `--raw`, `--lazy`), `instantiate`, `build`
(`-o`, `--no-link`, `-j`, `-L`, `--keep-failed`), `show-derivation`,
`hash path|file|convert`, `nar dump|restore`, and
`store add|path-info|sign|closure|ls|verify|gc` (`path-info --json -r
--closure-size`, also against a cache with `--store URL`), `copy --to URL` and
`copy --from URL` for `file://` and `https://` caches, and
`key generate-secret|convert-secret-to-public`. Global options: `--store`,
`-I`, `--arg`, `--argstr`, `--system`, `--pure`, `--option`. `NIX_PATH`
entries that are absolute paths are honoured.

## Scope

Implemented: the Nix language (including `with`, `rec`, formals with
defaults and `@` patterns, dynamic attributes, `__functor`, `__toString`,
indented strings, path interpolation, search paths, `<nix/fetchurl.nix>`),
string contexts, `derivation`/`derivationStrict` with structured attributes,
`__ignoreNulls`, multiple outputs and fixed-output derivations,
`builtins.path`/`filterSource`, import from derivation, the local store
operations listed above, and binary caches: narinfo reading and writing,
signatures, substitution and `copy`.

Not implemented: the daemon and its wire protocol, S3 and SSH stores,
narinfo disk caching, sandboxing, remote builders,
flakes, `fetchGit`/`fetchTarball`/`fetchTree`, content-addressed
(floating) and impure derivations, `fromTOML`, `toXML`, `unsafeGetAttrPos`
(returns `null`), and profiles/`nix-env`.

## Testing

* `cargo test` runs unit tests that pin hashes, store paths and `.drv` paths
  to values produced by Nix.
* `tests/difftest.py` evaluates every expression in `tests/exprs.nix` with
  both `nix-instantiate --eval --strict --json` and `oxnix eval --json` and
  compares the output. The corpus covers the language, the builtins,
  derivation hashing, nixpkgs `lib` (including the module system and
  `systems.elaborate`) and the `drvPath`s of `hello`, `python3` and `git`
  from nixpkgs.
* `tests/build.nix` exercises the builder: parallel leaves, references,
  `passAsFile`, multiple outputs and a fixed-output derivation.

## Profiling

The `oxnix` binary uses mimalloc. On macOS its C sources are compiled and
linked with clang (`.cargo/config.toml`), since GCC there emulates
thread-local storage. A heap-profiling build swaps in dhat:

```bash
cargo build --release --features dhat-heap --target-dir target/dhat
```

Running it writes `dhat-heap.json` to the current directory, viewable with
dhat's `dh_view.html`. Profiling slows evaluation by about 200×.

See [docs/comparison.md](docs/comparison.md) for how this relates to Nix,
Lix and Snix.
