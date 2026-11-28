<p align="center">
  <img src="site/favicon.svg" alt="cranix logo: a crane lifting a package" width="128" height="128">
</p>

<h1 align="center">cranix</h1>

<p align="center">
  <strong>The Nix package manager, rebuilt in Rust with the EU&nbsp;CRA in mind.</strong>
</p>

<p align="center">
  <a href="https://cranix.cc">cranix.cc</a> ·
  <a href="LICENSE">LGPL-2.1-or-later</a> ·
  bit-compatible with Nix 2.24
</p>

A Rust implementation of the Nix package manager: the Nix language, store
derivations, the NAR format, a local store with garbage collection, and a
parallel derivation builder. It is written from the specification of Nix's
observable behaviour (store path fingerprints, ATerm, NAR, evaluation
semantics) and designed around Rust idioms; it is not a line-by-line
translation of the C++ code base. The name joins the EU Cyber Resilience
Act (CRA) and *Kranich*, German for crane.

Its output is bit-compatible with Nix 2.24: evaluating
`(import <nixpkgs> {}).hello.drvPath` produces the same `.drv` path as
`nix-instantiate`, which means every derivation in the darwin stdenv
bootstrap graph hashes identically.

## Layout

| Crate          | Lines | Contents |
|----------------|------:|----------|
| `cranix-core`   | 2.0k  | Hashes (md5/sha1/sha256/sha512), nix-base32, SRI, store paths and their fingerprints, streaming NAR writer/reader, derivations (ATerm, `hashDerivationModulo`, input-addressed, fixed-output, floating and impure outputs), narinfo and ed25519 signatures |
| `cranix-store`  | 5.8k  | Local store, path metadata, `add_text`/`add_path`, reference scanning, closures, GC roots and collection, verification, parallel builder, build sandbox, realisations of content-addressed outputs, binary caches (files, HTTP, GitLab and GitHub registries) and substitution, settings |
| `cranix-eval`   | 7.8k  | Lexer/parser, scope-resolving compiler, lazy evaluator, ~120 builtins including `fromTOML` and `toXML`, `derivationStrict`, printing, JSON, error rendering with source snippets and traces |
| `cranix-daemon` | 3.8k  | Nix worker protocol (up to 1.37) and serve protocol (2.7): `cranix daemon`, `cranix store serve`, clients for `unix://`, `ssh-ng://` and `ssh://` stores, remote builders |
| `cranix-fetchers` | 3.0k | Fetchers for files, tarballs, paths, Git and GitHub/GitLab/SourceHut, the fetcher cache, flake registries |
| `cranix-sbom`   | 1.9k  | CycloneDX and SPDX SBOMs of closures and lock files, Go and Rust binary metadata, SLSA provenance statements and DSSE signatures, release source bundles |
| `cranix`        | 2.4k  | CLI, flake commands and installables |

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

Parsed files are cached on disk under `$XDG_CACHE_HOME/cranix/ast` (default
`~/.cache/cranix/ast`) in a compact binary form with a shared string table,
keyed by the SHA-256 of the cranix version, the source text and the
directories that path literals resolve against. A file read again is decoded
instead of lexed and parsed; entries are written by a background thread, and
a damaged entry is parsed again. `CRANIX_AST_CACHE=0` turns the cache off.

`CRANIX_EVAL=vm` runs a bytecode VM in place of the tree walker. Each file,
lambda body and thunk body is compiled on first use into a chunk of ops on
a value stack; the ops share the tree walker's operations, and the error
frames and positions the walker adds around a sub-expression are regions
over its ops. Results, errors and traces are the same as the tree walker's;
the VM is 4–7% slower on nixpkgs (see [docs/comparison.md](docs/comparison.md)).

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
objects live below `~/.local/share/cranix/nix/store` (a chroot store), so
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
Each builder runs in its own process group, which is killed when it exits,
fails or exceeds `timeout` or `max-silent-time`.

**Sandbox.** The `sandbox` setting (`true`, `false` or `relaxed`; enabled by
default on Linux, disabled on macOS, as in Nix) confines builders to their
input closure, `sandbox-paths` and their build directory. On Linux the
builder is PID 1 of new user, mount, PID, IPC, UTS and network namespaces,
in a chroot assembled from bind mounts (inputs and sandbox paths read-only)
with minimal `/dev`, `/proc`, `/dev/shm`, a writable `/tmp`, the build
directory at `/build`, hostname `localhost`, a loopback-only network and
Nix's `/etc/passwd`, `/etc/group` and `/etc/hosts`. As in Nix, Linux
builds run without address space randomisation, and `i686-linux` builds on
x86_64 (and 32-bit ARM builds) with the 32-bit personality. Inside, it is `nixbld`
(uid 1000, gid 100), mapped to the invoking user, so no privileges are
needed. On macOS it runs under `sandbox-exec` with a profile generated like
Nix's, honouring `__impureHostDeps` (within `allowed-impure-host-deps`),
`__sandboxProfile` and `__darwinAllowLocalNetworking`. Fixed-output
and impure derivations keep network access. In relaxed mode `__noChroot`,
fixed-output and impure derivations build unconfined. Where the kernel does not allow
user namespaces, `sandbox-fallback` (default `true`) builds unsandboxed with
a warning.

**Substitution.** Before building, `realise` asks the configured binary
caches (default `https://cache.nixos.org`) for the missing outputs of each
derivation; derivations whose outputs are all available are fetched with
their closures instead of built, and their inputs are skipped. Lookups and
downloads run in parallel (`max-substitution-jobs`). NARs are streamed from
`curl` through the decompressor (xz, zstd, bzip2 or none) into the store
while the file and NAR hashes are checked, and paths are registered in
dependency order once their references are valid. With `require-sigs`, a
narinfo must carry an ed25519 signature by one of `trusted-public-keys` over
Nix's fingerprint, or be content-addressed, or come from a cache whose URL
has the parameter `trusted=true`. Cache URLs take Nix's parameters
`priority`, `trusted`, `compression` and `secret-key`
(`https://host/cache?priority=10&trusted=true`). `builtins.storePath` substitutes
missing paths the same way. Caches hold `/nix/store` paths, so substitution
applies to the default chroot store. HTTP requests are retried on
connection errors, 408, 429 and 5xx (`download-attempts`), and take
credentials from `netrc-file` (default `~/.config/cranix/netrc`). Lookups,
including misses, are remembered per cache under the store's
`narinfo-cache` directory for `narinfo-cache-positive-ttl` (30 days) and
`narinfo-cache-negative-ttl` (1 hour). `copy --to` uploads each NAR before
the narinfo that names it, so an interrupted upload never leaves a narinfo
without its NAR.

Content-addressed outputs are substituted through their realisations:
`realise` reads `realisations/<id>.doi` from the caches and, with
`require-sigs`, uses one only if it carries a signature by one of
`trusted-public-keys` over Nix's realisation fingerprint. Realisations the
store registers, from its own builds or from daemon clients, are signed
with `secret-key-files`, and `copy --to` uploads the realisations of the
outputs it copies, signed with the copy keys.

**Upload while building.** With `upload-to` (`build --upload-to URL`), each
output goes to that cache as soon as it is built and registered, while
later builds run, on `upload-jobs` threads (default 4). Any cache URL
works, the registry caches included. A path is uploaded only once every
path it references is in the cache, and its NAR before its narinfo, so the
cache holds complete closures at every moment, also when the build is
stopped half way. At the end the closures of the requested outputs are in
the cache, substituted and already present paths included, with the
realisations of content-addressed outputs. Uploads are signed with
`secret-key-files` and the URL's `secret-key`. A failed upload prints a
warning with the URL's secrets hidden, keeps the paths that refer to the
failed one out of the cache, and fails the build only with
`upload-required` (`--upload-required`). The daemon uploads what it builds
for its clients, and a store using remote builders uploads the outputs
they return, through the same queue.

```sh
cranix --store ~/build build --upload-to 'file:///tmp/cache?compression=zstd' --secret-key-files ./key ./default.nix
cranix build --upload-to 'gitlab://gitlab.example.com/group/project?token-file=/run/secrets/gl' --upload-jobs 8 .#hello
```

**Choosing what goes into a cache.** `copy --to` and uploads while
building take the same filters. Each chosen path goes up with its runtime
closure, and a path whose closure holds a left-out path is left out too,
so a cache only ever holds complete closures.

| `copy` flag | upload setting | effect |
|---|---|---|
| `--type TYPES` | `upload-types` | take these kinds of paths from the derivation graph of the given paths (a `.drv`, or an output's deriver): `source`, `drv`, `drv-out-path`, `fixed-output-drv`, `fixed-output-out-path`, `build-drv`, `build-out-path`, `toplevel-drv`; without types, the given paths themselves |
| `--exclude-host GLOB` | `upload-exclude-hosts` | leave out outputs of fixed-output derivations whose `url` or `urls` name a matching host (`*.github.com`) |
| `--exclude-name GLOB` | `upload-exclude-names` | leave out derivations whose name matches, their outputs, and everything built from them |
| `--exclude-class system\|test` | `upload-exclude-classes` | the same for built-in name patterns: `system` for the parts of one machine (`nixos-system-*`, `etc`, `etc-*`, `unit-*`, `initrd*`, `system-path`, `system-units`, `user-units`, `*.pam`, `udev-rules`, `tmpfiles.d`, `security-wrapper-*`, `X-Restart-Triggers-*`, `*-image`, `*.img`, `*.iso`, …), `test` for `vm-test-run-*`, `nixos-test-*`, `*-test`, `*-tests` |
| `--exclude-local` | `upload-exclude-local` | leave out outputs of derivations with `preferLocalBuild = true` or `allowSubstitutes = false`, except fixed-output ones (nixpkgs' fetchers set `preferLocalBuild` too) |

Name and class matches spread to everything built from the derivation,
also without a runtime reference: a package built against generated
configuration is as specific as the configuration. Host and local-build
matches apply to outputs only, so the `.drv` files of the derivations built
from them stay complete. Paths missing from the local store are left out
with a warning that lists them. `copy --dry-run` prints `copy PATH (TYPE)`
for each path it would upload (`reference` for paths taken as part of a
closure) and `skip PATH: REASON` for each one it leaves out.
`copy --to-nars DIR` writes the selection as `DIR/<path>.nar` files with
`DIR/index.json` (path, NAR hash and size, references, deriver,
signatures, in upload order); `--to file:///DIR` writes a binary cache.

A shared cache for generic builds, filled while building a system image:

```sh
cranix build .#targetImage --upload-to 'gitlab://gitlab.example.com/group/common-cache?token-file=/run/secrets/gl' \
  --upload-exclude-classes system --upload-exclude-local --upload-exclude-names 'myproject-*'
cranix copy --to-nars /tmp/x --dry-run --type build-drv --exclude-class system --exclude-local ./image.drv
```

**Registry caches.** The package registry of a GitLab or GitHub project
serves as a binary cache:

* `gitlab://HOST/GROUP/PROJECT` keeps files in the project's GitLab generic
  package registry (`https://HOST/api/v4/projects/GROUP%2FPROJECT/packages/generic/PACKAGE/VERSION/FILE`).
* `github://OWNER/REPO` keeps them in the GitHub container registry
  (`ghcr.io/OWNER/REPO/PACKAGE`). Each file is an OCI manifest tagged
  `VERSION.FILE` whose one layer is the file, stored as a content-addressed
  blob. `registry=URL` names another OCI registry.

Files are grouped into registry packages. A narinfo goes to
`nix-<first two characters of its hash>`, realisations and logs to
`nix-meta`, and NARs by the `layout` parameter: `hash` (the default, by
the first two characters of the file hash, beside the narinfos), `name`
(one package per store path name without its version, such as `hello`) or
`group=NAME` (one package for everything, for example all a release
needs). The package of a NAR is part of the `URL:` in its narinfo, so
reading needs no layout. `version` (default `v1`) is the package version
(GitLab) or tag prefix (GitHub). `nix-cache-info` is answered locally
(`StoreDir: /nix/store`, or `store-dir=DIR`). File names are checked before
any request is sent: segments of `[A-Za-z0-9._+:!=-]`, none empty, `.` or
`..`; other characters are escaped in registry file names and tags.

Reads (`GET`, `HEAD`) send the read token and uploads the write token, each
standing in for the other when only one is given: `read-token-file=FILE`,
`write-token-file=FILE` or `token-file=FILE` for both, otherwise the
`access-tokens` entry of the host (`gitlab.example.com=TOKEN`, or
`github.com=TOKEN` for ghcr.io). GitLab tokens go in `PRIVATE-TOKEN`
(`Deploy-Token` for `gldt-` tokens, `JOB-TOKEN` with `token-type=job`).
For GitHub the token is exchanged at the registry's token endpoint for a
bearer token per repository. Messages hide all tokens.
`scheme=http` talks plain HTTP to a GitLab host.

```sh
cranix copy --to 'gitlab://gitlab.example.com/group/project?write-token-file=/run/secrets/gl&secret-key=/path/to/key' ./result
cranix --option extra-substituters 'github://owner/repo?layout=name' build .#hello
cranix cache serve --listen 127.0.0.1:5000 'gitlab://gitlab.example.com/group/project?token-file=/run/secrets/gl'
nix copy --from http://127.0.0.1:5000 /nix/store/...-hello-2.12.1
```

`cache serve [--listen ADDR:PORT] URL` answers `GET` and `HEAD` for the
files of any cache URL cranix opens, so that Nix and other HTTP clients read
a registry cache. It prints its URL (`http://127.0.0.1:5000` by default)
and streams NARs as they arrive.

**SBOMs.** `cranix sbom INSTALLABLE` (or a file, `--expr`, `-A`) writes a
software bill of materials as CycloneDX 1.6 JSON, or SPDX 2.3 JSON with
`--format spdx`, to standard output or `-o FILE`. It builds or substitutes
the outputs and follows their runtime references; for a path from the host
store, the references come from a scan for the hashes of the build graph.
`--build-time` takes the build graph instead and needs no outputs.

* Components: the outputs of one derivation form one component, named by
  `pname` and `version` (else the name split before the version), with each
  store path as a `nix:store_path` property. Paths without a version, such
  as sources and generated files, are no components; dependencies pass
  through them. Downloads (fixed-output derivations) are the sources of the
  components that use them, with their URL and file hash.
* Identifiers: `pkg:nix/NAME@VERSION`, and the ecosystem purl where the
  derivation shows one (`pkg:pypi` for Python packages, `pkg:npm` with
  `npmDeps`, `pkg:cargo` with `cargoDeps`, `pkg:golang` from a Go binary's
  main module), which CycloneDX gets as `purl` and the others as
  properties. CPEs are `meta.identifiers.cpe`, else built from name and
  version with an unknown vendor.
* Metadata: licences (SPDX IDs, other licences by name), descriptions and
  homepages come from `meta` of the derivations reachable from the
  evaluated value through its build-input attributes. For a NixOS
  configuration (`.#nixosConfigurations.NAME`) the SBOM describes
  `config.system.build.toplevel`, and the metadata also comes from
  `environment.systemPackages`, `systemd.packages`, `services.udev.packages`,
  the kernel and `hardware.firmware`.
* Linked code, by default from the derivations: crate downloads
  (`crate-NAME-VERSION.tar.gz`), the `Cargo.lock` of the vendored
  `cargoDeps` (a tarball or directory) and the `modules.txt` of
  `goModules`, which are fetched when missing (`--no-fetch-deps` keeps to
  what is in the store). They are listed below the package as nested
  components with `cranix:found-in`.
* `--scan-binaries` also reads ELF and Mach-O files: the module list of Go
  binaries and the crate list `cargo auditable` writes into `.dep-v0`, and
  names executables with statically linked code and no such list
  (`cranix:unlisted-binary`), so the gaps show. `--scan-sources` reads
  `Cargo.lock` and `package-lock.json` files in unpacked sources.
* `cranix sbom lock Cargo.lock|package-lock.json` writes the SBOM of a lock
  file, and `--merge DOC` adds the components of CycloneDX documents to an
  SBOM.
* The output is deterministic: no timestamp, components and dependencies
  sorted, and the serial number (SPDX: the namespace) a UUID made from the
  content. SPDX requires a creation time; it is `SOURCE_DATE_EPOCH`, else
  the Unix epoch.

```sh
cranix sbom nixpkgs#ripgrep -o ripgrep.cdx.json
cranix sbom .#nixosConfigurations.target --build-time --format spdx -o system.spdx.json
cranix sbom lock ./Cargo.lock -o deps.cdx.json
```

**Vulnerability scanning.** `cranix vuln-scan SBOM` checks a CycloneDX
SBOM from `cranix sbom` against a local database of OSV advisories and NVD
CVEs and fails while a finding that nobody assessed remains:

```sh
cranix vuln-db update                      # OSV (PyPI, crates.io, npm, Go) and the NVD feeds
cranix sbom .#app -o app.cdx.json
cranix vuln-scan app.cdx.json --vex release.vex.json --fail-on high --max-db-age 7d --report findings.json
```

* The database lives in `~/.cache/cranix/vulndb` (`--db DIR`) as compact
  indexes with the time of the update. `vuln-db update` downloads the OSV
  dumps of `--ecosystems` and the NVD 2.0 feeds of `--nvd-years` (or
  `--no-nvd`); `vuln-db import --osv FILE|DIR|ZIP --nvd FEED.json[.gz]`
  builds one from files already at hand, such as a mirror.
* Ecosystem packages (`pkg:pypi`, `pkg:cargo`, `pkg:npm`, `pkg:golang`, also
  the crates and Go modules nested in a package) are matched against the
  OSV advisories of their ecosystem, by `introduced`/`fixed`/`last_affected`
  ranges and listed versions.
* Other components are matched against the NVD by CPE product: the product
  of the component's CPE (or its name, with `-` and `_` treated alike), any
  vendor unless the SBOM's CPE names one, and the release part of the
  version (`5.2p37` is `5.2`) against the CVE's exact version or range.
* A vulnerability appears once per product and version, listing every
  component that maps to it.
* `--vex FILE` (repeatable) reads OpenVEX 0.2.0 documents. A statement names
  the vulnerability (or an alias), products by purl (a purl without a
  version names every version) or `bom-ref`, and a status. `not_affected`
  (which needs a `justification` or `impact_statement`) and `fixed` remove
  the finding; `affected` and `under_investigation` keep it in the report
  as assessed. Later statements win.
* Exit codes: 0 when no unassessed finding of at least `--fail-on` severity
  (`any`, the default, `low`, `medium`, `high`, `critical`) remains, 2 when
  one does, 3 when the database is missing or older than `--max-db-age`
  (`7d`, `12h`; without it, an older than a week database gives a
  warning), 64 for wrong arguments. Findings without a score count at every
  threshold. Severities are CVSS base scores (CVSS 3 vectors are computed),
  else the advisory's own severity.
* `--report FILE` writes the remaining findings as JSON: ID, aliases,
  severity, score, what matched, the components and the assessment.

Matching by product name has limits. A Nix package name that differs from
the NVD product (`python3` against `python`, `gtk3` against
`gtk+`) misses CVEs, and a name shared by unrelated software can match
CVEs of the other one; a CPE in `meta.identifiers.cpe` with its vendor
makes the match exact. Versions are compared by their release part, so
Nix's patch levels and distribution patches are invisible: a package
patched against a CVE still matches until a VEX statement says `fixed`.
NVD ranges written for another versioning scheme compare loosely.

**Build provenance.** `cranix provenance INSTALLABLE` (or a file, `--expr`,
`-A`) builds the installable and writes, for each output, an in-toto
Statement v1 with a SLSA Provenance v1 predicate, one per line (JSON Lines):

```sh
cranix provenance .#app -o app.provenance.jsonl
cranix provenance .#app --sign --to gitlab://group/project
cranix provenance verify app.provenance.jsonl --public-key ./cache-key.pub
cranix provenance verify --from gitlab://group/project /nix/store/...-app-1.0
```

* The subject is the output path with the SHA-256 of its NAR (its
  `NarHash`). The build definition names the derivation and output, and
  lists the `.drv` file, the input sources and the outputs of the input
  derivations with their NAR hashes; its internal parameters hold the
  system, the system features, the sandbox mode, paths and allowed host
  dependencies, `timeout` and `max-silent-time`. The builder is cranix and
  its version. [docs/provenance.md](docs/provenance.md) describes the
  build type.
* Statements hold no wall-clock time and their keys are sorted, so the same
  build gives the same statements on every run.
* `--sign` wraps each statement in a DSSE envelope signed with the ed25519
  keys of `secret-key-files`; `keyid` is the key name.
* `--to URL` (which signs) stores each envelope as `<hash>.provenance.json`
  beside the narinfo of the output, in any binary cache that `copy --to`
  takes, the registry caches included.
* `provenance verify` reads envelopes from a file (or stdin) or, with
  `--from URL PATH...`, from a cache. Each needs a valid signature by a key
  of `trusted-public-keys` or `--public-key` (a key or a file holding one),
  an in-toto statement as payload, and, for paths this store holds,
  subject digests that match their NAR hashes.

**Release sources.** `cranix source-archive INSTALLABLE` (or a file,
`--expr`, `-A`) bundles every source the build graph of the installable is
made from, for the documentation and retention duties of the EU Cyber
Resilience Act:

```sh
cranix source-archive .#app -o app-1.0-sources
cranix source-archive .#app --tarball app-1.0-sources.tar.gz
cranix source-archive .#app --drvs --to gitlab://group/project
```

* It walks the `.drv` graph (the build-time closure) of the installable and
  takes the outputs of fixed-output derivations (`fetchurl`,
  `fetchTarball`, `fetchGit`, `fetchTree`) and the local `inputSrcs` of
  every derivation, which include paths fetched during evaluation, with the
  closure of their references. `--drvs` adds the derivations, so the exact
  build graph rebuilds without evaluating again.
* Missing downloads are substituted, or else built, inputs first. Nothing
  that is not fixed-output is built: a download whose fetcher needs such a
  derivation that is not in the store counts as unavailable. `--no-fetch`
  takes only what the store holds.
* The bundle is a binary cache: `-o DIR` writes it to a directory,
  `--tarball FILE` to a gzip-compressed tar archive (the same bytes on every
  run), and `--to URL` to any cache that `copy --to` takes (`file://`,
  `gitlab://`, `github://`, HTTP), signed with the keys of
  `secret-key-files`. The filters of `copy` (`--exclude-host`,
  `--exclude-name`, `--exclude-class`, `--exclude-local`) leave sources out.
* `sources.json` at its root lists each entry with its kind (`fetched`,
  `local` or `derivation`), the derivation that fetches it, its URLs, its
  hash as the derivation states it, the licences of the packages that use
  it and those packages. A source that cannot be fetched has
  `"available": false` and a `reason`, is counted in `missing` and makes the
  command exit non-zero after the bundle is written; one a filter left out
  has a `reason` and is counted in `excluded`.
* All its paths are content-addressed, so `cranix copy --from URL PATH...`
  takes them into a store without signatures, and the release rebuilds
  there without network access.
* Paths that import-from-derivation creates exist only after a full
  evaluation that builds them; the bundle holds those that the evaluation
  before it produced.

**Reproducibility checks.** `cranix build --check` (or `--rebuild`) builds
the installable as usual, then rebuilds each of its derivations and compares
the result with the outputs already present, as `nix build --rebuild` does.
It fails with one line per differing file, and the first differing line of
text files:

```text
error: output '/nix/store/...-stamp' of '/nix/store/...-stamp.drv' differs from its rebuild:
  share/stamp: contents differ at line 1
    - Sat Nov 28 10:23:42 CET 2026
    + Sat Nov 28 10:23:43 CET 2026
the rebuild is kept at '/nix/store/...-stamp.check'
```

The existing outputs stay registered and return to their paths whatever the
result; with `--keep-failed` a differing rebuild stays at `<path>.check`.
Outputs whose path depends on their contents (floating content-addressed
outputs) cannot be checked this way.

**Settings.** One configuration value, in `nix.conf` syntax, feeds builds,
substitution, fetchers, experimental features, remote builders and the
daemon. It is read in Nix's order, later sources winning:
`$NIX_CONF_DIR/nix.conf` (`/etc/nix/nix.conf`), the user `nix.conf`
(`$NIX_USER_CONF_FILES`, else `nix/nix.conf` under `$XDG_CONFIG_DIRS` and
`$XDG_CONFIG_HOME`), `~/.config/cranix/cranix.conf`, `$CRANIX_CONFIG`,
`$NIX_CONFIG`, and then the command line. Files may `include` and
`!include` others, and list settings take `extra-NAME` to append. Every
setting also has the flags Nix derives from it: `--option NAME VALUE`,
`--NAME VALUE`, `--extra-NAME VALUE` for lists and `--NAME`/`--no-NAME` for
Booleans. Settings of Nix that cranix does not use are accepted silently;
unknown ones produce one warning each. `cranix config show [NAME]` prints
the values in effect.

**Daemon and remote builders.** `cranix daemon` serves a store to Nix
clients over a Unix socket (or stdin/stdout with `--stdio`, which is what
`ssh-ng://` runs on the far side), one thread per client. It speaks the
worker protocol of Nix 2.24 (protocol 1.37): framed NAR transfers, log
and error messages, and the operations real clients use, from
`QueryPathInfo` and `AddMultipleToStore` to `BuildPathsWithResults`,
`BuildDerivation`, `NarFromPath` and `CollectGarbage`. Every path a
connection adds, builds or asks to keep becomes a temporary GC root that
lives as long as the connection. Build output streams to the client as
Nix's build activities, so `nix build -L` shows it live; substitutions and
resolved derivations are reported in the same stream. The daemon builds
with its own settings, so its `sandbox`, `sandbox-paths` and substituters
apply whatever the client asks for; clients may set `cores`, `timeout`,
`max-silent-time` and `useSubstitutes`, and trusted clients may enable
`ca-derivations`. Missing paths are substituted from the daemon's caches,
with signature checks, for `EnsurePath`, `BuildPaths` and
`BuildPathsWithResults`, and `QueryMissing` and the substitutable-path
queries answer from the caches. Content-addressed derivations build through
`BuildPaths` and `BuildDerivation`, `QueryRealisation` and
`RegisterDrvOutput` read and record realisations (untrusted clients need a
signature by a trusted key), and build results carry the realisations of
the outputs. Clients build
concurrently; each derivation's outputs are locked while it builds, so a
second request for it waits and then finds it built. The daemon's own user and
`trusted-users` are trusted; other clients may add content-addressed paths
only (their names are checked against their contents) and cannot build
input-addressed derivations with `BuildDerivation`.

`cranix store serve [--write]` (also `cranix --serve`, matching
`nix-store --serve`) speaks the serve protocol of `ssh://` stores and
builders, as client and server. As in Nix, `localhost` in an `ssh://` or
`ssh-ng://` URI runs the remote command directly, without ssh.

`--store daemon`, `unix://SOCKET`, `ssh-ng://HOST` or `ssh://HOST` builds
through a daemon (or `nix-store --serve`): evaluation writes `.drv` files and sources into a local store with
the daemon's store directory, their closure is copied over, and the daemon
builds and roots the result. Remote builders come from the `builders`
setting (Nix's machines format, default `@/etc/nix/machines`); a derivation goes to the least loaded machine that
supports its system and `requiredSystemFeatures`, its input closure is
copied there, it is built with `BuildDerivation` and its outputs are copied
back, with the remote build's output shown as the local build's. Unreachable machines are skipped, and the build falls back to the
local builder when it can run the derivation.

## Usage

```bash
cargo build --release
```

```bash
target/release/cranix eval --expr '(import <nixpkgs> {}).hello.drvPath' -I nixpkgs=/path/to/nixpkgs
```

```bash
target/release/cranix --store ~/oxstore build tests/build.nix -j 8 -L
```

```bash
target/release/cranix build --expr '(import <nixpkgs> {}).hello' -I nixpkgs=/path/to/nixpkgs
```

```bash
target/release/cranix copy --to 'file:///tmp/cache?compression=zstd&secret-key=/path/to/key' ./result
```

```bash
target/release/cranix --store ~/oxstore daemon --socket /tmp/cranix.sock
```

```bash
nix-store --store "unix:///tmp/cranix.sock?store=$HOME/oxstore/store" -q --references PATH
```

```bash
target/release/cranix --store daemon build tests/build.nix
```

```bash
target/release/cranix build tests/build.nix --builders 'ssh-ng://builder@host x86_64-linux - 4'
```

Commands: `eval` (`--json`, `--raw`, `--lazy`), `instantiate`, `build`
(`-o`, `--no-link`, `-j`, `-L`, `--keep-failed`, `--check`, `--upload-to`,
`--upload-jobs`, `--upload-required`), `provenance` and `provenance verify`,
`source-archive` (`-o`, `--tarball`, `--to`, `--drvs`, `--no-fetch` and the
filters of `copy`),
`show-derivation`,
`realisation info`,
`hash path|file|convert`, `nar dump|restore`, and
`store add|path-info|sign|closure|ls|verify|gc|serve` (`path-info --json -r
--closure-size`, also against a cache with `--store URL`), `copy --to URL` and
`copy --from URL` for `file://`, `http(s)://`, `gitlab://` and `github://`
caches (uploads with `PUT`; filters, `--dry-run` and `--to-nars`), `cache serve`, and
`key generate-secret|convert-secret-to-public`, `config show [NAME]`, and
`daemon` (`--stdio`, `--socket`, `--force-trusted`, `--force-untrusted`).
Global options: `--store`, `-I`, `--arg`, `--argstr`, `--pure`,
`--show-trace`, `--option NAME VALUE` and the flags of every setting, such
as `--system`, `--builders`, `--sandbox`/`--no-sandbox`, `--timeout`,
`--max-silent-time`, `--trusted-users` and
`--extra-experimental-features`. `NIX_PATH`
entries that are absolute paths or `flake:` references (`nixpkgs=flake:nixpkgs`)
are honoured.

Flakes: `flake metadata|show|lock|update|check|init|new`, and installables
such as `.#hello` or `nixpkgs#hello` for `eval`, `build`, `run`, `shell` and
`develop`, with the default attribute lookup of Nix (`packages.<system>.default`,
`legacyPackages.<system>.`, `apps.<system>.`, `devShells.<system>.`).
Flake evaluation is pure unless `--impure` is given; the lock flags of Nix
(`--no-write-lock-file`, `--update-input`, `--override-input`,
`--override-flake`, `--recreate-lock-file`, `--commit-lock-file`,
`--refresh`, …) are accepted. `eval`, `build` and `instantiate` of a flake
installable keep their results (the printed value, or the derivations to
build) in an evaluation cache under `$XDG_CACHE_HOME/cranix/eval-cache-v1`,
one JSON file per flake fingerprint, so a repeated command on the same
locked flake only locks it; derivations a cached entry names must be valid
in the store. Dirty trees, unlocked inputs and `--impure` get no cache, and
`--no-eval-cache` (the `eval-cache` setting) turns it off. `run`, `shell` and `develop` use outputs that
are already in the host store and build the missing ones: through the
daemon given with `--store` (such as `--store daemon` for the system Nix
daemon), else in the evaluation store, which substitutes what it can and
hands builds to the configured remote builders. When the default chroot
store would have to build and no builders are configured, they say how to
make building possible.

```bash
target/release/cranix eval nixpkgs#hello.drvPath
target/release/cranix flake lock && target/release/cranix flake metadata
```

macOS has no shell in the sandbox unless one is listed:

```bash
target/release/cranix --store ~/oxstore build tests/build.nix --option sandbox true --option sandbox-paths "/bin/sh /bin/bash /bin/cat /bin/mkdir"
```

## Scope

Implemented: the Nix language (including `with`, `rec`, formals with
defaults and `@` patterns, dynamic attributes, `__functor`, `__toString`,
indented strings, path interpolation, search paths, `<nix/fetchurl.nix>`),
string contexts, `derivation`/`derivationStrict` with structured attributes,
`__ignoreNulls`, multiple outputs and fixed-output derivations,
`builtins.path`/`filterSource`, import from derivation, `fromTOML` (TOML
1.0) and `toXML`, content-addressed (floating) and impure derivations
behind the `ca-derivations` and `impure-derivations` experimental features
(realisations, resolution of inputs, `text` hashing with
`dynamic-derivations`), the local store operations listed above, binary
caches (narinfo reading and writing,
signatures, substitution and `copy`), the daemon protocol (server and
client), remote builders over `ssh-ng://` and `ssh://`, the fetchers (`fetchurl`, `fetchTarball`,
`fetchGit`, `fetchTree` with the types `file`, `tarball`, `path`, `git`,
`github`, `gitlab`, `sourcehut` and `indirect`) and flakes (`flake.nix`,
`flake.lock` version 7, flake references, the user, system and global
registries, `getFlake`, `parseFlakeRef`).

Fetched inputs get the same store paths and attributes as in Nix, and lock
files are interchangeable with Nix's. Downloads, Git clones and ref lookups
are cached in the store's state directory (`fetcher-cache`, `gitv3`) and
expire after `tarball-ttl` (read from `nix.conf`). Archives are decompressed
with `gzip`, `xz`, `bzip2` or `zstd` and Git repositories are read with the
`git` command line tool.

Errors are printed like Nix 2.24: the position with the surrounding source
lines, a short trace (all frames with `--show-trace`), and hints such as
close names for a missing attribute or an undefined variable.

Not implemented: S3 stores, `fetchMercurial`, the evaluation cache, the
`git` hashing mode, `unsafeGetAttrPos` (returns
`null`), and profiles/`nix-env`.

## Testing

* `cargo test` runs unit tests that pin hashes, store paths and `.drv` paths
  to values produced by Nix.
* `tests/difftest.py` evaluates every expression in `tests/exprs.nix` with
  both `nix-instantiate --eval --strict --json` and `cranix eval --json` and
  compares the output. The corpus covers the language, the builtins,
  derivation hashing, nixpkgs `lib` (including the module system and
  `systems.elaborate`) and the `drvPath`s of `hello`, `python3` and `git`
  from nixpkgs.
* `crates/cranix-eval/tests/errors.rs` pins the rendered output of evaluation
  errors: snippets, traces, hints and colour.
* `tests/catest.py` builds content-addressed, impure and text-hashed
  derivations with Nix and with cranix in the same scratch store location and
  compares drvPaths, output paths, realisations, rebuilds and messages, then
  has real Nix build the same derivations through `cranix daemon`
  (`nix build --store unix://…`) and compares again.
* `crates/cranix-daemon/tests/daemon.rs` runs a client against an in-process
  daemon: copying closures, NAR transfer, temporary roots against the
  collector, untrusted clients, remote builds through a daemon socket,
  concurrent clients building overlapping graphs, substitution of signed
  paths from the local cache server (and refusal of paths signed by an
  untrusted key), and every command of the serve protocol.
* `crates/cranix/tests/settings.rs` checks the precedence of every
  configuration source and of the command line flags through
  `cranix config show`, and that unknown settings warn once.
* `crates/cranix/tests/flake_build.rs` runs a flake package with `cranix run`
  and `cranix shell` through a `cranix daemon` that builds it, and checks
  the error without any builder.
* `crates/cranix-store/tests/realisations.rs` signs the realisation of a
  content-addressed build, uploads it, substitutes it into a store that
  cannot build, and refuses one signed by an untrusted key.
* `tests/flaketest.py` compares fetchers and flakes with Nix: store paths
  and attributes of `fetchGit` (clean and dirty trees, export-ignore),
  `fetchTree`, `fetchTarball` and `fetchurl`; the `flake.lock` of a flake
  with a `follows` input, which `nix flake metadata` must leave unchanged;
  flake outputs, `getFlake` and `flake metadata --json`; and
  `nixpkgs#hello.drvPath`. `--network` adds remote Git and GitHub inputs.
  The unit tests round-trip a `flake.lock` written by Nix.
* `tests/build.nix` exercises the builder: parallel leaves, references,
  `passAsFile`, multiple outputs and a fixed-output derivation.
* `tests/langtest.py` runs the language tests of Nix 2.24.10
  (`tests/functional/lang`) and of Snix (`snix_tests`), cloned at pinned
  revisions with `--fetch` into `~/.cache/cranix/langtests`: `eval-okay`
  cases must print their `.exp` output, `eval-fail` and `parse-fail` cases
  must fail, `parse-okay` cases must parse and Snix's `identity` cases must
  evaluate to their own text. For failing cases it also counts how often
  the first error line matches Nix's. Tests cranix does not pass yet are
  listed in `tests/langtest-known.txt`; a test outside the list that fails,
  fails the run, and `--update-known` rewrites the list.
* The `vuln` integration test of the CLI imports a fixture database (OSV
  records as files and a zip archive, an NVD feed) and checks matching by
  ecosystem, by CPE product with and without vendor and by release part,
  one finding per product, OpenVEX statements by purl, alias and
  `bom-ref`, severity thresholds, the report and the exit codes 0, 2, 3
  and 64.
* `cranix-sbom` compares the CycloneDX and SPDX documents of a small SBOM
  with golden files, and the `sbom` integration test of the CLI builds a
  closure with `meta`, vendored crates and Go modules and checks the
  components, both formats, lock files, merging, `--build-time` and that
  two runs give identical documents. `tests/sbom-schema.py` validates the
  golden files and generated SBOMs against the CycloneDX 1.6 and SPDX 2.3
  schemas in `crates/cranix-sbom/tests/schemas` (it needs Python's
  `jsonschema`).
* The `provenance` integration test of the CLI builds a derivation with two
  outputs, a source and an input derivation, and checks the statements,
  that two runs give identical output, that signed envelopes verify from a
  file and from a `file://` cache, and that an envelope without a trusted
  key or with a changed payload fails. `tests/provenance-schema.py`
  validates generated statements and envelopes against the in-toto
  Statement v1, SLSA Provenance v1 and DSSE schemas in the same directory.
* The `source_archive` integration test of the CLI bundles a package with a
  fetched and a local source, a download that fails and one whose fetcher
  needs a derivation that is not fixed-output. It checks the index (URL,
  hash, licence, users, reasons, the exit code), that nothing else is
  built, that two tarballs are identical, that `--exclude-host` leaves a
  download out, and that a tarball and a `file://` cache restore into a
  collected store in which the package rebuilds after its upstream is gone.
  `tests/registry-cache.sh` pushes a release with `--drvs` to the fake
  GitLab and GitHub registries and reads a source back.
* The `build_check` integration test of the CLI checks that `--check`
  passes for a reproducible derivation, and fails for one that writes the
  time with the differing line, keeping the rebuild with `--keep-failed`
  and the existing output unchanged.
* The `copy_filters` integration test of the CLI builds a small graph
  (a source, a download, packages, a generated unit, a build input matched
  by name, a system toplevel and a test) and checks each path type and
  filter with `copy --dry-run`, `--to-nars`, `--to file://` and the
  `upload-*` filter settings.
* The `upload` integration test of the CLI builds a chain of derivations
  with `--upload-to` and checks that each output reaches the cache while
  the next one builds, that a build killed half way leaves only complete
  closures, and that failed uploads warn with the URL's secrets hidden or,
  with `--upload-required`, fail the build. A daemon test checks the
  uploads of the daemon and of remote builds.
  `tests/upload-while-building.sh` reads such a cache with
  `nix path-info` and `nix store verify`.
* `tests/http-cache.sh` uploads a closure to a local HTTP cache (the
  `cache-server` example of `cranix-store`) and reads it back with
  `nix path-info`, `nix store verify` and `nix copy`. The same server backs
  the `http_cache` integration test run by `cargo test`.
* `tests/registry-cache.sh` copies a closure to a `gitlab://` and a
  `github://` cache on a fake registry (the `registry-server` example of
  `cranix-store`), reads it back with `copy --from`, and with `nix path-info`,
  `nix store verify` and `nix copy` through `cache serve`. The same fake
  registry, which checks read and write tokens and the services' naming
  rules, backs the `registry_cache` integration test.
* `tests/registry-live.sh` runs the same round trip against real GitLab and
  GitHub projects named by `CRANIX_TEST_GITLAB` and `CRANIX_TEST_GITHUB`, with
  tokens from `CRANIX_TEST_GITLAB_TOKEN_FILE` and `CRANIX_TEST_GITHUB_TOKEN_FILE`.
* `cargo test` also builds it sandboxed, and builds the derivations of
  `tests/sandbox.nix` to show that a sandboxed builder can neither read a
  host file outside its closure nor reach the host's network, that a
  fixed-output derivation can, that `__noChroot` needs relaxed mode, and
  that `timeout` and `max-silent-time` kill a build with its background
  processes. The same probe runs through `cranix daemon` started with
  `--option sandbox true` and with `--no-sandbox`. On Linux these need
  unprivileged user namespaces.
* `tests/sandbox-linux.sh [SYSTEM...]` builds cranix with nixpkgs and runs
  those checks inside a Nix build, as the unprivileged build user, for
  `aarch64-linux` and `x86_64-linux` on this machine or its remote builders.
  Systems without a builder are skipped.

## Profiling

The `cranix` binary uses mimalloc. On macOS its C sources are compiled and
linked with clang (`.cargo/config.toml`), since GCC there emulates
thread-local storage. A heap-profiling build swaps in dhat:

```bash
cargo build --release --features dhat-heap --target-dir target/dhat
```

Running it writes `dhat-heap.json` to the current directory, viewable with
dhat's `dh_view.html`. Profiling slows evaluation by about 200×.

See [docs/comparison.md](docs/comparison.md) for how this relates to Nix,
Lix and Snix.
