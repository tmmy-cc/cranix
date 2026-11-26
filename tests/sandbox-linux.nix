# Linux sandbox check run by an unprivileged user: builds oxnix from this
# checkout with nixpkgs, then, inside a Nix build (as the build user, with
# no capabilities on the host), runs sandboxed oxnix builds of
# tests/build.nix and tests/sandbox.nix and checks what they could reach.
#
# Run it with tests/sandbox-linux.sh, which picks a Linux builder.
{
  system ? "aarch64-linux",
  nixpkgs ? <nixpkgs>,
}:
let
  pkgs = import nixpkgs { inherit system; };
  inherit (pkgs) lib busybox;
  bash = "${pkgs.bash}/bin/bash";

  oxnix = pkgs.rustPlatform.buildRustPackage {
    pname = "oxnix";
    version = "0.1.0";
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [ ../Cargo.toml ../Cargo.lock ../crates ];
    };
    cargoLock.lockFile = ../Cargo.lock;
    # nixpkgs may ship a rustc older than the workspace's rust-version;
    # the code does not depend on the difference.
    cargoBuildFlags = [ "-p" "oxnix" "--ignore-rust-version" ];
    doCheck = false;
  };
in
pkgs.runCommand "oxnix-sandbox-check-${system}" { tests = ../tests; } ''
  set -eu
  ox() {
    ${oxnix}/bin/oxnix --store /tmp/s build --no-link \
      --option sandbox true --option sandbox-fallback false \
      --option sandbox-paths "/nix/store /bin=${busybox}/bin" "$@"
  }
  probe() {
    ox $tests/sandbox.nix --argstr bash ${bash} --argstr sleep ${busybox}/bin/sleep "$@"
  }
  expect() {
    grep -qx "$1" "$2" || { echo "expected '$1' in $2:"; cat "$2"; exit 1; }
  }

  echo "running as uid $(id -u)"
  ox $tests/build.nix -j 4 >/dev/null

  # The store lives outside the build directory, which is /build here too.
  echo outside > /tmp/secret
  port=8123
  (while :; do echo "hello from the network" | ${busybox}/bin/nc -l -p $port || :; done) &
  server=$!
  sleep 1

  report=$(probe -A probe --argstr secret /tmp/secret --argstr port $port)
  cat $report
  expect 'read: denied' $report
  expect 'network: denied' $report
  expect 'hostname: localhost' $report
  expect 'uid: 1000' $report
  expect 'build-top: /build' $report

  fetched=$(probe -A fetch --argstr secret / --argstr port $port)
  expect 'hello from the network' $fetched
  kill $server

  if probe -A nochroot --argstr secret / --argstr port 1 2>err; then
    echo "__noChroot built with sandbox = true"; exit 1
  fi
  grep -q "__noChroot" err

  start=$(date +%s)
  if probe -A slow --argstr secret / --argstr port 1 --timeout 2 2>err; then
    echo "slow build did not time out"; exit 1
  fi
  grep -q "timed out after 2 seconds" err
  [ $(( $(date +%s) - start )) -lt 30 ]

  per() {
    local out
    out=$(probe -A personality --argstr secret / --argstr port 1 --argstr targetSystem "$1") && cat "$out"
  }
  p=$(per ${system})
  echo "personality of ${system} builds: $p"
  [ $(( 0x$p & 0x40000 )) -ne 0 ]
  ${lib.optionalString (system == "x86_64-linux") ''
    # Emulated x86_64 (qemu-user, Rosetta) refuses the 32-bit personality.
    if p=$(per i686-linux 2>err); then
      echo "personality of i686-linux builds: $p"
      [ $(( 0x$p & 0x8 )) -ne 0 ]
    elif grep -q "setting the 32-bit personality: errno 22" err; then
      echo "skipping i686-linux: this kernel or emulator refuses the 32-bit personality"
    else
      cat err; exit 1
    fi
  ''}

  echo ok > $out
''
