#!/bin/sh
# Builds a chain of derivations with `cranix build --upload-to` and reads
# the filled cache with real Nix.
#
#   tests/upload-while-building.sh  (from the repository root, Nix on PATH)
set -eu

cargo build --release --quiet --bin cranix
cranix=$PWD/target/release/cranix
tmp=$(cd "$(mktemp -d)" && pwd -P)
trap 'chmod -R u+w "$tmp"; rm -rf "$tmp"' EXIT
export XDG_DATA_HOME=$tmp/data XDG_CONFIG_HOME=$tmp/config
nixx() { nix --extra-experimental-features nix-command "$@"; }

cat > "$tmp/chain.nix" <<'NIX'
let
  sh = name: script: derivation { inherit name; system = builtins.currentSystem; builder = "/bin/sh"; args = [ "-c" script ]; };
  a = sh "a" "echo a > $out";
  b = sh "b" "/bin/sleep 1; echo ${a} > $out";
in sh "c" "/bin/sleep 1; echo ${b} > $out"
NIX

"$cranix" key generate-secret --key-name test-1 > "$tmp/sk"
pk=$("$cranix" key convert-secret-to-public < "$tmp/sk")
out=$("$cranix" --store "$tmp/s" --option substituters "" --secret-key-files "$tmp/sk" \
    build --no-link --upload-to "file://$tmp/cache" "$tmp/chain.nix")

store="file://$tmp/cache?store=$tmp/s/store"
[ "$(nixx path-info --store "$store" -r "$out" | wc -l | tr -d ' ')" = 3 ]
nixx store verify --store "$store" --trusted-public-keys "$pk" --sigs-needed 1 -r "$out"
echo "upload while building: ok"
