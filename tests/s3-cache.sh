#!/bin/sh
# Copies a closure to an S3 cache in a local MinIO server with `cranix
# copy --to`, reads it back with `cranix copy --from` and with real Nix,
# and archives a release's sources there. Only the example keys of the
# AWS documentation are used.
#
#   tests/s3-cache.sh              (from the repository root, Nix on PATH)
set -eu

cargo build --release --quiet --bin cranix
cranix=$PWD/target/release/cranix
tmp=$(mktemp -d)
pids=
trap 'kill $pids 2>/dev/null || true; chmod -R u+w "$tmp"; rm -rf "$tmp"' EXIT
export XDG_DATA_HOME=$tmp/data XDG_CONFIG_HOME=$tmp/config HOME=$tmp/home
nixx() { nix --extra-experimental-features nix-command "$@"; }

set -- $(nix --extra-experimental-features 'nix-command flakes' build --no-link --print-out-paths nixpkgs#minio nixpkgs#minio-client)
minio=$1/bin/minio mc=$2/bin/mc

export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_EC2_METADATA_DISABLED=true
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
MINIO_ROOT_USER=$AWS_ACCESS_KEY_ID MINIO_ROOT_PASSWORD=$AWS_SECRET_ACCESS_KEY \
    "$minio" server --quiet --address "127.0.0.1:$port" --console-address 127.0.0.1:0 "$tmp/minio" > "$tmp/minio.log" 2>&1 &
pids="$pids $!"
until curl -sf "http://127.0.0.1:$port/minio/health/live" > /dev/null; do sleep 0.2; done
"$mc" --config-dir "$tmp/mc" alias set local "http://127.0.0.1:$port" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" > /dev/null
"$mc" --config-dir "$tmp/mc" mb local/cache > /dev/null
url="s3://cache?endpoint=127.0.0.1:$port&scheme=http&region=us-east-1"

"$cranix" key generate-secret --key-name test-1 > "$tmp/sk"
pk=$("$cranix" key convert-secret-to-public < "$tmp/sk")
top=$("$cranix" eval --raw --expr 'builtins.toFile "top" "${builtins.toFile "leaf" "x"}"')
# 6 MiB of random data goes up in two parts.
head -c 6291456 /dev/urandom > "$tmp/big"
big=$("$cranix" store add "$tmp/big")

paths() { python3 -c 'import json,sys; d=json.load(sys.stdin); d=d.values() if isinstance(d,dict) else d; print(len(list(d)))'; }
"$cranix" copy --to "$url&secret-key=$tmp/sk" "$top"
"$cranix" copy --to "$url" "$top" 2>&1 | grep -q 'copied 0 paths'
"$cranix" copy --to "$url&secret-key=$tmp/sk&compression=none&multipart-threshold=1&buffer-size=5242880" "$big"
[ "$("$cranix" --store "$url" store path-info -r --json "$top" | paths)" = 2 ]
# Messages never show the secret.
if "$cranix" copy --to "$url" "$top" 2>&1 | grep -q EXAMPLEKEY; then exit 1; fi

XDG_DATA_HOME=$tmp/fresh "$cranix" --option trusted-public-keys "$pk" copy --from "$url" "$top" "$big"
[ -f "$tmp/fresh/cranix$top" ]
cmp "$tmp/big" "$tmp/fresh/cranix$big"

# Real Nix reads the cache.
[ "$(nixx path-info --store "$url" -r --json "$top" | paths)" = 2 ]
nixx store verify --store "$url" --trusted-public-keys "$pk" -r "$top" "$big"
nixx copy --from "$url" --to "file://$tmp/nix-cache" --trusted-public-keys "$pk" "$top" "$big"
[ "$(nixx path-info --store "file://$tmp/nix-cache" -r --json "$top" "$big" | paths)" = 3 ]

# A release's sources go to the bucket with source-archive.
cat > "$tmp/release.nix" <<'NIX'
derivation {
  name = "release-1.0"; system = builtins.currentSystem; builder = "/bin/sh";
  src = builtins.toFile "release-src" "source";
  args = [ "-c" "/bin/cat $src > $out" ];
}
NIX
src=$("$cranix" eval --raw --expr 'builtins.toFile "release-src" "source"')
"$cranix" source-archive "$tmp/release.nix" --drvs --to "$url" 2> "$tmp/archive.log"
grep -q 'archived 0 fetched and 1 local sources and 1 derivations' "$tmp/archive.log"
XDG_DATA_HOME=$tmp/src "$cranix" copy --from "$url" "$src"
[ -f "$tmp/src/cranix$src" ]

# Wrong credentials are refused, and the secret is not shown.
if AWS_SECRET_ACCESS_KEY=wrong-secret-EXAMPLEKEY "$cranix" copy --to "$url" "$big" > "$tmp/wrong.log" 2>&1; then exit 1; fi
if grep -q EXAMPLEKEY "$tmp/wrong.log"; then exit 1; fi
echo "s3 caches: ok"
