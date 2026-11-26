#!/bin/sh
# Uploads a closure to an HTTP binary cache with `cranix copy --to` and
# reads it back with cranix and with real Nix.
#
#   tests/http-cache.sh            (from the repository root, Nix on PATH)
set -eu

cargo build --release --quiet --bin cranix --example cache-server
cranix=$PWD/target/release/cranix
tmp=$(mktemp -d)
trap 'kill $server 2>/dev/null || true; chmod -R u+w "$tmp"; rm -rf "$tmp"' EXIT
export XDG_DATA_HOME=$tmp/data XDG_CONFIG_HOME=$tmp/config
nixx() { nix --extra-experimental-features nix-command "$@"; }

target/release/examples/cache-server "$tmp/served" > "$tmp/url" &
server=$!
while [ ! -s "$tmp/url" ]; do sleep 0.1; done
url=$(cat "$tmp/url")

"$cranix" key generate-secret --key-name test-1 > "$tmp/sk"
pk=$("$cranix" key convert-secret-to-public < "$tmp/sk")

# A closure of three paths: a tree with an executable and a symlink, a
# leaf file and a file that refers to both.
mkdir -p "$tmp/tree/sub"
printf 'data\n' > "$tmp/tree/sub/file"
printf '#!/bin/sh\n' > "$tmp/tree/run" && chmod +x "$tmp/tree/run"
ln -s sub/file "$tmp/tree/link"
top=$("$cranix" eval --raw --expr "builtins.toFile \"top\" \"\${$tmp/tree} \${builtins.toFile \"leaf\" \"x\"}\"")

"$cranix" copy --to "$url?secret-key=$tmp/sk" "$top"
"$cranix" copy --to "$url?secret-key=$tmp/sk" "$top" 2>&1 | grep -q 'copied 0 paths'

paths() { python3 -c 'import json,sys; d=json.load(sys.stdin); d=d.values() if isinstance(d,dict) else d; print(len(list(d)))'; }
[ "$("$cranix" --store "$url" store path-info -r --json "$top" | paths)" = 3 ]
[ "$(nixx path-info --store "$url" -r --json "$top" | paths)" = 3 ]
nixx store verify --store "$url" --trusted-public-keys "$pk" -r "$top"
# These paths are content-addressed, so Nix would accept them unsigned;
# check that every narinfo carries the cranix signature as well.
signed='import json,sys; d=json.load(sys.stdin); d=d.values() if isinstance(d,dict) else d; print(sum(any(s.startswith("test-1:") for s in i["signatures"]) for i in d))'
[ "$(nixx path-info --store "$url" -r --json "$top" | python3 -c "$signed")" = 3 ]

# Nix copies the closure on, checking the signatures.
nixx copy --from "$url" --to "file://$tmp/nix-cache" --trusted-public-keys "$pk" "$top"
[ "$(nixx path-info --store "file://$tmp/nix-cache" -r --json "$top" | paths)" = 3 ]

# cranix substitutes it into a fresh store.
XDG_DATA_HOME=$tmp/data2 "$cranix" --option trusted-public-keys "$pk" copy --from "$url" "$top"
[ "$(cat "$tmp/data2/cranix$(sed 's/ .*//' "$tmp/data2/cranix$top")/sub/file")" = data ]
[ -x "$tmp/data2/cranix$(sed 's/ .*//' "$tmp/data2/cranix$top")/run" ]

echo "http-cache: ok"
