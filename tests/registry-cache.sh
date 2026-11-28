#!/bin/sh
# Copies a closure to a GitLab and a GitHub registry cache (a local fake
# registry) with `cranix copy --to`, reads it back with `cranix copy
# --from` and with real Nix through `cranix cache serve`.
#
#   tests/registry-cache.sh        (from the repository root, Nix on PATH)
set -eu

cargo build --release --quiet --bin cranix --example registry-server
cranix=$PWD/target/release/cranix
tmp=$(mktemp -d)
pids=
trap 'kill $pids 2>/dev/null || true; chmod -R u+w "$tmp"; rm -rf "$tmp"' EXIT
export XDG_DATA_HOME=$tmp/data XDG_CONFIG_HOME=$tmp/config
nixx() { nix --extra-experimental-features nix-command "$@"; }
wait_for() { while [ ! -s "$1" ]; do sleep 0.1; done; }

printf 'glpat-TESTREAD0123456789\n' > "$tmp/read"
printf 'glpat-TESTTOKEN0123456789\n' > "$tmp/write"
target/release/examples/registry-server "$(cat "$tmp/read")" "$(cat "$tmp/write")" > "$tmp/addr" &
pids="$pids $!"
wait_for "$tmp/addr"
addr=$(cat "$tmp/addr")
tokens="read-token-file=$tmp/read&write-token-file=$tmp/write"

"$cranix" key generate-secret --key-name test-1 > "$tmp/sk"
pk=$("$cranix" key convert-secret-to-public < "$tmp/sk")
top=$("$cranix" eval --raw --expr 'builtins.toFile "top" "${builtins.toFile "leaf" "x"}"')

# A release whose sources go to the registry with source-archive.
cat > "$tmp/release.nix" <<'NIX'
derivation {
  name = "release-1.0"; system = builtins.currentSystem; builder = "/bin/sh";
  src = builtins.toFile "release-src" "source";
  args = [ "-c" "/bin/cat $src > $out" ];
}
NIX
src=$("$cranix" eval --raw --expr 'builtins.toFile "release-src" "source"')

paths() { python3 -c 'import json,sys; d=json.load(sys.stdin); d=d.values() if isinstance(d,dict) else d; print(len(list(d)))'; }
n=0
for url in "gitlab://$addr/group/project?scheme=http&$tokens" \
           "github://owner/repo?registry=http://$addr&layout=name&$tokens"; do
    n=$((n + 1))
    "$cranix" copy --to "$url&secret-key=$tmp/sk" "$top"
    "$cranix" copy --to "$url" "$top" 2>&1 | grep -q 'copied 0 paths'
    [ "$("$cranix" --store "$url" store path-info -r --json "$top" | paths)" = 2 ]
    # Messages hide the tokens.
    if "$cranix" copy --to "$url" "$top" 2>&1 | grep -q TEST; then exit 1; fi

    XDG_DATA_HOME=$tmp/fresh$n "$cranix" --option trusted-public-keys "$pk" copy --from "$url" "$top"
    [ -f "$tmp/fresh$n/cranix$top" ]

    "$cranix" cache serve --listen 127.0.0.1:0 "$url" > "$tmp/serve$n" 2> "$tmp/serve$n.log" &
    pids="$pids $!"
    wait_for "$tmp/serve$n"
    served=$(cat "$tmp/serve$n")
    [ "$(nixx path-info --store "$served" -r --json "$top" | paths)" = 2 ]
    nixx store verify --store "$served" --trusted-public-keys "$pk" -r "$top"
    nixx copy --from "$served" --to "file://$tmp/nix-cache$n" --trusted-public-keys "$pk" "$top"
    [ "$(nixx path-info --store "file://$tmp/nix-cache$n" -r --json "$top" | paths)" = 2 ]
    if grep -q TEST "$tmp/serve$n.log"; then exit 1; fi

    "$cranix" source-archive "$tmp/release.nix" --drvs --to "$url" 2> "$tmp/archive$n.log"
    grep -q 'archived 0 fetched and 1 local sources and 1 derivations' "$tmp/archive$n.log"
    if grep -q TEST "$tmp/archive$n.log"; then exit 1; fi
    XDG_DATA_HOME=$tmp/src$n "$cranix" copy --from "$url" "$src"
    [ -f "$tmp/src$n/cranix$src" ]
done
echo "registry caches: ok"
