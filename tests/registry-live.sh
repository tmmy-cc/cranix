#!/bin/sh
# Opt-in test against real registries. Each part runs when its variables
# are set:
#
#   CRANIX_TEST_GITLAB=gitlab://HOST/GROUP/PROJECT
#   CRANIX_TEST_GITLAB_TOKEN_FILE=FILE     token with api or package scope
#   CRANIX_TEST_GITHUB=github://OWNER/REPO
#   CRANIX_TEST_GITHUB_TOKEN_FILE=FILE     token with write:packages
#
#   tests/registry-live.sh          (from the repository root, Nix on PATH)
#
# It uploads one new path per run into the package group `cranix-test`.
set -eu

cargo build --release --quiet --bin cranix
cranix=$PWD/target/release/cranix
tmp=$(mktemp -d)
pids=
trap 'kill $pids 2>/dev/null || true; chmod -R u+w "$tmp"; rm -rf "$tmp"' EXIT
export XDG_DATA_HOME=$tmp/data XDG_CONFIG_HOME=$tmp/config
nixx() { nix --extra-experimental-features nix-command "$@"; }

"$cranix" key generate-secret --key-name live-test > "$tmp/sk"
pk=$("$cranix" key convert-secret-to-public < "$tmp/sk")
top=$("$cranix" eval --raw --expr "builtins.toFile \"cranix-live-test\" \"$(date +%s)-$$\"")

run() {
    url="$1?group=cranix-test&token-file=$2"
    "$cranix" copy --to "$url&secret-key=$tmp/sk" "$top"
    XDG_DATA_HOME=$tmp/fresh-$3 "$cranix" --option trusted-public-keys "$pk" copy --from "$url" "$top"
    "$cranix" cache serve --listen 127.0.0.1:0 "$url" > "$tmp/serve-$3" &
    pids="$pids $!"
    while [ ! -s "$tmp/serve-$3" ]; do sleep 0.1; done
    nixx store verify --store "$(cat "$tmp/serve-$3")" --trusted-public-keys "$pk" "$top"
    echo "$3: ok"
}

ran=0
if [ -n "${CRANIX_TEST_GITLAB:-}" ]; then run "$CRANIX_TEST_GITLAB" "$CRANIX_TEST_GITLAB_TOKEN_FILE" gitlab; ran=1; fi
if [ -n "${CRANIX_TEST_GITHUB:-}" ]; then run "$CRANIX_TEST_GITHUB" "$CRANIX_TEST_GITHUB_TOKEN_FILE" github; ran=1; fi
[ $ran = 1 ] || echo "set CRANIX_TEST_GITLAB or CRANIX_TEST_GITHUB to run this test"
