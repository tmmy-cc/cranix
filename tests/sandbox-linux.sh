#!/usr/bin/env bash
# Runs tests/sandbox-linux.nix for each given Linux system (default: both
# aarch64-linux and x86_64-linux), on this machine or a configured remote
# builder. Systems nothing here can build are skipped.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)

if ! command -v nix >/dev/null; then
  echo "skipping: nix is not installed"
  exit 0
fi

# Systems this machine builds itself, plus those of its remote builders.
config=$(nix config show 2>/dev/null || true)
setting() { sed -n "s/^$1 = //p" <<<"$config"; }
available=" $(setting system) $(setting extra-platforms) "
builders=$(setting builders)
case "$builders" in
  @*) builders=$(cat "${builders#@}" 2>/dev/null || true) ;;
esac
while read -r _ systems _; do
  available+=" ${systems//,/ } "
done < <(tr ';' '\n' <<<"$builders" | grep -v '^\s*\(#\|$\)' || true)

systems=("$@")
[ ${#systems[@]} -gt 0 ] || systems=(aarch64-linux x86_64-linux)

for system in "${systems[@]}"; do
  if [[ "$available" != *" $system "* ]]; then
    echo "skipping $system: no builder for it"
    continue
  fi
  echo "checking $system"
  nix-build "$here/sandbox-linux.nix" --argstr system "$system" --no-out-link
done
