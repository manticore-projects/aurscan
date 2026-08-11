#!/usr/bin/env bash
#
# Sync packaging/*/PKGBUILD to an upstream release tag.
#
#   ./packaging/sync-release.sh 0.7.1
#   ./packaging/sync-release.sh          # newest published release
#
# Binary checksums are lifted from the release's GPG-signed SHA256SUMS manifest
# rather than recomputed locally, so the values committed here are the signed
# ones by construction. Run this once at release time and commit the result:
# the version users install is then always visible in a reviewable diff, never
# resolved silently on their machine at build time.

set -euo pipefail

_repo='manticore-projects/aurscan'
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_ver="${1-}"
if [[ -z $_ver ]]; then
  _ver="$(curl -fsSL "https://api.github.com/repos/${_repo}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')" || true
  if [[ -z $_ver ]]; then
    echo "could not read the latest release tag (API unreachable or rate-limited)." >&2
    echo "pass the version explicitly, e.g.:  $0 0.7.1" >&2
    exit 1
  fi
fi
_ver="${_ver#v}"
[[ $_ver =~ ^[0-9]+(\.[0-9]+)*$ ]] || { echo "bad version: $_ver" >&2; exit 1; }

_rel="https://github.com/${_repo}/releases/download/v${_ver}"
_raw="https://raw.githubusercontent.com/${_repo}/v${_ver}"

_tmp="$(mktemp -d)"
trap 'rm -rf "$_tmp"' EXIT

echo "==> fetching v${_ver}"
curl -fsSL "$_rel/SHA256SUMS" -o "$_tmp/SHA256SUMS"
curl -fsSL "$_raw/LICENSE"    -o "$_tmp/LICENSE"
curl -fsSL "$_raw/README.md"  -o "$_tmp/README.md"
curl -fsSL "https://github.com/${_repo}/archive/refs/tags/v${_ver}.tar.gz" \
  -o "$_tmp/src.tar.gz"

_hash() { sha256sum "$1" | cut -d' ' -f1; }
_signed() { awk -v a="$1" '$2 == a { print $1 }' "$_tmp/SHA256SUMS"; }

_amd64="$(_signed aurscan-linux-amd64)"
_arm64="$(_signed aurscan-linux-arm64)"
if [[ -z $_amd64 || -z $_arm64 ]]; then
  echo "signed manifest is missing a linux asset" >&2
  exit 1
fi

_manifest="$(_hash "$_tmp/SHA256SUMS")"
_license="$(_hash "$_tmp/LICENSE")"
_readme="$(_hash "$_tmp/README.md")"
_tarball="$(_hash "$_tmp/src.tar.gz")"

# Replace the 64-hex literal on whichever line carries the matching trailing
# comment, so the arrays stay human-readable and reviewable.
_retag() { # _retag <file> <comment-anchor> <new-hash>
  sed -i -E "s|'[0-9a-f]{64}'(.*# $2\$)|'$3'\1|" "$1"
}

_bin="$_here/aurscan-bin/PKGBUILD"
_src="$_here/aurscan/PKGBUILD"

for _f in "$_bin" "$_src"; do
  sed -i -E "s|^pkgver=.*|pkgver=$_ver|; s|^pkgrel=.*|pkgrel=1|" "$_f"
done

_retag "$_bin" 'SHA256SUMS' "$_manifest"
_retag "$_bin" 'LICENSE'    "$_license"
_retag "$_bin" 'README.md'  "$_readme"
sed -i -E "s|^sha256sums_x86_64=.*|sha256sums_x86_64=('$_amd64')|" "$_bin"
sed -i -E "s|^sha256sums_aarch64=.*|sha256sums_aarch64=('$_arm64')|" "$_bin"

sed -i -E "s|^sha256sums=.*|sha256sums=('$_tarball')|" "$_src"

# Fail rather than emit a PKGBUILD with a stale hash in it.
for _f in "$_bin" "$_src"; do
  bash -n "$_f"
  grep -q "^pkgver=$_ver\$" "$_f" || { echo "pkgver not applied in $_f" >&2; exit 1; }
done
grep -q "'$_amd64'" "$_bin" && grep -q "'$_arm64'" "$_bin" \
  || { echo "arch checksums not applied" >&2; exit 1; }
grep -q "'$_tarball'" "$_src" \
  || { echo "tarball checksum not applied" >&2; exit 1; }

echo "==> synced to v${_ver}"
printf '    x86_64   %s\n    aarch64  %s\n    tarball  %s\n' \
  "$_amd64" "$_arm64" "$_tarball"
