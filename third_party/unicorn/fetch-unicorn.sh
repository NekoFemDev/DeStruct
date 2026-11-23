#!/bin/sh
# Fetch + unpack a pinned Unicorn Engine release for DeStruct.
# Usage: fetch-unicorn.sh [version]
#   version: explicit tag like 2.1.4, or "latest".
#
# Unicorn is GPLv2; it is only used by the optional -tags unicorn build.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="${1:-2.1.4}"

if [ "$VERSION" = "latest" ]; then
  VERSION="$(git ls-remote --tags https://github.com/unicorn-engine/unicorn.git 2>/dev/null \
    | awk '{print $2}' | sed 's#refs/tags/##' | grep -v '\^{}$' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1 || true)"
  if [ -z "$VERSION" ]; then
    echo "fetch-unicorn.sh: could not resolve latest tag" >&2
    exit 1
  fi
fi

SRC="$REPO_ROOT/unicorn-$VERSION"
LINK="$REPO_ROOT/unicorn-src"

if [ -f "$SRC/CMakeLists.txt" ] && [ "$(readlink "$LINK" 2>/dev/null || true)" = "unicorn-$VERSION" ]; then
  echo "Unicorn $VERSION already present"
  exit 0
fi

ARCHIVE="$REPO_ROOT/unicorn-$VERSION.tar.gz"
echo "Downloading Unicorn $VERSION..."
curl -fsSL --max-time 300 -o "$ARCHIVE" \
  "https://github.com/unicorn-engine/unicorn/archive/refs/tags/$VERSION.tar.gz"
tar -xzf "$ARCHIVE" -C "$REPO_ROOT"
rm -f "$ARCHIVE"
ln -sfn "unicorn-$VERSION" "$LINK"
echo "Unicorn $VERSION ready at $SRC"
