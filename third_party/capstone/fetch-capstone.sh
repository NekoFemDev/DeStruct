#!/bin/sh
# Fetch + unpack a pinned Capstone release for DeStruct.
# Usage: fetch-capstone.sh [version] [--force]
#   version: explicit tag like 6.0.0-Alpha11, or "latest" (default).
# "latest" is resolved via `git ls-remote --tags` (preferred, no API
# rate limits), falling back to the GitHub releases API.
# NOTE: the archive URL requires a .tar.gz (or .zip) suffix - the bare
# https://github.com/capstone-engine/capstone/archive/refs/tags/$version
# without a suffix returns 404.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="${1:-latest}"
FORCE=0
case "${2:-}" in --force|-f) FORCE=1;; esac
if [ "$VERSION" = "--force" ] || [ "$VERSION" = "-f" ]; then
  VERSION="latest"; FORCE=1
fi

latest_tag() {
  # Preferred: no auth, no rate limit.
  if command -v git >/dev/null 2>&1; then
    tag="$(git ls-remote --tags https://github.com/capstone-engine/capstone.git 2>/dev/null \
      | awk '{print $2}' | sed 's#refs/tags/##' | grep -v '\^{}$' \
      | grep -E '^[0-9]+\.[0-9]+\.[0-9]+(-Alpha[0-9]+)?$' | sort -V | tail -n 1 || true)"
    if [ -n "$tag" ]; then echo "$tag"; return 0; fi
  fi
  # Fallback: GitHub API (needs curl + python3 for JSON parsing).
  if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    curl -fsSL --max-time 30 "https://api.github.com/repos/capstone-engine/capstone/tags?per_page=100" \
      | python3 -c 'import json,sys,re; tags=[t["name"] for t in json.load(sys.stdin) if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+(-Alpha[0-9]+)?$", t["name"])]; print(tags[0] if tags else "")'
    return 0
  fi
  return 1
}

if [ "$VERSION" = "latest" ]; then
  VERSION="$(latest_tag)"
  if [ -z "$VERSION" ]; then
    echo "fetch-capstone.sh: could not resolve latest tag" >&2
    exit 1
  fi
  echo "fetch-capstone.sh: latest tag is $VERSION" >&2
fi

SRC_DIR="$REPO_ROOT/capstone-$VERSION"
LINK="$REPO_ROOT/capstone-src"
URL="https://github.com/capstone-engine/capstone/archive/refs/tags/$VERSION.tar.gz"

if [ -d "$SRC_DIR" ] && [ "$FORCE" -eq 0 ]; then
  echo "fetch-capstone.sh: $SRC_DIR already present, reusing" >&2
else
  TMPD="${TMPDIR:-/tmp}"
  TMPF="$TMPD/capstone-$VERSION.tar.gz.$$"
  echo "fetch-capstone.sh: downloading $URL ..." >&2
  curl -fL --max-time 300 -o "$TMPF" "$URL"
  rm -rf "$SRC_DIR"
  mkdir -p "$SRC_DIR"
  tar xzf "$TMPF" -C "$REPO_ROOT"
  rm -f "$TMPF"
  # tarball extracts to capstone-$VERSION/ already; guard against drift.
  if [ ! -f "$SRC_DIR/cs.c" ]; then
    echo "fetch-capstone.sh: unexpected archive layout in $SRC_DIR" >&2
    exit 1
  fi
fi

# Stable path for the Go cgo flags and the sub-make: everything else
# points at capstone-src, so version bumps never touch source files.
ln -sfn "capstone-$VERSION" "$LINK"
echo "fetch-capstone.sh: $LINK -> capstone-$VERSION" >&2

# The checked-in default; informational only (make passes version explicitly).
echo "$VERSION"
