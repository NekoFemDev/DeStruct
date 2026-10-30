#!/data/data/com.termux/files/usr/bin/bash
#
# DeStruct installer for Termux (Android aarch64 / arm / x86_64).
#
#   # from a fresh shell
#   curl -fsSL https://raw.githubusercontent.com/NekoFemDev/DeStruct/main/install-termux.sh | bash
#
#   # or from a clone
#   ./install-termux.sh --update
#
# NOTE on the shebang: Termux has no /usr/bin/env, and /bin/sh is Android's
# mksh rather than bash, so neither is a usable interpreter. $PREFIX/bin/bash
# is the only one guaranteed present and correct, hence the direct path.
# The portable invocation is `bash install-termux.sh ...`.
#
# What it does:
#   1. installs the Termux build deps (golang, clang, binutils, make, git, curl)
#   2. clones / refreshes the repo
#   3. fetches the pinned Capstone release and builds libcapstone.a
#   4. `go build`s the cgo binary for the host arch
#   5. installs it to $PREFIX/bin/destruct and smoke-tests it
#
set -Eeuo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
REPO_URL="${DESTRUCT_REPO_URL:-https://github.com/NekoFemDev/DeStruct.git}"
REPO_BRANCH="${DESTRUCT_BRANCH:-main}"
MODULE_PATH="github.com/destruct/destruct"   # must match go.mod

SRC_DIR="${DESTRUCT_DIR:-${HOME:-/data/data/com.termux/files/home}/DeStruct}"
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
BIN_PATH="$PREFIX/bin/destruct"

# Overridable build knobs. Capstone's AArch64Disassembler.c is a ~2 MB
# translation unit and -O3 on it peaks around half a gig per process, so an
# uncapped -j$(nproc) can OOM a mid-range phone mid-build. Default to 4; the
# user can raise it with --jobs on a device with headroom.
NPROC="${DESTRUCT_NPROC:-$(nproc 2>/dev/null || echo 4)}"
[ "$NPROC" -gt 4 ] && [ -z "${DESTRUCT_NPROC:-}" ] && NPROC=4
LDFLAGS="${DESTRUCT_LDFLAGS:--s -w}"
GOOS_OVERRIDE="${DESTRUCT_GOOS:-}"          # empty = host default (android)
GOARCH_OVERRIDE="${DESTRUCT_GOARCH:-}"      # empty = host default

# Did the caller pin the source dir? If so, in-place detection must not
# override it (the whole point of --dir is "not the checkout I'm standing in").
SRC_DIR_EXPLICIT=0
[ -n "${DESTRUCT_DIR:-}" ] && SRC_DIR_EXPLICIT=1

# Flags.
DO_DEPS=1
DO_UPDATE=0
DO_CLEAN=0
DO_FETCH=1
DO_UNINSTALL=0
FORCE=0
VERBOSE=0

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
    C_BLUE=$'\033[34m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'
else
    C_RESET=''; C_DIM=''; C_BOLD=''; C_BLUE=''; C_GREEN=''; C_YELLOW=''; C_RED=''
fi

STEP=0
step() { STEP=$((STEP + 1)); printf '\n%s[%d/%d]%s %s%s%s\n' "$C_BLUE" "$STEP" "$TOTAL_STEPS" "$C_RESET" "$C_BOLD" "$*" "$C_RESET"; }
info() { printf '      %s\n' "$*"; }
ok()   { printf '      %s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '      %s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '\n%serror:%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }
run()  { printf '      %s$ %s%s\n' "$C_DIM" "$*" "$C_RESET"; "$@"; }

# Mobile links drop long-lived HTTPS streams routinely ("RPC failed; curl 92
# HTTP/2 stream N reset by server" from git clone/fetch). HTTP/1.1 plus a few
# backoff retries turns a hard failure into a slow success.
retry() {  # retry <attempts> <label> <cmd> [args...]
    local n="$1" label="$2"; shift 2
    local i
    for i in $(seq 1 "$n"); do
        if "$@"; then return 0; fi
        [ "$i" -lt "$n" ] || break
        warn "$label failed (attempt $i/$n) - retrying in $((i * 5))s"
        sleep $((i * 5))
    done
    return 1
}

git_quiet() { git -c http.version=HTTP/1.1 "$@"; }

# Long compiles (Capstone, go build) are noisy - the bundled Capstone source
# alone emits hundreds of -Wmissing-prototypes warnings. Capture them, show a
# one-line progress note, and dump the tail only when something actually
# breaks. -V streams everything instead.
run_logged() {  # run_logged <logfile> <display-label> <cmd> [args...]
    local log="$1" label="$2"; shift 2
    printf '      %s$ %s%s\n' "$C_DIM" "$label" "$C_RESET"
    if [ "$VERBOSE" -eq 1 ]; then
        "$@" && return 0 || return 1
    fi
    if "$@" >"$log" 2>&1; then
        return 0
    fi
    printf '\n%s%s failed. Last 40 lines of output:%s\n' "$C_RED" "$label" "$C_RESET" >&2
    tail -n 40 "$log" | sed 's/^/      /' >&2
    return 1
}

usage() {
    cat <<'EOF'
DeStruct installer for Termux

Usage:
  install-termux.sh [options]

Options:
  -u, --update         fast-forward an existing clone (no hard reset; local
                       commits and uncommitted work are preserved)
  -c, --clean          wipe the Capstone build tree and rebuild from scratch
  -d, --dir <path>     source/build directory (default: $HOME/DeStruct)
  -b, --branch <name>  git branch to clone/update (default: main)
      --capstone <ver> override the Capstone tag (default: read from Makefile)
      --no-fetch       do not download Capstone; reuse capstone-src as-is
      --no-deps        do not run `pkg install` (assume deps are present)
      --uninstall      remove $PREFIX/bin/destruct and exit
      --force          proceed even if this does not look like Termux
  -V, --verbose        stream compiler output instead of capturing it
  -j, --jobs <n>       parallel compile jobs (default: min(nproc, 4))
  -h, --help           this text

Environment equivalents: DESTRUCT_DIR, DESTRUCT_REPO_URL, DESTRUCT_BRANCH,
DESTRUCT_NPROC, DESTRUCT_LDFLAGS, DESTRUCT_GOOS, DESTRUCT_GOARCH.

Run it from inside a DeStruct checkout and the current working tree is used
as-is (no clone, your uncommitted changes included).
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -u|--update)    DO_UPDATE=1 ;;
        -c|--clean)     DO_CLEAN=1 ;;
        -d|--dir)       [ $# -ge 2 ] || die "--dir needs a value"; SRC_DIR="$2"; SRC_DIR_EXPLICIT=1; shift ;;
        -b|--branch)    [ $# -ge 2 ] || die "--branch needs a value"; REPO_BRANCH="$2"; shift ;;
        --capstone)     [ $# -ge 2 ] || die "--capstone needs a value"; CAPSTONE_VERSION_OVERRIDE="$2"; shift ;;
        --no-fetch)     DO_FETCH=0 ;;
        --no-deps)      DO_DEPS=0 ;;
        --uninstall)    DO_UNINSTALL=1 ;;
        --force)        FORCE=1 ;;
        -V|--verbose)   VERBOSE=1 ;;
        -j|--jobs)      [ $# -ge 2 ] || die "--jobs needs a value"; NPROC="$2"; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

case "$NPROC" in ''|*[!0-9]*) die "--jobs must be a number, got '$NPROC'" ;; esac

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
TOTAL_STEPS=5
[ "$DO_UNINSTALL" -eq 1 ] && TOTAL_STEPS=1

WORKDIR="${TMPDIR:-/data/data/com.termux/files/usr/tmp}/destruct-install.$$"
cleanup() { [ -n "${WORKDIR:-}" ] && rm -rf "$WORKDIR"; return 0; }
trap cleanup EXIT

# `termux-build`/proot-distro Android roots still work; only warn.
[ -d "$PREFIX" ] || die "no usable PREFIX at '$PREFIX' - this installer targets Termux."
case "$PREFIX" in
    */com.termux/files/usr) ;;
    *)
        if [ "$FORCE" -eq 1 ]; then
            warn "PREFIX=$PREFIX does not look like Termux; continuing anyway (--force)"
        else
            die "PREFIX=$PREFIX does not look like a Termux prefix.
    This installer targets Termux (expected */com.termux/files/usr).
    Re-run with --force if you really know what you are doing."
        fi
        ;;
esac

# --- uninstall path ---
if [ "$DO_UNINSTALL" -eq 1 ]; then
    step "Uninstalling DeStruct"
    if [ -e "$BIN_PATH" ]; then
        rm -f "$BIN_PATH"
        ok "removed $BIN_PATH"
    else
        info "nothing installed at $BIN_PATH"
    fi
    info "source tree left at $SRC_DIR (remove it manually if you want it gone)"
    printf '\n'
    exit 0
fi

# --- reuse the checkout we were launched from ---
is_destruct_repo() {
    [ -f "$1/go.mod" ] && grep -q "^module $MODULE_PATH\$" "$1/go.mod" 2>/dev/null
}

if [ "$SRC_DIR_EXPLICIT" -eq 0 ] && is_destruct_repo "$PWD"; then
    SRC_DIR="$PWD"
    info "using the checkout in $PWD"
fi

printf '%sDeStruct installer%s  %s(%s, %s cores)%s\n' \
    "$C_BOLD" "$C_RESET" "$C_DIM" "$(uname -m)" "$NPROC" "$C_RESET"

mkdir -p "$WORKDIR"

# ---------------------------------------------------------------------------
# Step 1 - dependencies
# ---------------------------------------------------------------------------
step "Checking build dependencies"

# Termux package -> binaries it provides.
pkg_for() {
    case "$1" in
        go) echo golang ;;
        clang|cc) echo clang ;;
        ar) echo binutils ;;
        make) echo make ;;
        git) echo git ;;
        curl) echo curl ;;
        tar) echo tar ;;
    esac
}

have() { command -v "$1" >/dev/null 2>&1; }

missing_pkgs=""
for tool in go clang ar make git curl tar; do
    have "$tool" && continue
    [ "$DO_DEPS" -eq 1 ] || die "$tool not found and --no-deps was passed (pkg install $(pkg_for "$tool"))"
    missing_pkgs="${missing_pkgs} $(pkg_for "$tool")"
done

if [ -n "${missing_pkgs// /}" ]; then
    info "installing:${missing_pkgs}"
    run pkg install -y $missing_pkgs
    ok "dependencies installed"
else
    ok "all dependencies present"
fi

# cgo sanity probe: catches a clang install whose linker/sysroot is broken,
# which otherwise surfaces as a wall of confusing errors during `go build`.
cat > "$WORKDIR/probe.c" <<'EOF'
#include <stdio.h>
int main(void) { printf("ok"); return 0; }
EOF
have clang && CC=clang || CC=cc
export CC
"$CC" "$WORKDIR/probe.c" -o "$WORKDIR/probe" || die "$CC cannot link a trivial program — try: pkg reinstall clang"
[ "$("$WORKDIR/probe")" = "ok" ] || die "cgo toolchain probe failed"
ok "cgo toolchain works ($("$CC" --version | head -n1))"

# ---------------------------------------------------------------------------
# Step 2 - Go version gate
# ---------------------------------------------------------------------------
step "Checking Go toolchain"

# GOTOOLCHAIN=auto is actively harmful on Termux: go.mod asking for a newer
# Go than the Termux package ships makes the go command download
# `golang.org/toolchain@...linux-arm64`, which is a Linux ELF and cannot run
# on Android. Pin to the local toolchain so the failure is a clear version
# message instead of an exec-format error.
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

go_ver_raw="$(go version)"                 # e.g. "go version go1.27.1 android/arm64"
go_ver="$(printf '%s\n' "$go_ver_raw" | awk '{print $3}' | sed 's/^go//')"
info "$go_ver_raw"
info "GOTOOLCHAIN=$GOTOOLCHAIN (Termux cannot use the auto-downloaded linux toolchain)"

require_go=""
if is_destruct_repo "$SRC_DIR"; then
    require_go="$(sed -n 's/^go[[:space:]]\{1,\}\([0-9][0-9.]*\).*/\1/p' "$SRC_DIR/go.mod" | head -n1)"
fi

ver_ge() {  # ver_ge <have> <min>
    [ -n "$2" ] || return 0
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

if [ -n "$require_go" ] && ! ver_ge "$go_ver" "$require_go"; then
    warn "go.mod needs Go >= $require_go, Termux has $go_ver"
    if [ "$DO_DEPS" -eq 1 ] && have pkg; then
        info "attempting: pkg upgrade golang"
        pkg upgrade -y golang || true
        go_ver="$(go version | awk '{print $3}' | sed 's/^go//')"
    fi
    if ! ver_ge "$go_ver" "$require_go"; then
        die "Go >= $require_go is required (found $go_ver).
    Termux ships Go in the 'golang' package and it lags upstream by a few
    weeks at release time. Options:
      * pkg upgrade golang          (retry once the package lands)
      * pkg install golang-nightly  (if your repo has it)
      * lower the 'go' directive in go.mod if the code still compiles"
    fi
fi
ok "Go $go_ver is new enough"

# ---------------------------------------------------------------------------
# Step 3 - source
# ---------------------------------------------------------------------------
step "Acquiring the source tree"

if is_destruct_repo "$SRC_DIR"; then
    ok "using existing checkout at $SRC_DIR"
    if [ "$DO_UPDATE" -eq 1 ] && [ -d "$SRC_DIR/.git" ]; then
        if [ -n "$(git -C "$SRC_DIR" status --porcelain 2>/dev/null)" ]; then
            warn "worktree has local modifications; the fast-forward will refuse if it conflicts"
        fi
        run git_quiet -C "$SRC_DIR" fetch --quiet origin "$REPO_BRANCH" \
            || die "could not fetch origin/$REPO_BRANCH"
        # --ff-only, never a reset: local commits and uncommitted edits survive.
        run git -C "$SRC_DIR" merge --ff-only "origin/$REPO_BRANCH"
        ok "updated to origin/$REPO_BRANCH"
    fi
elif [ -e "$SRC_DIR" ] && [ -n "$(ls -A "$SRC_DIR" 2>/dev/null)" ]; then
    die "$SRC_DIR exists and is not a DeStruct checkout.
    Move it aside, pick another path with --dir, or delete it."
else
    [ "$DO_DEPS" -eq 1 ] || have git || die "git is required to clone"
    mkdir -p "$(dirname "$SRC_DIR")"
    info "cloning $REPO_URL ($REPO_BRANCH)"
    retry 3 "git clone" \
        git_quiet clone --quiet --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$SRC_DIR" \
        || { rm -rf "$SRC_DIR"; die "clone failed after 3 attempts - check your connection, or download the tarball manually and point --dir at it"; }
    ok "cloned $REPO_BRANCH"
fi

is_destruct_repo "$SRC_DIR" || die "$SRC_DIR is not a DeStruct checkout (go.mod module mismatch)"

# Capstone pin stays in sync with the repo Makefile unless overridden.
if [ -z "${CAPSTONE_VERSION_OVERRIDE:-}" ]; then
    CAPSTONE_VERSION="$(sed -n 's/^CAPSTONE_VERSION[[:space:]]*[?:]\{0,1\}=[[:space:]]*//p' "$SRC_DIR/Makefile" | head -n1)"
fi
CAPSTONE_VERSION="${CAPSTONE_VERSION_OVERRIDE:-${CAPSTONE_VERSION:-}}"
[ -n "$CAPSTONE_VERSION" ] || die "could not determine the Capstone version from the Makefile"
info "Capstone $CAPSTONE_VERSION"

# ---------------------------------------------------------------------------
# Step 4 - Capstone static library
# ---------------------------------------------------------------------------
step "Building libcapstone.a"

CS_SRC="$SRC_DIR/capstone-$CAPSTONE_VERSION"
CS_LINK="$SRC_DIR/capstone-src"

# The Capstone download is done here rather than by delegating to the repo's
# third_party/capstone/fetch-capstone.sh: that helper only exists in recent
# revisions, and an older checkout would leave the install half-broken. Doing
# it inline keeps the installer working against any commit of the repo.
if [ "$DO_FETCH" -eq 1 ]; then
    if [ -f "$CS_SRC/cs.c" ]; then
        info "reusing $CS_SRC"
    else
        CS_URL="https://github.com/capstone-engine/capstone/archive/refs/tags/${CAPSTONE_VERSION}.tar.gz"
        CS_TARBALL="$WORKDIR/capstone-${CAPSTONE_VERSION}.tar.gz"
        info "downloading Capstone $CAPSTONE_VERSION (~9 MB)"
        # -sS keeps curl's progress meter off the install log; on a phone
        # link this download is the slowest step and should not scroll.
        # NOTE: the archive URL needs an explicit suffix - the bare
        # .../refs/tags/$version returns 404.
        retry 3 "capstone download" \
            curl -fsSL --retry 3 --max-time 600 -o "$CS_TARBALL" "$CS_URL" \
            || die "could not download $CS_URL"
        rm -rf "$CS_SRC"
        # The tarball unpacks into capstone-$CAPSTONE_VERSION/ at the repo root.
        run tar xzf "$CS_TARBALL" -C "$SRC_DIR"
        [ -f "$CS_SRC/cs.c" ] || die "unexpected archive layout: $CS_SRC/cs.c missing"
        ok "fetched Capstone $CAPSTONE_VERSION"
    fi
    # Stable path that the cgo flags (-I .../capstone-src/include) and the
    # sub-make both key off, so a version bump never touches source files.
    run ln -sfn "capstone-$CAPSTONE_VERSION" "$CS_LINK"
else
    info "--no-fetch: reusing $CS_LINK as-is"
fi
[ -f "$CS_LINK/cs.c" ] || die "Capstone source not found at $CS_LINK/cs.c"

have llvm-ar && AR=llvm-ar || AR=ar
export AR

if [ "$DO_CLEAN" -eq 1 ]; then
    run make -C "$SRC_DIR/third_party/capstone" clean
    ok "cleaned previous Capstone objects"
fi

# The sub-make receives CC/AR on the command line, so they win over the
# Makefile's `CC ?= gcc` / `AR ?= ar` defaults (which do not exist on stock
# Termux without the gcc/binutils packages).
info "compiling ARM + AArch64 sources with $NPROC jobs (this is the slow part)"
run_logged "$WORKDIR/capstone.log" \
    "make -C third_party/capstone -j$NPROC CC=$CC AR=$AR" \
    make -C "$SRC_DIR/third_party/capstone" \
        -j"$NPROC" \
        CAPSTONE_DIR="$CS_LINK" \
        CC="$CC" AR="$AR" \
    || die "Capstone build failed"

[ -f "$SRC_DIR/third_party/capstone/build/libcapstone.a" ] \
    || die "libcapstone.a was not produced"
ok "libcapstone.a ($(du -h "$SRC_DIR/third_party/capstone/build/libcapstone.a" | cut -f1), statically linked into the binary)"

# ---------------------------------------------------------------------------
# Step 5 - build + install
# ---------------------------------------------------------------------------
step "Building and installing destruct"

export CGO_ENABLED=1
BUILD_OUT="$SRC_DIR/destruct"

# Optional cross-build (e.g. DESTRUCT_GOARCH=arm64 on an x86_64 emulator).
[ -n "$GOOS_OVERRIDE" ] && export GOOS="$GOOS_OVERRIDE"
[ -n "$GOARCH_OVERRIDE" ] && export GOARCH="$GOARCH_OVERRIDE"

go_build() {  # invoked by run_logged; subshell keeps the cd local
    ( cd "$SRC_DIR" && go build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_OUT" ./cmd/destruct )
}

info "compiling Go + cgo bindings (target ${GOOS:-host}/${GOARCH:-host})"
run_logged "$WORKDIR/build.log" \
    "go build -trimpath -ldflags \"$LDFLAGS\" -o destruct ./cmd/destruct" \
    go_build \
    || die "go build failed"
ok "built $BUILD_OUT ($(du -h "$BUILD_OUT" | cut -f1))"

mkdir -p "$PREFIX/bin"
if have install; then
    run install -m 0755 "$BUILD_OUT" "$BIN_PATH"
else
    run cp -f "$BUILD_OUT" "$BIN_PATH"
    run chmod 0755 "$BIN_PATH"
fi
ok "installed $BIN_PATH"

# Smoke test against the installed copy, not the build tree.
if ! "$BIN_PATH" version; then
    die "the installed binary does not run on this device"
fi
ok "smoke test passed"

case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *) warn "$PREFIX/bin is not on your PATH — add: export PATH=\"\$PREFIX/bin:\$PATH\"" ;;
esac

printf '\n%s%sDeStruct installed.%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
info "binary   $BIN_PATH"
info "source   $SRC_DIR"
info "capstone $CAPSTONE_VERSION (statically linked — no runtime deps)"
printf '\n%sNext%s\n' "$C_BOLD" "$C_RESET"
info "destruct il2cpp libil2cpp.so global-metadata.dat -o out/   # Unity"
info "destruct elf    libnative.so -o out/ --decompile           # ARM64 ELF"
info "destruct hex    libil2cpp.so -c 'info'                    # hex REPL"
info "rebuild after editing: cd $SRC_DIR && make build"
printf '\n%sNote%s\n' "$C_BOLD" "$C_RESET"
info "Android scoped storage: write -o targets under \$HOME, not /sdcard,"
info "unless you have granted storage access (termux-setup-storage)."
info "Remove with: install-termux.sh --uninstall"
printf '\n'