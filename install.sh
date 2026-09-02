#!/usr/bin/env sh
# Kaisen universal installer.
#
# Works on Termux (rooted or not), Kali, Debian/Ubuntu, Arch, Fedora, Alpine and
# macOS. It first tries to download a prebuilt binary from the latest GitHub
# release (fast path). If no release exists yet, the arch is unsupported, or the
# download fails for any reason, it falls back to building from source with Cargo.
# Installs `kaisen` (plus `kai` and `kaison` aliases) into a directory on PATH —
# preferring a user-writable location so root is never required.
#
# Environment variables:
#   KAISEN_BRANCH       – branch/tag to clone when building from source (default: main)
#   KAISEN_FROM_SOURCE  – set to 1 to skip the prebuilt check and always build
#
#   curl -fsSL https://raw.githubusercontent.com/nostraxiten/kaisen/main/install.sh | sh
#   # or, from a clone:
#   ./install.sh
set -eu

REPO_URL="https://github.com/nostraxiten/kaisen.git"
BRANCH="${KAISEN_BRANCH:-main}"

info()  { printf '\033[36m[kaisen]\033[0m %s\n' "$1"; }
warn()  { printf '\033[33m[kaisen]\033[0m %s\n' "$1" >&2; }
err()   { printf '\033[31m[kaisen]\033[0m %s\n' "$1" >&2; }
have()  { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# 1. Detect environment
# ---------------------------------------------------------------------------
IS_TERMUX=0
if [ -n "${PREFIX:-}" ] && printf '%s' "${PREFIX:-}" | grep -q "com.termux"; then
    IS_TERMUX=1
fi
OS="$(uname -s 2>/dev/null || echo unknown)"

info "Detected: OS=$OS termux=$IS_TERMUX"

# ---------------------------------------------------------------------------
# 2. Prebuilt binary (fast path — skips Rust entirely when a release exists)
# ---------------------------------------------------------------------------

# try_prebuilt: attempt to download and install a prebuilt binary from the
# latest GitHub release.  Returns 0 on success (binary installed, script will
# exit), 1 on any failure (caller should fall through to build-from-source).
try_prebuilt() {
    # Non-main branches or explicit opt-out: never use a release binary.
    if [ "${KAISEN_FROM_SOURCE:-0}" = "1" ]; then
        info "KAISEN_FROM_SOURCE=1 — skipping prebuilt check, building from source"
        return 1
    fi
    if [ "$BRANCH" != "main" ]; then
        info "Branch '$BRANCH' is not 'main' — skipping prebuilt check, building from source"
        return 1
    fi

    # Determine which asset this machine needs.
    ARCH="$(uname -m 2>/dev/null || echo unknown)"
    if [ "$IS_TERMUX" -eq 1 ]; then
        # Termux always needs the Android/Bionic binary regardless of arch reported.
        ASSET_NAME="kaisen-android-aarch64"
    elif [ "$OS" = "Darwin" ]; then
        case "$ARCH" in
            x86_64) ASSET_NAME="kaisen-macos-x86_64" ;;
            arm64)  ASSET_NAME="kaisen-macos-aarch64" ;;
            *)
                info "No prebuilt binary for macOS/$ARCH — building from source"
                return 1
                ;;
        esac
    else
        # Assume Linux.
        case "$ARCH" in
            x86_64)  ASSET_NAME="kaisen-linux-x86_64" ;;
            aarch64) ASSET_NAME="kaisen-linux-aarch64" ;;
            *)
                info "No prebuilt binary for Linux/$ARCH — building from source"
                return 1
                ;;
        esac
    fi

    info "Looking for prebuilt asset: ${ASSET_NAME}.tar.gz"

    # Query the GitHub releases API (no jq required — plain grep/sed).
    API_URL="https://api.github.com/repos/nostraxiten/kaisen/releases/latest"
    RELEASE_JSON="$(curl -fsSL "$API_URL" 2>/dev/null)" || true

    # A 404 or empty body means no release yet — fall through silently.
    if [ -z "$RELEASE_JSON" ] || printf '%s' "$RELEASE_JSON" | grep -q '"message".*Not Found'; then
        info "No GitHub release found yet — building from source"
        return 1
    fi

    # Extract the download URL for our asset (browser_download_url lines).
    DOWNLOAD_URL="$(printf '%s' "$RELEASE_JSON" \
        | grep '"browser_download_url"' \
        | grep "${ASSET_NAME}\.tar\.gz" \
        | sed 's/.*"browser_download_url": *"\([^"]*\)".*/\1/' \
        | head -n 1)"

    if [ -z "$DOWNLOAD_URL" ]; then
        info "Asset '${ASSET_NAME}.tar.gz' not found in latest release — building from source"
        return 1
    fi

    # Download and unpack into a temp directory.
    TMP_DIR="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/kaisen-prebuilt-$$")"
    TARBALL="$TMP_DIR/${ASSET_NAME}.tar.gz"

    info "Downloading prebuilt binary from $DOWNLOAD_URL"
    if ! curl -fsSL -o "$TARBALL" "$DOWNLOAD_URL" 2>/dev/null; then
        warn "Download failed — building from source"
        rm -rf "$TMP_DIR"
        return 1
    fi

    if ! tar -xzf "$TARBALL" -C "$TMP_DIR" 2>/dev/null; then
        warn "Failed to extract tarball — building from source"
        rm -rf "$TMP_DIR"
        return 1
    fi

    PREBUILT_BIN="$TMP_DIR/$ASSET_NAME"
    if [ ! -f "$PREBUILT_BIN" ]; then
        warn "Expected binary '$ASSET_NAME' not found in tarball — building from source"
        rm -rf "$TMP_DIR"
        return 1
    fi
    chmod +x "$PREBUILT_BIN"

    # Smoke-test: make sure the binary actually runs on this machine.
    if ! "$PREBUILT_BIN" --version >/dev/null 2>&1; then
        warn "Prebuilt binary failed smoke-test (wrong arch or corrupt download) — building from source"
        rm -rf "$TMP_DIR"
        return 1
    fi

    # All good — install and exit successfully.
    info "Prebuilt binary found for $ASSET_NAME, skipping build"
    install_one "$PREBUILT_BIN" "$BINDIR/kaisen"
    install_one "$PREBUILT_BIN" "$BINDIR/kai"
    install_one "$PREBUILT_BIN" "$BINDIR/kaison"
    rm -rf "$TMP_DIR"
    return 0
}

# ---------------------------------------------------------------------------
# 3. Ensure a Rust toolchain (only reached when no prebuilt was installed)
# ---------------------------------------------------------------------------
ensure_rust() {
    if have cargo; then
        info "Found cargo: $(cargo --version)"
        return
    fi
    info "Rust toolchain not found — installing..."
    if [ "$IS_TERMUX" -eq 1 ]; then
        pkg install -y rust git || { err "pkg install failed"; exit 1; }
    elif have apt-get; then
        (sudo -n true 2>/dev/null && SUDO=sudo || SUDO="")
        if have sudo; then SUDO=sudo; else SUDO=""; fi
        $SUDO apt-get update -y && $SUDO apt-get install -y cargo git build-essential \
            || { warn "apt install failed; trying rustup"; install_rustup; }
    elif have pacman; then
        (have sudo && sudo pacman -Sy --noconfirm rust git) || install_rustup
    elif have dnf; then
        (have sudo && sudo dnf install -y cargo git) || install_rustup
    elif have apk; then
        (have sudo && sudo apk add cargo git build-base) || install_rustup
    elif have brew; then
        brew install rust git || install_rustup
    else
        install_rustup
    fi
}

install_rustup() {
    info "Installing Rust via rustup..."
    if ! have curl; then err "curl is required to install rustup"; exit 1; fi
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1090
    . "$HOME/.cargo/env"
}

# ---------------------------------------------------------------------------
# 4. Obtain the source
# ---------------------------------------------------------------------------
build_from_source() {
    ensure_rust
    # Make freshly-installed cargo visible in this shell.
    if ! have cargo && [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1090
        . "$HOME/.cargo/env"
    fi

    SRC_DIR=""
    if [ -f "Cargo.toml" ] && grep -q 'name = "kaisen"' Cargo.toml 2>/dev/null; then
        SRC_DIR="$(pwd)"
        info "Building from current checkout: $SRC_DIR"
    else
        if ! have git; then err "git is required to clone the repository"; exit 1; fi
        SRC_DIR="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/kaisen-src")"
        info "Cloning $REPO_URL ($BRANCH) into $SRC_DIR"
        git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$SRC_DIR"
    fi

    # -------------------------------------------------------------------------
    # 5. Build
    # -------------------------------------------------------------------------
    info "No prebuilt binary available, building from source (this can take a few minutes)..."
    ( cd "$SRC_DIR" && cargo build --release )
    BIN="$SRC_DIR/target/release/kaisen"
    [ -x "$BIN" ] || { err "build did not produce $BIN"; exit 1; }
}

# ---------------------------------------------------------------------------
# 6. Choose an install directory: prefer whatever is ALREADY on PATH (so the
#    install "just works" with no shell restart / profile edit needed), and
#    only fall back to creating a fresh, not-yet-on-PATH directory as a last
#    resort. On Kali (and most distros) a root shell already has
#    /usr/local/bin on PATH, so a root install lands there directly instead
#    of ~/.local/bin, which usually isn't on PATH out of the box.
# ---------------------------------------------------------------------------
choose_bindir() {
    if [ "$IS_TERMUX" -eq 1 ]; then
        echo "$PREFIX/bin"; return
    fi
    for d in "$HOME/.local/bin" "$HOME/bin" "/usr/local/bin"; do
        case ":$PATH:" in
            *":$d:"*)
                mkdir -p "$d" 2>/dev/null
                [ -w "$d" ] && { echo "$d"; return; }
                ;;
        esac
    done
    # Nothing already on PATH was writable. Root can still write to
    # /usr/local/bin — the standard location, on PATH for virtually every
    # login shell even when this script's own (possibly minimal) PATH
    # didn't show it above — so prefer that over an unlisted ~/.local/bin.
    if [ "$(id -u 2>/dev/null)" = "0" ] && mkdir -p /usr/local/bin 2>/dev/null && [ -w /usr/local/bin ]; then
        echo "/usr/local/bin"; return
    fi
    # ~/.local/bin even if not yet on PATH (we'll warn)
    if mkdir -p "$HOME/.local/bin" 2>/dev/null && [ -w "$HOME/.local/bin" ]; then
        echo "$HOME/.local/bin"; return
    fi
    echo "/usr/local/bin"
}

BINDIR="$(choose_bindir)"
info "Installing to $BINDIR"

install_one() {
    src="$1"; dst="$2"
    if [ -w "$(dirname "$dst")" ]; then
        cp -f "$src" "$dst" && chmod +x "$dst"
    elif have sudo; then
        sudo cp -f "$src" "$dst" && sudo chmod +x "$dst"
    else
        err "cannot write $dst and sudo unavailable"; exit 1
    fi
}

# ---------------------------------------------------------------------------
# 7. Main flow: try prebuilt first, fall back to build from source
# ---------------------------------------------------------------------------
if try_prebuilt; then
    # install_one calls already happened inside try_prebuilt; nothing more to do.
    BIN="$BINDIR/kaisen"
else
    build_from_source
    BIN="$SRC_DIR/target/release/kaisen"
    install_one "$BIN" "$BINDIR/kaisen"
    # Aliases as copies (symlinks may not survive some Termux filesystems).
    install_one "$BIN" "$BINDIR/kai"
    install_one "$BIN" "$BINDIR/kaison"
fi

# ---------------------------------------------------------------------------
# 8. PATH check + done
# ---------------------------------------------------------------------------
case ":$PATH:" in
    *":$BINDIR:"*) : ;;
    *)
        warn "$BINDIR is not on your PATH."
        warn "Add it, e.g.:  echo 'export PATH=\"$BINDIR:\$PATH\"' >> ~/.profile && . ~/.profile"
        ;;
esac

info "Done! Installed: kaisen, kai, kaison"
"$BINDIR/kaisen" --version || true
info "Try:  kaisen --help"
