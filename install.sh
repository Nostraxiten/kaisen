#!/usr/bin/env sh
# Kaisen universal installer.
#
# Works on Termux (rooted or not), Kali, Debian/Ubuntu, Arch, Fedora, Alpine and
# macOS. It ensures a Rust toolchain is available, builds the release binary, and
# installs `kaisen` (plus `kai` and `kaison` aliases) into a directory on PATH —
# preferring a user-writable location so root is never required.
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
# 2. Ensure a Rust toolchain
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

ensure_rust
# Make freshly-installed cargo visible in this shell.
if ! have cargo && [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1090
    . "$HOME/.cargo/env"
fi

# ---------------------------------------------------------------------------
# 3. Obtain the source
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# 4. Build
# ---------------------------------------------------------------------------
info "Building release binary (this can take a few minutes)..."
( cd "$SRC_DIR" && cargo build --release )
BIN="$SRC_DIR/target/release/kaisen"
[ -x "$BIN" ] || { err "build did not produce $BIN"; exit 1; }

# ---------------------------------------------------------------------------
# 5. Choose an install directory on PATH (prefer user-writable, no root)
# ---------------------------------------------------------------------------
choose_bindir() {
    if [ "$IS_TERMUX" -eq 1 ]; then
        echo "$PREFIX/bin"; return
    fi
    for d in "$HOME/.local/bin" "$HOME/bin"; do
        case ":$PATH:" in *":$d:"*) mkdir -p "$d" && [ -w "$d" ] && { echo "$d"; return; };; esac
    done
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

install_one "$BIN" "$BINDIR/kaisen"
# Aliases as copies (symlinks may not survive some Termux filesystems).
install_one "$BIN" "$BINDIR/kai"
install_one "$BIN" "$BINDIR/kaison"

# ---------------------------------------------------------------------------
# 6. PATH check + done
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
