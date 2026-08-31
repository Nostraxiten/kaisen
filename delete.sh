#!/usr/bin/env sh
# Kaisen uninstaller & system cleaner script.
#
# Completely removes any trace of Kaisen (binaries, aliases, build artifacts,
# temporary files, and caches) for clean reinstalls.
#
# Works on Termux, Linux (Debian, Ubuntu, Kali, Arch, Fedora, Alpine) and macOS.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/nostraxiten/kaisen/main/delete.sh | sh
#   # or, from a clone:
#   ./delete.sh

set -eu

info() { printf '\033[36m[kaisen]\033[0m %s\n' "$1"; }
warn() { printf '\033[33m[kaisen]\033[0m %s\n' "$1" >&2; }
err()  { printf '\033[31m[kaisen]\033[0m %s\n' "$1" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

info "Starting complete removal of Kaisen..."

# Detect environment
IS_TERMUX=0
if [ -n "${PREFIX:-}" ] && printf '%s' "${PREFIX:-}" | grep -q "com.termux"; then
    IS_TERMUX=1
fi

# List of binary names and aliases
BINARIES="kaisen kai kaison kaisen.exe kai.exe kaison.exe"

# List of potential installation directories
SEARCH_DIRS=""
if [ "$IS_TERMUX" -eq 1 ]; then
    SEARCH_DIRS="$PREFIX/bin"
fi
SEARCH_DIRS="$SEARCH_DIRS $HOME/.local/bin $HOME/bin $HOME/.cargo/bin /usr/local/bin /usr/bin"

REMOVED_COUNT=0

remove_file() {
    file="$1"
    if [ -f "$file" ] || [ -L "$file" ]; then
        if [ -w "$(dirname "$file")" ] || [ -w "$file" ]; then
            rm -f "$file"
            info "Removed: $file"
            REMOVED_COUNT=$((REMOVED_COUNT + 1))
        elif have sudo; then
            sudo rm -f "$file"
            info "Removed (via sudo): $file"
            REMOVED_COUNT=$((REMOVED_COUNT + 1))
        else
            warn "Cannot remove $file (permission denied, sudo unavailable)"
        fi
    fi
}

remove_dir() {
    dir="$1"
    if [ -d "$dir" ]; then
        if [ -w "$dir" ] || [ -w "$(dirname "$dir")" ]; then
            rm -rf "$dir"
            info "Cleaned directory: $dir"
        elif have sudo; then
            sudo rm -rf "$dir"
            info "Cleaned directory (via sudo): $dir"
        fi
    fi
}

# 1. Remove binaries and aliases from all search directories
for dir in $SEARCH_DIRS; do
    if [ -d "$dir" ]; then
        for bin in $BINARIES; do
            remove_file "$dir/$bin"
        done
    fi
done

# 2. Check current PATH for any remaining binary
for bin in kaisen kai kaison; do
    while have "$bin"; do
        loc="$(command -v "$bin" 2>/dev/null || true)"
        if [ -n "$loc" ]; then
            remove_file "$loc"
        else
            break
        fi
    done
done

# 3. Clean build artifacts if inside a kaisen repository checkout
if [ -f "Cargo.toml" ] && grep -q 'name = "kaisen"' Cargo.toml 2>/dev/null; then
    if [ -d "target" ]; then
        info "Cleaning local build artifacts (target/)..."
        cargo clean 2>/dev/null || rm -rf target
        info "Cleaned local target/ directory"
    fi
fi

# 4. Clean temporary clone/build directories
TMP_PARENT="${TMPDIR:-/tmp}"
if [ -d "$TMP_PARENT" ]; then
    find "$TMP_PARENT" -maxdepth 1 -name "kaisen*" -type d 2>/dev/null | while read -r d; do
        remove_dir "$d"
    done
fi

# 5. Clean user configuration / cache folders if present
remove_dir "$HOME/.config/kaisen"
remove_dir "$HOME/.cache/kaisen"
remove_dir "$HOME/.kaisen"

info "Removal complete! Total binaries removed: $REMOVED_COUNT"
info "System is clean. You can now perform a fresh installation anytime."
