#!/bin/sh
set -e

# snare installer
# Usage: curl -fsSL https://snare.sh/install | sh

REPO="peg/snare"
INSTALL_DIR="${SNARE_INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="snare"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

info()  { printf "${BOLD}  snare${RESET} %s\n" "$*"; }
ok()    { printf "${GREEN}  ✓${RESET} %s\n" "$*"; }
fail()  { printf "${RED}  ✗${RESET} %s\n" "$*" >&2; exit 1; }

# Detect OS and arch
detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)  OS="linux" ;;
        Darwin) OS="darwin" ;;
        *)      fail "Unsupported OS: $OS (Linux and macOS are supported)" ;;
    esac

    case "$ARCH" in
        x86_64)          ARCH="amd64" ;;
        aarch64 | arm64) ARCH="arm64" ;;
        *)               fail "Unsupported architecture: $ARCH" ;;
    esac

    PLATFORM="${OS}-${ARCH}"
}

# Get the latest release version from GitHub
get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' \
            | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    elif command -v wget >/dev/null 2>&1; then
        VERSION="$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' \
            | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    else
        fail "curl or wget is required"
    fi

    if [ -z "$VERSION" ]; then
        fail "Could not determine latest version. Check https://github.com/${REPO}/releases"
    fi
}

# Download the binary and verify its checksum
download_binary() {
    BINARY="snare-${PLATFORM}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}"
    CHECKSUM_URL="${URL}.sha256"
    TMP_FILE="$(mktemp)"
    TMP_CHECKSUM="$(mktemp)"

    info "Downloading snare ${VERSION} for ${PLATFORM}..."

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$URL" -o "$TMP_FILE" || fail "Download failed: $URL"
        curl -fsSL "$CHECKSUM_URL" -o "$TMP_CHECKSUM" || fail "Checksum download failed: $CHECKSUM_URL"
    else
        wget -qO "$TMP_FILE" "$URL" || fail "Download failed: $URL"
        wget -qO "$TMP_CHECKSUM" "$CHECKSUM_URL" || fail "Checksum download failed: $CHECKSUM_URL"
    fi

    # Verify SHA-256 checksum
    info "Verifying checksum..."
    EXPECTED="$(awk '{print $1}' "$TMP_CHECKSUM")"
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL="$(sha256sum "$TMP_FILE" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL="$(shasum -a 256 "$TMP_FILE" | awk '{print $1}')"
    else
        rm -f "$TMP_FILE" "$TMP_CHECKSUM"
        fail "sha256sum or shasum is required for checksum verification"
    fi
    rm -f "$TMP_CHECKSUM"

    if [ "$ACTUAL" != "$EXPECTED" ]; then
        rm -f "$TMP_FILE"
        fail "Checksum mismatch! Expected ${EXPECTED}, got ${ACTUAL}. The download may be corrupted or tampered with."
    fi
    ok "Checksum verified"

    chmod +x "$TMP_FILE"
    echo "$TMP_FILE"
}

# Install the binary
install_binary() {
    TMP_FILE="$1"

    # Try install dir, fall back to ~/.local/bin
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
        ok "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
    elif [ "$(id -u)" = "0" ]; then
        mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
        ok "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
    else
        LOCAL_BIN="${HOME}/.local/bin"
        mkdir -p "$LOCAL_BIN"
        mv "$TMP_FILE" "${LOCAL_BIN}/${BINARY_NAME}"
        ok "Installed to ${LOCAL_BIN}/${BINARY_NAME}"

        # Check if ~/.local/bin is in PATH
        case ":$PATH:" in
            *":${LOCAL_BIN}:"*) ;;
            *)
                printf "\n  ${BOLD}Note:${RESET} Add this to your shell profile:\n"
                printf "  export PATH=\"\$HOME/.local/bin:\$PATH\"\n\n"
                ;;
        esac
    fi
}

main() {
    printf "\n  ${BOLD}snare${RESET} — compromise detection for AI agents\n\n"

    detect_platform
    get_latest_version
    TMP="$(download_binary)"
    install_binary "$TMP"

    printf "\n  ${BOLD}Next steps:${RESET}\n\n"
    printf "  1. Run ${BOLD}snare init${RESET} to initialize snare\n"
    printf "  2. Run ${BOLD}snare plant${RESET} to deploy your first canaries\n"
    printf "  3. Run ${BOLD}snare test${RESET} to verify alerts are working\n\n"
    printf "  Questions? https://github.com/${REPO}\n\n"
}

main
