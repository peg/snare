#!/bin/sh
# Snare install script
# Usage: curl -fsSL https://snare.sh/install | sh
set -e

REPO="peg/snare"
BINARY="snare"
INSTALL_DIR="${SNARE_INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

case "$OS" in
  linux|darwin) ;;
  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
esac

# Fetch latest release version
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' \
  | sed 's/.*"tag_name": "\(.*\)".*/\1/')

if [ -z "$LATEST" ]; then
  echo "Failed to fetch latest release" >&2
  exit 1
fi

TARBALL="${BINARY}_${OS}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${TARBALL}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${LATEST}/checksums.txt"

echo "Installing snare ${LATEST} (${OS}/${ARCH})..."

# Create temp dir
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Download binary
curl -fsSL "$DOWNLOAD_URL" -o "${TMP}/${TARBALL}"

# Verify checksum
curl -fsSL "$CHECKSUM_URL" -o "${TMP}/checksums.txt"
EXPECTED=$(grep "$TARBALL" "${TMP}/checksums.txt" | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
  echo "Failed to find checksum for ${TARBALL} in checksums.txt" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "${TMP}/${TARBALL}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "${TMP}/${TARBALL}" | awk '{print $1}')
else
  echo "Need sha256sum or shasum to verify ${TARBALL}" >&2
  exit 1
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Checksum mismatch — download may be corrupt or tampered" >&2
  echo "  expected: $EXPECTED" >&2
  echo "  actual:   $ACTUAL" >&2
  exit 1
fi
echo "✓ Checksum verified"

# Extract
tar -xzf "${TMP}/${TARBALL}" -C "$TMP"

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mv "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

chmod +x "${INSTALL_DIR}/${BINARY}"

echo "✓ Installed to ${INSTALL_DIR}/${BINARY}"
echo ""
echo "Get started:"
echo "  snare arm --webhook <discord-or-slack-url>"
echo ""
echo "Docs: https://snare.sh"
