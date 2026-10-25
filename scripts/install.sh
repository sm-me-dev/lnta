#!/bin/sh
# Universal LNTA Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/sm-me-dev/lnta/main/scripts/install.sh | bash
# Usage: curl -fsSL https://raw.githubusercontent.com/sm-me-dev/lnta/main/scripts/install.sh | sudo bash
#
# This script:
# 1. Detects architecture (amd64/arm64) and distribution
# 2. Downloads the appropriate package (.deb/.rpm/.pkg.tar.zst) or static binary
# 3. Verifies SHA-256 checksums
# 4. Installs via native package manager or places binary in /usr/local/bin

set -eu

REPO="sm-me-dev/lnta"
BINARY_NAME="lnta"
INSTALL_DIR="/usr/local/bin"
EXPECTED_KEY_FINGERPRINT="45BFE7B566C24F984EF00F6AEE0178A118050BDB"
RELEASE_KEY_URL="https://raw.githubusercontent.com/${REPO}/main/scripts/apt/lnta-archive-keyring.asc"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { printf "${BLUE}%s${NC}\n" "$*"; }
success() { printf "${GREEN}%s${NC}\n" "$*"; }
warn() { printf "${YELLOW}%s${NC}\n" "$*"; }
error() { printf "${RED}%s${NC}\n" "$*"; }

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) error "Unsupported architecture: $ARCH"; exit 1 ;;
esac
info "Detected architecture: $ARCH"

# Detect distribution and select package format
PKG_FMT="tar.gz"  # fallback
if [ -f /etc/os-release ]; then
  . /etc/os-release
  case "$ID" in
    ubuntu|debian) PKG_FMT="deb" ;;
    fedora|rhel|centos|rocky|almalinux|opensuse*) PKG_FMT="rpm" ;;
    arch|manjaro|endeavouros|garuda) PKG_FMT="pkg.tar.zst" ;;
    *) PKG_FMT="tar.gz" ;;
  esac
  info "Detected distribution: $PRETTY_NAME (package format: $PKG_FMT)"
else
  warn "Could not detect distribution; using static binary fallback"
fi

# Fetch latest release info
LATEST_URL="https://api.github.com/repos/$REPO/releases/latest"
info "Fetching latest release from GitHub..."

# Try curl first, then wget
if command -v curl >/dev/null 2>&1; then
  RELEASE_JSON=$(curl -fsSL "$LATEST_URL" 2>/dev/null)
elif command -v wget >/dev/null 2>&1; then
  RELEASE_JSON=$(wget -qO- "$LATEST_URL" 2>/dev/null)
else
  error "Need curl or wget to download release info"
  exit 1
fi

if [ -z "$RELEASE_JSON" ]; then
  error "Failed to fetch release info; check network connectivity"
  exit 1
fi

# Parse version from JSON
VERSION=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "v\?\([^"]*\)".*/\1/')
if [ -z "$VERSION" ]; then
  error "Failed to parse version from release"
  exit 1
fi
if ! printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$'; then
  error "Release metadata contains an invalid version"
  exit 1
fi
info "Latest version: $VERSION"

# Determine asset name based on package format
case "$PKG_FMT" in
  deb) ASSET="lnta_${VERSION}_linux_${ARCH}.deb" ;;
  rpm) ASSET="lnta-${VERSION}-1.${ARCH}.rpm" ;;
  pkg.tar.zst) ASSET="lnta-${VERSION}-1-${ARCH}.pkg.tar.zst" ;;
  tar.gz) ASSET="lnta_${VERSION}_linux_${ARCH}.tar.gz" ;;
esac

DOWNLOAD_URL="https://github.com/$REPO/releases/download/v${VERSION}/${ASSET}"
CHECKSUMS_URL="https://github.com/$REPO/releases/download/v${VERSION}/checksums.txt"
SIGNATURE_URL="${CHECKSUMS_URL}.sig"

# Download to temp directory
TMPDIR=$(mktemp -d)
STAGED_PATH=""
cleanup() {
  rm -rf "$TMPDIR"
  if [ -n "$STAGED_PATH" ]; then
    if [ -w "$INSTALL_DIR" ]; then rm -f "$STAGED_PATH"; else sudo rm -f "$STAGED_PATH"; fi
  fi
}
trap cleanup EXIT

if ! command -v gpg >/dev/null 2>&1 || ! command -v gpgv >/dev/null 2>&1; then
  error "gpg and gpgv are required to authenticate release checksums"
  exit 1
fi
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$RELEASE_KEY_URL" -o "$TMPDIR/release-key.asc"
else
  wget -q "$RELEASE_KEY_URL" -O "$TMPDIR/release-key.asc"
fi
ACTUAL_KEY_FINGERPRINT=$(gpg --batch --show-keys --with-colons "$TMPDIR/release-key.asc" | awk -F: '$1 == "fpr" { print $10; exit }')
if [ "$ACTUAL_KEY_FINGERPRINT" != "$EXPECTED_KEY_FINGERPRINT" ]; then
  error "Release signing key fingerprint did not match the pinned LNTA key"
  exit 1
fi
gpg --batch --dearmor --output "$TMPDIR/release-key.gpg" "$TMPDIR/release-key.asc"

info "Downloading $ASSET..."
if command -v curl >/dev/null 2>&1; then
  if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMPDIR/$ASSET"; then
    error "Failed to download $ASSET"
    exit 1
  fi
elif command -v wget >/dev/null 2>&1; then
  if ! wget -q "$DOWNLOAD_URL" -O "$TMPDIR/$ASSET"; then
    error "Failed to download $ASSET"
    exit 1
  fi
fi

info "Downloading checksums..."
if command -v curl >/dev/null 2>&1; then
  if ! curl -fsSL "$CHECKSUMS_URL" -o "$TMPDIR/checksums.txt"; then
    error "Failed to download checksums"
    exit 1
  fi
elif command -v wget >/dev/null 2>&1; then
  if ! wget -q "$CHECKSUMS_URL" -O "$TMPDIR/checksums.txt"; then
    error "Failed to download checksums"
    exit 1
  fi
fi

info "Downloading checksum signature..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$SIGNATURE_URL" -o "$TMPDIR/checksums.txt.sig"
else
  wget -q "$SIGNATURE_URL" -O "$TMPDIR/checksums.txt.sig"
fi
if ! gpgv --keyring "$TMPDIR/release-key.gpg" "$TMPDIR/checksums.txt.sig" "$TMPDIR/checksums.txt"; then
  error "Release checksum signature is invalid"
  exit 1
fi

# Verify checksum
cd "$TMPDIR"
EXPECTED=$(grep "$ASSET" checksums.txt | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
  error "Checksum for $ASSET not found in checksums.txt"
  exit 1
fi
ACTUAL=$(sha256sum "$ASSET" | awk '{print $1}')
if [ "$EXPECTED" != "$ACTUAL" ]; then
  error "Checksum mismatch!"
  error "  Expected: $EXPECTED"
  error "  Actual:   $ACTUAL"
  error "Manual installation recommended:"
  error "  Download from: https://github.com/$REPO/releases/latest"
  error "  Verify SHA-256 yourself"
  exit 1
fi
success "Checksum verified: $ACTUAL"

# Install based on package format
info "Installing $ASSET..."
case "$PKG_FMT" in
  deb)
    if command -v dpkg >/dev/null 2>&1; then
      sudo dpkg -i "$ASSET"
    else
      error "dpkg not found; cannot install .deb"
      exit 1
    fi
    ;;
  rpm)
    if command -v rpm >/dev/null 2>&1; then
      sudo rpm -i "$ASSET"
    elif command -v dnf >/dev/null 2>&1; then
      sudo dnf install -y "$ASSET"
    else
      error "rpm/dnf not found; cannot install .rpm"
      exit 1
    fi
    ;;
  pkg.tar.zst)
    if command -v pacman >/dev/null 2>&1; then
      sudo pacman -U --noconfirm "$ASSET"
    else
      error "pacman not found; cannot install .pkg.tar.zst"
      exit 1
    fi
    ;;
  tar.gz)
    tar -xzf "$ASSET" -C "$TMPDIR"
    if [ ! -f "$TMPDIR/$BINARY_NAME" ]; then error "Release archive did not contain $BINARY_NAME"; exit 1; fi
    chmod 0755 "$TMPDIR/$BINARY_NAME"
    if [ -w "$INSTALL_DIR" ]; then
      STAGED_PATH=$(mktemp "$INSTALL_DIR/.${BINARY_NAME}.install.XXXXXX")
      install -m 0755 "$TMPDIR/$BINARY_NAME" "$STAGED_PATH"
      mv -f "$STAGED_PATH" "$INSTALL_DIR/$BINARY_NAME"
    else
      sudo install -d -m 0755 "$INSTALL_DIR"
      STAGED_PATH=$(sudo mktemp "$INSTALL_DIR/.${BINARY_NAME}.install.XXXXXX")
      sudo install -m 0755 "$TMPDIR/$BINARY_NAME" "$STAGED_PATH"
      sudo mv -f "$STAGED_PATH" "$INSTALL_DIR/$BINARY_NAME"
    fi
    STAGED_PATH=""
    ;;
esac

success "LNTA $VERSION installed successfully!"
info "Run 'lnta --version' to verify."
info "Get started: lnta \"create a desktop launcher for my script\""
