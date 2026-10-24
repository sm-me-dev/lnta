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

# Download to temp directory
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

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
    if [ -w "$INSTALL_DIR" ]; then
      mv "$TMPDIR/$BINARY_NAME" "$INSTALL_DIR/"
    else
      sudo mv "$TMPDIR/$BINARY_NAME" "$INSTALL_DIR/"
    fi
    ;;
esac

success "LNTA $VERSION installed successfully!"
info "Run 'lnta --version' to verify."
info "Get started: lnta \"create a desktop launcher for my script\""