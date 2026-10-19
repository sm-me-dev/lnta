#!/bin/sh
# LNTA Install Script Contract
# Universal one-line installer for all Linux distributions

## Version Detection
# Must fetch latest release from GitHub API
# Expected format: `curl -fsSL https://api.github.com/repos/sm-me/lnta/releases/latest`

## Architecture Detection
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

## Distribution Detection
if [ -f /etc/os-release ]; then
  . /etc/os-release
  case "$ID" in
    ubuntu|debian) PKG_FMT="deb" ;;
    fedora|rhel|centos|rocky|almalinux|opensuse*) PKG_FMT="rpm" ;;
    arch|manjaro|endeavouros|garuda) PKG_FMT="pkg.tar.zst" ;;
    *) PKG_FMT="tar.gz" ;;  # fallback to static binary
  esac
else
  PKG_FMT="tar.gz"
fi

## Release Fetching
LATEST_URL="https://api.github.com/repos/sm-me/lnta/releases/latest"
RELEASE_JSON=$(curl -fsSL "$LATEST_URL" 2>/dev/null || wget -qO- "$LATEST_URL" 2>/dev/null)

if [ -z "$RELEASE_JSON" ]; then
  echo "Failed to fetch latest release; check network connectivity"; exit 1
fi

VERSION=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "v\?\([^"]*\)".*/\1/')
if [ -z "$VERSION" ]; then
  echo "Failed to parse version from release"; exit 1
fi

## Asset Selection
case "$PKG_FMT" in
  deb) ASSET="lnta_${VERSION}_linux_${ARCH}.deb" ;;
  rpm) ASSET="lnta-${VERSION}-1.${ARCH}.rpm" ;;
  pkg.tar.zst) ASSET="lnta-${VERSION}-1-${ARCH}.pkg.tar.zst" ;;
  tar.gz) ASSET="lnta_${VERSION}_linux_${ARCH}.tar.gz" ;;
esac

DOWNLOAD_URL="https://github.com/sm-me/lnta/releases/download/v${VERSION}/${ASSET}"
CHECKSUMS_URL="https://github.com/sm-me/lnta/releases/download/v${VERSION}/checksums.txt"

## Download
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${ASSET}..."
if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMPDIR/${ASSET}"; then
  echo "Failed to download ${ASSET}; check URL and network"; exit 1
fi

echo "Downloading checksums..."
if ! curl -fsSL "$CHECKSUMS_URL" -o "$TMPDIR/checksums.txt"; then
  echo "Failed to download checksums; retrying later may help"; exit 1
fi

## Checksum Verification
cd "$TMPDIR"
EXPECTED=$(grep "$ASSET" checksums.txt | awk '{print $1}')
ACTUAL=$(sha256sum "$ASSET" | awk '{print $1}')
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Checksum mismatch! Expected: ${EXPECTED}, Got: ${ACTUAL}"
  echo "Manual installation recommended:"
  echo "  Download from: https://github.com/sm-me/lnta/releases/latest"
  echo "  Verify SHA-256 yourself"; exit 1
fi
echo "Checksum verified."

## Installation
case "$PKG_FMT" in
  deb)
    if command -v dpkg >/dev/null 2>&1; then
      sudo dpkg -i "$ASSET"
    else
      echo "dpkg not found; cannot install .deb"; exit 1
    fi
    ;;
  rpm)
    if command -v rpm >/dev/null 2>&1; then
      sudo rpm -i "$ASSET"
    elif command -v dnf >/dev/null 2>&1; then
      sudo dnf install -y "$ASSET"
    else
      echo "rpm/dnf not found; cannot install .rpm"; exit 1
    fi
    ;;
  pkg.tar.zst)
    if command -v pacman >/dev/null 2>&1; then
      sudo pacman -U --noconfirm "$ASSET"
    else
      echo "pacman not found; cannot install .pkg.tar.zst"; exit 1
    fi
    ;;
  tar.gz)
    tar -xzf "$ASSET" -C "$TMPDIR"
    BINARY_NAME="lnta"
    if [ -w /usr/local/bin ]; then
      mv "$TMPDIR/${BINARY_NAME}" /usr/local/bin/
    else
      sudo mv "$TMPDIR/${BINARY_NAME}" /usr/local/bin/
    fi
    ;;
esac

echo "LNTA ${VERSION} installed successfully!"
echo "Run 'lnta --version' to verify."