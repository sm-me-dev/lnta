#!/bin/sh
# LNTA Official APT Repository Installer
# Supported: Ubuntu, Debian, Linux Mint, Pop!_OS and Debian-derivatives
# Usage: curl -fsSL https://sm-me-dev.github.io/lnta/install-apt.sh | sudo sh

set -eu

KEYRING_DIR="/etc/apt/keyrings"
KEYRING_FILE="${KEYRING_DIR}/lnta.gpg"
SOURCES_DIR="/etc/apt/sources.list.d"
SOURCES_FILE="${SOURCES_DIR}/lnta.list"
REPO_URL="https://sm-me-dev.github.io/lnta"
KEY_URL="${REPO_URL}/lnta-archive-keyring.asc"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { printf "${BLUE}==>${NC} %s\n" "$*"; }
success() { printf "${GREEN}==>${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}==>${NC} %s\n" "$*"; }
error() { printf "${RED}Error:${NC} %s\n" "$*" >&2; }

# 1. Require root execution
if [ "$(id -u)" -ne 0 ]; then
  error "This installation script must be run as root. Run with sudo:"
  printf "       curl -fsSL %s/install-apt.sh | sudo sh\n" "${REPO_URL}" >&2
  exit 1
fi

# 2. Check for APT and dpkg
if ! command -v apt-get >/dev/null 2>&1 || ! command -v dpkg >/dev/null 2>&1; then
  error "apt-get and dpkg not found. This installer only supports Debian/Ubuntu-based distributions."
  printf "       For other distributions, use: curl -fsSL https://raw.githubusercontent.com/sm-me-dev/lnta/main/scripts/install.sh | sh\n" >&2
  exit 1
fi

# 3. Detect architecture
ARCH="$(dpkg --print-architecture)"
case "$ARCH" in
  amd64|arm64) ;;
  *)
    error "Unsupported architecture: ${ARCH}. LNTA APT repository provides amd64 and arm64 packages."
    exit 1
    ;;
esac
info "Detected architecture: ${ARCH}"

# 4. Ensure curl or wget is installed
FETCH=""
if command -v curl >/dev/null 2>&1; then
  FETCH="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  FETCH="wget -qO-"
else
  info "Installing curl..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends curl ca-certificates
  FETCH="curl -fsSL"
fi

# 5. Ensure gpg is installed
if ! command -v gpg >/dev/null 2>&1; then
  info "Installing gnupg..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends gnupg
fi

# 6. Ensure keyring directory exists with 0755
info "Configuring repository keyrings directory (${KEYRING_DIR})..."
install -m 0755 -d "${KEYRING_DIR}"

# 7. Download and dearmor repository signing key
info "Fetching official LNTA repository signing key..."
TMP_KEY="$(mktemp "${KEYRING_DIR}/lnta.gpg.tmp.XXXXXX")"
trap 'rm -f "${TMP_KEY}"' EXIT

if ! ${FETCH} "${KEY_URL}" | gpg --dearmor -o "${TMP_KEY}"; then
  error "Failed to fetch or dearmor repository key from ${KEY_URL}."
  exit 1
fi

mv "${TMP_KEY}" "${KEYRING_FILE}"
chmod 0644 "${KEYRING_FILE}"
trap - EXIT

# 8. Configure APT sources list (Modern DEB822 single-line format)
info "Configuring APT sources in ${SOURCES_FILE}..."
mkdir -p "${SOURCES_DIR}"
cat <<EOF > "${SOURCES_FILE}"
deb [arch=${ARCH} signed-by=${KEYRING_FILE}] ${REPO_URL} stable main
EOF
chmod 0644 "${SOURCES_FILE}"

# 9. Update APT package index and install LNTA
info "Updating package lists..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y

info "Installing lnta..."
apt-get install -y lnta

success "LNTA installed successfully via official APT repository!"
printf "\n"
printf "Next steps:\n"
printf "  • Verify installation:      lnta --version\n"
printf "  • Check kernel sandboxing:  lnta doctor\n"
printf "  • Try your first command:   lnta \"show listening ports\"\n"
printf "  • Multi-turn chat:          lnta chat\n"
printf "\n"
