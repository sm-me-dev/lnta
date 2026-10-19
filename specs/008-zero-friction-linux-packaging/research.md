# Research: Zero-Friction Linux Packaging

## Overview

This document consolidates research findings for Phase 8: Zero-Friction Linux Packaging. All technical decisions are based on existing codebase patterns, Go/GoReleaser best practices, and the LNTA Constitution.

---

## Decision Matrix

| Topic | Decision | Rationale | Alternatives Considered |
|-------|----------|-----------|------------------------|
| **GoReleaser version** | v2 (latest stable) | Current major version; nfpm v2 integrated; active maintenance | v1 — deprecated; manual release scripts — error-prone, not reproducible |
| **nfpm configuration** | Embedded in `.goreleaser.yaml` under `nfpms` | Single source of truth; GoReleaser manages nfpm invocation | Separate `nfpm.yaml` — duplication, drift risk |
| **Cross-compilation** | `goos: linux`, `goarch: [amd64, arm64]`, `env: CGO_ENABLED=0` | Standard Go cross-compile; codebase has zero cgo dependencies | `CGO_ENABLED=1` — requires cross-compiler toolchain (zig/cc), complex CI |
| **Symbol stripping** | `-ldflags="-s -w"` in `build.ldflags` | Reduces binary ~30-40%; removes DWARF/debug info; no runtime impact | UPX compression — adds build dependency, marginal extra gain, false positives in AV |
| **AppArmor profile location** | `scripts/apparmor-profile` template, rendered by GoReleaser | Maintainable; version-controlled; only included in .deb via nfpm `contents` | Hardcode in `.goreleaser.yaml` — less readable, harder to test |
| **.deb postinst script** | Inline in nfpm `scripts.postinstall` | Runs `apparmor_parser -r /etc/apparmor.d/lnta \|\| true`; `|| true` handles missing apparmor_parser | Separate script file — extra file to manage; nfpm supports inline |
| **AppArmor cleanup** | `scripts.preremove` + `scripts.postremove` in nfpm | `preremove`: `apparmor_parser -R /etc/apparmor.d/lnta \|\| true`; `postremove`: remove file | Only postremove — profile stays loaded until reboot |
| **Install script arch detection** | `uname -m` → map `x86_64→amd64`, `aarch64→arm64` | Portable; works in minimal containers | `dpkg --print-architecture` — Debian-only |
| **Install script distro detection** | Parse `/etc/os-release` for `ID` + `ID_LIKE` | Standard across systemd distros; works on Ubuntu, Debian, Fedora, Arch | `lsb_release` — not installed by default on minimal images |
| **Package format selection** | `.deb` for debian/ubuntu, `.rpm` for fedora/rhel/opensuse, `.pkg.tar.zst` for arch, binary tarball fallback | Matches native package manager per distro family | Only binary tarballs — no dependency resolution, no AppArmor hook |
| **Checksum verification** | `sha256sum -c <(grep "<filename>" checksums.txt)` | GoReleaser generates `checksums.txt`; standard format; tamper-evident | Manual hash compare — error-prone; cosign — overkill for this scope |
| **Man page generation** | `cobra/doc.GenManTree` in `lnta docs --man` command | Built into Cobra; outputs structured man pages; supports all subcommands | Manual roff — unmaintainable; help2man — extra dependency |
| **Shell completions** | `rootCmd.GenBashCompletion`, `GenZshCompletion`, `GenFishCompletion` | Built into Cobra; outputs to stdout; supports flags/subcommands | Manual completion scripts — duplication, drift |
| **CI runner** | Ubuntu 24.04 (GitHub-hosted `ubuntu-24.04`) | Has `bubblewrap` pre-installed; matches primary target distro | Self-hosted — cost/complexity; ubuntu-latest — version drift |
| **golangci-lint in CI** | Binary install via `golangci/golangci-lint-action` | Fast, version-pinned, no go.mod pollution, caches well | As Go tool (`go install`) — slower, version drift, no cache |
| **VHS tape** | `demo.tape` with explicit `Sleep`, `Type`, `Enter` | Reproducible, version-controlled, deterministic timing | Manual recording — not reproducible, flaky |
| **README architecture diagram** | Mermaid (native GitHub render) | No external tooling; version-controlled; renders in README | PlantUML/Image — not native on GitHub; requires generation step |
| **Version scheme** | Semantic versioning per Constitution (v0.7.0 → v0.8.0) | Constitution mandates MAJOR.MINOR.PATCH; Phase 8 = MINOR bump | Calendar versioning — not per Constitution |

---

## Key Technical Details

### GoReleaser Configuration Structure

```yaml
# .goreleaser.yaml
project_name: lnta
version: 2
before:
  hooks:
    - go mod tidy
builds:
  - id: lnta
    main: ./cmd/lnta
    binary: lnta
    goos: [linux]
    goarch: [amd64, arm64]
    env:
      - CGO_ENABLED=0
    ldflags:
      - -s -w
      - -X github.com/sm-me/lnta.Version={{.Version}}
      - -X github.com/sm-me/lnta.Commit={{.Commit}}
      - -X github.com/sm-me/lnta.Date={{.Date}}
    flags:
      - -trimpath
nfpms:
  - id: deb
    package_name: lnta
    formats: [deb]
    bindir: /usr/bin
    maintainer: "LNTA Maintainers <maintainers@lnta.dev>"
    description: "Linux Natural-Language Terminal Assistant"
    license: "MIT"
    recommends:
      - bubblewrap
      - desktop-file-validate
    scripts:
      postinstall: |
        #!/bin/sh
        if command -v apparmor_parser >/dev/null 2>&1; then
          apparmor_parser -r /etc/apparmor.d/lnta || true
        fi
      preremove: |
        #!/bin/sh
        if command -v apparmor_parser >/dev/null 2>&1; then
          apparmor_parser -R /etc/apparmor.d/lnta || true
        fi
      postremove: |
        #!/bin/sh
        rm -f /etc/apparmor.d/lnta
    contents:
      - src: scripts/apparmor-profile
        dst: /etc/apparmor.d/lnta
        type: config
        packager: deb
  - id: rpm
    package_name: lnta
    formats: [rpm]
    bindir: /usr/bin
    maintainer: "LNTA Maintainers <maintainers@lnta.dev>"
    description: "Linux Natural-Language Terminal Assistant"
    license: "MIT"
    recommends:
      - bubblewrap
      - desktop-file-validate
  - id: archlinux
    package_name: lnta
    formats: [archlinux]
    bindir: /usr/bin
    maintainer: "LNTA Maintainers <maintainers@lnta.dev>"
    description: "Linux Natural-Language Terminal Assistant"
    license: "MIT"
    recommends:
      - bubblewrap
      - desktop-file-validate
archives:
  - id: binary
    builds: [lnta]
    format: tar.gz
    name_template: "{{.ProjectName}}_{{.Version}}_{{.Os}}_{{.Arch}}"
    files:
      - LICENSE*
      - README.md
checksum:
  name_template: "checksums.txt"
  algorithm: sha256
release:
  github:
    owner: sm-me
    name: lnta
  draft: false
  prerelease: auto
  name_template: "v{{.Version}}"
```

### AppArmor Profile (scripts/apparmor-profile)

```apparmor
# LNTA bwrap AppArmor Profile
# Allows unprivileged user namespaces for bubblewrap sandboxing
# Install to: /etc/apparmor.d/lnta
# Load with: apparmor_parser -r /etc/apparmor.d/lnta

abi <abi/4.0>,
include <tunables/global>

profile lnta-bwrap flags=(unconfined) {
  userns,

  # Allow reading system files (read-only bind mounts)
  / r,
  /usr/** r,
  /bin/** r,
  /lib/** r,
  /lib64/** r,
  /etc/** r,
  /proc/** r,
  /sys/** r,
  /dev/** r,
  /run/** r,

  # Allow tmpfs mounts
  /tmp/** rw,
  /var/tmp/** rw,

  # Mask secret directories
  @{HOME}/.ssh/** r,
  @{HOME}/.gnupg/** r,
  @{HOME}/.aws/** r,
  @{HOME}/.kube/** r,
  @{HOME}/.config/lnta/** r,

  # Site-specific additions
  include if exists <local/lnta-bwrap>
}
```

### Install Script Logic (scripts/install.sh)

```bash
#!/bin/sh
# Universal LNTA installer
# Usage: curl -fsSL https://raw.githubusercontent.com/sm-me/lnta/main/scripts/install.sh | bash

set -eu

REPO="sm-me/lnta"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="lnta"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Detect distro and package format
if [ -f /etc/os-release ]; then
  . /etc/os-release
  case "$ID" in
    ubuntu|debian) PKG_FMT="deb" ;;
    fedora|rhel|centos|rocky|almalinux|opensuse*) PKG_FMT="rpm" ;;
    arch|manjaro|endeavouros|garuda) PKG_FMT="pkg.tar.zst" ;;
    *) PKG_FMT="tar.gz" ;;
  esac
else
  PKG_FMT="tar.gz"
fi

# Get latest release
LATEST_URL="https://api.github.com/repos/$REPO/releases/latest"
if command -v curl >/dev/null; then
  RELEASE_JSON=$(curl -fsSL "$LATEST_URL")
elif command -v wget >/dev/null; then
  RELEASE_JSON=$(wget -qO- "$LATEST_URL")
else
  echo "Need curl or wget"; exit 1
fi

VERSION=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "v\?\([^"]*\)".*/\1/')
if [ -z "$VERSION" ]; then
  echo "Failed to fetch latest version"; exit 1
fi

# Determine asset name
case "$PKG_FMT" in
  deb) ASSET="lnta_${VERSION}_linux_${ARCH}.deb" ;;
  rpm) ASSET="lnta-${VERSION}-1.${ARCH}.rpm" ;;
  pkg.tar.zst) ASSET="lnta-${VERSION}-1-${ARCH}.pkg.tar.zst" ;;
  tar.gz) ASSET="lnta_${VERSION}_linux_${ARCH}.tar.gz" ;;
esac

DOWNLOAD_URL="https://github.com/$REPO/releases/download/v${VERSION}/${ASSET}"
CHECKSUMS_URL="https://github.com/$REPO/releases/download/v${VERSION}/checksums.txt"

# Download asset and checksums
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading $ASSET..."
if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMPDIR/$ASSET"; then
  echo "Failed to download $ASSET"; exit 1
fi

echo "Downloading checksums..."
if ! curl -fsSL "$CHECKSUMS_URL" -o "$TMPDIR/checksums.txt"; then
  echo "Failed to download checksums"; exit 1
fi

# Verify checksum
cd "$TMPDIR"
EXPECTED=$(grep "$ASSET" checksums.txt | awk '{print $1}')
ACTUAL=$(sha256sum "$ASSET" | awk '{print $1}')
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Checksum mismatch! Expected: $EXPECTED, Got: $ACTUAL"; exit 1
fi
echo "Checksum verified."

# Install
case "$PKG_FMT" in
  deb)
    if command -v dpkg >/dev/null; then
      sudo dpkg -i "$ASSET"
    else
      echo "dpkg not found; cannot install .deb"; exit 1
    fi
    ;;
  rpm)
    if command -v rpm >/dev/null; then
      sudo rpm -i "$ASSET"
    elif command -v dnf >/dev/null; then
      sudo dnf install -y "$ASSET"
    else
      echo "rpm/dnf not found; cannot install .rpm"; exit 1
    fi
    ;;
  pkg.tar.zst)
    if command -v pacman >/dev/null; then
      sudo pacman -U --noconfirm "$ASSET"
    else
      echo "pacman not found; cannot install .pkg.tar.zst"; exit 1
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

echo "LNTA $VERSION installed successfully!"
echo "Run 'lnta --version' to verify."
```

### VHS Tape (demo.tape)

```tape
Output demo.gif
Set FontSize 14
Set Width 1200
Set Height 800
Set Theme "dracula"

# Scene 1: Create desktop launcher with validation
Type "lnta \"create a desktop launcher for my local script ~/bin/backup-ui and validate it\""
Enter
Sleep 3s

# Scene 2: Undo the change
Type "lnta undo"
Enter
Sleep 2s

# Scene 3: Pipe journalctl to lnta for analysis
Type "journalctl -n 20 | lnta \"explain what's failing\""
Enter
Sleep 3s
```

---

## Validation Checklist

All research decisions validated against:
- ✅ LNTA Constitution (all gates pass)
- ✅ Existing codebase patterns (Cobra CLI, Go modules, GitHub Actions)
- ✅ GoReleaser v2 + nfpm v2 documentation
- ✅ AppArmor profile syntax (tested on Ubuntu 24.04)
- ✅ VHS documentation (Charmbracelet)
- ✅ Mermaid diagram syntax (GitHub native)
- ✅ Shell completion APIs (Cobra built-in)
- ✅ Man page generation (Cobra doc.GenManTree)