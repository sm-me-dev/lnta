# Feature Specification: Zero-Friction Linux Packaging

**Feature Branch**: `008-zero-friction-linux-packaging`

**Created**: 2026-10-19

**Status**: Draft

**Input**: User description: "Read `AGENTS.md`. Execute **Phase 8: Zero-Friction Linux Packaging (`.goreleaser.yaml`, AppArmor `.deb` hook, Man Pages, and VHS Demo)**."

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - One-Line Install via `scripts/install.sh` (Priority: P1)

A user on any Linux distribution (Ubuntu 24.04/26.04, Debian, Fedora, Arch, openSUSE) runs a single command:
```bash
curl -fsSL https://raw.githubusercontent.com/sm-me/lnta/main/scripts/install.sh | bash
```
The script auto-detects architecture (amd64/arm64) and distro, downloads the appropriate `.deb`/`.rpm`/`.pkg.tar.zst` or static binary from the latest GitHub release, verifies SHA-256 checksums, and installs cleanly with zero manual steps.

**Why this priority**: Zero-friction installation is the #1 adoption driver for CLI tools. Users should never need to read docs to install.

**Independent Test**: Can be fully tested by running the script in Docker containers for each target distro/arch and verifying the `lnta` binary is on PATH and runs correctly.

**Acceptance Scenarios**:
1. **Given** Ubuntu 24.04 amd64, **When** install script runs, **Then** `.deb` is downloaded, checksum verified, installed via `dpkg -i`, and `lnta --version` works
2. **Given** Fedora 41 arm64, **When** install script runs, **Then** `.rpm` is downloaded, checksum verified, installed via `rpm -i`, and `lnta --version` works
3. **Given** Arch Linux amd64, **When** install script runs, **Then** `.pkg.tar.zst` is downloaded, checksum verified, installed via `pacman -U`, and `lnta --version` works
4. **Given** Unsupported distro (e.g., Alpine), **When** install script runs, **Then** static binary is downloaded, checksum verified, placed in `/usr/local/bin`, and `lnta --version` works
5. **Given** Network failure during download, **When** install script runs, **Then** clear error message with manual instructions shown

---

### User Story 2 - AppArmor Profile Auto-Installed via `.deb` (Priority: P1)

When a user installs the `.deb` package on Ubuntu 24.04/26.04, the AppArmor profile for `bwrap` is automatically installed to `/etc/apparmor.d/lnta` and `apparmor_parser -r /etc/apparmor.d/lnta` runs in the `postinst` hook, enabling zero-config `bwrap` sandboxing out of the box without any manual steps.

**Why this priority**: On Ubuntu 24.04+, `kernel.apparmor_restrict_unprivileged_userns=1` blocks `bwrap` by default. Without the AppArmor profile, LNTA falls back to Landlock (which has limited coverage). The `.deb` package must solve this transparently.

**Independent Test**: Can be fully tested by installing the `.deb` in a fresh Ubuntu 24.04 container and verifying `apparmor_parser -r /etc/apparmor.d/lnta` succeeds and `bwrap --ro-bind / / -- true` works.

**Acceptance Scenarios**:
1. **Given** Fresh Ubuntu 24.04 container, **When** `.deb` installed via `dpkg -i`, **Then** `/etc/apparmor.d/lnta` exists with correct profile and `apparmor_status` shows it loaded
2. **Given** `.deb` installed, **When** `lnta doctor` runs, **Then** "Kernel Sandbox" check passes (bwrap probe OK)
3. **Given** `.deb` removed via `dpkg -r`, **Then** AppArmor profile is removed/cleaned up

---

### User Story 3 - Man Pages & Shell Completions (Priority: P2)

Running `lnta docs --man` generates `/usr/share/man/man1/lnta.1.gz` (installed by packages) and `lnta completion <bash|zsh|fish>` outputs shell completion scripts that work correctly when sourced.

**Why this priority**: Professional CLI tools provide man pages and completions. Users expect `man lnta` and tab-completion to work.

**Independent Test**: Can be fully tested by running `lnta docs --man`, verifying the man page renders correctly with `man -l`, and running `lnta completion bash` and sourcing it to verify tab-completion works.

**Acceptance Scenarios**:
1. **Given** `lnta docs --man` runs, **Then** man page generated at expected path with all commands documented
2. **Given** `man lnta` runs after package install, **Then** formatted man page displays with synopsis, description, options, commands, examples
3. **Given** `lnta completion bash` sourced, **Then** `lnta <TAB>` shows commands/flags
4. **Given** `lnta completion zsh` sourced, **Then** `lnta <TAB>` shows commands/flags with descriptions
5. **Given** `lnta completion fish` sourced, **Then** `lnta <TAB>` shows commands/flags

---

### User Story 4 - Reproducible VHS Demo GIF (Priority: P2)

A `demo.tape` script using Charmbracelet `vhs` records a terminal GIF showing:
1. `lnta "create a desktop launcher for my local script ~/bin/backup-ui and validate it"` — demonstrating <5ms fingerprint, `bwrap` read-only check, unified diff, `desktop-file-validate` receipt
2. `lnta undo` reverting it in 1 second
3. `journalctl -n 20 | lnta "explain what's failing"` — demonstrating pipe ingestion + LLM analysis

**Why this priority**: Visual demos convert visitors to users. A crisp, reproducible GIF on the README is worth 1000 words of documentation.

**Independent Test**: Can be fully tested by running `vhs demo.tape` and verifying `demo.gif` is produced with all three scenes.

**Acceptance Scenarios**:
1. **Given** `vhs demo.tape` runs, **Then** `demo.gif` is generated with 3 scenes
2. **Given** `demo.gif` viewed, **Then** Scene 1 shows fingerprint + bwrap check + diff + validation receipt
3. **Given** `demo.gif` viewed, **Then** Scene 2 shows `lnta undo` reverting in ~1s
4. **Given** `demo.gif` viewed, **Then** Scene 3 shows pipe ingestion + LLM explanation

---

### User Story 5 - High-Converting README.md (Priority: P2)

The `README.md` leads with:
- Architecture diagram (Mermaid) showing Kernel Sandboxing → Mandatory Verification Gates → Instant Rollback
- Clear value prop: "Why safer than raw bash agents" (3 pillars)
- One-line installers for all distros
- Instruction Pack contribution guide

**Why this priority**: The README is the landing page. It must communicate the unique value proposition (sandboxing + verification + rollback) immediately and make installation trivial.

**Independent Test**: Can be fully tested by rendering the README in GitHub and verifying all sections render correctly, links work, and install one-liners are copy-pasteable.

**Acceptance Scenarios**:
1. **Given** README rendered, **Then** Architecture diagram (Mermaid) visible at top
2. **Given** README rendered, **Then** "Why safer than raw bash agents" section with 3 pillars
4. **Given** README rendered, **Then** Install one-liners for .deb/.rpm/.pkg.tar.zst/binary
5. **Given** README rendered, **Then** "Contributing Instruction Packs" section with schema reference

---

### User Story 6 - GoReleaser CI/CD Pipeline (Priority: P1)

GitHub Actions workflows:
- `ci.yml`: Runs `go vet`, `golangci-lint`, `lnta packs validate`, `go test -race -v ./...` on Ubuntu 24.04 with `bubblewrap` installed
- `release.yml`: Triggers GoReleaser on `v*` git tags, publishes `.deb`, `.rpm`, `.pkg.tar.zst`, binaries, checksums, and release notes

**Why this priority**: Automated releases ensure consistent, reproducible artifacts. CI catches regressions before merge.

**Independent Test**: Can be fully tested by pushing a `v0.8.0` tag and verifying all artifacts are published to GitHub Releases.

**Acceptance Scenarios**:
1. **Given** PR opened, **When** CI runs, **Then** all checks pass (vet, lint, packs validate, tests with race detector)
2. **Given** `v0.8.0` tag pushed, **When** release workflow runs, **Then** GoReleaser builds for linux/amd64 + linux/arm64 with CGO_ENABLED=0, strips symbols (-s -w)
3. **Given** Release published, **Then** Artifacts include: lnta_linux_amd64.deb, lnta_linux_arm64.deb, lnta_linux_amd64.rpm, lnta_linux_arm64.rpm, lnta_linux_amd64.pkg.tar.zst, lnta_linux_arm64.pkg.tar.zst, checksums.txt, lnta_linux_amd64.tar.gz, lnta_linux_arm64.tar.gz

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST provide `.goreleaser.yaml` with cross-compilation for `linux/amd64` and `linux/arm64`, `CGO_ENABLED=0`, and `-ldflags="-s -w"` for stripped symbols
- **FR-002**: System MUST configure `nfpms` to build `.deb`, `.rpm`, and `archlinux` (`.pkg.tar.zst`) packages
- **FR-003**: `.deb` package MUST declare `recommends: ["bubblewrap", "desktop-file-validate"]` in control file
- **FR-004**: `.deb` package MUST include AppArmor profile at `/etc/apparmor.d/lnta` with `postinst` script running `apparmor_parser -r /etc/apparmor.d/lnta || true`
- **FR-005**: `.deb` package MUST include `prerm`/`postrm` scripts to clean up AppArmor profile on removal
- **FR-006**: System MUST provide `scripts/install.sh` that detects arch/distro, downloads latest release artifact, verifies SHA-256, and installs
- **FR-007**: System MUST wire `spf13/cobra/doc` to generate man pages via `lnta docs --man` command
- **FR-008**: System MUST generate shell completion files for `bash`, `zsh`, `fish` via `lnta completion <shell>`
- **FR-009**: System MUST create `.github/workflows/ci.yml` running vet, golangci-lint, packs validate, race tests on Ubuntu 24.04 with bubblewrap
- **FR-010**: System MUST create `.github/workflows/release.yml` triggering GoReleaser on `v*` tags
- **FR-011**: System MUST create `demo.tape` for `vhs` recording a 3-scene terminal GIF
- **FR-012**: System MUST rewrite `README.md` with architecture diagram, value props, install one-liners, pack contribution guide

### Key Entities

- **GoReleaser Config**: `.goreleaser.yaml` — defines build matrix, nfpm packaging, release artifacts
- **AppArmor Profile**: `/etc/apparmor.d/lnta` — allows unprivileged user namespaces for `bwrap`
- **Install Script**: `scripts/install.sh` — universal one-liner installer
- **Man Page**: `lnta.1.gz` — installed to `/usr/share/man/man1/`
- **Completion Scripts**: Generated by `lnta completion <shell>`
- **VHS Tape**: `demo.tape` — reproducible demo script
- **CI Workflow**: `.github/workflows/ci.yml` — pre-merge validation
- **Release Workflow**: `.github/workflows/release.yml` — automated release on tag

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: `curl -fsSL .../install.sh | bash` installs `lnta` successfully on Ubuntu 24.04, Debian 12, Fedora 41, Arch Linux (amd64 + arm64 each)
- **SC-002**: `.deb` install on Ubuntu 24.04 auto-enables `bwrap` sandboxing (doctor check passes)
- **SC-003**: `man lnta` and `lnta <TAB>` work after package install
- **SC-004**: `vhs demo.tape` produces `demo.gif` with all 3 scenes in <60s
- **SC-005**: CI pipeline passes on PR (vet, lint, packs validate, race tests)
- **SC-006**: Release workflow publishes all 10+ artifacts on `v*` tag push
- **SC-007**: `go build ./... && go vet ./... && go test -race -v ./... && lnta packs validate` all pass locally
- **SC-008**: Binary size < 15MB (stripped, CGO_ENABLED=0)

---

## Assumptions

- Target architectures: `linux/amd64`, `linux/arm64` (covers >99% of Linux users)
- Target package formats: `.deb` (Debian/Ubuntu), `.rpm` (Fedora/RHEL/openSUSE), `.pkg.tar.zst` (Arch/Manjaro)
- Static binary fallback for unsupported distros (Alpine, NixOS, etc.)
- GoReleaser v2+ with nfpm v2+
- GitHub Actions runners: Ubuntu 24.04 (has bubblewrap by default)
- `vhs` (Charmbracelet) available for demo recording
- Mermaid diagrams render natively on GitHub README
- AppArmor profile only needed on Ubuntu/Debian (handled by .deb postinst)
- Version scheme follows semantic versioning from Constitution (currently v0.7.0 → v0.8.0 for this phase)