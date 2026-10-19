# Quickstart: Zero-Friction Linux Packaging

Validate that the Phase 8 packaging infrastructure works end-to-end.

---

## Prerequisites

- Go 1.23+ installed
- `go install` available
- `curl` or `wget`
- `sha256sum` (standard on Linux)
- Docker (optional, for cross-distro testing)
- `golangci-lint` (for CI pre-commit check)

---

## Step 1: Build & Verify Locally

```bash
# Build and verify all checks pass
go build ./...
go vet ./...
go test -race -v ./...
lnta packs validate
```

Expected: All pass with zero errors.

---

## Step 2: Generate GoReleaser Config

If not already present, create `.goreleaser.yaml`:

```bash
# The file should already exist from the speckit-plan output
# Verify it exists and has correct structure:
ls -la .goreleaser.yaml
```

Expected: `.goreleaser.yaml` exists with builds for linux/amd64 + linux/arm64, nfpm configs for deb/rpm/archlinux, CGO_ENABLED=0, -s -w flags.

---

## Step 3: Run Install Script (Local Test)

```bash
# Generate a mock release and test the install script
# Create a test release asset first (or use existing)
chmod +x scripts/install.sh
# Run in a dry-run or with a known-release binary
./scripts/install.sh
```

Expected: Script downloads, verifies checksum, and installs `lnta` binary to PATH.

---

## Step 4: Test .deb Package Build

```bash
# Build the .deb package via GoReleaser (cross-compilation)
# Requires GoReleaser installed or run via Docker
goreleaser release --clean

# Or via Docker:
docker run --rm -v "$PWD":/work -w /work \
  goreleaser/goreleaser:latest release --clean

# Verify .deb output
ls -la dist/
```

Expected: `.deb` file produced in `dist/` directory.

---

## Step 5: Verify .deb AppArmor Integration

```bash
# On a Debian/Ubuntu system (or Docker container):
dpkg -i dist/lnta_0.8.0_linux_amd64.deb

# Check AppArmor profile installed
ls -la /etc/apparmor.d/lnta

# Load the profile
apparmor_parser -r /etc/apparmor.d/lnta || true

# Verify bwrap now works
bwrap --ro-bind / / -- true
echo "bwrap sandboxing enabled: $?"
```

Expected: `/etc/apparmor.d/lnta` exists; `apparmor_parser` runs without error; `bwrap` user namespace works.

---

## Step 6: Test Shell Completions

```bash
# Generate and source completions
lnta completion bash > /etc/bash_completion.d/lnta
lnta completion zsh > "${ZDOTDIR:-~}/.zsh_completions/lnta"
lnta completion fish > "${XDG_CONFIG_HOME:-~/.config}/fish/completions/lnta.fish"

# Test tab completion
type lnta
# Should show: lnta [flags] [prompt]...
```

Expected: All 3 shells have working completion with commands/flags.

---

## Step 7: Run Man Page Generation

```bash
lnta docs --man
ls -la /usr/share/man/man1/lnta.1.gz  # or ./man/lnta.1.gz locally
man lnta  # should render properly
```

Expected: Man page generated at `/usr/share/man/man1/lnta.1.gz` and renders correctly.

---

## Step 8: Verify VHS Demo

```bash
# Generate the demo.tape if not present
# Run vhs to produce the GIF
which vhs  # should be available
vhs demo.tape

# Expected output: demo.gif created with 3 scenes
ls -la demo.gif
```

Expected: `demo.gif` produced showing:
- Scene 1: `lnta "create a desktop launcher..."` with <5ms fingerprint, bwrap check, diff, validation
- Scene 2: `lnta undo` reverting in ~1s
- Scene 3: `journalctl -n 20 | lnta "explain what's failing"` with pipe ingestion

---

## Step 9: Verify README.md Structure

```bash
# Check all key sections are present
grep -c "Architecture Diagram\|Why Safer\|Installation\|Contributing" README.md
# Should be ≥ 4

# Verify install one-liners are present
grep -E "curl.*install\.sh|apt.*install|lnta.*deb|dnf.*install" README.md
```

Expected: README.md leads with architecture diagram (Mermaid), value proposition (3 pillars), install one-liners for all distros, and contributing guide for Instruction Packs.

---

## Full Validation Command

```bash
# Run everything that can be checked locally
go build ./... && \
go vet ./... && \
go test -race -v ./... && \
lnta packs validate && \
lnta docs --man 2>&1 | head -5 && \
ls dist/lnta_*.deb dist/*.rpm dist/*.pkg.tar.zst 2>/dev/null && \
echo "All quickstart checks passed!"
```

Expected: All checks pass, confirming repository is ready for public release.