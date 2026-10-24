# Phase 19: Zero-Cost Signed APT Repository on GitHub Pages (`reprepro`) & `lnta self-update` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (Native execution) or superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish an automated, zero-cost, signed Debian/Ubuntu APT repository hosted on GitHub Pages (`https://sm-me-dev.github.io/lnta`) via `reprepro`, complete with an instant one-line installer (`install-apt.sh`), a modern dark-mode landing page, automated release workflow integration, smart `lnta self-update` detection for standalone installations, and a Linuxbrew formula.

**Architecture:**
- **Packaging & Publishing Pipeline:** `.goreleaser.yaml` builds native `.deb` artifacts (amd64 and arm64). `.github/workflows/release.yml` extends the release job to import the dedicated release signing key (`GPG_PRIVATE_KEY`), initialize/update the `gh-pages` branch, populate the APT repository using `reprepro includedeb`, generate an `.nojekyll` file and dark-mode `index.html` landing page, and push the branch to GitHub Pages.
- **In-Place Self Update:** Standalone binary users who did not use `apt` can run `lnta self-update` (or `lnta upgrade`). It inspects the running binary with `dpkg -S` (and `rpm`/`pacman` fallbacks). If package-managed, it alerts the user to use `apt upgrade`. If standalone, it fetches release metadata from GitHub, checks semantic versioning, downloads the tarball + `checksums.txt`, verifies the SHA-256 hash in Go, and atomically swaps the binary.

**Tech Stack:** Go 1.23+, `reprepro`, GPG/Ed25519, GitHub Pages, GitHub Actions, POSIX shell (DEB822 APT standards).

**Spec:** User prompt Phase 19 specification.

## Global Constraints
- Go 1.23+ clean compilation (`go build ./...`) and tests (`go test -race -v ./...`).
- Zero Stubs: Never write `// TODO` or mock implementations.
- POSIX shell compliance for `scripts/apt/install-apt.sh` and `scripts/apt/generate-index.sh`.
- Modern Ubuntu/Debian DEB822 format (`/etc/apt/keyrings/lnta.gpg` with `0644` permissions, `/etc/apt/sources.list.d/lnta.list`).
- Non-breaking GitHub Actions: If `GPG_PRIVATE_KEY` is not yet set in repo secrets, the workflow logs a warning and builds an unsigned test repository index without failing the release job.
- `.nojekyll` present on `gh-pages` root so GitHub Pages serves `pool/` files containing underscores.

## Review Focus
1. **APT Repository Underscores / GitHub Pages 404:** GitHub Pages runs Jekyll by default, ignoring files or folders with underscores or periods. Must verify `.nojekyll` is generated in `gh-pages` root.
2. **Atomic Binary Replacement:** Replacing a currently running executable on Linux cannot be done by naive writing; it requires writing to a temp file on the *same filesystem* (`filepath.Dir(execPath)`) and calling `os.Rename`.
3. **Cross-Package Conflict Prevention:** `lnta self-update` must reliably identify when `/usr/bin/lnta` is owned by `dpkg` to prevent corrupting package manager manifests.
4. **Missing GPG Secret Graceful Handling:** First-time releases before the user runs Part 1 one-time GPG setup must not crash `release.yml`.
5. **Checksum & Architecture Matching:** Self-update must match `runtime.GOARCH` (`amd64` / `arm64`) and verify SHA-256 against `checksums.txt` before unarchiving.

---

### Task 1: Package Naming & Version Variables
**Files:**
- Modify: `version.go`
- Modify: `.goreleaser.yaml`
- Create: `Formula/lnta.rb`

- [ ] Change `const Version` in `version.go` to mutable `var Version = "0.6.0"`, `var Commit = "dev"`, and `var Date = "unknown"`.
- [ ] Explicitly specify `file_name_template` in `.goreleaser.yaml` for `deb`, `rpm`, and `archlinux` NFPM packages.
- [ ] Add `brews` configuration in `.goreleaser.yaml` with `skip: "{{ not .Env.HOMEBREW_TAP_GITHUB_TOKEN }}"`.
- [ ] Create `Formula/lnta.rb` with Linuxbrew formula structure.
- [ ] Run `go build ./...` to verify clean compilation.

---

### Task 2: APT Repository Configuration, Bootstrap Installer & Landing Page Generator
**Files:**
- Create: `scripts/apt/distributions`
- Create: `scripts/apt/install-apt.sh`
- Create: `scripts/apt/generate-index.sh`

- [ ] Create `scripts/apt/distributions` with `reprepro` distribution configuration.
- [ ] Create `scripts/apt/install-apt.sh` with root check, DEB822 keyrings and sources setup, error handling, and `apt-get install -y lnta`.
- [ ] Create `scripts/apt/generate-index.sh` producing dark-theme landing page with copyable commands, architecture tags, and download links.
- [ ] Validate shell syntax with `sh -n scripts/apt/install-apt.sh` and test `scripts/apt/generate-index.sh`.

---

### Task 3: Automated GitHub Pages APT Publishing in Release Workflow
**Files:**
- Modify: `.github/workflows/release.yml`

- [ ] Grant `pages: write` permission in `release.yml`.
- [ ] Add the post-build `Publish APT Repository to GitHub Pages` step.
- [ ] Ensure step handles secret presence/absence gracefully: imports `GPG_PRIVATE_KEY` if present, strips `SignWith: yes` and issues GitHub warning if absent.
- [ ] Manage `gh-pages` branch clone/orphan init, run `reprepro includedeb`, create `.nojekyll`, generate `index.html`, export keyring, copy `install-apt.sh`, and push to `gh-pages`.

---

### Task 4: In-Place `lnta self-update` Command & Verification Tests
**Files:**
- Create: `cmd/lnta/selfupdate.go`
- Create: `cmd/lnta/selfupdate_test.go`
- Modify: `cmd/lnta/main.go`

- [ ] Implement `compareSemVer`, `parseChecksums`, `verifySHA256`, `extractBinaryFromTarGz`, and `detectPackageManager` in `cmd/lnta/selfupdate.go`.
- [ ] Implement `selfUpdateCmd` with `--check` and `--force` flags.
- [ ] Register `selfUpdateCmd` in `cmd/lnta/main.go`.
- [ ] Write unit tests in `cmd/lnta/selfupdate_test.go` covering semver comparisons, checksum verification, archive extraction, and package manager detection.
- [ ] Run `go test -race -v ./cmd/lnta/...`.

---

### Task 5: Documentation & Installation Guides
**Files:**
- Modify: `README.md`

- [ ] Add **Option 1: Official APT Repository (Ubuntu / Debian — Recommended)** at the top of the Installation section with `curl -fsSL https://sm-me-dev.github.io/lnta/install-apt.sh | sudo sh`.
- [ ] Add collapsible `<details><summary>Manual APT Keyring & Sources Setup</summary>` block showing DEB822 commands.
- [ ] Document Homebrew / Linuxbrew Tap and `lnta self-update`.
- [ ] Retain Standalone Binary and Build from Source options.

---

### Task 6: End-to-End Verification
- [ ] Run `go test -race -v ./...`.
- [ ] Run `go build -o lnta ./cmd/lnta`.
- [ ] Test `./lnta self-update --help` and `./lnta self-update --check`.
- [ ] Verify shell scripts pass validation.
