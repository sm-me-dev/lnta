# Implementation Plan: Zero-Friction Linux Packaging

**Branch**: `008-zero-friction-linux-packaging` | **Date**: 2026-10-19 | **Spec**: specs/008-zero-friction-linux-packaging/spec.md

**Input**: Feature specification from `/specs/008-zero-friction-linux-packaging/spec.md`

**Note**: This template is filled in by the `/speckit-plan` command; its definition describes the execution workflow.

## Summary

This feature adds zero-friction Linux packaging to LNTA:
1. **GoReleaser + nfpm**: Cross-compile for linux/amd64 + linux/arm64 (CGO_ENABLED=0, stripped symbols), build .deb/.rpm/.pkg.tar.zst packages
2. **AppArmor .deb hook**: Package AppArmor profile into /etc/apparmor.d/lnta with postinst script running apparmor_parser -r for zero-config bwrap sandboxing on Ubuntu 24.04/26.04
3. **Universal installer**: scripts/install.sh detects arch/distro, downloads latest release artifact, verifies SHA-256, installs cleanly
4. **Man pages & completions**: Wire spf13/cobra/doc for lnta docs --man generating /usr/share/man/man1/lnta.1.gz and lnta completion <bash|zsh|fish>
5. **CI/CD**: GitHub Actions ci.yml (vet, golangci-lint, packs validate, race tests on Ubuntu 24.04 with bubblewrap) and release.yml (GoReleaser on v* tags)
6. **VHS demo + README**: demo.tape for 3-scene terminal GIF, high-converting README with architecture diagram, value props, install one-liners, pack contribution guide

Technical approach: Add .goreleaser.yaml with nfpm config, AppArmor profile template, install.sh script, docs/completion commands to Cobra CLI, GitHub Actions workflows, demo.tape, and rewritten README.md.

## Technical Context

**Language/Version**: Go 1.27.2

**Primary Dependencies**:
- `github.com/spf13/cobra` — CLI framework (existing, need to add docs/completion commands)
- `github.com/charmbracelet/lipgloss` — Output styling (existing)
- `github.com/goreleaser/goreleaser/v2` — Release automation (new dev dependency)
- `github.com/goreleaser/nfpm/v2` — Linux packaging (via GoReleaser)
- `vhs` (Charmbracelet) — Demo recording (dev dependency, not in Go module)
- `golangci-lint` — Linting (dev dependency)

**Storage**: N/A (packaging artifacts only)

**Testing**: Go standard library testing (`go test -v ./...`), plus integration testing of install script in Docker containers

**Target Platform**: Linux (primary: Ubuntu 24.04/26.04, Debian 12, Fedora 41, Arch Linux), amd64 + arm64

**Project Type**: CLI tool (packaging/release infrastructure)

**Performance Goals**:
- GoReleaser build: <5 min for full matrix (2 arches × 3 package formats + binaries)
- Install script: <30s end-to-end on clean system
- Binary size: <15MB (stripped, CGO_ENABLED=0)
- VHS recording: <60s for 3 scenes

**Constraints**:
- Must not break existing build/test workflow
- CGO_ENABLED=0 for static binaries (no cgo dependencies in codebase)
- AppArmor profile only installed via .deb (Ubuntu/Debian); .rpm/.pkg.tar.zst don't need it
- Install script must work without root for binary fallback (installs to ~/.local/bin)
- Man pages/completions generated at build time, included in packages
- Release workflow only triggers on v* git tags (semantic versioning)

**Scale/Scope**:
- 2 architectures (amd64, arm64)
- 3 package formats (.deb, .rpm, .pkg.tar.zst) + static tarballs
- 3 shell completions (bash, zsh, fish)
- 1 man page
- 1 install script
- 2 GitHub Actions workflows
- 1 VHS tape (3 scenes)
- 1 rewritten README

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Based on the LNTA Constitution (`.specify/memory/constitution.md`):

| Principle | Check | Status |
|-----------|-------|--------|
| I. Zero-Raw-Bash Execution Model | Packaging is build-time only; no runtime bash execution added. Install script is user-run, not LLM-invoked. | ✅ PASS |
| II. Instruction Pack Engine as Single Source of Truth | No new instruction packs or capabilities added; packaging is infra only | ✅ PASS |
| III. Zero-Latency Fingerprinting | Unchanged — fingerprinting runs at runtime, not build time | ✅ PASS |
| IV. Test-First & Zero Stubs | Install script testable in Docker; VHS tape is deterministic; GoReleaser config validated by CI | ✅ PASS |
| V. Deterministic Verification Gates | GoReleaser validates builds; CI runs vet/lint/tests; packages verified by installation tests | ✅ PASS |
| Architectural Constraints (Tech Stack) | Uses GoReleaser/nfpm (standard Go tooling); vhs for demo; no new runtime deps | ✅ PASS |
| Security Requirements | Install script verifies SHA-256; packages signed by GoReleaser; AppArmor profile restricts bwrap | ✅ PASS |
| Performance Standards | Build <5min, install <30s, binary <15MB — all within reasonable bounds | ✅ PASS |

**All gates pass.** No violations to justify.

## Project Structure

### Documentation (this feature)

```text
specs/008-zero-friction-linux-packaging/
├── plan.md              # This file (/speckit-plan command output)
├── research.md          # Phase 0 output (/speckit-plan command)
├── data-model.md        # Phase 1 output (/speckit-plan command)
├── quickstart.md        # Phase 1 output (/speckit-plan command)
├── contracts/           # Phase 1 output (/speckit-plan command)
└── tasks.md             # Phase 2 output (/speckit-tasks command - NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
.github/
├── workflows/
│   ├── ci.yml           # NEW: CI pipeline (vet, lint, packs validate, race tests)
│   └── release.yml      # NEW: Release pipeline (GoReleaser on v* tags)

scripts/
├── install.sh           # NEW: Universal one-line installer
├── apparmor-profile     # NEW: AppArmor profile template for .deb

cmd/lnta/
├── docs_cmd.go          # NEW: `lnta docs --man` command for man page generation
├── completion_cmd.go    # NEW: `lnta completion <bash|zsh|fish>` command
├── root_cmd.go          # MODIFIED: Add docs/completion subcommands

.goreleaser.yaml         # NEW: GoReleaser config with nfpm for .deb/.rpm/.pkg.tar.zst
demo.tape                # NEW: VHS script for 3-scene terminal GIF
README.md                # REWRITTEN: Architecture diagram, value props, install, pack guide
```

**Structure Decision**: Single project (Option 1). Packaging infrastructure files at repo root; new CLI commands in `cmd/lnta/` following existing pattern; GitHub Actions in `.github/workflows/`.

## Complexity Tracking

No Constitution Check violations — no complexity tracking needed.

---

## Phase 0: Research

All technical unknowns from the spec have been resolved using existing codebase patterns and standard Go/GoReleaser practices. No external research needed.

### Research Findings

| Topic | Decision | Rationale | Alternatives Considered |
|-------|----------|-----------|------------------------|
| GoReleaser version | v2 (latest stable) | Current major version; nfpm v2 integrated | v1 — deprecated; manual release scripts — error-prone |
| nfpm config | In .goreleaser.yaml under `nfpms` | Single source of truth for packaging | Separate nfpm.yaml — duplication |
| Cross-compilation | `goos: linux`, `goarch: [amd64, arm64]`, `env: CGO_ENABLED=0` | Standard Go cross-compile; no cgo in codebase | CGO_ENABLED=1 — requires cross-compiler toolchain |
| Symbol stripping | `-ldflags="-s -w"` in `ldflags` | Reduces binary ~30%; no debug info needed | UPX compression — adds complexity, marginal gain |
| AppArmor profile | Template in `scripts/apparmor-profile`, rendered by GoReleaser | Profile allows `userns` for bwrap; included only in .deb | Hardcode in .goreleaser.yaml — less maintainable |
| .deb postinst script | Inline in nfpm `scripts.postinstall` | Runs `apparmor_parser -r /etc/apparmor.d/lnta || true` | Separate script file — extra file |
| Install script detection | `uname -m` + `/etc/os-release` parsing | Portable across all target distros | `lsb_release` — not always installed |
| Checksum verification | `sha256sum -c` against GoReleaser-generated checksums.txt | Standard GoReleaser output; tamper-proof | Manual hash compare — error-prone |
| Man page generation | `cobra/doc.GenManTree` in `lnta docs --man` | Built into Cobra; outputs to directory | Manual roff — unmaintainable |
| Shell completions | `rootCmd.GenBashCompletion`, `GenZshCompletion`, `GenFishCompletion` | Built into Cobra; outputs to stdout | Manual completion scripts — duplication |
| CI runner | Ubuntu 24.04 (github-hosted) | Has bubblewrap pre-installed; matches target | Self-hosted — cost/complexity |
| golangci-lint | Binary install in CI (not Go module) | Faster, version-pinned, no go.mod pollution | As Go tool — slower, version drift |
| VHS tape | `demo.tape` with explicit timing/waits | Reproducible, version-controlled | Manual recording — not reproducible |
| README diagram | Mermaid (native GitHub render) | No external tooling; version-controlled | PlantUML/Image — not native on GitHub |

---

## Phase 1: Design & Contracts

### 1. Data Model (`data-model.md`)

See `specs/008-zero-friction-linux-packaging/data-model.md`

### 2. Contracts (`contracts/`)

See `specs/008-zero-friction-linux-packaging/contracts/`

### 3. Quickstart Validation Guide (`quickstart.md`)

See `specs/008-zero-friction-linux-packaging/quickstart.md`

---

## Generated Artifacts Summary

| Artifact | Path | Phase |
|----------|------|-------|
| Research Document | `specs/008-zero-friction-linux-packaging/research.md` | Phase 0 |
| Data Model | `specs/008-zero-friction-linux-packaging/data-model.md` | Phase 1 |
| Contracts | `specs/008-zero-friction-linux-packaging/contracts/` | Phase 1 |
| Quickstart | `specs/008-zero-friction-linux-packaging/quickstart.md` | Phase 1 |

Plan workflow complete. Ready for `/speckit-tasks` to generate implementation tasks.