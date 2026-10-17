# LNTA — Linux Natural-Language Terminal Assistant

LNTA grounds LLM actions in local system truth. It fingerprints the machine,
routes a user prompt to the matching executable instruction pack(s), gathers
ground-truth context, and shows exactly what would be done — before anything
touches the system.

> **Phase 1 scaffold.** Core scaffolding, the zero-latency system fingerprinter,
> the executable instruction pack engine, and three production packs. No system
> mutation is performed in this phase.

## Architecture non-negotiables

- **Language & stack**: Go 1.23+. CLI via `spf13/cobra`; YAML frontmatter via
  `adrg/frontmatter`.
- **No raw unbounded bash**: The LLM never gets an unrestricted shell. Actions
  are strictly typed and go through scoped, approved primitives.
- **Zero stubs**: Every phase compiles cleanly (`go build ./...`) and passes
  unit/integration tests (`go test -v ./...`).

## Directory layout

```
cmd/lnta/            Cobra CLI (lnta <prompt>, chat, undo, packs list)
internal/fingerprint/   Zero-latency system fingerprinter (<5 ms, no LLM)
internal/packs/     Executable instruction pack engine + local intent router
internal/sandbox/   (placeholder — future phase)
internal/agent/     (placeholder — future phase)
internal/audit/     (placeholder — future phase)
packs/              Embedded default instruction packs (embed.FS)
  linux-desktop-entries.md
  systemd-user-services.md
  network-ports-processes.md
  general-diagnostics.md          (fallback pack)
~/.config/lnta/packs/   User pack overrides (same id wins over embedded)
```

## Quick start

```bash
go build ./...
go test -v ./...
go run ./cmd/lnta "create a .desktop launcher for my app"
```

Example output:

```
## System Context
- os: ubuntu 26.04 (Ubuntu 26.04 LTS)
- shell: /usr/bin/zsh
- session: wayland / ubuntu:GNOME
- home: /home/sm-me
- cwd: /home/sm-me/Codes/linux/lnta
- user: sm-me (uid=1000 gid=1000)
- binaries:
    - bwrap: true
    - systemctl: true
    - desktop-file-validate: true
    - ss: true
    - ufw: true
    - git: true

## Matched Pack (1)
- Linux Desktop Entries (linux-desktop-entries)
  required_bins: [desktop-file-validate]
  context_cmd: desktop-file-validate --version
  verify_cmd: desktop-file-validate "${target}"

# Linux Desktop Entries
Create, validate, and install `.desktop` launchers in
~/.local/share/applications/.
...
```

## Commands

| Command | Purpose |
|---------|---------|
| `lnta <prompt>` | Route prompt to matching pack(s), show context + what would be done |
| `lnta chat` | Interactive session (stub in Phase 1) |
| `lnta undo <run_id>` | Undo a previous run (stub in Phase 1) |
| `lnta packs list` | List loaded instruction packs |

## Instruction pack schema

Each pack is a Markdown file with YAML frontmatter:

```yaml
---
id: linux-desktop-entries
name: Linux Desktop Entries
triggers:
  - desktop
  - .desktop
  - launcher
allowed_paths:
  - "~/.local/share/applications/*.desktop"
required_bins:
  - desktop-file-validate
context_cmd: desktop-file-validate --version   # ground-truth fact gathering
verify_cmd: desktop-file-validate "${target}"   # deterministic completion check
---
# Markdown body — guidance for the LLM
```

- `triggers` are matched against the user prompt via tokenized keyword + bigram
  scoring (top 1–2 packs above threshold).
- `allowed_paths` support `~` expansion and glob patterns.
- `context_cmd` runs automatically when a pack is selected (fast, read-only).
- `verify_cmd` is the deterministic shell check run before allowing task
  completion.

## Running tests

```bash
go build ./...
go vet ./...
go test -count=1 ./...
```

Fingerprinting is asserted to run under 5 ms with zero LLM calls.

## License

Private / internal.