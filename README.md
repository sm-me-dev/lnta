# LNTA — Linux Natural-Language Terminal Assistant

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go&logoColor=white" alt="Go Version">
  <img src="https://img.shields.io/badge/Platform-Linux-blue?logo=linux&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/github/v/release/sm-me/lnta?display_name=tag" alt="Latest Release">
</p>

LNTA grounds LLM actions in local system truth. It fingerprints the machine, routes your prompt to matching executable **Instruction Packs**, gathers ground-truth context, shows exactly what would be done — then waits for your approval before anything touches the system.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LNTA ARCHITECTURE                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   User Prompt  ──►  Fingerprint (<5ms)  ──►  Pack Router (triggers)        │
│       │                                            │                        │
│       ▼                                            ▼                        │
│   ┌─────────┐                              ┌───────────────┐               │
│   │ Context │ ◄───────────────────────────►│ Instruction   │               │
│   │ Gather  │     verify_cmd / context_cmd │ Pack Engine   │               │
│   └────┬────┘                              └───────┬───────┘               │
│        │                                           │                       │
│        ▼                                           ▼                       │
│   ┌───────────────────────────────────────────────────────┐              │
│   │              MUTATION GATE (huh.Confirm)              │              │
│   │  Shows exact command + cwd + risk level + rationale   │              │
│   │  Requires explicit human approval (Y/N)               │              │
│   └───────────────────────┬───────────────────────────────┘              │
│                           │                                               │
│                           ▼                                               │
│   ┌───────────────────────────────────────────────────────┐              │
│   │              EXECUTION SANDBOX (bwrap/Landlock)       │              │
│   │  • Read-only root FS (--ro-bind / /)                  │              │
│   │  • Masked secrets (~/.ssh, ~/.gnupg, ~/.aws, ~/.config)│              │
│   │  • Private /tmp (tmpfs)                               │              │
│   │  • Stdin = /dev/null, non-interactive env             │              │
│   └───────────────────────┬───────────────────────────────┘              │
│                           │                                               │
│                           ▼                                               │
│   ┌───────────────────────────────────────────────────────┐              │
│   │          VERIFICATION GATE (verify_cmd)               │              │
│   │  Deterministic shell check — no LLM self-reporting    │              │
│   │  Exit 0 = success, Exit ≠ 0 = retry with error        │              │
│   └───────────────────────┬───────────────────────────────┘              │
│                           │                                               │
│                           ▼                                               │
│   ┌───────────────────────────────────────────────────────┐              │
│   │              SNAPSHOT + UNDO (instant rollback)       │              │
│   │  Atomic backup → ~/.local/share/lnta/snapshots/       │              │
│   │  One command: lnta undo [run_id]                      │              │
│   └───────────────────────────────────────────────────────┘              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Why Safer Than Raw Bash Agents

| ❌ Raw Bash Agent | ✅ LNTA |
|-------------------|---------|
| Unbounded shell access — can `rm -rf /` | **Kernel Sandboxing**: `bwrap`/`Landlock` read-only FS, masked secrets, no network |
| No verification — assumes LLM succeeded | **Mandatory Verification Gates**: `verify_cmd` must pass deterministically |
| No rollback — mistakes are permanent | **Instant Rollback**: `lnta undo` reverts in ~1s from atomic snapshots |
| Prompt injection = system compromise | **Scoped Tools Only**: `inspect_system`, `write_scoped_file`, `mutate_system`, `complete_task` |
| Silent failures, no audit trail | **Full Audit Log**: Every mutation logged with command, cwd, rationale, timestamp |

---

## Quick Install

### One-Line Installer (All Distros)

```bash
# Downloads correct package (.deb/.rpm/.pkg.tar.zst) or static binary,
# verifies SHA-256, installs cleanly
curl -fsSL https://raw.githubusercontent.com/sm-me/lnta/main/scripts/install.sh | bash
```

### Distribution Packages

| Distro | Command |
|--------|---------|
| **Ubuntu / Debian** | `curl -fsSL https://github.com/sm-me/lnta/releases/latest/download/lnta_0.8.0_linux_amd64.deb -o lnta.deb && sudo dpkg -i lnta.deb` |
| **Fedora / RHEL / openSUSE** | `curl -fsSL https://github.com/sm-me/lnta/releases/latest/download/lnta-0.8.0-1.x86_64.rpm -o lnta.rpm && sudo rpm -i lnta.rpm` |
| **Arch / Manjaro** | `curl -fsSL https://github.com/sm-me/lnta/releases/latest/download/lnta-0.8.0-1-x86_64.pkg.tar.zst -o lnta.pkg.tar.zst && sudo pacman -U --noconfirm lnta.pkg.tar.zst` |
| **Any (static binary)** | `curl -fsSL https://github.com/sm-me/lnta/releases/latest/download/lnta_0.8.0_linux_amd64.tar.gz | tar -xz && sudo mv lnta /usr/local/bin/` |

> **Note**: On Ubuntu 24.04+, the `.deb` package automatically installs the AppArmor profile for `bwrap`, enabling zero-config kernel sandboxing out of the box.

---

## Usage

```bash
# One-shot: describe what you want
lnta "create a .desktop launcher for my backup script at ~/bin/backup-ui"

# Interactive chat with history
lnta chat

# Explain mode (read-only, no mutations possible)
lnta --explain "why is nginx failing?"

# Dry-run: see diffs without writing
lnta --dry-run "create a systemd user service for my app"

# Undo a previous run
lnta undo

# Fix the last failed command (requires shell integration)
lnta fix

# Pipe logs for analysis
journalctl -u nginx -n 50 | lnta "explain the error"

# Generate shell integration (Ctrl+G widget, lnta fix, last-cmd capture)
eval "$(lnta init zsh)"   # or bash, fish

# Generate man page
lnta docs --man

# Validate instruction packs
lnta packs validate

# System diagnostics
lnta doctor
```

### Example Output

```
## System Context
- os: ubuntu 26.04 (Ubuntu 26.04 LTS)
- shell: /usr/bin/zsh
- session: wayland / ubuntu:GNOME
- home: /home/user
- cwd: /home/user/Codes/project
- binaries: bwrap ✓, systemctl ✓, desktop-file-validate ✓, ss ✓

## Matched Pack (1)
- Linux Desktop Entries (linux-desktop-entries)
  required_bins: [desktop-file-validate]
  context_cmd: desktop-file-validate --version
  verify_cmd: desktop-file-validate "${target}"

# Linux Desktop Entries
Create, validate, and install .desktop launchers in ~/.local/share/applications/.

## Plan
1. Create ~/.local/share/applications/backup-ui.desktop with Exec=/home/user/bin/backup-ui
2. Run desktop-file-validate on the created file

## Result
✅ Verification Receipt (run-20260115T143022)
  • Status: COMPLETED
  • Verified: /home/user/.local/share/applications/backup-ui.desktop
  • desktop-file-validate: passed

Hint: Run 'lnta undo run-20260115T143022' to revert.
```

---

## Shell Integration

Add to your shell RC file (`.zshrc`, `.bashrc`, `config.fish`):

```bash
# zsh
eval "$(lnta init zsh)"

# bash
eval "$(lnta init bash)"

# fish
lnta init fish | source
```

This enables:
- **`Ctrl+G`**: Type natural language at prompt, press `Ctrl+G` → replaced with verified command
- **`lnta fix`**: After a command fails, run `lnta fix` to auto-capture and remediate
- **Last-command capture**: `_LNTA_LAST_CMD` / `_LNTA_LAST_EXIT` exported on every prompt

---

## Instruction Packs

LNTA's capabilities come from **Instruction Packs** — Markdown files with YAML frontmatter:

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
  - "~/.config/autostart/*.desktop"
required_bins:
  - desktop-file-validate
context_cmd: desktop-file-validate --version
verify_cmd: desktop-file-validate "${target}"
---
# Markdown body guides the LLM...
```

### Built-in Packs

| Pack ID | Triggers | Purpose |
|---------|----------|---------|
| `linux-desktop-entries` | desktop, .desktop, launcher | Create/validate `.desktop` launchers |
| `systemd-user-services` | systemd, service, user service | Manage user systemd units |
| `network-ports-processes` | port, listening, ss, netstat | Inspect network state |
| `general-diagnostics` | (fallback) | Generic system diagnostics |
| `docker-compose-diagnostics` | docker, compose | Debug Docker Compose |
| `git-repo-hygiene` | git, repo, hygiene | Repository health checks |
| `ssh-gpg-permissions` | ssh, gpg, permissions | Fix SSH/GPG file permissions |
| `systemd-timers-cron` | timer, cron, schedule | Manage systemd timers |
| `udev-device-rules` | udev, device, rules | Create udev rules |
| `ufw-firewall-ports` | ufw, firewall, port | Manage UFW rules |
| `disk-mounts-fstab` | mount, fstab, disk | Configure `/etc/fstab` |

### Contributing New Packs

1. Create `packs/your-pack-name.md` with the schema above
2. Test locally: `lnta packs validate --strict`
3. Add trigger scoring test, `allowed_paths` coverage test, `verify_cmd` determinism test
4. PR to `main` — CI validates automatically

---

## Demo

<p align="center">
  <img src="demo.gif" alt="LNTA Demo" width="800">
</p>

*The demo shows: (1) creating a validated desktop launcher with fingerprint + sandbox + diff + receipt, (2) instant `lnta undo`, (3) pipe ingestion from `journalctl` with LLM analysis.*

---

## Architecture Deep Dive

### Zero-Raw-Bash Execution Model

The LLM **never** gets raw shell access. It operates through four strictly typed tools:

1. **`inspect_system`** — Read-only commands in `bwrap` sandbox (`--ro-bind / /`, masked secrets, no network)
2. **`write_scoped_file`** — Atomic writes with backup, validated against pack's `allowed_paths` glob
3. **`mutate_system`** — Pauses for human confirmation via `huh.Confirm` (shows exact command, cwd, risk, rationale)
4. **`complete_task`** — Triggers pack's `verify_cmd`; cannot exit success until verification passes

### Deterministic Verification Gates

Every operation has a `verify_cmd` in its Instruction Pack:
- Runs **without LLM involvement**
- Returns exit code 0 **only on true completion**
- Produces machine-parseable output for CI integration
- Single source of truth for "task complete" — no LLM self-reporting

### Zero-Latency Fingerprinting

System fingerprint runs at startup in **<5ms** with **zero LLM calls**:
- OS, kernel, distro, shell, session type
- Available binaries (bwrap, systemctl, validators, etc.)
- User, home, cwd, PATH
- Independently benchmarked: `go test -bench=BenchmarkFingerprint`

---

## Development

```bash
# Build
go build ./...

# Test (includes race detector)
go test -race -v ./...

# Lint
golangci-lint run

# Validate packs
lnta packs validate --strict

# Fingerprint benchmark
go test -bench=BenchmarkFingerprint -benchtime=1s ./internal/fingerprint/
```

### Project Structure

```
cmd/lnta/                    # Cobra CLI
  ├── main.go                # Entry point, root command
  ├── docs_cmd.go            # Man page generation
  ├── init_cmd.go            # Shell integration generator
  ├── fix_cmd.go             # Last-command fix workflow
  └── ...

internal/
  ├── agent/                 # LLM agent orchestrator
  ├── fingerprint/           # <5ms system fingerprinter
  ├── packs/                 # Instruction pack engine + router
  ├── sandbox/               # bwrap/Landlock sandbox + transactional writer
  ├── shell/                 # Pipe handling, /dev/tty, shell scripts
  ├── mcp/                   # MCP server (JSON-RPC over stdio)
  ├── audit/                 # Mutation audit logging
  └── ui/                    # Terminal rendering (lipgloss)

packs/                       # Embedded instruction packs (embed.FS)
  ├── linux-desktop-entries.md
  ├── systemd-user-services.md
  ├── network-ports-processes.md
  └── ...

specs/                       # Feature specifications (SpecKit)
  ├── 001-core-scaffold/
  ├── 002-instruction-packs/
  ├── 003-sandbox/
  ├── 004-terminal-ui/
  ├── 005-kernel-hardening/
  ├── 006-unix-pipe-shell/
  ├── 007-instruction-pack-library/
  └── 008-zero-friction-packaging/
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Links

- **GitHub**: https://github.com/sm-me/lnta
- **Releases**: https://github.com/sm-me/lnta/releases
- **Issues**: https://github.com/sm-me/lnta/issues