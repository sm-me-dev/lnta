# LNTA Pack Authoring Guide: Extend LNTA in 5 Minutes

> How to create, test, and distribute custom Executable Instruction Packs for the Linux Natural-Language Terminal Assistant (`lnta`).

---

## Table of Contents

- [Overview](#overview)
- [5-Minute Quickstart Tutorial](#5-minute-quickstart-tutorial)
  - [Step 1: Create the User Pack Directory](#step-1-create-the-user-pack-directory)
  - [Step 2: Write the Pack File (`wireguard-vpn.md`)](#step-2-write-the-pack-file-wireguard-vpnmd)
  - [Step 3: Validate the Pack](#step-3-validate-the-pack)
  - [Step 4: Test in Dry-Run Mode](#step-4-test-in-dry-run-mode)
- [Frontmatter Specification](#frontmatter-specification)
  - [`id` (Required)](#id-required)
  - [`name` (Required)](#name-required)
  - [`triggers` (Required)](#triggers-required)
  - [`allowed_paths` (Required for File Mutations)](#allowed_paths-required-for-file-mutations)
  - [`required_bins` (Recommended)](#required_bins-recommended)
  - [`context_cmd` (Optional)](#context_cmd-optional)
  - [`verify_cmd` (Crucial)](#verify_cmd-crucial)
- [Writing the Markdown Runbook Body](#writing-the-markdown-runbook-body)
- [Testing & Linting Packs (`lnta packs validate`)](#testing--linting-packs-lnta-packs-validate)
  - [CLI Flags & Options](#cli-flags--options)
  - [Interpreting Validator Output](#interpreting-validator-output)
  - [Automating in CI/CD](#automating-in-cicd)
- [Pack Priority & Overrides](#pack-priority--overrides)
- [Real-World Reference Examples](#real-world-reference-examples)

---

## Overview

In LNTA, **Instruction Packs** are self-contained Markdown files (`.md`) with YAML frontmatter. They define:
1. **Routing Triggers**: Natural-language keywords and phrases that activate the pack (<5ms router).
2. **Safety Boundaries**: The exact directory and file globs LNTA is permitted to modify (`allowed_paths`).
3. **Ground-Truth Gathering**: Sandboxed, read-only commands that discover current system state (`context_cmd`).
4. **Deterministic Verification**: Objective shell commands that must pass before task completion (`verify_cmd`).
5. **Domain Runbook**: Specialized domain knowledge, examples, and edge-case handling for the LLM.

User packs live in `~/.config/lnta/packs/` and take precedence over embedded system packs.

---

## 5-Minute Quickstart Tutorial

Let's build a custom pack to manage **WireGuard Client VPN configurations** under `~/.config/wireguard/`.

### Step 1: Create the User Pack Directory

```bash
mkdir -p ~/.config/lnta/packs
```

### Step 2: Write the Pack File (`wireguard-vpn.md`)

Create `~/.config/lnta/packs/wireguard-vpn.md`:

```markdown
---
id: wireguard-vpn
name: WireGuard Client VPN
triggers:
  - wireguard
  - wg
  - vpn
  - wg-quick
allowed_paths:
  - "~/.config/wireguard/*.conf"
required_bins:
  - wg
  - wg-quick
context_cmd: wg show 2>&1 || true
verify_cmd: wg-quick strip "${target}" >/dev/null && echo "config valid"
---
# WireGuard Client VPN

Create and manage client WireGuard configurations under `~/.config/wireguard/`.

## What this pack covers
- Generating client interface sections (`[Interface]`) with PrivateKey and Address.
- Configuring remote peer sections (`[Peer]`) with PublicKey, AllowedIPs, and Endpoint.
- Validating configuration syntax via `wg-quick strip`.

## Safety Rules
- Files must be created with 0600 permissions.
- Never write private keys to unencrypted public directories.
- Always use `${target}` in verification checks.
```

### Step 3: Validate the Pack

Run LNTA's built-in pack validator:

```bash
lnta packs validate ~/.config/lnta/packs/wireguard-vpn.md
```

```text
✓ Validating pack: wireguard-vpn (/home/user/.config/lnta/packs/wireguard-vpn.md)
  [OK] id: wireguard-vpn (kebab-case)
  [OK] name: WireGuard Client VPN
  [OK] triggers: 4 defined (no collisions)
  [OK] allowed_paths: ~/.config/wireguard/*.conf
  [OK] required_bins: wg ✓, wg-quick ✓
  [OK] verify_cmd: uses ${target} placeholder

Result: VALID (0 errors, 0 warnings)
```

### Step 4: Test in Dry-Run Mode

Test routing and execution without modifying disk:

```bash
lnta --dry-run "create a wireguard client config for office-vpn with IP 10.0.0.2/24"
```

LNTA matches `wireguard-vpn`, gathers ground truth via `wg show`, and previews the generated configuration file.

---

## Frontmatter Specification

Every pack requires a YAML frontmatter block enclosed by triple hyphens (`---`):

```yaml
---
id: service-or-task-name
name: Human Readable Name
triggers:
  - primary keyword
  - secondary phrase
allowed_paths:
  - "~/.config/app/*.conf"
required_bins:
  - app-cli
context_cmd: app-cli status --json
verify_cmd: app-cli check-syntax "${target}"
---
```

---

### `id` (Required)
- **Type**: `string`
- **Format**: Lowercase kebab-case: `^[a-z0-9]+(-[a-z0-9]+)*$`
- **Example**: `docker-compose-diagnostics`
- **Rules**: Must be globally unique across all loaded packs. If a user pack shares the `id` of an embedded pack, the user pack overrides the embedded one.

---

### `name` (Required)
- **Type**: `string`
- **Example**: `Docker Compose Diagnostics`
- **Purpose**: Human-readable label displayed in status lines, execution summaries, and TUI session logs.

---

### `triggers` (Required)
- **Type**: `[]string`
- **Example**:
  ```yaml
  triggers:
    - ufw
    - firewall
    - open port
    - block ip
  ```
- **Routing Engine**: LNTA tokenizes user prompts into unigrams and bigrams, calculating term overlap against pack triggers in <5ms.
- **Best Practice**: Include both tool names (`ufw`, `iptables`) and intent phrases (`open port`, `allow incoming connection`). Avoid single common stop-words (e.g. `linux`, `check`, `file`).

---

### `allowed_paths` (Required for File Mutations)
- **Type**: `[]string` (Glob patterns)
- **Example**:
  ```yaml
  allowed_paths:
    - "~/.local/share/applications/*.desktop"
    - "~/.config/autostart/*.desktop"
  ```
- **Enforcement**: Any call to `write_scoped_file` checks the target path against these globs. If a path does not match:
  - The harness denies the write.
  - A `SCOPE_VIOLATION` error is returned to the agent loop.
  - Execution halts safely before disk alteration.
- **Safety**: Path traversal tokens (`..`) are disallowed.

---

### `required_bins` (Recommended)
- **Type**: `[]string`
- **Example**: `[desktop-file-validate, update-desktop-database]`
- **Preflight Check**: During fingerprinting, LNTA checks `$PATH` for each binary. If any binary is missing, LNTA warns the user and falls back to diagnostic guidance.

---

### `context_cmd` (Optional)
- **Type**: `string` (Shell command)
- **Example**: `desktop-file-validate --version && ss -tulpn`
- **Execution Environment**: Runs inside the **Tier 1 / Tier 2 Sandbox** (read-only filesystem, no network, private `/tmp`).
- **Purpose**: Feeds ground-truth system state to the LLM before planning starts.
- **Rules**: Must be non-mutating and fast (<2s). Use `2>&1 || true` if the binary might return non-zero when inactive.

---

### `verify_cmd` (Crucial)
- **Type**: `string` (Shell command with `${placeholder}`)
- **Example**: `desktop-file-validate "${target}"`
- **Execution**: Invoked by the harness when the LLM calls `complete_task`.
- **Exit Code Semantics**:
  - `Exit 0`: Task completed successfully.
  - `Exit ≠ 0`: Task rejected. Stderr and stdout are fed back to the LLM for automatic self-correction.
- **Supported Placeholders**:

| Placeholder | Context | Example Value |
|---|---|---|
| `${target}` | Absolute file path written | `/home/user/.local/share/applications/app.desktop` |
| `${unit}` | Systemd service unit name | `syncthing.service` |
| `${port}` | Network port number | `8080` |
| `${rule_num}` | Firewall rule index | `4` |
| `${device}` | Udev device node or subsystem | `/dev/bus/usb/001/004` |
| `${calendar_expr}` | Systemd timer calendar expression | `*-*-* 04:00:00` |
| `${branch_name}` | Git branch name | `feature/auth-cleanup` |

---

## Writing the Markdown Runbook Body

The Markdown body below the frontmatter serves as the system prompt context for that specific domain:

```markdown
# Linux Desktop Entries

Create, validate, and install `.desktop` launchers in `~/.local/share/applications/`.

## What this pack covers
- Writing valid `.desktop` files adhering to the Freedesktop.org specification.
- Checking that `Exec` points to an existing binary or executable in `$PATH`.
- Adding correct `Categories` (Development, Network, Utility).

## Common Traps
- Forgetting `Type=Application`.
- Using relative paths in `Exec` or `Icon`.
- Placing user files in `/usr/share/applications` instead of `~/.local/share/applications`.
```

---

## Testing & Linting Packs (`lnta packs validate`)

LNTA includes a built-in static analysis engine and sandbox linter for packs.

```bash
# Validate all embedded packs
lnta packs validate

# Validate user packs directory
lnta packs validate ~/.config/lnta/packs/

# Validate a specific pack file
lnta packs validate ~/.config/lnta/packs/custom-pack.md
```

### CLI Flags & Options

| Flag | Purpose | Default |
|---|---|---|
| `--check-binaries` | Check if `required_bins` exist on host `$PATH` | `true` |
| `--run-context-cmd` | Execute `context_cmd` inside `bwrap` sandbox to verify it exits 0 | `false` |
| `--strict` | Treat warnings as fatal errors; exit with status code 1 | `false` |
| `--json` | Output machine-readable JSON results for automated CI | `false` |

```bash
# Strict verification including sandboxed context execution
lnta packs validate ~/.config/lnta/packs/ --run-context-cmd --strict
```

### Interpreting Validator Output

```text
PACK: ufw-firewall-ports (/home/user/Codes/linux/lnta/packs/ufw-firewall-ports.md)
  Status: VALID
  Binaries:
    ✓ ufw (found in /usr/sbin/ufw)
    ✓ ss (found in /usr/bin/ss)
  Globs:
    ✓ ~/.config/lnta/*.md
  Verification Gate:
    ✓ verify_cmd contains ${rule_num} placeholder
```

If errors are detected:
```text
PACK: my-broken-pack (/home/user/.config/lnta/packs/my-broken-pack.md)
  Status: INVALID
  Issues (1):
    [ERROR] allowed_paths: glob "../etc/shadow" contains '..' path traversal
  Warnings (1):
    [WARN] verify_cmd: verify_cmd is empty - verification gate will not run
```

### Automating in CI/CD

Integrate pack linting into your GitHub Actions or GitLab CI pipeline:

```yaml
# .github/workflows/packs.yml
name: Validate Instruction Packs
on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
      - name: Build LNTA
        run: go build -o lnta ./cmd/lnta
      - name: Validate Packs (Strict JSON)
        run: ./lnta packs validate packs/ --strict --json
```

---

## Pack Priority & Overrides

LNTA resolves instruction packs in two tiers:

```text
┌────────────────────────────────────────────────────────┐
│                   Pack Router Registry                 │
├────────────────────────────────────────────────────────┤
│ 1. User Packs:     ~/.config/lnta/packs/*.md           │
│    (Loaded first; overrides embedded packs by ID)      │
│                                                        │
│ 2. Embedded Packs: binary embedded (packs/*.md)        │
│    (Default system packs bundled with executable)      │
└────────────────────────────────────────────────────────┘
```

To customize an embedded pack (e.g. `ufw-firewall-ports`), copy it into `~/.config/lnta/packs/` with the same `id`:

```bash
mkdir -p ~/.config/lnta/packs
# Any custom pack with `id: ufw-firewall-ports` will now replace the built-in version
```

---

## Real-World Reference Examples

<details>
<summary><strong>Systemd User Service Pack (`packs/systemd-user-services.md`)</strong></summary>

```markdown
---
id: systemd-user-services
name: Systemd User Services
triggers:
  - systemd
  - service
  - daemon
  - background process
  - autostart service
allowed_paths:
  - "~/.config/systemd/user/*.service"
required_bins:
  - systemctl
  - systemd-analyze
context_cmd: systemctl --user --version
verify_cmd: systemd-analyze --user verify "${unit}"
---
# Systemd User Services

Create, validate, reload, and manage systemd user services in `~/.config/systemd/user/`.

## What this pack covers
- Authoring unit files with `[Unit]`, `[Service]`, and `[Install]` sections.
- Validating unit syntax via `systemd-analyze --user verify`.
- Reloading manager configuration with `systemctl --user daemon-reload`.
- Enabling and starting user services.
```
</details>

<details>
<summary><strong>Linux Desktop Launcher Pack (`packs/linux-desktop-entries.md`)</strong></summary>

```markdown
---
id: linux-desktop-entries
name: Linux Desktop Entries
triggers:
  - desktop
  - .desktop
  - launcher
  - application menu
allowed_paths:
  - "~/.local/share/applications/*.desktop"
  - "~/.config/autostart/*.desktop"
required_bins:
  - desktop-file-validate
context_cmd: desktop-file-validate --version
verify_cmd: desktop-file-validate "${target}"
---
# Linux Desktop Entries

Create, validate, and install `.desktop` launchers in `~/.local/share/applications/`.
```
</details>
