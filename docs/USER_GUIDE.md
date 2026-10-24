# LNTA User Guide: Everyday Workflows & Modes

> Complete walkthrough of interaction modes, everyday sysadmin workflows, shell integration, and LLM configuration for the Linux Natural-Language Terminal Assistant (`lnta`).

---

## Table of Contents

- [Overview](#overview)
- [Quick Reference](#quick-reference)
- [Interaction Modes](#interaction-modes)
  - [1. One-Shot Command Mode](#1-one-shot-command-mode)
  - [2. Interactive Multi-Turn Chat (`lnta chat`)](#2-interactive-multi-turn-chat-lnta-chat)
  - [3. Pipe & Fix Mode (`| lnta`, `lnta fix`)](#3-pipe--fix-mode--lnta-lnta-fix)
  - [4. Shell Hotkey Widget (`Ctrl+G`)](#4-shell-hotkey-widget-ctrlg)
  - [5. Explain & Dry-Run Modes (`--explain`, `--dry-run`)](#5-explain--dry-run-modes---explain---dry-run)
  - [6. Time-Machine Rollback (`lnta undo`, `lnta sessions`)](#6-time-machine-rollback-lnta-undo-lnta-sessions)
  - [7. Remote SSH Mode (`--ssh`)](#7-remote-ssh-mode---ssh)
  - [8. Local Offline Mode (`--local` with Ollama)](#8-local-offline-mode---local-with-ollama)
- [Configuration Reference (`config.yaml`)](#configuration-reference-configyaml)
  - [Config File Location](#config-file-location)
  - [Ready-to-Copy Provider Templates](#ready-to-copy-provider-templates)
  - [Environment Variable Overrides](#environment-variable-overrides)
- [Advanced Shell Integration](#advanced-shell-integration)
- [Frequently Asked Questions](#frequently-asked-questions)

---

## Overview

`lnta` is a grounded Linux assistant. Unlike raw shell wrappers that pipe arbitrary commands directly into `/bin/bash`, `lnta`:
1. Gathers context using **airgapped kernel sandboxing** (`bwrap` or Linux Landlock).
2. Constrains writes to **explicit paths** declared in targeted Instruction Packs.
3. Classifies risks and requires **interactive human approval** before executing system mutations.
4. Validates changes using **deterministic shell commands** (`verify_cmd`).
5. Creates **atomic filesystem snapshots** enabling instant rollback (`lnta undo`).

---

## Quick Reference

| Command | Purpose | Mutation Risk |
|---|---|---|
| `lnta "<prompt>"` | Execute one-shot task with automatic pack routing | Approved only |
| `lnta --json "<prompt>"` | Emit structured `RunSummary` JSON to stdout for CI/automation | Approved only |
| `lnta chat` | Multi-turn conversational session with run persistence | Approved only |
| `journalctl -xe \| lnta "fix"` | Pipe system logs into LNTA for diagnosis and repair | Approved only |
| `lnta fix` | Automatically diagnose and fix the last failed shell command | Approved only |
| `lnta --explain "<prompt>"` | Read-only analysis; disables all mutation tools | **Zero** |
| `lnta --dry-run "<prompt>"` | Preview planned diffs and commands without touching disk | **Zero** |
| `lnta undo` | Revert the most recent filesystem mutations | Restorative |
| `lnta undo -i` / `lnta sessions` | Visual Time Machine TUI for browsing and reverting past runs | Restorative |
| `lnta --ssh user@host "<prompt>"` | Execute operations safely on a remote host | Approved only |
| `lnta --local "<prompt>"` | Force 100% offline execution via local Ollama models | Approved only |
| `lnta setup` | 20-second interactive onboarding wizard (Ollama / Cloud providers) | **Zero** |
| `lnta gc [--keep-last N]` | Garbage collect old run snapshots and rotate audit logs | **Zero** |
| `lnta doctor` | Diagnose API connectivity, kernel sandboxing, and validators | **Zero** |

---

## Interaction Modes

### 1. One-Shot Command Mode

Use one-shot mode for targeted actions. Pass your natural language intent as arguments:

```bash
lnta "create a systemd user service named api-sync that runs ~/bin/sync.sh every 10m"
```

#### What Happens Under the Hood:
1. **Fingerprint (<5ms)**: Detects host distribution, kernel, init system (`systemd`), and installed binaries.
2. **Pack Selection**: Routes to the `systemd-user-services` pack based on trigger keywords (`systemd`, `user service`).
3. **Sandboxed Inspection**: Executes `systemctl --user --version` inside an unshared mount/PID sandbox.
4. **Tool Execution**: Generates the unit file and stages it via `write_scoped_file` under `~/.config/systemd/user/`.
5. **Approval Gate**: Prompts via `huh.Confirm` for system mutations (e.g. `systemctl --user daemon-reload`).
6. **Harness Verification**: Executes `systemd-analyze --user verify ~/.config/systemd/user/api-sync.service`.
7. **Snapshot Saved**: Pre-write state backed up to `~/.local/share/lnta/snapshots/<run_id>/`.

```text
## System Context
- os: ubuntu 26.04 (Ubuntu 26.04 LTS)
- shell: /usr/bin/zsh
- binaries: bwrap ✓, systemctl ✓, systemd-analyze ✓

## Matched Pack (1)
- Systemd User Services (systemd-user-services)
  required_bins: [systemctl, systemd-analyze]
  verify_cmd: systemd-analyze --user verify "${unit}"

[write_scoped_file] ~/.config/systemd/user/api-sync.service (created, 248 bytes)

? Execute mutation: systemctl --user daemon-reload (low risk: user-space reload) [y/N]: y

[complete_task] Unit file verified successfully.
Run ID: 20261024-103522-a1f9
```

---

### 2. Interactive Multi-Turn Chat (`lnta chat`)

Launch an interactive chat session when troubleshooting multi-step issues or iterating on system configurations:

```bash
lnta chat
```

```text
╭──────────────────────────────────────────────────────────╮
│  LNTA Interactive Chat Mode                              │
│  Type your instructions or questions below.              │
│  Commands: exit, quit, undo, clear, help                 │
╰──────────────────────────────────────────────────────────╯

lnta> Why is my SSH service rejecting public keys?
... Inspecting ~/.ssh permissions and /var/log/auth.log ...
Found incorrect permissions on ~/.ssh (0775, must be 0700).

lnta> Fix it
... Staged chmod 0700 ~/.ssh and chmod 0600 ~/.ssh/authorized_keys ...
? Execute: chmod 0700 ~/.ssh && chmod 0600 ~/.ssh/authorized_keys [y/N]: y
Verified: ssh-gpg-permissions check passed.
```

- **Session Continuity**: Conversation context and file snapshots are linked across turns.
- **Built-in Commands**:
  - `undo`: Immediately rolls back file changes made during the current chat session.
  - `clear`: Clears conversation history without wiping past run snapshots.
  - `exit` or `quit`: Gracefully terminates the chat session.

---

### 3. Pipe & Fix Mode (`| lnta`, `lnta fix`)

LNTA integrates natively with standard Unix pipelines and your shell history.

#### Piping Logs Directly to LNTA
Pipe command output, logs, or stack traces directly into `lnta`:

```bash
journalctl -u nginx -n 50 --no-pager | lnta "why did nginx crash and how do I fix it?"
```

```bash
docker compose logs backend --tail 100 | lnta "explain database connection timeout"
```

> [!TIP]
> **Tail-Preserving Truncation**: When piped input exceeds 64KB, LNTA preserves the first 16KB (headers/initialization) and the final 48KB (fatal crash traces) with a central marker, preventing context window exhaustion while retaining critical crash evidence.

#### Controlling TTY During Pipelines
When stdin is piped, `lnta` automatically redirects interactive approval prompts to `/dev/tty`. This ensures you can still confirm or deny mutations safely without breaking pipeline execution.

#### Automatic Command Repair (`lnta fix`)
When shell integration is active, `lnta` tracks the command name and exit code of your last executed prompt. If a command fails, repair it instantly:

```bash
$ ufw allow 8080/tcp
Command 'ufw' not found, did you mean: ... (exit 127)

$ lnta fix
Detected failed command: "ufw allow 8080/tcp" (exit 127)
Diagnosing missing package and alternative firewall rules...
```

---

### 4. Shell Hotkey Widget (`Ctrl+G`)

With shell integration loaded, type a natural-language description directly on your command line and hit `Ctrl+G` to replace your prompt with the verified command:

```bash
$ find all files larger than 100MB modified in the last 7 days<Ctrl+G>
```

Instantly transforms into:

```bash
$ find . -type f -size +100M -mtime -7
```

#### How It Works:
The `Ctrl+G` widget invokes `lnta --command-only "$BUFFER"`. LNTA runs fingerprinting, routes to the matching pack, extracts the exact executable command, and replaces the command line buffer using your shell's native line editor (ZLE for Zsh, Readline for Bash).

---

### 5. Explain & Dry-Run Modes (`--explain`, `--dry-run`)

For maximum safety in production or multi-tenant environments:

#### Explain Mode (`--explain`)
Removes all mutation tools (`write_scoped_file`, `mutate_system`) at the harness level. The LLM is physically incapable of making modifications:

```bash
lnta --explain "why is port 5432 unreachable from 192.168.1.50?"
```

- Inspects system state via `bwrap` (read-only mounts).
- Provides root cause analysis and prints recommended fix commands for manual review.

#### Dry-Run Mode (`--dry-run`)
Executes the agent planner and generates exact file diffs and command proposals, but aborts before writing anything to disk or executing mutations:

```bash
lnta --dry-run "configure ufw to allow wireguard on udp 51820"
```

```diff
--- /etc/ufw/user.rules (dry-run preview)
+++ /etc/ufw/user.rules (proposed)
@@ -24,3 +24,5 @@
+### tuple ### allow udp 51820 0.0.0.0/0 any 0.0.0.0/0 in
+-A ufw-user-input -p udp --dport 51820 -j ACCEPT
```

---

### 6. Time-Machine Rollback (`lnta undo`, `lnta sessions`)

Every file mutation made via `write_scoped_file` creates an atomic snapshot under `~/.local/share/lnta/snapshots/<run_id>/`.

#### Instant CLI Undo
Revert the most recent run in under a second:

```bash
lnta undo
```

Revert an older run by Run ID:

```bash
lnta undo 20261024-091500-b2c4
```

#### Interactive Time Machine TUI (`lnta sessions` or `lnta undo -i`)
Launch the terminal visual browser to inspect historical runs, view file diffs, and select runs to roll back:

```bash
lnta sessions
```

```text
┌─ Past Runs ───────────────────────┐┌─ Run Details: 20261024-101502 ────────────────┐
│ ✓ [desktop] create obsidian.desktop││ Timestamp: 2026-10-24 10:15:02                 │
│ ✓ [systemd] timer for restic backup││ Prompt:    create a desktop launcher for      │
│ ✗ [network] open port 443 in ufw  ││            /opt/obsidian/obsidian             │
│ ↩ [desktop] test bad launcher     ││ Status:    Verified (✓)                        │
│                                   ││ Pack:      linux-desktop-entries               │
│                                   ││ Modified:  ~/.local/share/applications/        │
│                                   ││            obsidian.desktop                    │
│                                   ││                                                │
│                                   ││ [Diff Preview]                                 │
│                                   ││ + [Desktop Entry]                              │
│                                   ││ + Name=Obsidian                                │
│                                   ││ + Exec=/opt/obsidian/obsidian %u               │
└───────────────────────────────────┘└────────────────────────────────────────────────┘
  ↑/↓: Navigate  •  /: Filter  •  Tab: Switch Pane  •  Enter/u: Rollback  •  q: Quit
```

---

### 7. Remote SSH Mode (`--ssh`)

Execute sysadmin tasks safely on remote servers without installing agents or daemons on the remote host:

```bash
lnta --ssh user@prod-web-01 "check why nginx failed to reload and verify certificate path"
```

```bash
lnta --ssh root@db-backup.internal:2222 "audit postgresql backup cron and disk space"
```

#### Remote Execution Flow:
1. **Preflight Fingerprinting**: Connects via system `ssh`, queries `/etc/os-release`, user ID, and binary availability.
2. **Remote Snapshots**: Remote files modified are backed up to `~/.local/share/lnta/snapshots/<run_id>/` on the remote host.
3. **Local Approval**: All mutation approvals are prompted on your local terminal with clear remote host attribution (`[prod-web-01]`).

---

### 8. Local Offline Mode (`--local` with Ollama)

Run `lnta` in airgapped environments or without paying for remote LLM API keys:

```bash
# Auto-detects local Ollama and executes via best installed model
lnta --local "generate a udev rule for my YubiKey"
```

```bash
# List discovered local models
lnta models
```

```text
Configured remote models:
  Model: gpt-4o-mini (BaseURL: https://api.openai.com/v1)

Auto-discovered local Ollama models:
  - qwen2.5-coder:7b (size: 4683073536 bytes) [tool-calling]
  - llama3.3:latest (size: 4294967296 bytes) [tool-calling]
```

- Probes `http://127.0.0.1:11434/api/tags` with a 150ms timeout.
- Prioritizes models with proven structured tool calling (`qwen2.5-coder`, `llama3.3`, `mistral`).
- Zero telemetry, zero external network traffic.

---

## Configuration Reference (`config.yaml`)

### Config File Location
Configuration is loaded from `~/.config/lnta/config.yaml`.

```bash
mkdir -p ~/.config/lnta
chmod 700 ~/.config/lnta
nano ~/.config/lnta/config.yaml
```

### Full Configuration Schema

```yaml
# ~/.config/lnta/config.yaml
api_key: "your-api-key-here"
base_url: "https://api.openai.com/v1"
model: "gpt-4o-mini"
temperature: 0.2
max_tokens: 4096
timeout_sec: 120
gc_max_runs: 100       # Maximum historical run snapshots to keep
gc_max_mb: 100         # Maximum snapshot disk storage before background pruning
```

---

### Secure Keyring Storage & Permission Hardening

LNTA protects secret credentials from world-readable exposure:
1. **OS Keyring Integration (`zalando/go-keyring`)**:
   Keys are securely stored using the native Linux Secret Service, GNOME Keyring, KWallet, or `libsecret` via D-Bus.
2. **0600 Fallback File (`~/.config/lnta/credentials`)**:
   In headless or container environments without D-Bus, keys fall back to `~/.config/lnta/credentials` enforced at strict `0600` (`-rw-------`) permissions.
3. **OpenSSH-Style Auto-Hardening**:
   If `config.yaml` or `credentials` has group- or world-readable permissions (`mode & 0077 != 0`), LNTA prints a clear security warning to `stderr` and automatically executes `chmod 0600`.

---

### Interactive Setup Wizard (`lnta setup`)

If you run `lnta` without a configured API key or local Ollama, LNTA launches an interactive 20-second setup wizard powered by `charmbracelet/huh`:
1. Auto-detects if a local Ollama instance is active on `:11434` and offers 1-click zero-key configuration.
2. Lets you choose your preferred cloud provider (OpenRouter, Anthropic, OpenAI, Gemini, Custom).
3. Safely prompts for your API key (masked) and stores it in the OS Keyring.
4. Executes a 1-second connectivity and sandbox self-test (`lnta doctor`).

You can re-run the wizard anytime with:
```bash
lnta setup
```

---

### Automatic Storage Garbage Collection (`lnta gc`)

To prevent snapshot directories and audit logs from growing unbounded over time:
- **Automatic Background Pruning**: At the end of every run, LNTA prunes older snapshots beyond `gc_max_runs` (default `100`) or `gc_max_mb` (default `100MB`).
- **Log Rotation**: If `~/.local/share/lnta/logs/audit.jsonl` exceeds `10MB`, it is rotated to `audit.jsonl.1` with strict `0600` permissions.
- **Manual Pruning**:
  ```bash
  lnta gc --keep-last 20
  ```

---

### Scripting, CI/CD, and CLI Standards Compliance

#### Deterministic Exit Codes
For robust shell scripting and CI gate enforcement:
- `0` = Completed & Verified (`TASK_COMPLETE:` and verification passed).
- `1` = General / Execution Error (configuration, network, invalid arguments).
- `2` = Verification Failed (`HARNESS_VERIFICATION_FAILED` or `verify_cmd` non-zero).
- `3` = User Cancelled / Approval Denied (`huh.Confirm` rejected mutation or SIGINT).
- `4` = Sandbox / Environment Error (`bwrap` missing, Landlock restriction failure).

#### Machine-Readable JSON Mode (`--json`)
Emits the complete structured `RunSummary` (run id, prompt, plan, diffs, commands executed, verification receipt, exit code) as clean JSON to `stdout`:
```bash
lnta --json "audit open network ports and bound processes"
```

#### Color and Terminal UX (`NO_COLOR`, `TERM=dumb`)
LNTA respects standard terminal environments:
- Setting `NO_COLOR=1` or `TERM=dumb` instantly disables all ANSI color escapes across all `lipgloss` styles and headers.

---

### Ready-to-Copy Provider Templates

#### 1. OpenRouter (Recommended for Multi-Model Access)
```yaml
# ~/.config/lnta/config.yaml
api_key: "sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
base_url: "https://openrouter.ai/api/v1"
model: "meta-llama/llama-3.3-70b-instruct"
temperature: 0.1
max_tokens: 4096
```

#### 2. Anthropic (via OpenAI-Compatible Proxy / LiteLLM)
```yaml
# ~/.config/lnta/config.yaml
api_key: "sk-ant-api03-xxxxxxxxxxxxxxxxxxxx"
base_url: "http://localhost:4000/v1"  # LiteLLM proxy pointing to Anthropic
model: "claude-3-5-sonnet-20241022"
temperature: 0.1
max_tokens: 4096
```

#### 3. OpenAI Official
```yaml
# ~/.config/lnta/config.yaml
api_key: "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx"
base_url: "https://api.openai.com/v1"
model: "gpt-4o-mini"
temperature: 0.2
max_tokens: 4096
```

#### 4. Google Gemini (via OpenAI Compatibility Endpoint)
```yaml
# ~/.config/lnta/config.yaml
api_key: "AIzaSyxxxxxxxxxxxxxxxxxxxxxxx"
base_url: "https://generativelanguage.googleapis.com/v1beta/openai/"
model: "gemini-2.0-flash"
temperature: 0.1
max_tokens: 4096
```

#### 5. Local Ollama (Always-On Default)
```yaml
# ~/.config/lnta/config.yaml
api_key: "ollama"  # Non-empty string required
base_url: "http://127.0.0.1:11434/v1"
model: "qwen2.5-coder:latest"
temperature: 0.2
max_tokens: 4096
```

---

### Environment Variable Overrides

Environment variables override any settings defined in `config.yaml`:

| Variable | Description | Example |
|---|---|---|
| `LNTA_API_KEY` | Overrides `api_key` | `export LNTA_API_KEY="sk-..."` |
| `LNTA_BASE_URL` | Overrides `base_url` | `export LNTA_BASE_URL="https://openrouter.ai/api/v1"` |
| `LNTA_MODEL` | Overrides `model` | `export LNTA_MODEL="meta-llama/llama-3.3-70b-instruct"` |

---

## Advanced Shell Integration

Generate and source the shell integration for your preferred shell:

<details>
<summary><strong>Zsh Setup (~/.zshrc)</strong></summary>

```bash
# Add to ~/.zshrc
eval "$(lnta init zsh)"
```

Features activated:
- `Ctrl+G`: In-line prompt to verified command conversion.
- `lnta fix`: Auto-captures last failed command and exit status via `add-zsh-hook precmd`.
</details>

<details>
<summary><strong>Bash Setup (~/.bashrc)</strong></summary>

```bash
# Add to ~/.bashrc
eval "$(lnta init bash)"
```

Features activated:
- `Ctrl+G`: In-line Readline buffer replacement (`bind -x`).
- `lnta fix`: Hooked into `PROMPT_COMMAND` to capture `$BASH_COMMAND` and exit codes.
</details>

<details>
<summary><strong>Fish Setup (~/.config/fish/config.fish)</strong></summary>

```fish
# Add to ~/.config/fish/config.fish
lnta init fish | source
```

Features activated:
- Event listener on `fish_prompt` capturing `$status` and `$history[1]`.
- Native `lnta_fix` command.
</details>

---

## Frequently Asked Questions

<details>
<summary><strong>How does LNTA know which files it is allowed to touch?</strong></summary>

Every Instruction Pack defines a strict glob list in `allowed_paths` (e.g. `~/.local/share/applications/*.desktop`). The agent cannot write to any path outside these globs; attempting to do so triggers an immediate harness error (`SCOPE_VIOLATION`) and aborts execution.
</details>

<details>
<summary><strong>What happens if the LLM hallucinates an invalid command?</strong></summary>

All proposed mutations are classified by the **Semantic Blast-Radius Classifier** and presented to you with an explanation. Furthermore, the task cannot complete until the pack's `verify_cmd` runs and exits with status `0`.
</details>

<details>
<summary><strong>Can LNTA run inside Docker containers or WSL2?</strong></summary>

Yes. `lnta` detects containerized and WSL2 environments during preflight fingerprinting and adjusts sandbox bindings automatically. Run `lnta doctor` to verify system compatibility.
</details>
