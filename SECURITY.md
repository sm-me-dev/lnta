# Security Policy: LNTA

LNTA is designed with an uncompromising defense-in-depth model. We take vulnerabilities and regressions in isolation, tool boundary enforcement, or secret protection extremely seriously.

---

## Supported Versions

| Version | Supported | Status |
|---|---|---|
| `main` (trunk) | :white_check_mark: | Actively maintained |
| `>= 0.1.0` | :white_check_mark: | Supported for critical security patches |
| `< 0.1.0` | :x: | End of life |

---

## Reporting a Vulnerability

If you discover a security vulnerability, sandbox escape, secret leakage vector, or bypass of our tool constraints, **please report it privately**. Do NOT open a public issue on GitHub.

### Reporting Channels
1. **GitHub Security Advisories (Preferred)**:
   Submit a private advisory report directly on the repository via GitHub's "Security" tab -> "Report a vulnerability".
2. **Security Contact**:
   Email: `security@sm-me.org` (or contact maintainers directly via repository security contacts).

### What to Include in Your Report
Please provide:
- A clear description of the vulnerability and its potential impact.
- Exact reproduction steps, proof-of-concept scripts, or sample prompt triggers.
- Information on your environment (Linux distribution, kernel version, `bwrap` version, AppArmor status).
- Any proposed remediation or patches.

### Response Timelines
- **Initial Triage & Acknowledgment**: Within 48 hours of receipt.
- **Vulnerability Assessment**: Within 5 business days.
- **Fix & Coordinated Disclosure**: Typically within 30 days of initial triage, depending on complexity.

We credit all security researchers who report vulnerabilities responsibly in our release notes and security advisories.

---

## Core Security Invariants

LNTA enforces the following technical boundaries:

### 1. No Raw Unbounded Bash
The agent orchestrator never exposes a generic shell execution primitive to the LLM. It exposes only four strictly typed tools:
- `inspect_system`: Executes strictly within a read-only, airgapped sandbox.
- `write_scoped_file`: Atomic, transactional write restricted to declared `allowed_paths` with automatic snapshots.
- `mutate_system`: Classified by the **Semantic Blast-Radius Classifier**; requires interactive human approval.
- `complete_task`: Enforces execution of deterministic shell verification (`verify_cmd`).

### 2. Airgapped Sandbox Execution
During context discovery, all commands execute inside an airgapped sandbox (`bwrap` or Linux Landlock fallback):
- Disconnected network namespace (`--unshare-net`) blocking all external egress.
- Read-only root filesystem (`--ro-bind / /`).
- Empty `tmpfs` mounts masking all credential repositories (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.config/lnta`, browser session stores).
- Recursive masking of project secrets (`.env*`, `credentials.json`, `terraform.tfvars`).
- Ephemeral `/tmp` and `/var/tmp` isolation.

### 3. Masking Unix Domain Sockets
To prevent sandbox escapes via AF_UNIX sockets, `/run` is masked with an empty `tmpfs`, shielding Docker (`docker.sock`), D-Bus (`/run/user/<uid>/bus`), SSH agent, and Podman sockets from sandboxed execution.

### 4. Defense Against Phantom Dotfile Exploits (CVE-2026-25725)
All startup dotfiles (`~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.bash_profile`, `~/.config/claude/settings.json`, `~/.ssh/authorized_keys`) are mapped to `/dev/null` or isolated within ephemeral memory even if the files do not exist on the host filesystem.

### 5. Anti-Fatigue Challenge Gates
Destructive operations (e.g. `rm -rf`, `dd if=`, `mkfs`, `ufw reset`, raw disk writes) bypass simple `[y/N]` prompts and require typing a cryptographically randomized 4-character challenge code.
