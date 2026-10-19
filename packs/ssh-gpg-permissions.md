---
id: ssh-gpg-permissions
name: SSH and GPG Permissions
triggers:
  - ssh
  - gpg
  - permission
  - authorized_keys
  - gnupg
  - ssh-keygen
  - ssh config
allowed_paths:
  - "~/.ssh/config"
  - "~/.ssh/authorized_keys"
  - "~/.ssh/*.pub"
  - "~/.gnupg/gpg.conf"
  - "~/.gnupg/gpg-agent.conf"
  - "~/.gnupg/*.gpg"
  - "~/.gnupg/*.kbx"
  - "~/.config/lnta/*.md"
required_bins:
  - ssh
  - ssh-keygen
  - gpg
  - stat
context_cmd: ssh -V 2>&1 | head -1 && ssh-keygen --version && gpg --version
verify_cmd: stat -c "%a" ~/.ssh | grep -q "^700$" && stat -c "%a" ~/.ssh/id_ed25519 2>/dev/null | grep -q "^600$" && echo "ssh permissions OK"
---
# SSH and GPG Permissions

Diagnose and fix `~/.ssh/config`, `authorized_keys`, and `~/.gnupg` permission regressions (directories `0700`, private keys `0600`, public keys `0644`) and verify via `ssh -G` / `ssh-keygen -lf`.

## What this pack covers

- Correct permissions for SSH files and directories
- Correct permissions for GPG files and directories
- Diagnosing permission issues with `stat` and `ssh -G`
- Validating key files with `ssh-keygen -lf`
- Fixing common permission regressions (often caused by file copies, sync tools, or misguided `chmod -R`)
- Verifying SSH config syntax with `ssh -G`

## Safety

**Critical**: Wrong permissions on SSH/GPG files can lock you out or expose private keys. SSH **requires** strict permissions and will ignore files that are too permissive. This pack provides read-only diagnostics by default. Permission fixes use `mutate_system` with approval. Always verify with `ssh -G <host>` and `ssh-keygen -lf <key>` after changes.

## Required permissions

| Path | Type | Permission | Reason |
|------|------|------------|--------|
| `~/.ssh/` | Directory | `0700` (drwx------) | SSH ignores if group/other readable |
| `~/.ssh/config` | File | `0600` (-rw-------) | Contains host aliases, may have secrets |
| `~/.ssh/authorized_keys` | File | `0600` (-rw-------) | SSH ignores if group/other readable |
| `~/.ssh/id_*` | Private key | `0600` (-rw-------) | **SSH refuses keys with loose perms** |
| `~/.ssh/id_*.pub` | Public key | `0644` (-rw-r--r--) | Safe to be readable |
| `~/.ssh/known_hosts` | File | `0644` (-rw-r--r--) | Standard |
| `~/.gnupg/` | Directory | `0700` (drwx------) | GPG requires strict perms |
| `~/.gnupg/*.gpg` | Keyring files | `0600` (-rw-------) | Private key material |
| `~/.gnupg/*.kbx` | Keybox files | `0600` (-rw-------) | Modern GPG format |
| `~/.gnupg/gpg.conf` | Config | `0600` (-rw-------) | May contain sensitive options |
| `~/.gnupg/gpg-agent.conf` | Config | `0600` (-rw-------) | Agent config |

## Diagnostics

### Check current permissions
```bash
# SSH directory and files
ls -la ~/.ssh/
stat -c "%a %n" ~/.ssh ~/.ssh/*

# GPG directory and files
ls -la ~/.gnupg/
stat -c "%a %n" ~/.gnupg ~/.gnupg/*
```

### Validate SSH config syntax
```bash
# Expand config for a host (shows all effective options)
ssh -G github.com

# Test specific host config
ssh -G myserver

# Dry-run connection (no auth, just config validation)
ssh -T -o BatchMode=yes github.com 2>&1 | head -5
```

### Validate key files
```bash
# List fingerprint and details of private key
ssh-keygen -lf ~/.ssh/id_ed25519

# List fingerprint of public key
ssh-keygen -lf ~/.ssh/id_ed25519.pub

# Verify private/public key pair matches
ssh-keygen -y -f ~/.ssh/id_ed25519  # Outputs public key from private
```

### Check GPG keyring
```bash
# List public keys
gpg --list-keys

# List secret keys (verifies keyring readable)
gpg --list-secret-keys

# Check trustdb
gpg --check-trustdb
```

## Common permission fixes

### Fix SSH permissions (run all)
```bash
# Directory
chmod 700 ~/.ssh

# Config and authorized_keys
chmod 600 ~/.ssh/config ~/.ssh/authorized_keys

# Private keys
chmod 600 ~/.ssh/id_* ~/.ssh/*_rsa ~/.ssh/*_ed25519 ~/.ssh/*_ecdsa 2>/dev/null || true

# Public keys
chmod 644 ~/.ssh/*.pub

# known_hosts (safe to be readable)
chmod 644 ~/.ssh/known_hosts
```

### Fix GPG permissions (run all)
```bash
# Directory
chmod 700 ~/.gnupg

# All files in .gnupg (keys, configs, caches)
chmod 600 ~/.gnupg/*
```

### One-liner to fix everything
```bash
# SSH
find ~/.ssh -type d -exec chmod 700 {} \;
find ~/.ssh -type f -name "id_*" ! -name "*.pub" -exec chmod 600 {} \;
find ~/.ssh -type f -name "*.pub" -exec chmod 644 {} \;
chmod 600 ~/.ssh/config ~/.ssh/authorized_keys 2>/dev/null
chmod 644 ~/.ssh/known_hosts 2>/dev/null

# GPG
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/*
```

## Troubleshooting common issues

### "Permissions too open" for private key
```bash
# SSH will refuse to use the key
# Fix:
chmod 600 ~/.ssh/id_ed25519
```

### "Bad permissions" on `authorized_keys`
```bash
# SSH ignores the file
# Fix:
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
```

### GPG "unsafe permissions" warning
```bash
# GPG complains on every operation
# Fix:
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/*
```

### Config syntax error
```bash
# ssh -G will show error
ssh -G myserver
# Fix config syntax, then re-test
```

## Verification

The `verify_cmd` checks that `~/.ssh` is `0700` and the primary private key (`~/.ssh/id_ed25519`) is `0600`. After fixing permissions, run `ssh -G <host>` to verify SSH config parses correctly, and `ssh-keygen -lf <key>` to verify key files are readable and valid. For GPG, run `gpg --list-secret-keys` to confirm keyring access works.