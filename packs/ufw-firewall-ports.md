---
id: ufw-firewall-ports
name: UFW Firewall Ports
triggers:
  - ufw
  - firewall
  - port
  - rule
  - ssh connection
  - allow
  - deny
allowed_paths:
  - "~/.config/lnta/*.md"
required_bins:
  - ufw
  - ss
context_cmd: ufw --version && ss --version
verify_cmd: ufw status numbered | grep -q "${rule_num}" && echo "rule ${rule_num} verified"
---
# UFW Firewall Ports

Inspect `ufw status numbered`, correlate with `ss -tulpn` listening sockets, safely draft firewall rules without locking out active `$SSH_CONNECTION` ports, and verify rule order and effectiveness.

## What this pack covers

- Listing current UFW rules with `ufw status numbered` (shows rule numbers for precise management)
- Correlating firewall rules with actual listening sockets via `ss -tulpn`
- Identifying the active SSH connection port to prevent lockout
- Drafting new rules with `ufw --dry-run` for safe preview
- Understanding rule order: UFW processes rules top-to-bottom, first match wins
- Verifying rule effectiveness after changes

## Safety

**Critical**: Never add a `deny` rule that could block your current SSH session. Always verify `$SSH_CONNECTION` port is allowed before applying restrictive rules. Use `ufw --dry-run` to preview changes. This pack defaults to read-only inspection; `mutate_system` with approval required for `ufw allow/deny/delete` operations.

## SSH connection protection

```bash
# Identify your current SSH connection
echo $SSH_CONNECTION
# Output format: client_ip client_port server_ip server_port
# The 4th field is the server port you're connected on (typically 22)

# ALWAYS ensure this port is allowed BEFORE adding deny rules
ufw status numbered | grep <server_port>
```

## Common workflows

### Inspect current state
```bash
ufw status numbered          # Numbered rules with action/target
ufw status verbose           # Verbose with logging, default policy
ss -tulpn                    # All listening sockets with PIDs
```

### Safe rule drafting (dry-run)
```bash
# Preview what a new rule would do
ufw --dry-run allow 8080/tcp
ufw --dry-run deny from 192.168.1.100
ufw --dry-run insert 1 allow from 10.0.0.0/8 to any port 22
```

### Adding rules safely
```bash
# 1. Check current SSH port
# 2. Ensure SSH is allowed (usually rule 1)
ufw status numbered | head -5

# 3. Add allow rules FIRST (if needed)
ufw allow 8080/tcp comment "web app"

# 4. Then add deny rules (processed after allows)
ufw deny from 192.168.1.100

# 5. Verify
ufw status numbered
```

### Rule ordering (critical)
```bash
# Rules processed top-to-bottom, first match wins
# Insert at specific position
ufw insert 1 allow from 10.0.0.0/8 to any port 22
ufw insert 2 deny 22/tcp

# Delete by rule number (from 'ufw status numbered')
ufw delete 3
```

### Common rule patterns
```bash
# Allow specific IP to specific port
ufw allow from 203.0.113.5 to any port 5432 proto tcp

# Allow subnet
ufw allow from 10.0.0.0/8

# Limit rate (logging)
ufw limit 22/tcp comment "SSH rate limit"

# Delete by spec (not number)
ufw delete allow 8080/tcp
```

## Verification

The `verify_cmd` checks that a specific rule number exists in `ufw status numbered` output. After making changes, verify the rule appears at the expected position. Always cross-reference with `ss -tulpn` to confirm the port is actually listening/blocked as intended.