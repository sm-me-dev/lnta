---
id: systemd-timers-cron
name: Systemd Timers and Cron
triggers:
  - timer
  - cron
  - OnCalendar
  - systemd timer
  - linger
  - user timer
allowed_paths:
  - "~/.config/systemd/user/*.timer"
  - "~/.config/systemd/user/*.service"
  - "/etc/systemd/system/*.timer"
  - "/etc/systemd/system/*.service"
required_bins:
  - systemctl
  - systemd-analyze
  - loginctl
context_cmd: systemctl --version && systemd-analyze --version && loginctl --version
verify_cmd: systemd-analyze calendar "${calendar_expr}" && echo "OnCalendar expression valid"
---
# Systemd Timers and Cron

Create, inspect, and validate systemd user and system timers (`.timer` + `.service` pairs), validate `OnCalendar` expressions via `systemd-analyze calendar`, and check `linger` status for user timers (`loginctl show-user`).

## What this pack covers

- Creating user-level timers in `~/.config/systemd/user/` (no root required)
- Creating system-level timers in `/etc/systemd/system/` (requires root via `mutate_system`)
- Understanding `.timer` + `.service` pair structure
- Validating `OnCalendar` expressions with `systemd-analyze calendar`
- Checking `linger` status for persistent user timers (`loginctl show-user <user> | grep Linger`)
- Enabling/starting/stopping timers with `systemctl --user` or `systemctl`
- Debugging timer activation with `systemctl list-timers --all`

## Safety

User timers run as the invoking user — no root required. System timers require root (`mutate_system` with approval). All writes constrained to `allowed_paths`. Always validate `OnCalendar` expressions with `systemd-analyze calendar` before enabling. Verify `linger` is enabled for user timers that must survive logout.

## Timer + Service pair structure

### Service unit (`myscript.service`)
```ini
[Unit]
Description=My periodic task

[Service]
Type=oneshot
ExecStart=/home/user/scripts/myscript.sh
# Optional: EnvironmentFile=~/.config/myscript.env
```

### Timer unit (`myscript.timer`)
```ini
[Unit]
Description=Run myscript daily at 03:00

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
```

## OnCalendar expression syntax

| Expression | Meaning |
|------------|---------|
| `*-*-* 03:00:00` | Daily at 03:00 |
| `Mon *-*-* 09:00:00` | Every Monday at 09:00 |
| `Mon,Fri *-*-* 09:00:00` | Mon & Fri at 09:00 |
| `*-*-1,15 00:00:00` | 1st and 15th of each month |
| `*-01,04,07,10-01 00:00:00` | Quarterly (Jan, Apr, Jul, Oct) |
| `hourly` | Every hour (shorthand) |
| `daily` | Daily at midnight (shorthand) |
| `weekly` | Weekly on Monday (shorthand) |
| `monthly` | Monthly on 1st (shorthand) |

### Validation (always do this first!)
```bash
systemd-analyze calendar "Mon *-*-* 09:00:00"
# Output shows next 3 activation times, or error if invalid
```

## User linger (critical for user timers)

By default, user systemd instances stop when the user logs out completely. For timers to run when logged out:

```bash
# Check current linger status
loginctl show-user $USER | grep Linger
# Linger=yes -> enabled, Linger=no -> disabled

# Enable linger (persistent across reboots)
sudo loginctl enable-linger $USER

# Disable linger
sudo loginctl disable-linger $USER
```

**Note**: `enable-linger` requires root. Use `mutate_system` with approval.

## Common workflows

### Create user timer
```bash
# 1. Create service
cat > ~/.config/systemd/user/myscript.service <<'EOF'
[Unit]
Description=My backup script

[Service]
Type=oneshot
ExecStart=/home/user/scripts/backup.sh
EOF

# 2. Create timer
cat > ~/.config/systemd/user/myscript.timer <<'EOF'
[Unit]
Description=Daily backup at 03:00

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

# 3. Validate OnCalendar
systemd-analyze calendar daily

# 4. Reload, enable, start
systemctl --user daemon-reload
systemctl --user enable --now myscript.timer
```

### Inspect and debug
```bash
# List all timers (user)
systemctl --user list-timers --all

# List all timers (system)
systemctl list-timers --all

# Show next activation times
systemctl --user list-timers --all | grep myscript

# Check timer status
systemctl --user status myscript.timer

# View last run logs
journalctl --user -u myscript.service -f
```

### Migrate from cron
```bash
# cron: 0 3 * * * /home/user/scripts/backup.sh
# systemd equivalent:
OnCalendar=*-*-* 03:00:00
```

## Verification

The `verify_cmd` validates an `OnCalendar` expression via `systemd-analyze calendar`. After creating/editing a timer, run this to confirm the expression is syntactically correct and shows expected next activation times. Then verify the timer appears in `systemctl --user list-timers --all` with the correct next elapse time.