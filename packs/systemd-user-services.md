---
id: systemd-user-services
name: Systemd User Services
triggers:
  - systemd
  - user service
  - systemctl --user
  - user-level systemd
  - daemon reload
allowed_paths:
  - "~/.config/systemd/user/*.service"
  - "~/.config/systemd/user/*.timer"
required_bins:
  - systemctl
context_cmd: systemctl --version
verify_cmd: systemctl --user status "${unit}"
---
# Systemd User Services

Inspect, explain, and create user-level systemd units in
`~/.config/systemd/user/`.

## What this pack covers
- Listing user units with `systemctl --user list-units`.
- Explaining an existing unit file.
- Writing a new `.service` or `.timer` unit with `Unit`, `Install`, and
  `Service`/`Timer` sections.
- Running `systemd-analyze verify` to catch syntax errors before enabling.
- `systemctl --user daemon-reload`, `enable --now`, `start`, `stop`, `status`.

## Safety
User units run as the invoking user — no root required. All writes are
constrained to `allowed_paths`. Verify with `systemd-analyze verify` before
enabling or starting a unit.
