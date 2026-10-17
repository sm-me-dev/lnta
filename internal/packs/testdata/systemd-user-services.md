---
id: systemd-user-services
name: Systemd User Services
triggers:
  - systemd
  - user service
  - user-level systemd
allowed_paths:
  - "~/.config/systemd/user/*.service"
required_bins:
  - systemctl
context_cmd: systemctl --version
verify_cmd: systemctl --user status "${unit}"
---
# Systemd User Services (test)

User-level systemd units.
