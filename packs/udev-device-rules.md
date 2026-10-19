---
id: udev-device-rules
name: udev Device Rules
triggers:
  - udev
  - usb
  - device
  - rule
  - block device
  - udevadm
allowed_paths:
  - "/etc/udev/rules.d/*.rules"
  - "~/.config/lnta/*.md"
required_bins:
  - udevadm
  - lsblk
context_cmd: udevadm --version && lsblk --version
verify_cmd: udevadm test --action=add /sys/class/block/${device} 2>&1 | grep -q "${rule_file}" && echo "rule matched"
---
# udev Device Rules

Inspect USB/block device attributes via `udevadm info -a`, write scoped rules in `/etc/udev/rules.d/`, and validate via `udevadm test`.

## What this pack covers

- Querying device attributes with `udevadm info -a -n /dev/sdX` or `udevadm info -a -p /sys/class/block/sdX`
- Writing udev rules in `/etc/udev/rules.d/<nn>-<name>.rules` (requires root via `mutate_system`)
- Understanding rule syntax: `ACTION`, `SUBSYSTEM`, `KERNEL`, `ATTR{key}`, `RUN`, `SYMLINK`, `OWNER`, `GROUP`, `MODE`
- Testing rules with `udevadm test --action=add /sys/class/block/<device>`
- Reloading rules with `udevadm control --reload-rules && udevadm trigger`
- Common use cases: persistent device naming, permission fixes, auto-mount triggers

## Safety

Writing to `/etc/udev/rules.d/` requires root (`mutate_system` with approval). **Test rules with `udevadm test` BEFORE deploying**. Bad rules can prevent device enumeration, break boot, or cause permission issues. Always use numbered prefixes (e.g., `99-`) to control rule order. This pack is read-only for inspection; rule creation requires explicit approval.

## Device attribute inspection

```bash
# By device node
udevadm info -a -n /dev/sdb

# By sysfs path (preferred - works even if /dev node missing)
udevadm info -a -p /sys/class/block/sdb

# Get all properties in key=value format (for scripting)
udevadm info --query=property -n /dev/sdb

# Get specific attribute
udevadm info --query=property -n /dev/sdb | grep ID_SERIAL
```

### Key attribute matches for rules

| Match key | Example | Use case |
|-----------|---------|----------|
| `SUBSYSTEM` | `block`, `usb`, `tty` | Broad device class |
| `KERNEL` | `sd*`, `ttyUSB*` | Kernel device name pattern |
| `ATTR{idVendor}` | `0x1234` | USB vendor ID |
| `ATTR{idProduct}` | `0x5678` | USB product ID |
| `ATTR{serial}` | `SN123456` | Device serial number |
| `ATTR{size}` | `2000000000` | Block device size in 512-byte sectors |
| `ENV{ID_FS_UUID}` | `abc123-def456` | Filesystem UUID |
| `ENV{ID_FS_LABEL}` | `MY_LABEL` | Filesystem label |

## Rule syntax

```udev
# Basic rule structure
ACTION=="add", SUBSYSTEM=="block", ATTR{idVendor}=="1234", ATTR{idProduct}=="5678", SYMLINK+="my_usb_disk", MODE="0660", GROUP="disk"

# Multiple assignments
ACTION=="add", KERNEL=="sd*", ENV{ID_FS_UUID}=="abc123-def456", SYMLINK+="backup_disk", TAG+="systemd", ENV{SYSTEMD_WANTS}="mount-backup@.service"

# Run program on device add (use sparingly)
ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="1234", RUN+="/usr/local/bin/usb-notify.sh %k"
```

### Common rule patterns

**Persistent symlink by serial:**
```udev
ACTION=="add", SUBSYSTEM=="block", ATTR{serial}=="SN123456", SYMLINK+="backup_disk"
```

**Fix permissions for specific USB device:**
```udev
ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="046d", ATTR{idProduct}=="c52b", MODE="0666", GROUP="plugdev"
```

**Trigger systemd mount unit:**
```udev
ACTION=="add", SUBSYSTEM=="block", ENV{ID_FS_UUID}=="abc123-def456", TAG+="systemd", ENV{SYSTEMD_WANTS}="mnt-backup.mount"
```

**Auto-load kernel module:**
```udev
ACTION=="add", SUBSYSTEM=="pci", ATTR{vendor}=="0x8086", ATTR{device}=="0x1234", RUN+="/sbin/modprobe -q my_driver"
```

## Rule validation and testing

### Test a rule before deploying
```bash
# Test against a specific device sysfs path
udevadm test --action=add /sys/class/block/sdb

# Output shows which rules match and what actions would be taken
# Look for your rule file in the output
```

### Deploy and activate
```bash
# 1. Write rule file (requires root)
sudo tee /etc/udev/rules.d/99-backup-disk.rules <<'EOF'
ACTION=="add", SUBSYSTEM=="block", ATTR{serial}=="SN123456", SYMLINK+="backup_disk"
EOF

# 2. Reload rules
sudo udevadm control --reload-rules

# 3. Trigger for existing devices
sudo udevadm trigger --action=add /sys/class/block/sdb

# 4. Verify symlink created
ls -l /dev/backup_disk
```

## Rule ordering

Rules processed in lexical order of filename. Use numeric prefixes:
- `00-` to `09-`: Early (before most rules)
- `50-` to `69-`: Default (most distro rules here)
- `70-` to `89-`: Late (after distro rules)
- `90-` to `99-`: Very late (override/cleanup)

**Best practice**: Use `99-` for custom rules to avoid conflicts.

## Debugging

```bash
# Monitor udev events in real-time
udevadm monitor --environment --udev

# Monitor kernel events
udevadm monitor --kernel

# Check current rules
ls /etc/udev/rules.d/
cat /etc/udev/rules.d/99-*.rules
```

## Verification

The `verify_cmd` runs `udevadm test --action=add /sys/class/block/<device>` and checks that the expected rule file appears in the matched rules output. This confirms the rule syntax is correct and will match the target device. After deploying, verify the actual symlink/permission/action takes effect with `ls -l /dev/<symlink>` or `udevadm info -n /dev/<device>`.