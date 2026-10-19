---
id: disk-mounts-fstab
name: Disk Mounts and fstab
triggers:
  - disk
  - mount
  - fstab
  - uuid
  - verify
  - lsblk
  - findmnt
  - blkid
allowed_paths:
  - "/etc/fstab"
  - "~/.config/lnta/*.md"
required_bins:
  - lsblk
  - findmnt
  - blkid
  - df
context_cmd: lsblk --version && findmnt --version && blkid --version
verify_cmd: findmnt --verify --fstab /etc/fstab && echo "fstab syntax OK"
---
# Disk Mounts and fstab

Inspect block devices with `lsblk -f`, check disk usage with `df -h`, view mounted filesystems with `findmnt`, draft UUID-based mount entries, and **always run mandatory `findmnt --verify` so a bad `/etc/fstab` edit NEVER bricks a reboot!**

## What this pack covers

- Listing block devices with filesystems: `lsblk -f` (shows FSTYPE, LABEL, UUID, MOUNTPOINT)
- Checking disk space: `df -h` and `df -i` (inodes)
- Viewing current mounts: `findmnt` (tree view) and `findmnt -T <path>` (specific path)
- Getting UUIDs for `/etc/fstab`: `blkid` or `lsblk -f -o +UUID`
- Drafting safe `/etc/fstab` entries with UUID (not device paths!)
- **Mandatory validation**: `findmnt --verify --fstab /etc/fstab` before any reboot
- Understanding mount options: `defaults`, `noatime`, `discard`, `x-systemd.automount`

## Safety

**CRITICAL**: A malformed `/etc/fstab` can prevent boot (emergency mode). **Always** run `findmnt --verify` after editing `/etc/fstab`. This pack defaults to read-only inspection. Writing to `/etc/fstab` requires `mutate_system` with approval and **must** be followed by `findmnt --verify` verification. Never use `/dev/sdX` paths in fstab — use `UUID=` or `LABEL=` instead.

## Device inspection

```bash
# Full block device info with filesystems
lsblk -f
# NAME   FSTYPE      LABEL    UUID                                 MOUNTPOINT
# sda
# ├─sda1 vfat        EFI      1234-ABCD                            /boot/efi
# └─sda2 ext4        root     a1b2c3d4-e5f6-7890-abcd-ef1234567890 /

# Just UUIDs
lsblk -f -o +UUID

# All block devices (no filesystem filter)
lsblk -o +FSTYPE,UUID,LABEL,MOUNTPOINT,SIZE,TYPE
```

### blkid for detailed UUID info
```bash
# All devices with UUID, TYPE, LABEL
blkid

# Specific device
blkid /dev/sda2
# /dev/sda2: UUID="a1b2c3d4..." TYPE="ext4" PARTUUID="..."
```

## Current mount inspection

```bash
# Tree view of all mounts
findmnt

# Specific mount point
findmnt -T /home

# Show specific columns
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS,UUID

# Show kernel mount table (includes bind mounts)
findmnt --kernel
```

### Disk usage
```bash
# Human-readable disk space
df -h

# Inode usage (critical for many small files)
df -i

# Specific filesystem
df -h /home
```

## Drafting fstab entries

### Never use device paths!
```bash
# BAD - device names can change on reboot
/dev/sda2  /  ext4  defaults  0  1

# GOOD - UUID is stable
UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890  /  ext4  defaults  0  1

# ALSO GOOD - LABEL (if unique and stable)
LABEL=root  /  ext4  defaults  0  1
```

### fstab column format
```
<device>  <mountpoint>  <fstype>  <options>  <dump>  <pass>
```

| Column | Description | Example |
|--------|-------------|---------|
| device | UUID=..., LABEL=..., or /dev/... | `UUID=abc123...` |
| mountpoint | Directory to mount on | `/`, `/home`, `/mnt/data` |
| fstype | Filesystem type | `ext4`, `xfs`, `btrfs`, `vfat`, `ntfs3` |
| options | Mount options (comma-separated) | `defaults,noatime` |
| dump | `dump` backup utility (0/1) | `0` (usually) |
| pass | `fsck` order (0=skip, 1=root, 2=others) | `1` for `/`, `2` for others |

### Common mount options

| Option | Effect |
|--------|--------|
| `defaults` | `rw,suid,dev,exec,auto,nouser,async` |
| `noatime` | Don't update access time (performance) |
| `relatime` | Update atime only if older than mtime (default on modern Linux) |
| `discard` | Issue TRIM/UNMAP (SSD) - prefer `fstrim` timer instead |
| `x-systemd.automount` | Mount on first access (boot speed) |
| `x-systemd.idle-timeout=10min` | Auto-unmount after idle (with automount) |
| `nofail` | Don't fail boot if device missing (external drives) |

### Example entries

```fstab
# Root filesystem
UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890  /  ext4  defaults,noatime  0  1

# Home partition
UUID=b2c3d4e5-f6a7-8901-bcde-f12345678901  /home  ext4  defaults,noatime  0  2

# EFI system partition
UUID=1234-ABCD  /boot/efi  vfat  umask=0077  0  1

# External backup drive (nofail + automount)
UUID=c3d4e5f6-a7b8-9012-cdef-123456789012  /mnt/backup  ext4  defaults,noatime,x-systemd.automount,x-systemd.idle-timeout=10min,nofail  0  2

# NFS share
192.168.1.100:/srv/nfs  /mnt/nfs  nfs4  defaults,_netdev,x-systemd.automount  0  0
```

## The mandatory verification step

```bash
# ALWAYS RUN THIS AFTER EDITING /etc/fstab
findmnt --verify --fstab /etc/fstab

# Exit code 0 = valid
# Exit code != 0 = INVALID - DO NOT REBOOT

# Verbose output (shows what would be mounted)
findmnt --verify --fstab /etc/fstab -v
```

### Why this matters

- Catches syntax errors (missing fields, invalid options)
- Catches UUID mismatches (device not found)
- Catches filesystem type mismatches
- Prevents emergency mode on next reboot
- **This is your safety net — use it every time**

## Common workflows

### Add a new data disk
```bash
# 1. Identify device and get UUID
lsblk -f
# Suppose /dev/sdb1 is the new partition, UUID=deadbeef-...

# 2. Create mount point
mkdir -p /mnt/data

# 3. Test mount manually first
mount UUID=deadbeef-... /mnt/data
# Verify it works
df -h /mnt/data

# 4. Add to fstab (requires root)
# UUID=deadbeef-...  /mnt/data  ext4  defaults,noatime  0  2

# 5. MANDATORY VERIFICATION
findmnt --verify --fstab /etc/fstab

# 6. Test mount from fstab
umount /mnt/data
mount -a  # Mounts all fstab entries
df -h /mnt/data
```

### Fix a broken fstab (from emergency mode)
```bash
# 1. Remount root read-write
mount -o remount,rw /

# 2. Edit fstab
# Fix the bad entry (wrong UUID, missing device, typo)

# 3. VERIFY
findmnt --verify --fstab /etc/fstab

# 4. Test
mount -a

# 5. Reboot
reboot
```

## Verification

The `verify_cmd` runs `findmnt --verify --fstab /etc/fstab` which validates the entire fstab syntax, checks that all UUIDs/LABELs resolve to existing devices, and verifies filesystem types match. **This must pass (exit code 0) before any reboot.** After editing fstab, always run this command. If it fails, fix the error before proceeding.