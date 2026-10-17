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
verify_cmd: test -f "${target}"
---
# Linux Desktop Entries

Create, validate, and install `.desktop` launchers in `~/.local/share/applications/`.

## What this pack covers
- Writing a `.desktop` file with `Type=Application`, `Exec`, `Name`, `Icon`.
- Checking that the binary referenced by `Exec` exists in `$PATH`.
- Running `desktop-file-validate` to lint the desktop entry.
- Ensuring MIME type / desktop database requirements are met.

## Safety
All writes go through `write_scoped_file` and are constrained to `allowed_paths`.
Never run arbitrary binaries from the `Exec` line without confirming they exist.
