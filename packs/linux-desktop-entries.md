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
verify_cmd: desktop-file-validate "${target}"
---
# Linux Desktop Entries

Create, validate, and install `.desktop` launchers in
`~/.local/share/applications/`.

## What this pack covers
- Writing a `.desktop` file with `Type=Application`, `Exec`, `Name`, `Icon`,
  `Terminal`, and `Categories`.
- Checking that the binary referenced by `Exec` exists in `$PATH`.
- Running `desktop-file-validate` to lint the desktop entry.
- Updating the desktop database / MIME associations where applicable.

## Safety
All writes go through `write_scoped_file` and are constrained to
`allowed_paths`. Confirm the `Exec` binary exists before writing the launcher.
