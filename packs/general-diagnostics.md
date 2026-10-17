---
id: general-diagnostics
name: General Diagnostics
triggers: []
allowed_paths: []
required_bins: []
context_cmd: true
verify_cmd: true
---
# General Diagnostics

Fallback instruction pack used when no other pack's triggers match the user
prompt. Provides safe, read-only system inspection guidance.

## What this pack covers
- Report the current system context (distro, shell, session, available binaries).
- Suggest which specialized pack may be relevant for the user's request.
- Decline any action that requires a more specific pack.

## Safety
Read-only by default. No writes are performed unless a more specific pack is
selected and explicitly confirms its allowed paths.
