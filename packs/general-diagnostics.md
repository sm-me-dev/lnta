---
id: general-diagnostics
name: General Diagnostics
triggers: []
allowed_paths: []
required_bins: []
context_cmd: true
verification_required: false
---
# General Diagnostics

Fallback instruction pack used when no other pack's triggers match the user
prompt. Provides safe, read-only system inspection guidance.

## What this pack covers
- Report the current system context (distro, shell, session, available binaries).
- Answer read-only host diagnostics with targeted `scope=host` commands that inspect only paths relevant to the request.
- For user files such as agent skill directories, search the locations named or implied by the request instead of crawling the home directory.
- Use host scope for requested paths outside the active project root.
- Suggest which specialized pack may be relevant for the user's request.
- Decline any action that requires a more specific pack.

## Safety
Read-only by default. No writes are performed unless a more specific pack is
selected and explicitly confirms its allowed paths.
