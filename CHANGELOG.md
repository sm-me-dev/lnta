# Release Notes

## v0.1.4 — 2026-10-26

### Security and sandboxing

- Scan project trees without following symlinks; reject detected changes, unreadable entries, and scan-limit exhaustion before accepting a result.
- Find and mask credentials across hidden, generated, dependency, and Git directories with bounded entry, depth, path-count, and byte limits.
- Apply an architecture-aware seccomp policy to block socket and io_uring operations in Bubblewrap and Landlock execution.
- Require Landlock ABI 8 or newer, enforce aggregate rule and configuration budgets, and close inherited descriptors before executing commands.
- Document the sandbox limits and the pre-launch validation race boundary.

### Validation

- Add effective Bubblewrap and Landlock checks for credential denial, permitted reads, blocked writes and sockets, and inherited descriptor isolation.
- Add large-project and adversarial fixture benchmarks for scanning time, memory, allocations, Landlock rules, and configuration size.

## v0.1.3 — 2026-10-25

### Security and reliability

- Manage child process groups consistently and preserve distinct timeout, cancellation, output-limit, and cleanup errors.
- Prevent approved mutation commands and Landlock-confined commands from escaping their managed process group with `setsid` or `setpgid`.
- Bound streamed model responses by text size, tool-call count, per-call argument size, and aggregate completion size.
- Scan and mask credentials from the project root even when a command uses a nested working directory.
- Exercise effective Bubblewrap credential and filesystem restrictions with harmless sentinels; report host-policy-dependent integration skips explicitly.
- Keep the reported terminal/desktop instability unresolved; no cause was reproduced in this release audit.

### CLI, packaging, and validation

- Make `lnta doctor` return nonzero when a required check fails.
- Preserve stdin beginning, middle, and end markers for large piped input.
- Validate Debian package inputs and APT repository metadata, and ensure CI installs GoReleaser before packaging checks.
- Add lifecycle, stream-limit, credential-masking, and effective sandbox regression coverage.
