# Release Notes

## v0.1.7 — 2026-10-27

### Host diagnostics

- Allow targeted host read-only commands to run in the sandbox without doing a project-tree or home-directory scan.
- Keep project inspection fail-closed and retain the typed `/proc` RAM report, which reads process names and RSS without reading process arguments or environments.
- Correct the `inspect_system` schema so a host query can use either a targeted command or the typed RAM query without the command/query mismatch.

### Validation

- Add regression coverage for host command routing, host tool argument validation, and project symlink refusal.

## v0.1.6 — 2026-10-27

### Diagnostics and outcomes

- Add a typed host RAM query backed by `/proc/meminfo` and `/proc/<pid>/stat`, reporting process RSS and grouped totals without reading process arguments or environments.
- Stop on unrecoverable or repeated inspection failures with an actionable blocked result; record blocked, completed, and completed-unverified outcomes distinctly in receipts, audit summaries, and exit codes.
- Keep unverified completion from claiming that the verification gate passed.

### Interactive experience

- Replace token-scanned chat input with an editable prompt that supports full-line text, cursor navigation, pasted prompts, and in-session prompt history.
- Retain bounded user/assistant context across chat prompts, add `/reset`, and keep each prompt's routing and verification run independent.
- Bind `Ctrl+X`, then `Ctrl+G` to the existing `lnta_fix` function in Zsh, Bash, and Fish while retaining `Ctrl+G` command conversion.

### Validation

- Add coverage for synthetic `/proc` data, project symlink refusal, blocked-run handling, chat editing and history, outcome receipts, and all shell bindings.
- Run the full test suite, race tests, build, vet, and configured lint checks.

## v0.1.5 — 2026-10-26

### Fixes

- Correct the RPM download link on the APT repository landing page to use the published `amd64` filename.
- Explain in `lnta doctor` that project credential masking scans the whole enclosing Git repository without following symlinks, and how to resolve a refused scan.
- Ignore Python bytecode and drop a stale ignore entry for the tracked embedded packs file.

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
