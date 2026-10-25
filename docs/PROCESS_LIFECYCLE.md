# Process lifecycle audit

Every child process LNTA starts goes through one lifecycle contract in
`internal/sandbox/proc.go`:

1. `exec.CommandContext` with a bounded context (timeout or cancellation).
2. `ConfigureProcessGroup(cmd)` — own process group (`Setpgid`), `Cancel`
   sends `SIGKILL` to the whole group, `WaitDelay` bounds pipe draining.
3. `StartChild(role, cmd)` — `cmd.Start()`, and only after it succeeds the
   child is added to the registry (a failed start leaves no entry).
4. `WaitChild(role, cmd, ...)` — waits, always unregisters, and logs a
   privacy-safe event (fixed role label, pid, pgid, timings, byte counts;
   never arguments, environment, prompts, or output).
5. `KillAllChildren()` — on shutdown or signal, SIGKILLs every registered group.

## Process-creation sites

| Site | Role | Bounded by | Output |
|---|---|---|---|
| `sandbox/bwrap.go` `ProbeBwrap` | `bwrap_probe` | caller timeout | capped 1 KiB / 4 KiB |
| `sandbox/bwrap.go` `runBwrapEnv` | `bwrap` | timeout, default if unset | capped, 8 MiB hard kill |
| `sandbox/landlock.go` `runLandlockEnv` | `landlock` | timeout | capped, 8 MiB hard kill |
| `sandbox/fs_tx.go` `runSSHDirectStdin` | `ssh_rollback` | context, 30 s default | capped, 8 MiB hard kill |
| `transport/ssh.go` `runSystemSSH` | `ssh` | timeout, 2 min default | capped, 8 MiB hard kill |
| `agent/tools.go` `mutateSystem` | `mutate_system` | 10 min | capped, 8 MiB hard kill |
| `agent/tools.go` desktop-file-validate | `desktop_file_validate` | 15 s | capped, 64 KiB hard kill |
| `cmd/lnta/selfupdate.go` `runUpdateCommand` | update role | 20 s | capped, 256 KiB hard kill |

All eight use the same start/wait/cleanup path; none is an exception.

### Justified exception: `syscall.Exec` in the Landlock launcher

`LandlockExecMain` replaces the launcher with `/bin/sh` via `syscall.Exec`
instead of starting a grandchild. The launcher pid therefore *is* the command,
the outer `WaitChild` observes its real exit status, and its process group is
the one that gets killed. Nothing in the launcher is untracked.

## Behavior guaranteed by `WaitChild`

- **Group reap before reaping the leader.** When the child leads its own
  group, `WaitChild` blocks on `waitid(WEXITED|WNOWAIT)`, then SIGKILLs the
  group, then reaps. While the unreaped leader exists its pid — and therefore
  the group id — cannot be recycled, so the group kill cannot hit an unrelated
  group. If the leader cannot be observed (already reaped elsewhere), no signal
  is sent.
- **Pipe-holding descendants.** Killing the group before `Wait` closes inherited
  output pipes, so a successful command is not reported as failed
  (`exec: WaitDelay expired`) and does not stall for `WaitDelay`.
- **Timeouts are distinguishable.** If the context deadline expired, the
  returned error matches `errors.Is(err, context.DeadlineExceeded)` and still
  unwraps to `*exec.ExitError` (`errors.As`). Explicit cancellation and the
  output-cap kill are *not* reported as timeouts. Callers must use
  `errors.As`, not type assertions, on `WaitChild` errors.
- **Output is bounded.** `CappedBuffer` retains a fixed prefix; a hard cap
  cancels the command's own context. The context passed to
  `exec.CommandContext` must be the one the cap's cancel function belongs to
  (this was not true for `ssh_rollback` before the fix).

## Known limitations

- **Descendants that leave the process group.** Group termination reaches only
  processes still in the child's group. Under Bubblewrap this is covered by
  `--unshare-pid --new-session --die-with-parent`. Under the Landlock fallback,
  `mutate_system` and `ssh` there is no PID namespace,
  so a descendant that calls `setsid()`/`setpgid()` survives the group kill.
  Landlock's seccomp filter blocks `kill`/`ptrace`-class syscalls but not
  `setsid`.
- **Background process group and the terminal.** Children run in their own
  process group, which is a background group for the controlling terminal. A
  `mutate_system` command that reads the terminal (for example a `sudo` prompt)
  is stopped by `SIGTTIN` and will wait until its timeout. stdin is `/dev/null`
  for most roles, which avoids this for them.
- **Deadline race.** A command that exits on its own in the instant between
  its exit and the deadline check can be reported as a timeout. The result is
  still a failure; only the classification is imprecise.
- **`os.Exit` skips deferred cleanup.** `main` defers `KillAllChildren`, but
  `os.Exit` does not run defers. By that point every child has been waited for
  and unregistered, so the registry is empty; the signal-handler path calls
  `KillAllChildren` directly.

## Tests

`internal/sandbox/proc_lifecycle_linux_test.go` covers: successful completion
and registry cleanup, failed start, nonzero exit, timeout (distinguishable,
descendants killed), cancellation (not a timeout, descendants killed), a child
that ignores SIGTERM/SIGINT/SIGHUP, a pipe-holding grandchild, runaway
stdout+stderr floods, repeated start/cancel, `KillAllChildren` scope, and the
`ssh_rollback` output cap. Every helper process is killed by `t.Cleanup`.
