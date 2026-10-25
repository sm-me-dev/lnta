# Collecting evidence after a terminal incident

LNTA has not been established as the cause of any terminal or desktop crash.
Capture host evidence before restarting the session when practical. These
commands only read system state. Use a time window that includes the incident
and preserve the host's timezone and clock information.

```bash
date --iso-8601=seconds
timedatectl
journalctl --user -b --since "2 hours ago" --no-pager
journalctl -k -b --since "2 hours ago" --no-pager | grep -Ei 'oom|out of memory|killed process|apparmor|segfault|trap'
coredumpctl list --since "2 hours ago"
loginctl list-sessions
loginctl session-status
ps -eo pid,ppid,pgid,sid,lstart,etime,%cpu,%mem,rss,stat,comm --sort=-rss | head -n 80
```

For a suspected process, collect its current limits and memory status while it
still exists:

```bash
ps -p PID -o pid,ppid,pgid,sid,lstart,etime,%cpu,%mem,rss,vsz,stat,comm
cat /proc/PID/status
cat /proc/PID/limits
```

For a Bubblewrap or AppArmor failure, inspect the loaded distro policy and
kernel messages:

```bash
sudo aa-status
cat /sys/kernel/security/apparmor/profiles
journalctl -k -b --since "2 hours ago" --no-pager | grep -i apparmor
lnta doctor --verbose
```

LNTA lifecycle events are written to
`~/.local/share/lnta/logs/audit.jsonl`. To show only the new child lifecycle
metadata without dumping other audit events:

```bash
jq -c 'select(.event == "process.start" or .event == "process.complete")' \
  ~/.local/share/lnta/logs/audit.jsonl | tail -n 200
```

Lifecycle events contain the internal child role, PID/process group, elapsed
time, exit status, cancellation and timeout flags, and stdout/stderr byte
counts. They do not record command text, prompts, environment values, or child
output. Other existing audit events may contain task details, so share only
the relevant lifecycle records after reviewing them.
