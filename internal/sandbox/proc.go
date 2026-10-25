package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sm-me-dev/lnta/internal/audit"
)

// childRegistry tracks live process groups so they can be killed on shutdown
// (Ctrl-C / cancellation), preventing orphans from bwrap/ssh/mutate children.
var childRegistry struct {
	mu   sync.Mutex
	pgid map[int]int // process PID -> process group ID
}

func init() {
	childRegistry.pgid = make(map[int]int)
}

// ConfigureProcessGroup puts cmd into its own process group so lifecycle
// helpers can terminate it on shutdown.
// Must be called after exec.CommandContext and before Start.
func ConfigureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative PID == the whole process group.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			return err
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
}

// RegisterChild adds a started process's PID to the registry so its group is
// killed by KillAllChildren. Call immediately after cmd.Start().
func RegisterChild(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	childRegistry.mu.Lock()
	defer childRegistry.mu.Unlock()
	registerChildLocked(cmd)
}

func registerChildLocked(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		pgid = cmd.Process.Pid
	}
	childRegistry.pgid[cmd.Process.Pid] = pgid
}

// UnregisterChild removes a finished process's PID from the registry.
// Call after cmd.Wait() or cmd.Run() completes.
func UnregisterChild(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	childRegistry.mu.Lock()
	defer childRegistry.mu.Unlock()
	delete(childRegistry.pgid, cmd.Process.Pid)
}

// StartChild starts a child, registers its process group, and writes a
// privacy-safe lifecycle event. Role is a fixed internal label, never a
// command, prompt, environment value, or child output.
func StartChild(role string, cmd *exec.Cmd) (time.Time, error) {
	started := time.Now()
	childRegistry.mu.Lock()
	if err := cmd.Start(); err != nil {
		childRegistry.mu.Unlock()
		return started, err
	}
	registerChildLocked(cmd)
	childRegistry.mu.Unlock()
	audit.Log("process.start", "", processStartDetails(role, cmd.Process.Pid))
	return started, nil
}

// WaitChild waits for a previously started child, unregisters it, and records
// bounded lifecycle metadata. Output content and command details are omitted.
//
// When the child leads its own process group, the whole group is killed as
// soon as the leader has exited, BEFORE the leader is reaped. While the
// unreaped leader exists its pid (and therefore the group id) cannot be
// recycled, so the group kill can never hit an unrelated group. Killing early
// also closes any output pipes a surviving descendant inherited, so Wait does
// not stall for WaitDelay and report a successful command as failed.
//
// If the context's deadline expired, the returned error additionally matches
// context.DeadlineExceeded (errors.Is) while still unwrapping to the
// *exec.ExitError, so timeouts are distinguishable from ordinary failures and
// from cancellation (including the output-cap kill, which cancels the context).
func WaitChild(role string, cmd *exec.Cmd, started time.Time, ctx context.Context, stdout, stderr *CappedBuffer) error {
	pgid := 0
	if cmd != nil && cmd.Process != nil {
		pgid = registeredProcessGroup(cmd.Process.Pid)
		// An inherited group is owned and reaped by its registered leader.
		if pgid > 0 && pgid == cmd.Process.Pid {
			killGroupAfterLeaderExit(pgid)
		}
	}
	err := cmd.Wait()
	UnregisterChild(cmd)
	if err != nil && ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded) {
		err = fmt.Errorf("%w: %w", err, context.DeadlineExceeded)
	}
	var stdoutBytes, stderrBytes int64
	if stdout != nil {
		stdoutBytes = stdout.Total()
	}
	if stderr != nil {
		stderrBytes = stderr.Total()
	}
	exitStatus := exitCodeOf(err)
	audit.Log("process.complete", "", processCompletionDetailsWithGroup(role, processID(cmd), strconv.Itoa(pgid), started, ctx, exitStatus, stdoutBytes, stderrBytes))
	return err
}

// killGroupAfterLeaderExit blocks until the process pid has exited without
// reaping it (waitid WNOWAIT), then SIGKILLs the process group pid. If the
// leader cannot be observed (for example it was already reaped elsewhere) no
// signal is sent, because the group id may no longer belong to this child.
func killGroupAfterLeaderExit(pid int) {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return
		}
		break
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}

func processStartDetails(role string, pid int) map[string]string {
	id := strconv.Itoa(pid)
	pgid := pid
	if actual, err := syscall.Getpgid(pid); err == nil {
		pgid = actual
	}
	return map[string]string{"role": role, "pid": id, "pgid": strconv.Itoa(pgid)}
}

func processCompletionDetails(role, id string, started time.Time, ctx context.Context, exitStatus int, stdoutBytes, stderrBytes int64) map[string]string {
	return processCompletionDetailsWithGroup(role, id, id, started, ctx, exitStatus, stdoutBytes, stderrBytes)
}

func processCompletionDetailsWithGroup(role, id, pgid string, started time.Time, ctx context.Context, exitStatus int, stdoutBytes, stderrBytes int64) map[string]string {
	canceled := ctx != nil && ctx.Err() != nil
	timedOut := ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)
	return map[string]string{
		"role":         role,
		"pid":          id,
		"pgid":         pgid,
		"elapsed_ms":   strconv.FormatInt(time.Since(started).Milliseconds(), 10),
		"exit_status":  strconv.Itoa(exitStatus),
		"canceled":     strconv.FormatBool(canceled),
		"timed_out":    strconv.FormatBool(timedOut),
		"stdout_bytes": strconv.FormatInt(stdoutBytes, 10),
		"stderr_bytes": strconv.FormatInt(stderrBytes, 10),
	}
}

func registeredProcessGroup(pid int) int {
	childRegistry.mu.Lock()
	defer childRegistry.mu.Unlock()
	return childRegistry.pgid[pid]
}

func processID(cmd *exec.Cmd) string {
	if cmd == nil || cmd.Process == nil {
		return ""
	}
	return strconv.Itoa(cmd.Process.Pid)
}

// KillAllChildren sends SIGKILL to every registered process group. Safe to call
// multiple times. Used on shutdown paths (main defer, signal handler).
func KillAllChildren() {
	childRegistry.mu.Lock()
	defer childRegistry.mu.Unlock()
	seen := make(map[int]struct{}, len(childRegistry.pgid))
	for _, pgid := range childRegistry.pgid {
		if _, ok := seen[pgid]; ok {
			continue
		}
		seen[pgid] = struct{}{}
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}
}

// hardOutputBytes is the amount of output after which a running command is
// killed outright. Only the first maxOutputBytes are ever retained.
const hardOutputBytes = 8 << 20

// CappedBuffer keeps only the first `limit` bytes written to it, counts the
// rest, and (optionally) invokes kill once more than `hard` bytes were written
// so a runaway producer (`yes`, `cat /dev/zero`) cannot exhaust memory or time.
type CappedBuffer struct {
	mu    sync.Mutex
	head  bytes.Buffer
	limit int
	hard  int64
	total int64
	kill  context.CancelFunc
}

// NewCappedBuffer returns a CappedBuffer retaining `limit` bytes. When kill is
// non-nil it is called once total output exceeds `hard` bytes.
func NewCappedBuffer(limit int, hard int64, kill context.CancelFunc) *CappedBuffer {
	return &CappedBuffer{limit: limit, hard: hard, kill: kill}
}

// Write implements io.Writer. It always reports full success so the child is
// not SIGPIPE'd before the kill takes effect.
func (c *CappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total += int64(len(p))
	if room := c.limit - c.head.Len(); room > 0 {
		if room > len(p) {
			room = len(p)
		}
		c.head.Write(p[:room])
	}
	if c.kill != nil && c.hard > 0 && c.total > c.hard {
		c.kill()
		c.kill = nil
	}
	return len(p), nil
}

// String returns the retained prefix.
func (c *CappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.head.String()
}

// Total returns the number of bytes written (retained or not).
func (c *CappedBuffer) Total() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

// Truncated reports whether bytes were discarded.
func (c *CappedBuffer) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total > int64(c.limit)
}

// Render returns the retained text with a truncation marker when needed.
func (c *CappedBuffer) Render() string {
	s := c.String()
	if !c.Truncated() {
		return s
	}
	marker := fmt.Sprintf("\n\n[OUTPUT TRUNCATED: %d total bytes]\n", c.Total())
	keep := c.limit - len(marker)
	if keep < 0 {
		keep = 0
	}
	if keep < len(s) {
		s = s[:keep]
	}
	return s + marker
}

// sandboxEnvMap is the ONLY environment ever given to a sandboxed command.
// Nothing is inherited from the host: no API keys, no SSH_AUTH_SOCK, no
// LD_PRELOAD/BASH_ENV/ENV/PROMPT_COMMAND/GIT_SSH_COMMAND.
func sandboxEnvMap(home, tmp string) map[string]string {
	if home == "" {
		home = "/nonexistent"
	}
	m := map[string]string{
		"PATH":                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME":                home,
		"LANG":                "C.UTF-8",
		"LC_ALL":              "C.UTF-8",
		"TERM":                "dumb",
		"DEBIAN_FRONTEND":     "noninteractive",
		"GIT_TERMINAL_PROMPT": "0",
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_PAGER":           "cat",
		"PAGER":               "cat",
		"SYSTEMD_PAGER":       "",
		"NO_COLOR":            "1",
	}
	if tmp != "" {
		m["TMPDIR"] = tmp
	}
	return m
}

// envList renders an env map (plus extra KEY=VALUE entries that override it)
// as a deterministic KEY=VALUE slice.
func envList(base map[string]string, extra []string) []string {
	merged := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		merged[k] = v
	}
	for _, kv := range extra {
		if i := strings.IndexByte(kv, '='); i > 0 {
			merged[kv[:i]] = kv[i+1:]
		}
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+merged[k])
	}
	return out
}
