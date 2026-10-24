package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// childRegistry tracks live process groups so they can be killed on shutdown
// (Ctrl-C / cancellation), preventing orphans from bwrap/ssh/mutate children.
var childRegistry struct {
	mu   sync.Mutex
	pgid map[int]struct{}
}

func init() {
	childRegistry.pgid = make(map[int]struct{})
}

// ConfigureProcessGroup puts cmd into its own process group and registers it
// in the child registry so KillAllChildren can terminate it on shutdown.
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

	childRegistry.mu.Lock()
	defer childRegistry.mu.Unlock()
	// Register after Start; placeholder here, updated by RegisterChild.
}

// RegisterChild adds a started process's PID to the registry so its group is
// killed by KillAllChildren. Call immediately after cmd.Start().
func RegisterChild(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	childRegistry.mu.Lock()
	defer childRegistry.mu.Unlock()
	childRegistry.pgid[cmd.Process.Pid] = struct{}{}
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

// KillAllChildren sends SIGKILL to every registered process group. Safe to call
// multiple times. Used on shutdown paths (main defer, signal handler).
func KillAllChildren() {
	childRegistry.mu.Lock()
	defer childRegistry.mu.Unlock()
	for pgid := range childRegistry.pgid {
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
