// Package sandbox provides Landlock LSM fallback for read-only sandboxed execution
// when bwrap is unavailable or blocked by AppArmor userns restrictions.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"

	"github.com/sm-me-dev/lnta/internal/audit"
)

const (
	// landlockHiddenCmd is the hidden subcommand that re-execs under Landlock.
	landlockHiddenCmd = "__sandbox_exec"
)

// landlockHiddenCmdEnv is the environment variable that signals we're in the
// Landlock child process.
const landlockHiddenCmdEnv = "LNTA_LANDLOCK_CHILD"

// minLandlockABI is the lowest Landlock ABI we accept: v4 adds TCP
// bind/connect control, without which the tier could not honour "no egress".
const minLandlockABI = 4

// ErrLandlockUnavailable is returned when Landlock is not supported (or is too
// old to provide the confinement lnta promises) on this kernel.
var ErrLandlockUnavailable = errors.New("landlock LSM not available on this kernel")

// ErrLandlockNotRootless is returned when Landlock rules cannot be applied
// because the process lacks the necessary ambient capabilities.
var ErrLandlockNotRootless = errors.New("landlock requires rootless/container environment")

// landlockExePath is the path to the lnta binary for self-re-exec.
// Can be overridden in tests.
var landlockExePath string

// landlockConfig is the sandbox description sent to the re-exec'd child over
// its stdin. It deliberately does NOT travel through the environment, where it
// would be visible to (and mutable by) every process on the way.
type landlockConfig struct {
	RODirs  []string `json:"ro_dirs"`
	ROFiles []string `json:"ro_files"`
	// ReadDirOnly are directories whose entries may be listed (and chdir'd
	// into) but whose children get no implicit access.
	ReadDirOnly []string `json:"read_dir_only"`
	RWDirs      []string `json:"rw_dirs"`
	RWFiles     []string `json:"rw_files"`
	Cwd         string   `json:"cwd"`
	Cmd         string   `json:"cmd"`
	Env         []string `json:"env"`
}

// landlockABI asks the kernel (not the library) which Landlock ABI it offers.
func landlockABI() (int, error) {
	const createRulesetVersion = 1 << 0 // LANDLOCK_CREATE_RULESET_VERSION
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, createRulesetVersion)
	if errno != 0 {
		return 0, errno
	}
	return int(v), nil
}

// LandlockProbe checks whether the running kernel supports Landlock at the ABI
// lnta needs. It queries the kernel directly: go-landlock's BestEffort mode
// silently degrades to "no restrictions at all", so it can never be used to
// decide availability. Does NOT apply any rules to the current process.
func LandlockProbe() error {
	abi, err := landlockABI()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLandlockUnavailable, err)
	}
	if abi < minLandlockABI {
		return fmt.Errorf("%w: ABI v%d < v%d (no network confinement)", ErrLandlockUnavailable, abi, minLandlockABI)
	}
	return nil
}

// grantTree adds read-only rules for `dir` while leaving out every path in
// `deny`. Landlock rights are inherited by everything beneath a granted
// directory and cannot be subtracted, so a directory that contains a denied
// path is not granted wholesale: it is listable, and each of its children is
// granted (or recursed into) individually. Symlinks are skipped.
func grantTree(cfg *landlockConfig, dir string, deny map[string]bool, ancestors map[string]bool) {
	if deny[dir] {
		return
	}
	if !ancestors[dir] {
		cfg.RODirs = append(cfg.RODirs, dir)
		return
	}
	cfg.ReadDirOnly = append(cfg.ReadDirOnly, dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if deny[p] {
			continue
		}
		switch {
		case e.Type()&os.ModeSymlink != 0:
			continue
		case e.IsDir():
			grantTree(cfg, p, deny, ancestors)
		case e.Type().IsRegular():
			cfg.ROFiles = append(cfg.ROFiles, p)
		}
	}
}

// buildLandlockConfig computes the allow-list for a run. Credential paths are
// never granted (Landlock is allow-list based, so "masked" means "absent").
func buildLandlockConfig(cwd, home, tmp, cmdStr string, extraEnv []string) landlockConfig {
	cfg := landlockConfig{
		Cwd: cwd,
		Cmd: cmdStr,
		Env: envList(sandboxEnvMap(home, tmp), extraEnv),
	}
	cfg.RODirs = append(cfg.RODirs, "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/proc", "/sys", "/opt", "/var/log")
	cfg.RWDirs = []string{tmp}
	cfg.RWFiles = []string{"/dev/null"}
	cfg.ROFiles = []string{"/dev/zero", "/dev/urandom", "/dev/random"}

	deny := map[string]bool{}
	// M4: exclude sensitive system directories under /etc
	for _, p := range []string{
		"/etc/ssh",
		"/etc/ssl/private",
		"/etc/cups/ssl",
		"/etc/shadow",
		"/etc/gshadow",
		"/etc/sudoers",
		"/etc/sudoers.d",
	} {
		deny[p] = true
	}
	if home != "" {
		for _, d := range secretMaskDirs(home) {
			deny[d] = true
		}
		for _, f := range secretMaskFiles(home) {
			deny[f] = true
		}
	}
	for _, f := range maskProjectSecrets(cwd) {
		deny[f] = true
	}
	ancestors := map[string]bool{}
	for p := range deny {
		for d := filepath.Dir(p); d != "/" && d != "."; d = filepath.Dir(d) {
			ancestors[d] = true
		}
	}

	roots := []string{"/etc"}
	if home != "" {
		roots = append(roots, home)
	}
	if cwd != "" && (home == "" || !under(cwd, home)) {
		roots = append(roots, cwd)
	}
	for _, r := range roots {
		if st, err := os.Stat(r); err == nil && st.IsDir() {
			grantTree(&cfg, r, deny, ancestors)
		}
	}
	sort.Strings(cfg.RODirs)
	return cfg
}

// runLandlock executes a command under Landlock LSM restrictions by
// re-executing the current binary with the hidden __sandbox_exec subcommand.
func runLandlock(ctx context.Context, cmdStr string, cwd string, timeout time.Duration) (CommandResult, error) {
	return runLandlockEnv(ctx, cmdStr, cwd, timeout, nil)
}

// runLandlockEnv is runLandlock with extra KEY=VALUE entries for the command.
func runLandlockEnv(ctx context.Context, cmdStr string, cwd string, timeout time.Duration, extraEnv []string) (CommandResult, error) {
	var res CommandResult
	start := time.Now()

	if err := LandlockProbe(); err != nil {
		return res, err // fail closed: never run "unsandboxed because Landlock is missing"
	}

	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	exe := landlockExePath
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return res, fmt.Errorf("get executable path: %w", err)
		}
	}

	absCwd, err := resolveCWD(cwd)
	if err != nil {
		return res, err
	}
	home := homeDir()

	// Private, per-run temp directory instead of the host's shared /tmp.
	tmp, err := os.MkdirTemp("", "lnta-sbx-*")
	if err != nil {
		return res, fmt.Errorf("create sandbox tmp: %w", err)
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o700); err != nil {
		return res, err
	}

	cfg := buildLandlockConfig(absCwd, home, tmp, cmdStr, extraEnv)
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return res, err
	}

	cmd := exec.CommandContext(ctx, exe, landlockHiddenCmd)
	cmd.Stdin = bytes.NewReader(cfgJSON)
	// The launcher child needs nothing from the host except its own marker.
	cmd.Env = []string{landlockHiddenCmdEnv + "=1", "PATH=/usr/local/bin:/usr/bin:/bin"}
	cmd.Dir = "/"
	ConfigureProcessGroup(cmd)

	stdout := NewCappedBuffer(maxOutputBytes, hardOutputBytes, cancel)
	stderr := NewCappedBuffer(maxOutputBytes, hardOutputBytes, cancel)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	RegisterChild(cmd)
	defer UnregisterChild(cmd)
	runErr := cmd.Run()
	res.Duration = time.Since(start)
	res.Stdout = stdout.Render()
	res.Stderr = stderr.Render()
	res.Truncated = stdout.Truncated() || stderr.Truncated()
	if runErr != nil {
		res.ExitCode = exitCodeOf(runErr)
		var ex *exec.ExitError
		if !errors.As(runErr, &ex) {
			res.Stderr = runErr.Error() + "\n" + res.Stderr
		}
	}

	audit.Log("sandbox.run", "", map[string]string{
		"cwd":      absCwd,
		"backend":  "landlock",
		"exit":     fmt.Sprintf("%d", res.ExitCode),
		"duration": res.Duration.String(),
	})

	return res, runErr
}

// applyLandlock applies the restrictions described by cfg to the current
// process. It is STRICT: it never uses BestEffort, so a kernel that cannot
// honour the policy yields an error instead of a silently unconfined process.
func applyLandlock(cfg landlockConfig) error {
	if err := LandlockProbe(); err != nil {
		return err
	}

	var rules []landlock.Rule
	for _, d := range cfg.RODirs {
		rules = append(rules, landlock.RODirs(d).IgnoreIfMissing())
	}
	for _, f := range cfg.ROFiles {
		rules = append(rules, landlock.ROFiles(f).IgnoreIfMissing())
	}
	for _, d := range cfg.ReadDirOnly {
		rules = append(rules, landlock.PathAccess(landlock.AccessFSSet(llsys.AccessFSReadDir), d).IgnoreIfMissing())
	}
	for _, d := range cfg.RWDirs {
		rules = append(rules, landlock.RWDirs(d).IgnoreIfMissing())
	}
	for _, f := range cfg.RWFiles {
		rules = append(rules, landlock.RWFiles(f).IgnoreIfMissing())
	}

	if err := landlock.V4.RestrictPaths(rules...); err != nil {
		return fmt.Errorf("apply Landlock filesystem rules: %w", err)
	}
	// Deny every TCP bind/connect (no rules == nothing permitted). Note: Linux
	// does not apply Landlock TCP rules to Multipath-TCP sockets
	// (landlock-lsm/linux#54); the bwrap tier's network namespace is the only
	// airtight egress barrier, which is why bwrap is preferred.
	if err := landlock.V4.RestrictNet(); err != nil {
		return fmt.Errorf("apply Landlock network rules: %w", err)
	}
	// Defence in depth where the kernel supports them: deny UDP, and abstract
	// Unix sockets / signals to processes outside the domain.
	_ = landlock.V10.BestEffort().RestrictNet()
	_ = landlock.V10.BestEffort().RestrictScoped()
	return nil
}

// LandlockExecMain is the entry point for the __sandbox_exec hidden command.
// It reads the sandbox description from stdin, applies Landlock, runs the
// target command and returns ITS exit status (128+signal when signalled).
func LandlockExecMain() int {
	if os.Getenv(landlockHiddenCmdEnv) != "1" {
		fmt.Fprintln(os.Stderr, "__sandbox_exec is internal and must not be invoked directly")
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read sandbox config:", err)
		return 2
	}
	var cfg landlockConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "decode sandbox config:", err)
		return 2
	}
	if cfg.Cmd == "" {
		fmt.Fprintln(os.Stderr, "sandbox config has no command")
		return 2
	}
	if err := applyLandlock(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "Landlock apply:", err)
		return 126
	}

	cwd := cfg.Cwd
	if cwd == "" {
		cwd = "."
	}
	cmd := exec.Command("sh", "-c", cfg.Cmd)
	cmd.Dir = cwd
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = cfg.Env
	RegisterChild(cmd)
	if err := cmd.Run(); err != nil {
		return exitCodeOf(err)
	}
	return 0
}

// LandlockExecCommand is LandlockExecMain adapted to an error return for
// callers that predate exit-status propagation.
func LandlockExecCommand() error {
	if code := LandlockExecMain(); code != 0 {
		return fmt.Errorf("sandboxed command exited with status %d", code)
	}
	return nil
}

// joinPaths joins non-empty paths with ':'.
func joinPaths(paths []string) string {
	var out []string
	for _, p := range paths {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ":")
}
