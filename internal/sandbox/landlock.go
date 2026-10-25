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
	"syscall"
	"time"
	"unsafe"

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

// minLandlockABI is the lowest Landlock ABI accepted. V10 adds UDP and
// scoped restrictions; seccomp additionally blocks IP socket creation.
const minLandlockABI = 10

// ErrLandlockUnavailable is returned when Landlock is not supported (or is too
// old to provide the confinement lnta promises) on this kernel.
var ErrLandlockUnavailable = errors.New("landlock LSM not available on this kernel")

// ErrLandlockExecutionProbe identifies a failure while testing the complete
// self-reexec and confinement path, beyond the ABI-only capability query.
var ErrLandlockExecutionProbe = errors.New("landlock execution probe failed")

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
	return checkLandlockABI(abi)
}

// ProbeLandlockExecution verifies the complete fallback path by running a
// bounded no-op through the same self-reexec and confinement setup as normal
// execution. ABI-only checks remain available through LandlockProbe.
func ProbeLandlockExecution(timeout time.Duration) error {
	if timeout <= 0 || timeout > 5*time.Second {
		timeout = 3 * time.Second
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get current directory: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err = runLandlockEnv(ctx, "true", cwd, timeout, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLandlockExecutionProbe, err)
	}
	return nil
}

func checkLandlockABI(abi int) error {
	if abi < minLandlockABI {
		return fmt.Errorf("%w: ABI v%d < v%d (complete network confinement unavailable)", ErrLandlockUnavailable, abi, minLandlockABI)
	}
	return nil
}

// grantTree adds read-only rules for `dir` while leaving out every path in
// `deny`. Landlock rights are inherited by everything beneath a granted
// directory and cannot be subtracted, so a directory that contains a denied
// path is not granted wholesale: it is listable, and each of its children is
// granted (or recursed into) individually. Symlinks are skipped.
const (
	maxLandlockTreeEntries = 20000
	maxLandlockTreeDepth   = 32
)

type landlockTreeScan struct{ entries int }

func grantTree(cfg *landlockConfig, dir string, deny map[string]bool, ancestors map[string]bool, scan *landlockTreeScan, depth int) error {
	if deny[dir] {
		return nil
	}
	if !ancestors[dir] {
		cfg.RODirs = append(cfg.RODirs, dir)
		return nil
	}
	if depth >= maxLandlockTreeDepth {
		return fmt.Errorf("landlock allowlist scan incomplete: depth limit %d reached at %q", maxLandlockTreeDepth, dir)
	}
	cfg.ReadDirOnly = append(cfg.ReadDirOnly, dir)
	file, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("read sandbox allowlist directory %q: %w", dir, err)
	}
	defer file.Close()
	for {
		entries, readErr := file.ReadDir(256)
		scan.entries += len(entries)
		if scan.entries > maxLandlockTreeEntries {
			return fmt.Errorf("landlock allowlist scan incomplete: entry limit %d exceeded", maxLandlockTreeEntries)
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
				if err := grantTree(cfg, p, deny, ancestors, scan, depth+1); err != nil {
					return err
				}
			case e.Type().IsRegular():
				cfg.ROFiles = append(cfg.ROFiles, p)
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return fmt.Errorf("read sandbox allowlist directory %q: %w", dir, readErr)
		}
	}
	return nil
}

// buildLandlockConfig computes the allow-list for a run. Credential paths are
// never granted (Landlock is allow-list based, so "masked" means "absent").
func buildLandlockConfig(cwd, home, tmp, cmdStr string, extraEnv []string) (landlockConfig, error) {
	cfg := landlockConfig{
		Cwd: cwd,
		Cmd: cmdStr,
		Env: envList(sandboxEnvMap(home, tmp), extraEnv),
	}
	// Landlock has no PID namespace. Do not grant /proc: same-user process
	// environments and descriptors can otherwise expose the parent agent's
	// credentials. The fallback intentionally cannot inspect host processes.
	baseRODirs := []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/sys", "/opt", "/var/log"}
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
	projectSecrets, err := maskProjectSecrets(cwd)
	if err != nil {
		return cfg, err
	}
	for _, f := range projectSecrets {
		deny[f] = true
	}
	ancestors := map[string]bool{}
	for p := range deny {
		for d := filepath.Dir(p); d != "/" && d != "."; d = filepath.Dir(d) {
			ancestors[d] = true
		}
	}

	roots := append([]string{"/etc"}, baseRODirs...)
	if home != "" {
		roots = append(roots, home)
	}
	if cwd != "" {
		covered := false
		for _, root := range roots {
			if pathWithin(cwd, root) {
				covered = true
				break
			}
		}
		if !covered {
			roots = append(roots, cwd)
		}
	}
	seenRoots := make(map[string]bool, len(roots))
	treeScan := &landlockTreeScan{}
	for _, r := range roots {
		if seenRoots[r] {
			continue
		}
		seenRoots[r] = true
		st, statErr := os.Stat(r)
		if statErr != nil {
			if !errors.Is(statErr, os.ErrNotExist) {
				return cfg, fmt.Errorf("inspect sandbox root %q: %w", r, statErr)
			}
			continue
		}
		if st.IsDir() {
			if err := grantLandlockRoot(&cfg, r, deny, ancestors, treeScan); err != nil {
				return cfg, err
			}
		}
	}
	sort.Strings(cfg.RODirs)
	return cfg, nil
}

func pathWithin(path, root string) bool {
	path, root = filepath.Clean(path), filepath.Clean(root)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func grantLandlockRoot(cfg *landlockConfig, root string, deny map[string]bool, ancestors map[string]bool, scan *landlockTreeScan) error {
	if deny[root] || ancestors[root] {
		return grantTree(cfg, root, deny, ancestors, scan, 0)
	}
	cfg.RODirs = append(cfg.RODirs, root)
	return nil
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

	cfg, err := buildLandlockConfig(absCwd, home, tmp, cmdStr, extraEnv)
	if err != nil {
		return res, err
	}
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

	childStarted, startErr := StartChild("landlock", cmd)
	if startErr != nil {
		return res, fmt.Errorf("start Landlock sandbox: %w", startErr)
	}
	runErr := WaitChild("landlock", cmd, childStarted, ctx, stdout, stderr)
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
	if err := landlock.V10.RestrictNet(); err != nil {
		return fmt.Errorf("apply Landlock network rules: %w", err)
	}
	if err := landlock.V10.RestrictScoped(); err != nil {
		return fmt.Errorf("apply Landlock scoped rules: %w", err)
	}
	if err := denyIPSocketCreation(); err != nil {
		return fmt.Errorf("apply network socket filter: %w", err)
	}
	if err := denyProcessControlSyscalls(); err != nil {
		return fmt.Errorf("apply process-control filter: %w", err)
	}
	return nil
}

// denyIPSocketCreation closes the Multipath-TCP gap in Landlock by denying
// socket(AF_INET/AF_INET6/AF_MPTCP, ...) for this process and its descendants.
func denyIPSocketCreation() error {
	filters := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 5, K: unix.SYS_SOCKET},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 2, Jf: 0, K: unix.AF_INET},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, Jf: 0, K: unix.AF_INET6},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: 45}, // AF_MPTCP
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if _, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return errno
	}
	_, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&program)))
	if errno != 0 {
		return errno
	}
	return nil
}

// denyProcessControlSyscalls prevents a Landlock fallback command from
// signaling or inspecting host processes when PID namespaces are unavailable.
func denyProcessControlSyscalls() error {
	blocked := []uint32{
		unix.SYS_KILL, unix.SYS_TKILL, unix.SYS_TGKILL, unix.SYS_PTRACE,
		unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
		unix.SYS_PIDFD_GETFD, unix.SYS_PIDFD_SEND_SIGNAL,
	}
	filters := []unix.SockFilter{{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}}
	for _, nr := range blocked {
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: nr},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		)
	}
	filters = append(filters, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	program := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if _, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return errno
	}
	_, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&program)))
	if errno != 0 {
		return errno
	}
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
	if err := os.Chdir(cwd); err != nil {
		fmt.Fprintln(os.Stderr, "change to sandbox cwd:", err)
		return 126
	}
	// Replace the launcher process instead of starting an untracked grandchild.
	// The outer lifecycle wrapper then observes the actual command's status and
	// owns cleanup of its complete process group.
	if err := syscall.Exec("/bin/sh", []string{"sh", "-c", cfg.Cmd}, cfg.Env); err != nil {
		fmt.Fprintln(os.Stderr, "exec sandboxed command:", err)
		return 126
	}
	return 126 // syscall.Exec only returns on failure.
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
