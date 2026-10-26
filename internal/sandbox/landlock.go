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
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
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

const minLandlockABI = 8

const (
	maxLandlockTreeEntries = 500_000
	maxLandlockTreeDepth   = 32
	maxLandlockRules       = 500_000
	maxLandlockPathBytes   = 8 << 20
	maxLandlockConfigBytes = 64 << 20
)

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
		return fmt.Errorf("%w: ABI v%d < v%d; use a kernel with Landlock ABI 8+ or operational Bubblewrap", ErrLandlockUnavailable, abi, minLandlockABI)
	}
	return nil
}

// grantTree adds read-only rules for `dir` while leaving out every path in
// `deny`. Landlock rights are inherited by everything beneath a granted
// directory and cannot be subtracted, so a directory that contains a denied
type landlockEntryIdentity struct {
	dev  uint64
	ino  uint64
	name string
}

type landlockTreeScan struct {
	entries   int
	rules     int
	pathBytes int
	seen      map[landlockEntryIdentity]struct{}
}

func (scan *landlockTreeScan) addPathBytes(path string) error {
	if len(path) > maxLandlockPathBytes-scan.pathBytes {
		return fmt.Errorf("landlock configuration exceeds path byte limit %d", maxLandlockPathBytes)
	}
	scan.pathBytes += len(path)
	return nil
}

func (scan *landlockTreeScan) addEntry(parent unix.Stat_t, name string) error {
	if scan.seen == nil {
		scan.seen = make(map[landlockEntryIdentity]struct{})
	}
	identity := landlockEntryIdentity{dev: uint64(parent.Dev), ino: parent.Ino, name: name}
	if _, exists := scan.seen[identity]; exists {
		return nil
	}
	scan.seen[identity] = struct{}{}
	scan.entries++
	if scan.entries > maxLandlockTreeEntries {
		return fmt.Errorf("landlock allowlist scan incomplete: entry limit %d exceeded", maxLandlockTreeEntries)
	}
	return nil
}

func (scan *landlockTreeScan) addRule(paths *[]string, path string) error {
	if scan.rules >= maxLandlockRules {
		return fmt.Errorf("landlock configuration exceeds rule limit %d", maxLandlockRules)
	}
	if len(path) > maxLandlockPathBytes-scan.pathBytes {
		return fmt.Errorf("landlock configuration exceeds path byte limit %d", maxLandlockPathBytes)
	}
	scan.rules++
	scan.pathBytes += len(path)
	*paths = append(*paths, path)
	return nil
}

func grantTree(cfg *landlockConfig, dir string, deny map[string]bool, ancestors map[string]bool, scan *landlockTreeScan, depth int) error {
	if deny[dir] {
		return nil
	}
	if !ancestors[dir] {
		return scan.addRule(&cfg.RODirs, dir)
	}
	if depth > maxLandlockTreeDepth {
		return fmt.Errorf("landlock allowlist scan incomplete: depth limit %d exceeded at %q", maxLandlockTreeDepth, dir)
	}
	fD, err := openAbsoluteDirNoFollow(dir)
	if err != nil {
		return fmt.Errorf("open sandbox allowlist directory %q without following links: %w", dir, err)
	}
	defer unix.Close(fD)
	return grantTreeFD(cfg, fD, dir, deny, ancestors, scan, depth)
}

func grantTreeFD(cfg *landlockConfig, dirFD int, dir string, deny map[string]bool, ancestors map[string]bool, scan *landlockTreeScan, depth int) error {
	var before unix.Stat_t
	if err := unix.Fstat(dirFD, &before); err != nil {
		return fmt.Errorf("inspect sandbox allowlist directory %q: %w", dir, err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("sandbox allowlist path %q is not a directory", dir)
	}
	if err := scan.addRule(&cfg.ReadDirOnly, dir); err != nil {
		return err
	}
	err := readDirAt(dirFD, func(entry os.DirEntry) error {
		if err := scan.addEntry(before, entry.Name()); err != nil {
			return err
		}
		path := filepath.Join(dir, entry.Name())
		stat, err := statAtNoFollow(dirFD, entry.Name())
		if err != nil {
			return fmt.Errorf("inspect sandbox allowlist entry %q: %w", path, err)
		}
		if deny[path] {
			return nil
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			return nil
		case unix.S_IFDIR:
			if !ancestors[path] {
				return scan.addRule(&cfg.RODirs, path)
			}
			if depth+1 > maxLandlockTreeDepth {
				return fmt.Errorf("landlock allowlist scan incomplete: depth limit %d exceeded at %q", maxLandlockTreeDepth, path)
			}
			childFD, _, err := openChildDirNoFollow(dirFD, entry.Name(), &stat)
			if err != nil {
				return fmt.Errorf("sandbox allowlist directory changed at %q: %w", path, err)
			}
			err = grantTreeFD(cfg, childFD, path, deny, ancestors, scan, depth+1)
			_ = unix.Close(childFD)
			if err != nil {
				return err
			}
			current, err := statAtNoFollow(dirFD, entry.Name())
			if err != nil || !sameTreeStat(stat, current) {
				return fmt.Errorf("sandbox allowlist directory changed during scan at %q", path)
			}
		case unix.S_IFREG:
			fileFD, err := unix.Openat(dirFD, entry.Name(), unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return fmt.Errorf("open sandbox allowlist file %q without following links: %w", path, err)
			}
			var opened unix.Stat_t
			statErr := unix.Fstat(fileFD, &opened)
			_ = unix.Close(fileFD)
			if statErr != nil || !sameTreeStat(stat, opened) {
				return fmt.Errorf("sandbox allowlist file changed during scan at %q", path)
			}
			return scan.addRule(&cfg.ROFiles, path)
		default:
			return fmt.Errorf("unsupported sandbox allowlist entry type at %q", path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("read sandbox allowlist directory %q: %w", dir, err)
	}
	if err := verifyDirUnchanged(dirFD, before); err != nil {
		return fmt.Errorf("sandbox allowlist directory changed during scan at %q", dir)
	}
	return nil
}

// buildLandlockConfig computes the allow-list for a run. Credential paths are
// never granted (Landlock is allow-list based, so "masked" means "absent").
func buildLandlockConfig(projectRoot, cwd, home, tmp, cmdStr string, extraEnv []string) (landlockConfig, error) {
	cfg := landlockConfig{
		RODirs:      []string{},
		ROFiles:     []string{},
		ReadDirOnly: []string{},
		RWDirs:      []string{},
		RWFiles:     []string{},
		Cwd:         cwd,
		Cmd:         cmdStr,
		Env:         envList(sandboxEnvMap(home, tmp), extraEnv),
	}
	treeScan := &landlockTreeScan{}
	if err := treeScan.addPathBytes(cwd); err != nil {
		return landlockConfig{}, err
	}
	// Landlock has no PID namespace. Do not grant /proc: same-user process
	// environments and descriptors can otherwise expose the parent agent's
	// credentials. The fallback intentionally cannot inspect host processes.
	baseRODirs := []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/sys", "/opt", "/var/log"}
	if err := treeScan.addRule(&cfg.RWDirs, tmp); err != nil {
		return landlockConfig{}, err
	}
	if err := treeScan.addRule(&cfg.RWFiles, "/dev/null"); err != nil {
		return landlockConfig{}, err
	}
	for _, path := range []string{"/dev/zero", "/dev/urandom", "/dev/random"} {
		if err := treeScan.addRule(&cfg.ROFiles, path); err != nil {
			return landlockConfig{}, err
		}
	}

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
	projectSecrets, err := maskProjectSecrets(projectRoot)
	if err != nil {
		return landlockConfig{}, err
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
	if projectRoot != "" {
		covered := false
		for _, root := range roots {
			if pathWithin(projectRoot, root) {
				covered = true
				break
			}
		}
		if !covered {
			roots = append(roots, projectRoot)
		}
	}
	seenRoots := make(map[string]bool, len(roots))
	for _, r := range roots {
		if seenRoots[r] {
			continue
		}
		seenRoots[r] = true
		st, statErr := os.Stat(r)
		if statErr != nil {
			if !errors.Is(statErr, os.ErrNotExist) {
				return landlockConfig{}, fmt.Errorf("inspect sandbox root %q: %w", r, statErr)
			}
			continue
		}
		if st.IsDir() {
			if err := grantLandlockRoot(&cfg, r, deny, ancestors, treeScan); err != nil {
				return landlockConfig{}, err
			}
		}
	}
	sort.Strings(cfg.RODirs)
	if err := validateLandlockConfigBudget(cfg); err != nil {
		return landlockConfig{}, err
	}
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
	return scan.addRule(&cfg.RODirs, root)
}

func validateLandlockConfigBudget(cfg landlockConfig) error {
	rules := len(cfg.RODirs) + len(cfg.ROFiles) + len(cfg.ReadDirOnly) + len(cfg.RWDirs) + len(cfg.RWFiles)
	if rules > maxLandlockRules {
		return fmt.Errorf("landlock configuration exceeds rule limit %d", maxLandlockRules)
	}
	pathBytes := len(cfg.Cwd)
	if pathBytes > maxLandlockPathBytes {
		return fmt.Errorf("landlock configuration exceeds path byte limit %d", maxLandlockPathBytes)
	}
	for _, paths := range [][]string{cfg.RODirs, cfg.ROFiles, cfg.ReadDirOnly, cfg.RWDirs, cfg.RWFiles} {
		for _, path := range paths {
			if len(path) > maxLandlockPathBytes-pathBytes {
				return fmt.Errorf("landlock configuration exceeds path byte limit %d", maxLandlockPathBytes)
			}
			pathBytes += len(path)
		}
	}
	if estimateLandlockJSONBytes(cfg) > maxLandlockConfigBytes {
		return fmt.Errorf("landlock configuration exceeds serialized JSON limit %d bytes", maxLandlockConfigBytes)
	}
	return nil
}

func estimateLandlockJSONBytes(cfg landlockConfig) int {
	fields := []struct {
		name  string
		value []string
	}{
		{name: `"ro_dirs":`, value: cfg.RODirs},
		{name: `,"ro_files":`, value: cfg.ROFiles},
		{name: `,"read_dir_only":`, value: cfg.ReadDirOnly},
		{name: `,"rw_dirs":`, value: cfg.RWDirs},
		{name: `,"rw_files":`, value: cfg.RWFiles},
	}
	size := 1
	for _, field := range fields {
		size += len(field.name) + jsonStringArraySize(field.value)
	}
	size += len(`,"cwd":`) + jsonStringSize(cfg.Cwd)
	size += len(`,"cmd":`) + jsonStringSize(cfg.Cmd)
	size += len(`,"env":`) + jsonStringArraySize(cfg.Env) + 1
	return size
}

func jsonStringArraySize(values []string) int {
	if values == nil {
		return len("null")
	}
	size := 2 + max(0, len(values)-1)
	for _, value := range values {
		size += jsonStringSize(value)
	}
	return size
}

func jsonStringSize(value string) int {
	size := 2
	for index := 0; index < len(value); {
		character := value[index]
		switch {
		case character == '"' || character == '\\' || character == '\b' || character == '\f' || character == '\n' || character == '\r' || character == '\t':
			size += 2
			index++
		case character < 0x20 || character == '<' || character == '>' || character == '&':
			size += 6
			index++
		case character < utf8.RuneSelf:
			size++
			index++
		default:
			runeValue, runeSize := utf8.DecodeRuneInString(value[index:])
			if runeValue == utf8.RuneError && runeSize == 1 {
				size += 3
				index++
			} else if runeValue == '\u2028' || runeValue == '\u2029' {
				size += 6
				index += runeSize
			} else {
				size += runeSize
				index += runeSize
			}
		}
	}
	return size
}

// runLandlock executes a command under Landlock LSM restrictions by
// re-executing the current binary with the hidden __sandbox_exec subcommand.
func runLandlock(ctx context.Context, cmdStr string, cwd string, timeout time.Duration) (CommandResult, error) {
	return runLandlockEnv(ctx, cmdStr, cwd, timeout, nil)
}

// runLandlockEnv is runLandlock with extra KEY=VALUE entries for the command.
func runLandlockEnv(ctx context.Context, cmdStr string, cwd string, timeout time.Duration, extraEnv []string) (CommandResult, error) {
	root, err := ResolveProjectRoot(cwd)
	if err != nil {
		return CommandResult{}, err
	}
	return runLandlockProjectEnv(ctx, cmdStr, root, cwd, timeout, extraEnv)
}

func runLandlockProjectEnv(ctx context.Context, cmdStr, projectRoot, cwd string, timeout time.Duration, extraEnv []string) (CommandResult, error) {
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

	absRoot, absCwd, err := resolveProjectAndCWD(projectRoot, cwd)
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

	cfg, err := buildLandlockConfig(absRoot, absCwd, home, tmp, cmdStr, extraEnv)
	if err != nil {
		return res, err
	}
	validatedCfg, err := buildLandlockConfig(absRoot, absCwd, home, tmp, cmdStr, extraEnv)
	if err != nil {
		return res, err
	}
	if !reflect.DeepEqual(cfg, validatedCfg) {
		return res, fmt.Errorf("project or allowlist changed during pre-launch validation")
	}
	cfg = validatedCfg
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return res, err
	}
	if len(cfgJSON) > maxLandlockConfigBytes {
		return res, fmt.Errorf("landlock configuration exceeds serialized JSON limit %d bytes", maxLandlockConfigBytes)
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
	if err := validateLandlockConfigBudget(cfg); err != nil {
		return err
	}
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
	if err := landlock.V8.RestrictNet(); err != nil {
		return fmt.Errorf("apply Landlock network rules: %w", err)
	}
	if err := landlock.V8.RestrictScoped(); err != nil {
		return fmt.Errorf("apply Landlock scoped rules: %w", err)
	}
	if err := denyNetworkSyscalls(); err != nil {
		return fmt.Errorf("apply network seccomp filter: %w", err)
	}
	if err := denyProcessControlSyscalls(); err != nil {
		return fmt.Errorf("apply process-control filter: %w", err)
	}
	return nil
}

func verifyPipeDescriptor(fd int, purpose string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect %s descriptor %d: %w", purpose, fd, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFIFO {
		return fmt.Errorf("%s descriptor %d is not a pipe", purpose, fd)
	}
	return nil
}

func sanitizeLandlockDescriptors(nullFD int) error {
	if err := unix.Dup3(nullFD, 0, 0); err != nil {
		return fmt.Errorf("replace sandbox stdin: %w", err)
	}
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_UNSHARE); err != nil {
		return fmt.Errorf("close inherited sandbox descriptors: %w", err)
	}
	return nil
}

// denyProcessControlSyscalls prevents a Landlock fallback command from
// signaling, inspecting, or escaping the managed process group when PID
// namespaces are unavailable.
func denyProcessControlSyscalls() error {
	blocked := []uint32{
		unix.SYS_KILL, unix.SYS_TKILL, unix.SYS_TGKILL, unix.SYS_PTRACE,
		unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
		unix.SYS_PIDFD_GETFD, unix.SYS_PIDFD_SEND_SIGNAL,
		unix.SYS_SETSID, unix.SYS_SETPGID,
	}
	return denySyscalls(blocked)
}

// denySessionGroupSyscalls prevents commands from escaping LNTA's managed
// process group. The filter is inherited by forked and exec'd descendants.
func denySessionGroupSyscalls() error {
	return denySyscalls([]uint32{unix.SYS_SETSID, unix.SYS_SETPGID})
}

func denySyscalls(blocked []uint32) error {
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
	for _, descriptor := range []struct {
		fd      int
		purpose string
	}{{0, "configuration input"}, {1, "stdout capture"}, {2, "stderr capture"}} {
		if err := verifyPipeDescriptor(descriptor.fd, descriptor.purpose); err != nil {
			return 126
		}
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxLandlockConfigBytes+1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read sandbox config:", err)
		return 2
	}
	if len(raw) > maxLandlockConfigBytes {
		fmt.Fprintf(os.Stderr, "sandbox configuration exceeds %d byte limit\n", maxLandlockConfigBytes)
		return 2
	}
	var cfg landlockConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "decode sandbox config:", err)
		return 2
	}
	if err := validateLandlockConfigBudget(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox config budget:", err)
		return 2
	}
	if cfg.Cmd == "" {
		fmt.Fprintln(os.Stderr, "sandbox config has no command")
		return 2
	}
	nullFD, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open sandbox stdin:", err)
		return 126
	}
	defer unix.Close(nullFD)
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
	if err := sanitizeLandlockDescriptors(nullFD); err != nil {
		fmt.Fprintln(os.Stderr, "sanitize sandbox descriptors:", err)
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
