package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestBubblewrapEffectiveSocketAndDescriptorPolicy(t *testing.T) {
	if err := probeBwrap(); err != nil {
		t.Skipf("Bubblewrap backend unavailable: %v", err)
	}
	testEffectiveSocketAndDescriptorPolicy(t, BackendBwrap)
}

func TestLandlockEffectiveSocketAndDescriptorPolicy(t *testing.T) {
	if err := ProbeLandlockExecution(5 * time.Second); err != nil {
		t.Skipf("Landlock backend unavailable: %v", err)
	}
	testEffectiveSocketAndDescriptorPolicy(t, BackendLandlock)
}

func testEffectiveSocketAndDescriptorPolicy(t *testing.T, backend SandboxBackend) {
	t.Helper()
	python := ""
	for _, candidate := range []string{"/usr/bin/python3", "/bin/python3"} {
		if stat, err := os.Stat(candidate); err == nil && stat.Mode().IsRegular() && stat.Mode().Perm()&0o111 != 0 {
			python = candidate
			break
		}
	}
	if python == "" {
		t.Skip("python3 is required for effective socket and descriptor probes")
	}
	var err error
	root, home := effectiveFixtureDir(t, "project"), effectiveFixtureDir(t, "home")
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("LNTA_EFFECTIVE_PROJECT_SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "public.txt"), []byte("allowed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "sentinel"), []byte("LNTA_EFFECTIVE_HOME_SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeTarget := filepath.Join(root, "host-write-sentinel")
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sockets[1])
	if err := unix.SetNonblock(sockets[0], true); err != nil {
		unix.Close(sockets[0])
		t.Fatal(err)
	}
	sentinelFD, err := unix.FcntlInt(uintptr(sockets[0]), unix.F_DUPFD_CLOEXEC, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(sockets[0]); err != nil {
		unix.Close(sentinelFD)
		t.Fatal(err)
	}
	sentinel := os.NewFile(uintptr(sentinelFD), "effective-socket-sentinel")
	defer sentinel.Close()

	socketProbe := `import errno,socket; exec("try:\n socket.socket()\nexcept OSError as e:\n print('socket-denied' if e.errno == errno.EPERM else 'socket-unexpected')\nelse:\n print('socket-open')")`
	fdProbe := `import errno,os; fd=int(os.environ["LNTA_TEST_SENTINEL_FD"]); exec("try:\n os.read(fd,1)\nexcept OSError as e:\n print('descriptor-closed' if e.errno == errno.EBADF else 'descriptor-unexpected')\nelse:\n print('descriptor-open')")`
	command := "printf 'PUBLIC='; cat public.txt; " +
		"printf '\\nPROJECT_SECRET='; cat .env 2>&1; " +
		"printf '\\nHOME_SECRET='; cat \"$HOME/.ssh/sentinel\" 2>&1; " +
		"printf '\\n'; " + shellQuote(python) + " -c " + shellQuote(socketProbe) + "; " +
		shellQuote(python) + " -c " + shellQuote(fdProbe) + "; " +
		"printf blocked > " + shellQuote(writeTarget) + " 2>&1"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var result CommandResult
	if backend == BackendBwrap {
		extraEnv := []string{"LNTA_TEST_SENTINEL_FD=" + strconv.Itoa(int(sentinel.Fd()))}
		result, err = runEffectiveBwrap(ctx, command, root, extraEnv)
	} else {
		extraEnv := []string{"LNTA_TEST_SENTINEL_FD=3"}
		result, err = runEffectiveLandlockWithSocketFD(ctx, command, root, home, extraEnv, sentinel)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("%s execution failed before command completion: %v", backend, err)
		}
	}
	output := result.Stdout + result.Stderr
	for _, expected := range []string{"allowed", "socket-denied", "descriptor-closed"} {
		if !strings.Contains(output, expected) {
			t.Errorf("%s output missing %q: %s", backend, expected, output)
		}
	}
	for _, secret := range []string{"LNTA_EFFECTIVE_PROJECT_SECRET", "LNTA_EFFECTIVE_HOME_SECRET"} {
		if strings.Contains(output, secret) {
			t.Errorf("%s exposed credential sentinel %q", backend, secret)
		}
	}
	if _, err := os.Stat(writeTarget); !os.IsNotExist(err) {
		t.Errorf("%s wrote to host project: %v", backend, err)
	}
	t.Logf("%s effective output: %s", backend, strings.TrimSpace(output))
}

func runEffectiveBwrap(ctx context.Context, command, root string, extraEnv []string) (CommandResult, error) {
	return runBwrapEnv(ctx, command, root, root, 10*time.Second, extraEnv)
}

func runEffectiveLandlockWithSocketFD(ctx context.Context, command, root, home string, extraEnv []string, sentinel *os.File) (CommandResult, error) {
	tmp, err := os.MkdirTemp("", "lnta-effective-landlock-")
	if err != nil {
		return CommandResult{}, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o700); err != nil {
		return CommandResult{}, err
	}
	cfg, err := buildLandlockConfig(root, root, home, tmp, command, extraEnv)
	if err != nil {
		return CommandResult{}, err
	}
	if err := validateLandlockConfigBudget(cfg); err != nil {
		return CommandResult{}, err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return CommandResult{}, err
	}
	if len(raw) > maxLandlockConfigBytes {
		return CommandResult{}, errors.New("effective Landlock configuration exceeds size limit")
	}
	exe, err := os.Executable()
	if err != nil {
		return CommandResult{}, err
	}
	cmd := exec.CommandContext(ctx, exe, landlockHiddenCmd)
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Env = []string{landlockHiddenCmdEnv + "=1", "PATH=/usr/local/bin:/usr/bin:/bin"}
	cmd.Dir = string(os.PathSeparator)
	cmd.ExtraFiles = []*os.File{sentinel}
	return runEffectiveCommand(ctx, "effective_landlock", cmd)
}

func runEffectiveCommand(ctx context.Context, role string, cmd *exec.Cmd) (CommandResult, error) {
	ConfigureProcessGroup(cmd)
	var result CommandResult
	stdout := NewCappedBuffer(maxOutputBytes, hardOutputBytes, nil)
	stderr := NewCappedBuffer(maxOutputBytes, hardOutputBytes, nil)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	started, err := StartChild(role, cmd)
	if err != nil {
		return result, err
	}
	err = WaitChild(role, cmd, started, ctx, stdout, stderr)
	result.Stdout = stdout.Render()
	result.Stderr = stderr.Render()
	if err != nil {
		result.ExitCode = exitCodeOf(err)
	}
	return result, err
}

func effectiveFixtureDir(t *testing.T, label string) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".lnta-effective-"+label+"-")
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(abs); err != nil {
			t.Errorf("remove effective fixture %q: %v", abs, err)
		}
	})
	return abs
}
