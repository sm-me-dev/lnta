package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case restrictedExecHiddenCmd:
			os.Exit(RestrictedExecMain())
		case landlockHiddenCmd:
			os.Exit(LandlockExecMain())
		case landlockDescriptorProbeCmd:
			os.Exit(landlockDescriptorProbeMain())
		}
	}
	os.Exit(m.Run())
}

func TestRestrictedExecSyscallProbe(t *testing.T) {
	if os.Getenv("LNTA_TEST_SESSION_FILTER") != "1" {
		return
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_SETSID, 0, 0, 0); errno != syscall.EPERM {
		t.Fatalf("setsid errno=%v, want EPERM", errno)
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_SETPGID, 0, 0, 0); errno != syscall.EPERM {
		t.Fatalf("setpgid errno=%v, want EPERM", errno)
	}
}

func TestRunRestrictedCommandBlocksSessionAndGroupEscape(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := "exec " + shellQuote(exe) + " -test.run=" + shellQuote("^TestRestrictedExecSyscallProbe$")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = RunRestrictedCommand(ctx, command, t.TempDir(), []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + t.TempDir(),
		"LNTA_TEST_SESSION_FILTER=1",
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("restricted syscall probe failed: %v", err)
	}
	if registrySize() != 0 {
		t.Fatalf("restricted launcher leaked %d process registry entries", registrySize())
	}
}

func TestRunRestrictedCommandReapsSameGroupDescendant(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := RunRestrictedCommand(ctx, "sleep 30 & echo $! > "+shellQuote(pidFile)+"; exit 0", t.TempDir(), []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + t.TempDir(),
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("restricted command failed: %v", err)
	}
	pid := readPIDFile(t, pidFile)
	if !waitProcessGone(pid, 2*time.Second) {
		t.Fatalf("same-group descendant %d survived launcher cleanup", pid)
	}
}

func TestRunRestrictedCommandCleansUpAfterLauncherSetupFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := RunRestrictedCommand(ctx, "true", filepath.Join(t.TempDir(), "missing"), nil, 3*time.Second)
	if err == nil {
		t.Fatal("launcher accepted a missing working directory")
	}
	if registrySize() != 0 {
		t.Fatalf("setup failure leaked %d process registry entries", registrySize())
	}
}
