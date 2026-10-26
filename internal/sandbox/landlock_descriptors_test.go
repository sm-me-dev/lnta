package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const landlockDescriptorProbeCmd = "__landlock_descriptor_probe"

func TestLandlockClosesInheritedSocketDescriptors(t *testing.T) {
	if err := ProbeLandlockExecution(5 * time.Second); err != nil {
		t.Skipf("Landlock backend unavailable: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, home, tmp := t.TempDir(), t.TempDir(), t.TempDir()
	cfg, err := buildLandlockConfig(root, root, home, tmp, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ROFiles = append(cfg.ROFiles, exe)
	cfg.Cmd = shellQuote(exe) + " " + landlockDescriptorProbeCmd
	if err := validateLandlockConfigBudget(cfg); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sockets[1])
	if err := unix.SetNonblock(sockets[0], true); err != nil {
		unix.Close(sockets[0])
		t.Fatal(err)
	}
	sentinel := os.NewFile(uintptr(sockets[0]), "parent-socket-sentinel")
	defer sentinel.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, landlockHiddenCmd)
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Env = []string{landlockHiddenCmdEnv + "=1", "PATH=/usr/local/bin:/usr/bin:/bin"}
	cmd.Dir = string(os.PathSeparator)
	cmd.ExtraFiles = []*os.File{sentinel}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	ConfigureProcessGroup(cmd)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Landlock descriptor probe failed: %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
}

func landlockDescriptorProbeMain() int {
	var byteBuffer [1]byte
	tests := []struct {
		name string
		nr   uintptr
		args [6]uintptr
		want syscall.Errno
	}{
		{name: "read", nr: unix.SYS_READ, args: [6]uintptr{3, uintptr(unsafe.Pointer(&byteBuffer[0])), 1}, want: unix.EBADF},
		{name: "write", nr: unix.SYS_WRITE, args: [6]uintptr{3, uintptr(unsafe.Pointer(&byteBuffer[0])), 1}, want: unix.EBADF},
		{name: "sendfile", nr: unix.SYS_SENDFILE, args: [6]uintptr{1, 3, 0, 1}, want: unix.EBADF},
		{name: "splice", nr: unix.SYS_SPLICE, args: [6]uintptr{3, 0, 1, 0, 1}, want: unix.EBADF},
		{name: "sendmsg", nr: unix.SYS_SENDMSG, args: [6]uintptr{3, 0, 0}, want: unix.EPERM},
	}
	for _, test := range tests {
		_, _, errno := unix.RawSyscall6(test.nr, test.args[0], test.args[1], test.args[2], test.args[3], test.args[4], test.args[5])
		if errno != test.want {
			fmt.Fprintf(os.Stderr, "%s errno=%v, want %v\n", test.name, errno, test.want)
			return 1
		}
	}
	return 0
}
