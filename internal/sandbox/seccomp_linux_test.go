package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const networkSeccompProbeEnv = "LNTA_TEST_NETWORK_SECCOMP"

func TestNetworkSeccompProbe(t *testing.T) {
	if os.Getenv(networkSeccompProbeEnv) != "1" {
		return
	}
	if err := denyNetworkSyscalls(); err != nil {
		t.Fatalf("install network seccomp: %v", err)
	}
	for _, number := range networkSeccompSyscalls() {
		if _, _, errno := unix.RawSyscall(uintptr(number), 0, 0, 0); errno != unix.EPERM {
			t.Fatalf("syscall %d errno=%v, want EPERM", number, errno)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestNetworkSeccompInheritedProbe$")
	child.Env = []string{networkSeccompProbeEnv + "_CHILD=1"}
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("inherited network filter child failed: %v: %s", err, output)
	}
}

func TestNetworkSeccompInheritedProbe(t *testing.T) {
	if os.Getenv(networkSeccompProbeEnv+"_CHILD") != "1" {
		return
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_SOCKET, unix.AF_UNIX, unix.SOCK_STREAM, 0); errno != unix.EPERM {
		t.Fatalf("inherited socket syscall errno=%v, want EPERM", errno)
	}
}

func TestNetworkSeccompDeniesAllSocketAndIOUringSyscalls(t *testing.T) {
	if _, err := nativeAuditArchitecture(); err != nil {
		t.Skip(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestNetworkSeccompProbe$")
	cmd.Env = []string{networkSeccompProbeEnv + "=1"}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("effective seccomp probe failed: %v: %s", err, output.String())
	}
}

func TestNetworkSeccompX32Probe(t *testing.T) {
	if os.Getenv("LNTA_TEST_X32_SECCOMP") != "1" {
		return
	}
	if err := denyNetworkSyscalls(); err != nil {
		t.Fatalf("install network seccomp: %v", err)
	}
	_, _, errno := unix.RawSyscall(uintptr(x32SyscallBit|uint32(unix.SYS_GETPID)), 0, 0, 0)
	t.Fatalf("x32 syscall unexpectedly returned: errno=%v", errno)
}

func TestNetworkSeccompKillsX32SyscallABI(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("x32 syscall ABI applies to x86-64")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestNetworkSeccompX32Probe$")
	cmd.Env = []string{"LNTA_TEST_X32_SECCOMP=1"}
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("x32 syscall unexpectedly succeeded: %s", output)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("x32 probe returned a non-exit error: %v", err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGSYS {
		t.Fatalf("x32 syscall termination=%v, want SIGSYS: %s", exitErr.Sys(), output)
	}
}

func TestNetworkSeccompArchitectureAndX32Guards(t *testing.T) {
	program, err := networkSeccompProgram()
	if err != nil {
		t.Fatal(err)
	}
	arch, err := nativeAuditArchitecture()
	if err != nil {
		t.Skip(err)
	}
	for _, tc := range []struct {
		name string
		arch uint32
		nr   uint32
		want uint32
	}{
		{name: "unknown architecture", arch: arch ^ 1, nr: uint32(unix.SYS_GETPID), want: unix.SECCOMP_RET_KILL_PROCESS},
		{name: "compat socketcall architecture", arch: 0x40000003, nr: 102, want: unix.SECCOMP_RET_KILL_PROCESS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := evaluateSeccompAction(program, tc.arch, tc.nr); got != tc.want {
				t.Fatalf("action %#x, want %#x", got, tc.want)
			}
		})
	}
	if runtime.GOARCH == "amd64" {
		if got := evaluateSeccompAction(program, arch, x32SyscallBit|uint32(unix.SYS_GETPID)); got != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatalf("x32 action %#x, want KILL_PROCESS", got)
		}
	}
	for _, number := range networkSeccompSyscalls() {
		if got := evaluateSeccompAction(program, arch, number); got&0xffff != uint32(unix.EPERM) {
			t.Errorf("syscall %d action %#x does not return EPERM", number, got)
		}
	}
	if raw := serializeSeccompProgram(program); len(raw) != len(program)*8 {
		t.Fatalf("serialized BPF size=%d, want %d", len(raw), len(program)*8)
	}
}

func TestBubblewrapSeccompDescriptorContainsSerializedProgram(t *testing.T) {
	file, err := newNetworkSeccompFile()
	if err != nil {
		t.Skipf("seccomp memfd unavailable: %v", err)
	}
	defer file.Close()
	got, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	program, err := networkSeccompProgram()
	if err != nil {
		t.Fatal(err)
	}
	want := serializeSeccompProgram(program)
	if !bytes.Equal(got, want) {
		t.Fatalf("Bubblewrap descriptor bytes differ from compiled filter: got %d, want %d", len(got), len(want))
	}
}

func TestBubblewrapCommandArgumentsInstallFilterBeforeCommandDelimiter(t *testing.T) {
	args, err := bwrapCommandArgs([]string{"--ro-bind", "/", "/", "--"}, "printf %s")
	if err != nil {
		t.Fatal(err)
	}
	if !hasArgSequence(args, "--seccomp", "3", "--", "sh", "-c", "printf %s") {
		t.Fatalf("Bubblewrap seccomp option is not attached to its option list: %v", args)
	}
	if _, err := bwrapCommandArgs([]string{"--ro-bind", "/", "/"}, "true"); err == nil {
		t.Fatal("Bubblewrap arguments without a command delimiter were accepted")
	}
}

func TestSeccompInstallationFailureIsReported(t *testing.T) {
	if os.Getenv("LNTA_TEST_INVALID_SECCOMP") != "1" {
		return
	}
	err := installSeccompProgram([]unix.SockFilter{{Code: 0xffff}})
	if err == nil {
		t.Fatal("invalid filter installation unexpectedly succeeded")
	}
}

func TestSeccompInvalidFilterFailsClosed(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestSeccompInstallationFailureIsReported$")
	cmd.Env = []string{"LNTA_TEST_INVALID_SECCOMP=1"}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("filter installation failure probe failed: %v: %s", err, output)
	}
}

func evaluateSeccompAction(program []unix.SockFilter, arch, number uint32) uint32 {
	var accumulator uint32
	for pc := 0; pc < len(program); {
		instruction := program[pc]
		switch instruction.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			if instruction.K == 4 {
				accumulator = arch
			} else {
				accumulator = number
			}
			pc++
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			accumulator &= instruction.K
			pc++
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if accumulator == instruction.K {
				pc += 1 + int(instruction.Jt)
			} else {
				pc += 1 + int(instruction.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return instruction.K
		default:
			panic(fmt.Sprintf("unsupported seccomp instruction %#x", instruction.Code))
		}
	}
	return unix.SECCOMP_RET_KILL_PROCESS
}
