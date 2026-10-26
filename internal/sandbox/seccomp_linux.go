package sandbox

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const x32SyscallBit = uint32(0x40000000)

func nativeAuditArchitecture() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return 0xc000003e, nil
	case "arm64":
		return 0xc00000b7, nil
	default:
		return 0, fmt.Errorf("seccomp policy does not support syscall architecture %q", runtime.GOARCH)
	}
}

func networkSeccompSyscalls() []uint32 {
	return []uint32{
		unix.SYS_SOCKET,
		unix.SYS_SOCKETPAIR,
		unix.SYS_CONNECT,
		unix.SYS_BIND,
		unix.SYS_LISTEN,
		unix.SYS_ACCEPT,
		unix.SYS_ACCEPT4,
		unix.SYS_SENDTO,
		unix.SYS_SENDMSG,
		unix.SYS_SENDMMSG,
		unix.SYS_RECVFROM,
		unix.SYS_RECVMSG,
		unix.SYS_RECVMMSG,
		unix.SYS_SHUTDOWN,
		unix.SYS_GETSOCKNAME,
		unix.SYS_GETPEERNAME,
		unix.SYS_SETSOCKOPT,
		unix.SYS_GETSOCKOPT,
		unix.SYS_IO_URING_SETUP,
		unix.SYS_IO_URING_ENTER,
		unix.SYS_IO_URING_REGISTER,
	}
}

func networkSeccompProgram() ([]unix.SockFilter, error) {
	arch, err := nativeAuditArchitecture()
	if err != nil {
		return nil, err
	}
	filters := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: arch},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
	}
	if runtime.GOARCH == "amd64" {
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
			unix.SockFilter{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: x32SyscallBit},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: 0},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		)
	}
	filters = append(filters, unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0})
	for _, syscallNumber := range networkSeccompSyscalls() {
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: syscallNumber},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		)
	}
	filters = append(filters, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	return filters, nil
}

func serializeSeccompProgram(filters []unix.SockFilter) []byte {
	raw := make([]byte, len(filters)*8)
	for index, filter := range filters {
		offset := index * 8
		binary.LittleEndian.PutUint16(raw[offset:offset+2], filter.Code)
		raw[offset+2] = filter.Jt
		raw[offset+3] = filter.Jf
		binary.LittleEndian.PutUint32(raw[offset+4:offset+8], filter.K)
	}
	return raw
}

func newNetworkSeccompFile() (*os.File, error) {
	filters, err := networkSeccompProgram()
	if err != nil {
		return nil, err
	}
	fd, err := unix.MemfdCreate("lnta-seccomp", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("create seccomp filter descriptor: %w", err)
	}
	file := os.NewFile(uintptr(fd), "lnta-seccomp")
	raw := serializeSeccompProgram(filters)
	written, err := file.Write(raw)
	if err != nil || written != len(raw) {
		_ = file.Close()
		if err == nil {
			err = fmt.Errorf("short write: %d of %d bytes", written, len(raw))
		}
		return nil, fmt.Errorf("write seccomp filter: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("rewind seccomp filter: %w", err)
	}
	return file, nil
}

func denyNetworkSyscalls() error {
	filters, err := networkSeccompProgram()
	if err != nil {
		return err
	}
	return installSeccompProgram(filters)
}

func installSeccompProgram(filters []unix.SockFilter) error {
	if len(filters) == 0 || len(filters) > unix.BPF_MAXINSNS {
		return fmt.Errorf("invalid seccomp filter instruction count %d", len(filters))
	}
	program := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if _, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return errno
	}
	_, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filters)
	if errno != 0 {
		return errno
	}
	return nil
}
