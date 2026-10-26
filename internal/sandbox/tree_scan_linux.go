package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openAbsoluteDirNoFollow(path string) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, fmt.Errorf("directory path %q is not absolute", path)
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.Trim(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		nextFD, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			_ = unix.Close(fd)
			return -1, openErr
		}
		_ = unix.Close(fd)
		fd = nextFD
	}
	return fd, nil
}

func openChildDirNoFollow(parentFD int, name string, expected *unix.Stat_t) (int, unix.Stat_t, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	var actual unix.Stat_t
	if err := unix.Fstat(fd, &actual); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	if expected != nil && !sameTreeStat(*expected, actual) {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, errors.New("directory changed while opening")
	}
	return fd, actual, nil
}

func readDirAt(fd int, visit func(os.DirEntry) error) error {
	dupFD, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(dupFD), "directory")
	defer file.Close()
	for {
		entries, readErr := file.ReadDir(256)
		for _, entry := range entries {
			if err := visit(entry); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func statAtNoFollow(dirFD int, name string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return stat, err
	}
	return stat, nil
}

func sameTreeIdentity(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode&unix.S_IFMT == right.Mode&unix.S_IFMT
}

func sameTreeStat(left, right unix.Stat_t) bool {
	return sameTreeIdentity(left, right) && left.Mode == right.Mode && left.Nlink == right.Nlink && left.Size == right.Size &&
		left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func verifyDirUnchanged(fd int, before unix.Stat_t) error {
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return err
	}
	if !sameTreeStat(before, after) {
		return errors.New("directory changed during scan")
	}
	return nil
}
