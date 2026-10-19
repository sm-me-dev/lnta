package shell

import (
	"bytes"
	"io"
	"os"
)

const (
	maxPipeContext = 64 * 1024 // 64KB
	headPreserve   = 16 * 1024 // 16KB
	tailPreserve   = 48 * 1024 // 48KB
)

// IsStdinPipe returns true if stdin is a pipe (not a TTY/character device).
func IsStdinPipe() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice == 0
}

// ReadPipeContext reads from stdin up to 64KB with tail-preserving truncation.
// If input > 64KB, keeps first 16KB + last 48KB with a truncation marker.
// Returns the context string, whether truncation occurred, and any error.
func ReadPipeContext(r io.Reader) (string, bool, error) {
	var buf bytes.Buffer
	_, err := io.CopyN(&buf, r, maxPipeContext+1) // read one extra to detect overflow
	if err != nil && err != io.EOF {
		return "", false, err
	}
	data := buf.Bytes()
	if int64(len(data)) <= maxPipeContext {
		return string(data), false, nil
	}
	// Tail-preserving truncation: head(16KB) + marker + tail(48KB)
	head := data[:headPreserve]
	tail := data[len(data)-tailPreserve:]
	marker := "\n...[truncated]...\n"
	return string(head) + marker + string(tail), true, nil
}