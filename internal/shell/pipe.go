package shell

import (
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

// ReadPipeContext streams stdin with bounded memory. Inputs up to maxPipeContext
// bytes are returned unchanged. Larger inputs retain the first 16 KiB and the
// true final 48 KiB, separated by a marker. The limit applies to input bytes;
// the rendered result is larger by the marker length.
func ReadPipeContext(r io.Reader) (string, bool, error) {
	head := make([]byte, 0, headPreserve)
	tail := make([]byte, tailPreserve)
	tailStart, tailLen := 0, 0
	total := 0
	chunk := make([]byte, 32*1024)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			p := chunk[:n]
			if len(head) < headPreserve {
				keep := min(headPreserve-len(head), len(p))
				head = append(head, p[:keep]...)
				p = p[keep:]
			}
			for len(p) > 0 {
				if tailLen < tailPreserve {
					keep := min(tailPreserve-tailLen, len(p))
					copy(tail[(tailStart+tailLen)%tailPreserve:], p[:keep])
					tailLen += keep
					p = p[keep:]
					continue
				}
				if len(p) >= tailPreserve {
					copy(tail, p[len(p)-tailPreserve:])
					tailStart = 0
					p = p[len(p):]
					continue
				}
				first := min(len(p), tailPreserve-tailStart)
				copy(tail[tailStart:tailStart+first], p[:first])
				copy(tail[:len(p)-first], p[first:])
				tailStart = (tailStart + len(p)) % tailPreserve
				p = p[len(p):]
			}
			total += n
		}
		if err != nil {
			if err != io.EOF {
				return "", false, err
			}
			break
		}
	}
	if total <= maxPipeContext {
		out := make([]byte, 0, total)
		out = append(out, head...)
		out = append(out, tail[:tailLen]...)
		return string(out), false, nil
	}
	orderedTail := make([]byte, tailLen)
	first := min(tailLen, tailPreserve-tailStart)
	copy(orderedTail, tail[tailStart:tailStart+first])
	copy(orderedTail[first:], tail[:tailLen-first])
	const marker = "\n...[stdin truncated: middle omitted]...\n"
	out := make([]byte, 0, len(head)+len(marker)+len(orderedTail))
	out = append(out, head...)
	out = append(out, marker...)
	out = append(out, orderedTail...)
	return string(out), true, nil
}
