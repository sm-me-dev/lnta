package shell

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

type chunkReader struct {
	data []byte
	step int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), min(len(r.data), r.step))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

type failingReader struct{ sent bool }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, errors.New("read failed")
	}
	r.sent = true
	return copy(p, "partial"), nil
}

func TestReadPipeContextBoundaries(t *testing.T) {
	for _, size := range []int{0, maxPipeContext - 1, maxPipeContext, maxPipeContext + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			input := strings.Repeat("x", size)
			got, truncated, err := ReadPipeContext(strings.NewReader(input))
			if err != nil {
				t.Fatal(err)
			}
			if size <= maxPipeContext {
				if truncated || got != input {
					t.Fatalf("size %d changed: truncated=%v len=%d", size, truncated, len(got))
				}
			} else if !truncated || !strings.Contains(got, "stdin truncated: middle omitted") {
				t.Fatalf("size %d not marked truncated: %v", size, truncated)
			}
		})
	}
}

func TestReadPipeContextKeepsTrueHeadAndTailIncrementally(t *testing.T) {
	input := "<BEGIN>" + strings.Repeat("H", headPreserve) + strings.Repeat("M", 160*1024) + "<MIDDLE>" + strings.Repeat("T", 80*1024) + "<ACTUAL-END>"
	got, truncated, err := ReadPipeContext(&chunkReader{data: []byte(input), step: 137})
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("expected truncation")
	}
	if !strings.HasPrefix(got, input[:headPreserve]) {
		t.Fatal("first 16 KiB were not preserved")
	}
	if !strings.HasSuffix(got, input[len(input)-tailPreserve:]) {
		t.Fatal("true final 48 KiB were not preserved")
	}
	if strings.Contains(got, "<MIDDLE>") {
		t.Fatal("middle marker unexpectedly survived truncation")
	}
	if !strings.Contains(got, "<BEGIN>") || !strings.Contains(got, "<ACTUAL-END>") {
		t.Fatal("distinct beginning/end markers missing")
	}
	if len(got) != headPreserve+tailPreserve+len("\n...[stdin truncated: middle omitted]...\n") {
		t.Fatalf("unexpected rendered length %d", len(got))
	}
}

func TestReadPipeContextPropagatesReaderError(t *testing.T) {
	if _, _, err := ReadPipeContext(&failingReader{}); err == nil || err.Error() != "read failed" {
		t.Fatalf("expected reader error, got %v", err)
	}
}

func TestIsStdinPipe(t *testing.T) {
	_ = IsStdinPipe
}
