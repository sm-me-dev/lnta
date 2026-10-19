package shell

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadPipeContext_UnderLimit(t *testing.T) {
	input := "short input"
	r := strings.NewReader(input)
	got, truncated, err := ReadPipeContext(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if truncated {
		t.Errorf("expected not truncated, got truncated")
	}
	if got != input {
		t.Errorf("expected %q, got %q", input, got)
	}
}

func TestReadPipeContext_AtLimit(t *testing.T) {
	input := strings.Repeat("x", 64*1024) // exactly 64KB
	r := strings.NewReader(input)
	got, truncated, err := ReadPipeContext(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if truncated {
		t.Errorf("expected not truncated at exactly 64KB, got truncated")
	}
	if got != input {
		t.Errorf("expected exact 64KB input unchanged")
	}
}

func TestReadPipeContext_OverLimit(t *testing.T) {
	input := strings.Repeat("a", 100*1024) // 100KB > 64KB
	r := strings.NewReader(input)
	got, truncated, err := ReadPipeContext(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !truncated {
		t.Errorf("expected truncated for input > 64KB")
	}
	// Should be head(16KB) + marker + tail(48KB) = 64KB + marker
	expectedLen := 16*1024 + len("\n...[truncated]...\n") + 48*1024
	if len(got) != expectedLen {
		t.Errorf("expected length %d (64KB + marker), got %d", expectedLen, len(got))
	}
	// Verify head preserved
	head := input[:16*1024]
	if !strings.HasPrefix(got, head) {
		t.Errorf("head (first 16KB) not preserved")
	}
	// Verify tail preserved
	tail := input[len(input)-48*1024:]
	if !strings.HasSuffix(got, tail) {
		t.Errorf("tail (last 48KB) not preserved")
	}
	// Verify marker present
	if !strings.Contains(got, "...[truncated]...") {
		t.Errorf("truncation marker not found")
	}
}

func TestReadPipeContext_Empty(t *testing.T) {
	r := strings.NewReader("")
	got, truncated, err := ReadPipeContext(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if truncated {
		t.Errorf("expected not truncated for empty input")
	}
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestReadPipeContext_Boundary(t *testing.T) {
	// 64KB + 1 byte should trigger truncation
	input := strings.Repeat("x", 64*1024+1)
	r := strings.NewReader(input)
	got, truncated, err := ReadPipeContext(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !truncated {
		t.Errorf("expected truncated for 64KB+1 bytes")
	}
	// Should contain marker
	if !strings.Contains(got, "...[truncated]...") {
		t.Errorf("truncation marker not found at boundary")
	}
}

func TestIsStdinPipe(t *testing.T) {
	// We can't easily test this without mocking os.Stdin,
	// but we can verify the function exists and compiles.
	// In practice, this is tested via integration tests.
	_ = IsStdinPipe
}

func TestReadPipeContext_LargeInputNoPanic(t *testing.T) {
	// 1MB input - should not panic, just truncate
	input := strings.Repeat("large ", 200*1024)
	r := strings.NewReader(input)
	got, truncated, err := ReadPipeContext(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !truncated {
		t.Errorf("expected truncated for 1MB input")
	}
	// Verify length is bounded
	if len(got) > 64*1024+100 {
		t.Errorf("output should be bounded to ~64KB + marker, got %d", len(got))
	}
	_ = bytes.NewBufferString(got) // ensure it's valid string
}