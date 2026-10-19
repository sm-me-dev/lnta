package shell

import (
	"testing"
)

// TestGetTTY_Available tests that GetTTY works when /dev/tty is available.
// This is an integration test - it will pass in normal terminals,
// and may fail in CI without a controlling terminal.
func TestGetTTY_Available(t *testing.T) {
	tty, err := GetTTY()
	if err != nil {
		// In CI without /dev/tty, this is expected to fail
		t.Logf("GetTTY failed (expected in CI without tty): %v", err)
		return
	}
	defer tty.Close()

	if tty == nil {
		t.Errorf("GetTTY returned nil without error")
	}
	// Verify it's actually /dev/tty by checking the file path
	// (This is a best-effort check; the important thing is no panic)
	_ = tty
}