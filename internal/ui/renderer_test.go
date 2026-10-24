package ui

import (
	"strings"
	"testing"
)

func TestEnforceColorProfileNoColor(t *testing.T) {
	// Set NO_COLOR=1
	t.Setenv("NO_COLOR", "1")
	t.Setenv("TERM", "xterm-256color")
	EnforceColorProfile()

	out := titleStyle.Render("Test Section")
	// ANSI escape sequences start with \x1b[
	if strings.Contains(out, "\x1b[38;") || strings.Contains(out, "\x1b[38;5;") || strings.Contains(out, "\x1b[94m") {
		t.Errorf("expected no ANSI color escape sequences with NO_COLOR=1, got %q", out)
	}

	// Reset profile
	ResetColorProfile()
}

func TestEnforceColorProfileTermDumb(t *testing.T) {
	// Set TERM=dumb
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	EnforceColorProfile()

	out := okStyle.Render("OK")
	if strings.Contains(out, "\x1b[38;") || strings.Contains(out, "\x1b[92m") {
		t.Errorf("expected no ANSI color escape sequences with TERM=dumb, got %q", out)
	}

	// Reset profile
	ResetColorProfile()
}
