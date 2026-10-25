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

func TestStatusLineInFlightDoesNotShowBlocked(t *testing.T) {
	// Planning phase must not show [Blocked ✗]
	outPlanning := StatusLine("general-diagnostics", "Planning", "", false)
	if strings.Contains(outPlanning, "Blocked") {
		t.Errorf("expected StatusLine during Planning not to contain 'Blocked', got %q", outPlanning)
	}
	if !strings.Contains(outPlanning, "Planning") {
		t.Errorf("expected StatusLine during Planning to contain 'Planning', got %q", outPlanning)
	}

	// Running phase must not show [Blocked ✗]
	outRunning := StatusLine("linux-desktop-entries", "Running", "", false)
	if strings.Contains(outRunning, "Blocked") {
		t.Errorf("expected StatusLine during Running not to contain 'Blocked', got %q", outRunning)
	}

	// Verified must show [Verified ✓]
	outVerified := StatusLine("linux-desktop-entries", "Writing", "~/.local/share/app.desktop", true)
	if !strings.Contains(outVerified, "Verified") {
		t.Errorf("expected verified StatusLine to contain 'Verified', got %q", outVerified)
	}

	// Terminal failure / blocked must show [Blocked ✗]
	outBlocked := StatusLine("linux-desktop-entries", "Blocked", "", false)
	if !strings.Contains(outBlocked, "Blocked") {
		t.Errorf("expected blocked StatusLine to contain 'Blocked', got %q", outBlocked)
	}
}
