package shell

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"unicode"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/x/term"
)

var ttyMu sync.Mutex

// GetTTY opens /dev/tty for interactive input.
// Returns an error if no controlling terminal is available (e.g., CI environments).
func GetTTY() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// SanitizeForDisplay escapes control characters, ANSI sequences, and bidi
// override runes so attacker-controlled text cannot spoof the approval UI.
func SanitizeForDisplay(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			fmt.Fprintf(&b, `\x%02x`, r)
		case unicode.Is(unicode.Cf, r): // bidi overrides, zero-width joiners, etc.
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ConfirmWithTTY renders a huh.Confirm on /dev/tty with a title and a full
// description. Terminal state is saved/restored and os.Stdin is restored via
// defer, so a panic or interruption cannot leave the terminal in raw mode or
// os.Stdin pointing at /dev/tty.
// If /dev/tty is unavailable (CI, no controlling terminal), it returns an error
// and the caller must deny the mutation (fail closed).
func ConfirmWithTTY(title, description string) (bool, error) {
	ttyMu.Lock()
	defer ttyMu.Unlock()

	tty, err := GetTTY()
	if err != nil {
		return false, fmt.Errorf("interactive confirmation required but no controlling terminal available (running in CI?): %w", err)
	}
	defer tty.Close()

	oldStdin := os.Stdin
	os.Stdin = tty
	defer func() { os.Stdin = oldStdin }()

	if st, serr := term.GetState(tty.Fd()); serr == nil {
		defer term.Restore(tty.Fd(), st)
	}

	var result bool
	form := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title(title).
			Description(description).
			Affirmative("Run it").Negative("Deny").
			Value(&result),
	))
	if err := form.Run(); err != nil {
		return false, err
	}
	return result, nil
}

// ConfirmChallengeWithTTY renders an interactive anti-fatigue challenge on /dev/tty
// where the operator must explicitly type the challenge code to approve a
// CRITICAL_DESTRUCTIVE command.
func ConfirmChallengeWithTTY(title, description, challengeCode string) (bool, error) {
	ttyMu.Lock()
	defer ttyMu.Unlock()

	tty, err := GetTTY()
	if err != nil {
		return false, fmt.Errorf("interactive confirmation required but no controlling terminal available: %w", err)
	}
	defer tty.Close()

	oldStdin := os.Stdin
	os.Stdin = tty
	defer func() { os.Stdin = oldStdin }()

	if st, serr := term.GetState(tty.Fd()); serr == nil {
		defer term.Restore(tty.Fd(), st)
	}

	var enteredCode string
	form := huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title(fmt.Sprintf("%s\nType confirmation code %q to execute:", title, challengeCode)).
			Description(description).
			Value(&enteredCode),
	))
	if err := form.Run(); err != nil {
		return false, err
	}
	return strings.TrimSpace(enteredCode) == strings.TrimSpace(challengeCode), nil
}
