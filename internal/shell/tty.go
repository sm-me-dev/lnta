package shell

import (
	"fmt"
	"os"

	"github.com/charmbracelet/huh"
)

// GetTTY opens /dev/tty for interactive input.
// Returns an error if no controlling terminal is available (e.g., CI environments).
func GetTTY() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// ConfirmWithTTY wraps huh.Confirm to read from /dev/tty instead of stdin.
// This is essential when stdin is occupied by a pipe.
// Returns the user's confirmation (true/false) and any error.
// If /dev/tty is unavailable, returns an error with a CI-friendly message.
func ConfirmWithTTY(prompt string) (bool, error) {
	tty, err := GetTTY()
	if err != nil {
		return false, fmt.Errorf("interactive confirmation required but no controlling terminal available (running in CI?): %w", err)
	}
	defer tty.Close()

	var result bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(prompt).
				Affirmative("Yes").
				Negative("No").
				Value(&result),
		),
	)

	// Temporarily replace os.Stdin with /dev/tty for the form run
	oldStdin := os.Stdin
	os.Stdin = tty
	err = form.Run()
	os.Stdin = oldStdin
	return result, err
}