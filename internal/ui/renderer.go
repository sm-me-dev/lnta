// Package ui renders LNTA's terminal UI: a compact status line during
// execution, syntax-highlighted unified diffs, and the structured Verification
// Receipt printed at task completion.
//
// All rendering is pure (no I/O) and built on charmbracelet/lipgloss so it can
// be reused by both the lnta CLI and the lnta-eval harness.
package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// EnforceColorProfile respects NO_COLOR and TERM=dumb environment variables.
// If either NO_COLOR is non-empty or TERM equals "dumb", Lipgloss color output is disabled.
func EnforceColorProfile() {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
}

// ResetColorProfile resets the color profile based on the current environment.
func ResetColorProfile() {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		lipgloss.SetColorProfile(termenv.Ascii)
	} else {
		lipgloss.SetColorProfile(termenv.EnvColorProfile())
	}
}

func init() {
	EnforceColorProfile()
}

// ---------------------------------------------------------------------------
// Palette
// ---------------------------------------------------------------------------

var (
	// titleStyle renders section headings.
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12")). // light blue
			MarginBottom(1)

	// labelStyle renders field labels.
	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("10")) // light green

	// mutedStyle renders dim secondary text.
	mutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8")) // gray

	// okStyle renders success / verified indicators.
	okStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("10")) // light green

	// errStyle renders failure indicators.
	errStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("9")) // light red

	// warnStyle renders warning / partial indicators.
	warnStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("11")) // light yellow

	// bullet is the separator used in the compact status line.
	bullet = mutedStyle.Render(" • ")
)

// ---------------------------------------------------------------------------
// Status line
// ---------------------------------------------------------------------------

// packPill renders a single "[Pack: ...]" pill.
func packPill(pack string) string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("12")).
		Render(fmt.Sprintf("[Pack: %s]", pack))
}

// phasePill renders a single "[<phase>]" pill.
func phasePill(phase string) string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("11")).
		Render(fmt.Sprintf("[%s]", phase))
}

// pathPill renders a single "[<path>]" pill.
func pathPill(path string) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("15")).
		Render(fmt.Sprintf("[%s]", path))
}

// statusPill renders the final "[Verified ✓]" / "[Blocked ✗]" pill.
func statusPill(verified bool) string {
	if verified {
		return okStyle.Render("[Verified ✓]")
	}
	return errStyle.Render("[Blocked ✗]")
}

// StatusLine renders the compact, non-intrusive execution status line:
//
//	[Pack: linux-desktop-entries] • [Inspecting...] • [Writing ~/.local/share/applications/app.desktop] • [Verified ✓]
//
// Any segment may be empty; empty segments are omitted. If verified is false and
// phase is an active in-flight phase (e.g. "Planning", "Running"), the terminal
// [Blocked ✗] status is omitted so in-flight execution is not misrepresented.
func StatusLine(pack, phase, path string, verified bool) string {
	var parts []string
	if pack != "" {
		parts = append(parts, packPill(pack))
	}
	if phase != "" {
		parts = append(parts, phasePill(phase))
	}
	if path != "" {
		parts = append(parts, pathPill(path))
	}
	if verified {
		parts = append(parts, statusPill(true))
	} else if phase == "" || phase == "Failed" || phase == "Blocked" {
		parts = append(parts, statusPill(false))
	}
	return strings.Join(parts, bullet)
}

// ---------------------------------------------------------------------------
// Unified diff rendering
// ---------------------------------------------------------------------------

// diffStyle colors the leading diff marker.
var (
	addStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("10")) // green +
	delStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))  // red -
	ctxStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))  // gray context
	hunkStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("13")) // magenta @@ hunk header
	fileStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12")) // light blue --- / +++
)

// RenderDiff renders a unified diff with syntax highlighting. Added lines are
// green, removed lines are red, context lines are gray, hunk headers and file
// headers are highlighted. The input may be empty (returns empty string).
func RenderDiff(diff string) string {
	if strings.TrimSpace(diff) == "" {
		return ""
	}
	var b strings.Builder
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++ ") || strings.HasPrefix(line, "--- "):
			b.WriteString(fileStyle.Render(line))
		case strings.HasPrefix(line, "@@"):
			b.WriteString(hunkStyle.Render(line))
		case strings.HasPrefix(line, "+"):
			b.WriteString(addStyle.Render(line))
		case strings.HasPrefix(line, "-"):
			b.WriteString(delStyle.Render(line))
		default:
			b.WriteString(ctxStyle.Render(line))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Verification Receipt
// ---------------------------------------------------------------------------

// VerificationResult records one verification command executed by the harness.
type VerificationResult struct {
	Command  string
	ExitCode int
	Output   string
}

// ReceiptStatus is the overall task completion status.
type ReceiptStatus string

const (
	// ReceiptCompleted means the task completed and verification passed.
	ReceiptCompleted ReceiptStatus = "COMPLETED"
	// ReceiptUnverified means the task completed without a passing verification.
	ReceiptUnverified ReceiptStatus = "COMPLETED — NOT VERIFIED"
	// ReceiptBlocked means the harness stopped because a blocker prevented completion.
	ReceiptBlocked ReceiptStatus = "BLOCKED"
	// ReceiptPartial means the task completed but verification only partially
	// passed or some targets could not be verified.
	ReceiptPartial ReceiptStatus = "PARTIAL"
	// ReceiptFailed means the task did not complete or verification failed.
	ReceiptFailed ReceiptStatus = "FAILED"
)

// VerificationReceipt renders the structured Verification Receipt printed at
// task completion:
//
//	╔═══════════════════════════════════════════════════════════╗
//	║  VERIFICATION RECEIPT                                    ║
//	║  Status   : COMPLETED                                    ║
//	║  Run ID   : run-20261017T120000                          ║
//	║           : Run 'lnta undo <run_id>' to revert            ║
//	║  Changed  : ~/.local/share/applications/app.desktop      ║
//	║  Verified : desktop-file-validate "..." (exit 0)         ║
//	╚═══════════════════════════════════════════════════════════╝
func VerificationReceipt(status ReceiptStatus, runID string, changedPaths []string, results []VerificationResult) string {
	// Determine status style.
	var statusLabel string
	var statusSt lipgloss.Style
	switch status {
	case ReceiptCompleted:
		statusLabel = string(ReceiptCompleted)
		statusSt = okStyle
	case ReceiptUnverified:
		statusLabel = string(ReceiptUnverified)
		statusSt = warnStyle
	case ReceiptBlocked:
		statusLabel = string(ReceiptBlocked)
		statusSt = errStyle
	case ReceiptPartial:
		statusLabel = string(ReceiptPartial)
		statusSt = warnStyle
	default:
		statusLabel = string(ReceiptFailed)
		statusSt = errStyle
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("12")).
		Padding(0, 1).
		MarginTop(1).
		MarginBottom(1)

	var lines []string
	lines = append(lines, labelStyle.Render("VERIFICATION RECEIPT"))
	lines = append(lines, fmt.Sprintf("%s  %s", labelStyle.Render("Status   :"), statusSt.Render(statusLabel)))
	lines = append(lines, fmt.Sprintf("%s  %s", labelStyle.Render("Run ID   :"), runID))
	lines = append(lines, fmt.Sprintf("%s  Run 'lnta undo %s' to revert", mutedStyle.Render("           :"), runID))

	if len(changedPaths) > 0 {
		paths := strings.Join(changedPaths, "\n                  ")
		lines = append(lines, fmt.Sprintf("%s  %s", labelStyle.Render("Changed  :"), paths))
	} else {
		lines = append(lines, fmt.Sprintf("%s  (none)", labelStyle.Render("Changed  :")))
	}

	if len(results) > 0 {
		for _, r := range results {
			ok := r.ExitCode == 0
			st := okStyle
			if !ok {
				st = errStyle
			}
			out := r.Output
			if out != "" {
				out = " — " + strings.TrimSpace(out)
			}
			lines = append(lines, fmt.Sprintf("%s  %s (exit %d)%s",
				labelStyle.Render("Verified :"),
				st.Render(r.Command),
				r.ExitCode,
				out,
			))
		}
	} else {
		lines = append(lines, fmt.Sprintf("%s  (no verification commands executed)", labelStyle.Render("Verified :")))
	}

	content := strings.Join(lines, "\n")
	return box.Render(content)
}

// ---------------------------------------------------------------------------
// Diff block (heading + rendered diff)
// ---------------------------------------------------------------------------

// DiffBlock renders a file-change block: a heading followed by the rendered
// unified diff, suitable for dry-run and approval output.
func DiffBlock(path, diff string) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(fmt.Sprintf("File change: %s", path)))
	b.WriteString("\n")
	b.WriteString(RenderDiff(diff))
	return b.String()
}
