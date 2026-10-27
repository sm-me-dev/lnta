// Package ui renders LNTA's terminal UI components including the time-machine
// session browser for reviewing and rolling back past runs.
package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/sm-me-dev/lnta/internal/audit"
	"github.com/sm-me-dev/lnta/internal/sandbox"
)

// TimeMachineModel is the main model for the time-machine TUI.
type TimeMachineModel struct {
	list      list.Model
	viewport  viewport.Model
	runs      []*audit.RunSummary
	selected  *audit.RunSummary
	width     int
	height    int
	status    string
	err       error
	quitting  bool
	focusLeft bool // true = left pane (list), false = right pane (viewport)
}

// runItem wraps a RunSummary for the list component.
type runItem struct {
	run *audit.RunSummary
}

func (i runItem) Title() string {
	icon := statusIcon(i.run.Status)
	packBadge := packBadgeStyle.Render(fmt.Sprintf("[%s]", i.run.SelectedPack))
	return fmt.Sprintf("%s %s %s", icon, packBadge, truncateString(i.run.Prompt, 50))
}

func (i runItem) Description() string {
	return fmt.Sprintf("%s • %s", i.run.Timestamp.Local().Format("2006-01-02 15:04:05"), i.run.CWD)
}

func (i runItem) FilterValue() string {
	return i.run.Prompt + " " + i.run.SelectedPack
}

func statusIcon(status audit.RunStatus) string {
	switch status {
	case audit.RunStatusVerified, audit.RunStatusCompleted:
		return okStyle.Render("✓")
	case audit.RunStatusFailed, audit.RunStatusBlocked:
		return errStyle.Render("✗")
	case audit.RunStatusRolledBack:
		return warnStyle.Render("↩")
	case audit.RunStatusCompletedUnverified:
		return warnStyle.Render("!")
	default:
		return mutedStyle.Render("?")
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Styles (reusing from renderer.go where possible, adding new ones)
var (
	packBadgeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("13"))

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("12"))

	focusedBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("10"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")).
			MarginTop(1)
)

// NewTimeMachineModel creates a new time-machine TUI model.
func NewTimeMachineModel() *TimeMachineModel {
	// Create list with custom delegate
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.
		Foreground(lipgloss.Color("15")).
		Background(lipgloss.Color("12")).
		Bold(true)
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.
		Foreground(lipgloss.Color("15")).
		Background(lipgloss.Color("12"))
	delegate.Styles.NormalTitle = delegate.Styles.NormalTitle.
		Foreground(lipgloss.Color("15"))
	delegate.Styles.NormalDesc = delegate.Styles.NormalDesc.
		Foreground(lipgloss.Color("8"))

	items := []list.Item{}
	l := list.New(items, delegate, 0, 0)
	l.Title = "LNTA Time Machine — Past Runs"
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = mutedStyle
	l.Styles.HelpStyle = helpStyle

	vp := viewport.New(0, 0)
	vp.Style = borderStyle

	return &TimeMachineModel{
		list:      l,
		viewport:  vp,
		runs:      []*audit.RunSummary{},
		focusLeft: true,
	}
}

// loadRuns loads all run summaries from disk.
func (m *TimeMachineModel) loadRuns() tea.Cmd {
	return func() tea.Msg {
		runs, err := audit.ListRunSummaries()
		if err != nil {
			return errMsg{err}
		}
		return runsLoadedMsg{runs}
	}
}

type runsLoadedMsg struct {
	runs []*audit.RunSummary
}

type errMsg struct {
	err error
}

func (e errMsg) Error() string {
	return e.err.Error()
}

// Init initializes the model.
func (m *TimeMachineModel) Init() tea.Cmd {
	return tea.Batch(
		m.loadRuns(),
		tea.EnterAltScreen,
	)
}

// Update handles messages and updates the model.
func (m *TimeMachineModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateLayout()
		return m, nil

	case runsLoadedMsg:
		m.runs = msg.runs
		m.updateList()
		if len(m.runs) > 0 {
			m.selectRun(0)
		}
		return m, nil

	case errMsg:
		m.err = msg.err
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case rollbackResultMsg:
		if msg.err != nil {
			m.status = errStyle.Render("Rollback failed: " + msg.err.Error())
		} else {
			m.status = okStyle.Render("Run rolled back successfully")
			// Reload runs to get updated status
			return m, m.loadRuns()
		}
		return m, nil

	case exportResultMsg:
		if msg.err != nil {
			m.status = errStyle.Render("Export failed: " + msg.err.Error())
		} else {
			m.status = okStyle.Render(fmt.Sprintf("Exported to %s", msg.path))
		}
		return m, nil

	case resumeChatMsg:
		// This would launch a new chat session - for now just show message
		m.status = warnStyle.Render("Resume chat not yet implemented")
		return m, nil
	}

	// Delegate to sub-components
	var listCmd, vpCmd tea.Cmd
	m.list, listCmd = m.list.Update(msg)
	m.viewport, vpCmd = m.viewport.Update(msg)
	cmds = append(cmds, listCmd, vpCmd)

	return m, tea.Batch(cmds...)
}

type rollbackResultMsg struct {
	err error
}

type exportResultMsg struct {
	err  error
	path string
}

type resumeChatMsg struct{}

func (m *TimeMachineModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle list filtering
	if m.list.FilterState() == list.Filtering {
		// Don't handle other keys while filtering
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	switch msg.String() {
	case "ctrl+c", "q":
		m.quitting = true
		return m, tea.Quit

	case "tab":
		// Switch focus between panes
		m.focusLeft = !m.focusLeft
		m.updateLayout()
		return m, nil

	case "up", "k":
		if m.focusLeft {
			var cmd tea.Cmd
			m.list, cmd = m.list.Update(msg)
			m.selectRun(m.list.Index())
			return m, cmd
		} else {
			m.viewport.ScrollUp(1)
			return m, nil
		}

	case "down", "j":
		if m.focusLeft {
			var cmd tea.Cmd
			m.list, cmd = m.list.Update(msg)
			m.selectRun(m.list.Index())
			return m, cmd
		} else {
			m.viewport.ScrollDown(1)
			return m, nil
		}

	case "left", "h":
		if !m.focusLeft {
			m.focusLeft = true
			m.updateLayout()
		}
		return m, nil

	case "right", "l":
		if m.focusLeft {
			m.focusLeft = false
			m.updateLayout()
		}
		return m, nil

	case "enter", "u":
		// Rollback selected run
		if m.selected != nil && m.selected.Status != audit.RunStatusRolledBack {
			return m, m.rollbackSelected()
		}
		return m, nil

	case "r":
		// Resume chat session
		if m.selected != nil {
			return m, m.resumeChat()
		}
		return m, nil

	case "d":
		// Export run
		if m.selected != nil {
			return m, m.exportRun()
		}
		return m, nil

	case "pgup":
		m.viewport.PageUp()
		return m, nil

	case "pgdown":
		m.viewport.PageDown()
		return m, nil
	}

	// Pass unhandled keys to focused component
	if m.focusLeft {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		m.selectRun(m.list.Index())
		return m, cmd
	}
	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m *TimeMachineModel) updateLayout() {
	leftWidth := m.width * 2 / 5
	rightWidth := m.width - leftWidth - 2 // -2 for border/padding

	m.list.SetWidth(leftWidth)
	m.list.SetHeight(m.height - 4) // -4 for title, status, help

	m.viewport.Width = rightWidth
	m.viewport.Height = m.height - 4
}

func (m *TimeMachineModel) updateList() {
	items := make([]list.Item, len(m.runs))
	for i, run := range m.runs {
		items[i] = runItem{run: run}
	}
	m.list.SetItems(items)
}

func (m *TimeMachineModel) selectRun(index int) {
	if index >= 0 && index < len(m.runs) {
		m.selected = m.runs[index]
		m.renderDetail()
	}
}

func (m *TimeMachineModel) renderDetail() {
	if m.selected == nil {
		m.viewport.SetContent(mutedStyle.Render("No run selected"))
		return
	}

	run := m.selected
	var b strings.Builder

	// Header
	b.WriteString(titleStyle.Render(fmt.Sprintf("Run: %s", run.RunID)))
	b.WriteString("\n\n")

	// Metadata
	b.WriteString(labelStyle.Render("Timestamp:   "))
	b.WriteString(run.Timestamp.Local().Format("2006-01-02 15:04:05 MST"))
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Prompt:      "))
	b.WriteString(run.Prompt)
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Pack:        "))
	b.WriteString(packBadgeStyle.Render(run.SelectedPack))
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("CWD:         "))
	b.WriteString(run.CWD)
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Status:      "))
	b.WriteString(statusIcon(run.Status))
	b.WriteString(" ")
	b.WriteString(string(run.Status))
	b.WriteString("\n")
	if run.Error != "" {
		b.WriteString(labelStyle.Render("Error:       "))
		b.WriteString(errStyle.Render(run.Error))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// Token usage
	b.WriteString(labelStyle.Render("Tokens:      "))
	fmt.Fprintf(&b, "prompt=%d completion=%d total=%d",
		run.TokensUsed.PromptTokens, run.TokensUsed.CompletionTokens, run.TokensUsed.TotalTokens)
	b.WriteString("\n\n")

	// Files changed
	if len(run.FilesChanged) > 0 {
		b.WriteString(titleStyle.Render("Files Changed"))
		b.WriteString("\n")
		for _, diff := range run.FilesChanged {
			fmt.Fprintf(&b, "  %s %s\n",
				func() string {
					if diff.Created {
						return okStyle.Render("[NEW]")
					}
					return labelStyle.Render("[MOD]")
				}(),
				diff.TargetPath)
			if diff.Diff != "" {
				b.WriteString(RenderDiff(diff.Diff))
			}
		}
		b.WriteString("\n")
	}

	// Commands executed
	if len(run.CommandsExecuted) > 0 {
		b.WriteString(titleStyle.Render("Commands Executed"))
		b.WriteString("\n")
		for _, cmd := range run.CommandsExecuted {
			statusStr := okStyle.Render("✓")
			if cmd.ExitCode != 0 {
				statusStr = errStyle.Render(fmt.Sprintf("✗ (%d)", cmd.ExitCode))
			}
			fmt.Fprintf(&b, "  %s [%s] %s\n", statusStr, cmd.Source, truncateString(cmd.Command, 60))
			if cmd.Stdout != "" && len(cmd.Stdout) < 200 {
				b.WriteString(mutedStyle.Render("    → " + strings.TrimSpace(cmd.Stdout) + "\n"))
			}
		}
		b.WriteString("\n")
	}

	// Verification receipt
	if len(run.VerificationReceipt) > 0 {
		b.WriteString(titleStyle.Render("Verification"))
		b.WriteString("\n")
		for _, vr := range run.VerificationReceipt {
			statusStr := okStyle.Render("✓ passed")
			if !vr.Passed {
				statusStr = errStyle.Render("✗ failed")
			}
			fmt.Fprintf(&b, "  %s %s (exit %d)\n", statusStr, vr.Command, vr.ExitCode)
			if vr.Output != "" && len(vr.Output) < 200 {
				b.WriteString(mutedStyle.Render("    → " + strings.TrimSpace(vr.Output) + "\n"))
			}
		}
		b.WriteString("\n")
	}

	m.viewport.SetContent(b.String())
	m.viewport.GotoTop()
}

func (m *TimeMachineModel) rollbackSelected() tea.Cmd {
	if m.selected == nil {
		return nil
	}
	runID := m.selected.RunID
	return func() tea.Msg {
		// H6: call the real RollbackRun (not just a status flag) so the
		// filesystem is actually restored. Keyed by immutable run ID.
		if err := sandbox.RollbackRun(runID); err != nil {
			return rollbackResultMsg{err: err}
		}
		if err := audit.UpdateRunStatus(runID, audit.RunStatusRolledBack); err != nil {
			return rollbackResultMsg{err: err}
		}
		return rollbackResultMsg{err: nil}
	}
}

func (m *TimeMachineModel) resumeChat() tea.Cmd {
	if m.selected == nil {
		return nil
	}
	// For now, just return a message
	return func() tea.Msg {
		return resumeChatMsg{}
	}
}

func (m *TimeMachineModel) exportRun() tea.Cmd {
	if m.selected == nil {
		return nil
	}
	run := m.selected
	return func() tea.Msg {
		// Export as markdown
		mdPath := fmt.Sprintf("run-%s.md", run.RunID)
		mdContent := exportMarkdown(run)
		if err := os.WriteFile(mdPath, []byte(mdContent), 0o644); err != nil {
			return exportResultMsg{err: err}
		}

		// Export as shell script
		shPath := fmt.Sprintf("run-%s.sh", run.RunID)
		shContent := exportShellScript(run)
		if err := os.WriteFile(shPath, []byte(shContent), 0o755); err != nil {
			return exportResultMsg{err: err}
		}

		return exportResultMsg{err: nil, path: mdPath + " and " + shPath}
	}
}

// View renders the UI.
func (m *TimeMachineModel) View() string {
	if m.quitting {
		return "Goodbye!\n"
	}

	if m.err != nil {
		return errStyle.Render("Error: "+m.err.Error()) + "\n"
	}

	if len(m.runs) == 0 {
		return titleStyle.Render("No runs found") + "\n\n" + mutedStyle.Render("Run 'lnta <prompt>' to create some runs first.") + "\n"
	}

	// Left pane
	leftBorder := borderStyle
	if m.focusLeft {
		leftBorder = focusedBorderStyle
	}
	leftContent := leftBorder.Render(m.list.View())

	// Right pane
	rightBorder := borderStyle
	if !m.focusLeft {
		rightBorder = focusedBorderStyle
	}
	rightContent := rightBorder.Render(m.viewport.View())

	// Status line
	status := m.status
	if status == "" {
		status = helpStyle.Render("Tab: switch panes | ↑/↓/j/k: navigate | Enter/u: rollback | r: resume | d: export | q: quit")
	}

	// Join horizontally
	return lipgloss.JoinHorizontal(lipgloss.Top, leftContent, rightContent) + "\n" + status
}

// exportMarkdown generates a Markdown report for a run.
func exportMarkdown(run *audit.RunSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# LNTA Run Report: %s\n\n", run.RunID)
	fmt.Fprintf(&b, "- **Timestamp**: %s\n", run.Timestamp.Local().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Prompt**: %s\n", run.Prompt)
	fmt.Fprintf(&b, "- **Pack**: %s\n", run.SelectedPack)
	fmt.Fprintf(&b, "- **CWD**: %s\n", run.CWD)
	fmt.Fprintf(&b, "- **Status**: %s\n", run.Status)
	fmt.Fprintf(&b, "- **Tokens**: prompt=%d completion=%d total=%d\n\n",
		run.TokensUsed.PromptTokens, run.TokensUsed.CompletionTokens, run.TokensUsed.TotalTokens)

	if run.Error != "" {
		fmt.Fprintf(&b, "**Error**: %s\n\n", run.Error)
	}

	if len(run.FilesChanged) > 0 {
		b.WriteString("## Files Changed\n\n")
		for _, diff := range run.FilesChanged {
			fmt.Fprintf(&b, "### %s %s\n\n",
				func() string {
					if diff.Created {
						return "[NEW]"
					}
					return "[MODIFIED]"
				}(),
				diff.TargetPath)
			if diff.Diff != "" {
				b.WriteString("```diff\n")
				b.WriteString(diff.Diff)
				b.WriteString("\n```\n\n")
			}
		}
	}

	if len(run.CommandsExecuted) > 0 {
		b.WriteString("## Commands Executed\n\n")
		for _, cmd := range run.CommandsExecuted {
			fmt.Fprintf(&b, "### %s [%s] (exit %d)\n\n", cmd.Source, cmd.Command, cmd.ExitCode)
			if cmd.Stdout != "" {
				b.WriteString("**Stdout:**\n```\n")
				b.WriteString(cmd.Stdout)
				b.WriteString("\n```\n\n")
			}
			if cmd.Stderr != "" {
				b.WriteString("**Stderr:**\n```\n")
				b.WriteString(cmd.Stderr)
				b.WriteString("\n```\n\n")
			}
		}
	}

	if len(run.VerificationReceipt) > 0 {
		b.WriteString("## Verification Receipt\n\n")
		for _, vr := range run.VerificationReceipt {
			status := "PASSED"
			if !vr.Passed {
				status = "FAILED"
			}
			fmt.Fprintf(&b, "- **%s**: %s (exit %d)\n", status, vr.Command, vr.ExitCode)
			if vr.Output != "" {
				b.WriteString("  ```\n")
				b.WriteString(vr.Output)
				b.WriteString("\n  ```\n")
			}
		}
	}

	return b.String()
}

// exportShellScript generates an executable shell script that reproduces the run.
func exportShellScript(run *audit.RunSummary) string {
	var b strings.Builder
	b.WriteString("#!/bin/bash\n")
	fmt.Fprintf(&b, "# LNTA Run Reproduction Script: %s\n", shellQuote(run.RunID))
	sanitizedPrompt := strings.ReplaceAll(run.Prompt, "\n", " ")
	fmt.Fprintf(&b, "# Original prompt: %s\n", sanitizedPrompt)
	fmt.Fprintf(&b, "# Pack: %s\n", run.SelectedPack)
	b.WriteString("set -euo pipefail\n\n")
	fmt.Fprintf(&b, "cd %s\n\n", shellQuote(run.CWD))

	for _, cmd := range run.CommandsExecuted {
		if cmd.Source == "inspect_system" || cmd.Source == "mutate_system" {
			fmt.Fprintf(&b, "# %s (exit %d)\n", cmd.Source, cmd.ExitCode)
			b.WriteString(cmd.Command + "\n\n")
		}
	}

	if len(run.FilesChanged) > 0 {
		b.WriteString("# File changes (apply manually or with a tool)\n")
		for _, diff := range run.FilesChanged {
			if diff.Created {
				fmt.Fprintf(&b, "# Created: %s\n", diff.TargetPath)
			} else {
				fmt.Fprintf(&b, "# Modified: %s\n", diff.TargetPath)
			}
		}
	}

	b.WriteString("# Verification commands\n")
	for _, vr := range run.VerificationReceipt {
		fmt.Fprintf(&b, "# %s (exit %d)\n", vr.Command, vr.ExitCode)
		b.WriteString(vr.Command + "\n")
	}

	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// RunTimeMachine launches the time-machine TUI.
func RunTimeMachine() error {
	p := tea.NewProgram(NewTimeMachineModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// RunTimeMachineForUndo launches the time-machine TUI in undo mode (pre-selects latest run).
func RunTimeMachineForUndo() error {
	// For now, just run the regular time machine
	// Could add a flag to pre-select the latest run
	return RunTimeMachine()
}
