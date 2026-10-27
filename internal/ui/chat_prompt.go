package ui

import (
	"errors"
	"os"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// ErrChatPromptCanceled is returned when the user cancels the current prompt.
var ErrChatPromptCanceled = errors.New("chat prompt canceled")

type chatPromptModel struct {
	input        textinput.Model
	history      []string
	historyIndex int
	draft        string
	value        string
	done         bool
	canceled     bool
}

func newChatPromptModel(history []string) chatPromptModel {
	input := textinput.New()
	input.Prompt = "lnta> "
	input.Focus()
	input.CharLimit = 0
	return chatPromptModel{
		input:        input,
		history:      append([]string(nil), history...),
		historyIndex: len(history),
	}
}

func (m chatPromptModel) Init() tea.Cmd { return textinput.Blink }

func (m chatPromptModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if ok {
		switch key.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			m.canceled = true
			return m, tea.Quit
		case tea.KeyEnter:
			m.value = m.input.Value()
			m.done = true
			return m, tea.Quit
		case tea.KeyUp:
			m.recallPrevious()
			return m, nil
		case tea.KeyDown:
			m.recallNext()
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m chatPromptModel) View() string { return m.input.View() }

func (m *chatPromptModel) recallPrevious() {
	if len(m.history) == 0 || m.historyIndex == 0 {
		return
	}
	if m.historyIndex == len(m.history) {
		m.draft = m.input.Value()
	}
	m.historyIndex--
	m.input.SetValue(m.history[m.historyIndex])
}

func (m *chatPromptModel) recallNext() {
	if m.historyIndex >= len(m.history) {
		return
	}
	m.historyIndex++
	if m.historyIndex == len(m.history) {
		m.input.SetValue(m.draft)
		return
	}
	m.input.SetValue(m.history[m.historyIndex])
}

// ReadChatPrompt reads an editable prompt with cursor navigation and in-session history.
func ReadChatPrompt(history []string) (string, error) {
	program := tea.NewProgram(newChatPromptModel(history), tea.WithInput(os.Stdin), tea.WithOutput(os.Stdout))
	result, err := program.Run()
	if err != nil {
		return "", err
	}
	model, ok := result.(chatPromptModel)
	if !ok {
		return "", errors.New("chat prompt ended unexpectedly")
	}
	if model.canceled {
		return "", ErrChatPromptCanceled
	}
	return model.value, nil
}
