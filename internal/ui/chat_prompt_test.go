package ui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func chatKey(m chatPromptModel, key tea.KeyMsg) chatPromptModel {
	updated, _ := m.Update(key)
	return updated.(chatPromptModel)
}

func TestChatPromptKeepsMultiwordPastedInput(t *testing.T) {
	m := newChatPromptModel(nil)
	m = chatKey(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("show RAM usage now")})
	m = chatKey(m, tea.KeyMsg{Type: tea.KeyEnter})
	if !m.done || m.value != "show RAM usage now" {
		t.Fatalf("prompt=%q done=%v", m.value, m.done)
	}
}

func TestChatPromptArrowEditing(t *testing.T) {
	m := newChatPromptModel(nil)
	m = chatKey(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("helo")})
	m = chatKey(m, tea.KeyMsg{Type: tea.KeyLeft})
	m = chatKey(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("l")})
	if got := m.input.Value(); got != "hello" {
		t.Fatalf("arrow-edited prompt=%q", got)
	}
}

func TestChatPromptHistoryAndDraftNavigation(t *testing.T) {
	m := newChatPromptModel([]string{"first multiword prompt", "second prompt"})
	m.input.SetValue("unfinished draft")
	m = chatKey(m, tea.KeyMsg{Type: tea.KeyUp})
	if got := m.input.Value(); got != "second prompt" {
		t.Fatalf("first history value=%q", got)
	}
	m = chatKey(m, tea.KeyMsg{Type: tea.KeyUp})
	if got := m.input.Value(); got != "first multiword prompt" {
		t.Fatalf("older history value=%q", got)
	}
	m = chatKey(m, tea.KeyMsg{Type: tea.KeyDown})
	if got := m.input.Value(); got != "second prompt" {
		t.Fatalf("newer history value=%q", got)
	}
	m = chatKey(m, tea.KeyMsg{Type: tea.KeyDown})
	if got := m.input.Value(); got != "unfinished draft" {
		t.Fatalf("draft restore value=%q", got)
	}
}

func TestChatPromptCancellation(t *testing.T) {
	m := chatKey(newChatPromptModel(nil), tea.KeyMsg{Type: tea.KeyCtrlC})
	if !m.canceled || m.done {
		t.Fatalf("canceled=%v done=%v", m.canceled, m.done)
	}
}
