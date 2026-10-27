package shell

import (
	"strings"
	"testing"
)

func TestGenerateInitScript_Zsh(t *testing.T) {
	script, err := GenerateInitScript("zsh", "test-version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all required components present
	required := []string{
		"__lnta_precmd",
		"_LNTA_LAST_CMD",
		"_LNTA_LAST_EXIT",
		"lnta_fix",
		"_lnta_ctrl_g_widget",
		"bindkey '^G'",
		"bindkey '^X^G' _lnta_ctrl_x_ctrl_g_fix_widget",
		"add-zsh-hook precmd",
	}
	for _, s := range required {
		if !strings.Contains(script, s) {
			t.Errorf("zsh script missing required component: %s", s)
		}
	}

	// Verify version substituted
	if !strings.Contains(script, "test-version") {
		t.Errorf("version not substituted in template")
	}

	// Verify no unsupported shell content
	if strings.Contains(script, "PROMPT_COMMAND") {
		t.Errorf("zsh script should not contain bash PROMPT_COMMAND")
	}
	if strings.Contains(script, "fish_prompt") {
		t.Errorf("zsh script should not contain fish fish_prompt")
	}
}

func TestGenerateInitScript_Bash(t *testing.T) {
	script, err := GenerateInitScript("bash", "test-version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	required := []string{
		"_lnta_prompt_command",
		"_LNTA_LAST_CMD",
		"_LNTA_LAST_EXIT",
		"lnta_fix",
		"_lnta_ctrl_g_widget",
		`bind -x '"\C-g"`,
		"PROMPT_COMMAND",
	}
	for _, s := range required {
		if !strings.Contains(script, s) {
			t.Errorf("bash script missing required component: %s", s)
		}
	}

	if !strings.Contains(script, "test-version") {
		t.Errorf("version not substituted in template")
	}

	if strings.Contains(script, "add-zsh-hook") {
		t.Errorf("bash script should not contain zsh add-zsh-hook")
	}
	if strings.Contains(script, "fish_prompt") {
		t.Errorf("bash script should not contain fish fish_prompt")
	}
}

func TestGenerateInitScript_Fish(t *testing.T) {
	script, err := GenerateInitScript("fish", "test-version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	required := []string{
		"_lnta_fish_prompt",
		"_LNTA_LAST_CMD",
		"_LNTA_LAST_EXIT",
		"lnta_fix",
		"_lnta_ctrl_g_widget",
		`bind \cg`,
		"commandline -r",
		"fish_prompt",
	}
	for _, s := range required {
		if !strings.Contains(script, s) {
			t.Errorf("fish script missing required component: %s", s)
		}
	}

	if !strings.Contains(script, "test-version") {
		t.Errorf("version not substituted in template")
	}

	if strings.Contains(script, "add-zsh-hook") {
		t.Errorf("fish script should not contain zsh add-zsh-hook")
	}
	if strings.Contains(script, "PROMPT_COMMAND") {
		t.Errorf("fish script should not contain bash PROMPT_COMMAND")
	}
}

func TestGenerateInitScript_Unknown(t *testing.T) {
	_, err := GenerateInitScript("unknown", "test-version")
	if err == nil {
		t.Errorf("expected error for unsupported shell")
	}
	if !strings.Contains(err.Error(), "unsupported shell") {
		t.Errorf("error message should mention unsupported shell: %v", err)
	}
}

func TestGenerateInitScript_ValidSyntax(t *testing.T) {
	// Verify all three shells produce non-empty output
	fixBindings := map[string]string{
		"zsh":  "bindkey '^X^G' _lnta_ctrl_x_ctrl_g_fix_widget",
		"bash": "\\C-x\\C-g",
		"fish": "bind \\cx\\cg _lnta_ctrl_x_ctrl_g_fix",
	}
	for _, shell := range []string{"zsh", "bash", "fish"} {
		script, err := GenerateInitScript(shell, "test")
		if err != nil {
			t.Errorf("%s: unexpected error: %v", shell, err)
			continue
		}
		if script == "" {
			t.Errorf("%s: generated empty script", shell)
		}
		if strings.Contains(script, "alias f=") {
			t.Errorf("%s: must not define an f alias", shell)
		}
		if !strings.Contains(script, fixBindings[shell]) {
			t.Errorf("%s: missing Ctrl+X, Ctrl+G lnta_fix binding", shell)
		}
		ctrlGBindings := map[string]string{
			"zsh":  "bindkey '^G' _lnta_ctrl_g_widget",
			"bash": "\\C-g",
			"fish": "bind \\cg _lnta_ctrl_g_widget",
		}
		if !strings.Contains(script, ctrlGBindings[shell]) {
			t.Errorf("%s: existing Ctrl+G conversion binding was lost", shell)
		}
		// Basic sanity: should contain lnta fix function
		if !strings.Contains(script, "lnta_fix") {
			t.Errorf("%s: missing lnta_fix function", shell)
		}
	}
}
