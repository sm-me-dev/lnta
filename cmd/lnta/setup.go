package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/sm-me/lnta/internal/agent"
	"github.com/sm-me/lnta/internal/shell"
	"github.com/sm-me/lnta/internal/ui"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive onboarding wizard to configure LLM providers and test environment",
	Long: `Interactive onboarding wizard that configures LNTA in seconds:
1. Auto-detects local Ollama instances for 1-click zero-key offline use.
2. Configures cloud providers (OpenRouter, Anthropic, OpenAI, Gemini, or custom).
3. Securely stores API keys via OS Keyring (with strict 0600 fallback).
4. Runs connectivity and sandbox diagnostics (lnta doctor).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSetup(cmd)
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

// runSetup executes the interactive first-run onboarding wizard.
func runSetup(cmd *cobra.Command) error {
	ui.EnforceColorProfile()

	// Redirect to /dev/tty if stdin is not a terminal but tty is available
	if !term.IsTerminal(os.Stdin.Fd()) {
		tty, err := shell.GetTTY()
		if err != nil {
			return fmt.Errorf("interactive setup requires a terminal: %w", err)
		}
		defer tty.Close()
		oldStdin := os.Stdin
		os.Stdin = tty
		defer func() { os.Stdin = oldStdin }()
	}

	fmt.Println(titleStyle.Render("=== LNTA Setup Wizard ==="))
	fmt.Println("Configuring Linux Natural-Language Terminal Assistant")
	fmt.Println()

	// 1. Auto-detect local Ollama at :11434
	models, _, err := agent.DiscoverLocalOllama()
	if err == nil && len(models) > 0 {
		var useOllama bool
		confirm := huh.NewConfirm().
			Title("Local Ollama Detected!").
			Description(fmt.Sprintf("Found Ollama running on :11434 with %d model(s).\nWould you like 1-click zero-key offline setup with local Ollama?", len(models))).
			Affirmative("Yes, use local Ollama (100% offline)").
			Negative("No, configure a cloud provider").
			Value(&useOllama)

		if err := confirm.Run(); err != nil {
			if errors.Is(err, huh.ErrUserAborted) {
				return agent.NewExitError(agent.ExitCodeUserCancelled, errors.New("setup cancelled by user"))
			}
			return err
		}

		if useOllama {
			selectedModel := models[0].ID
			for _, pref := range []string{"qwen2.5-coder", "llama3.3", "mistral", "codellama", "deepseek-coder"} {
				for _, m := range models {
					if m.ID == pref || strings.HasPrefix(m.ID, pref+":") {
						selectedModel = m.ID
						break
					}
				}
				if selectedModel != models[0].ID {
					break
				}
			}

			cfg := &agent.Config{
				BaseURL:     "http://127.0.0.1:11434/v1",
				Model:       selectedModel,
				LocalModels: models,
			}
			if err := agent.SaveConfigFile(userConfigDir, cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			if err := agent.SaveSecretToDir(userConfigDir, "ollama"); err != nil {
				return fmt.Errorf("save secret: %w", err)
			}

			fmt.Println()
			fmt.Printf("%s Local Ollama configured (%s)\n", labelStyle.Render("✓"), selectedModel)
			fmt.Printf("%s Configuration saved to %s\n\n", labelStyle.Render("✓"), filepath.Join(userConfigDir, "config.yaml"))
			fmt.Println(labelStyle.Render("Running connectivity & sandbox self-test (lnta doctor)..."))
			return runDoctor(cmd)
		}
	}

	// 2. Cloud provider selection
	var provider string
	selectProvider := huh.NewSelect[string]().
		Title("Select LLM Provider").
		Options(
			huh.NewOption("OpenRouter (Multi-model router)", "openrouter"),
			huh.NewOption("Anthropic (Claude 3.5 Sonnet)", "anthropic"),
			huh.NewOption("OpenAI (GPT-4o-mini / GPT-4o)", "openai"),
			huh.NewOption("Google Gemini (Gemini 2.0 Flash)", "gemini"),
			huh.NewOption("Custom OpenAI-compatible Endpoint", "custom"),
		).
		Value(&provider)

	if err := selectProvider.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return agent.NewExitError(agent.ExitCodeUserCancelled, errors.New("setup cancelled by user"))
		}
		return err
	}

	var baseURL, defaultMdl string
	switch provider {
	case "openrouter":
		baseURL = "https://openrouter.ai/api/v1"
		defaultMdl = "anthropic/claude-3.5-sonnet"
	case "anthropic":
		baseURL = "https://api.anthropic.com/v1"
		defaultMdl = "claude-3-5-sonnet-latest"
	case "openai":
		baseURL = "https://api.openai.com/v1"
		defaultMdl = "gpt-4o-mini"
	case "gemini":
		baseURL = "https://generativelanguage.googleapis.com/v1beta/openai/"
		defaultMdl = "gemini-2.0-flash"
	case "custom":
		baseURL = "https://api.openai.com/v1"
		defaultMdl = "gpt-4o-mini"
	}

	apiKey := ""
	model := defaultMdl

	var fields []huh.Field
	if provider == "custom" {
		fields = append(fields, huh.NewInput().
			Title("Base URL").
			Description("OpenAI-compatible chat completions base URL (must end in /v1)").
			Value(&baseURL).
			Validate(huh.ValidateNotEmpty()))
	}

	fields = append(fields,
		huh.NewInput().
			Title("API Key").
			Description("Stored securely in OS Keyring with strict 0600 file fallback").
			EchoMode(huh.EchoModePassword).
			Value(&apiKey).
			Validate(huh.ValidateNotEmpty()),
		huh.NewInput().
			Title("Default Model").
			Description("Recommended fast model for this provider").
			Value(&model).
			Validate(huh.ValidateNotEmpty()),
	)

	form := huh.NewForm(huh.NewGroup(fields...))
	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return agent.NewExitError(agent.ExitCodeUserCancelled, errors.New("setup cancelled by user"))
		}
		return err
	}

	// 3. Save secret securely (OS Keyring first, strict 0600 file fallback)
	if err := agent.SaveSecretToDir(userConfigDir, apiKey); err != nil {
		return fmt.Errorf("save API key: %w", err)
	}

	// 4. Save config file with strict 0600 permissions
	cfg := &agent.Config{
		BaseURL: baseURL,
		Model:   model,
	}
	if err := agent.SaveConfigFile(userConfigDir, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println()
	fmt.Println(labelStyle.Render("✓ Credentials saved securely (OS Keyring / strict 0600 permissions)."))
	fmt.Printf("%s Configuration written to %s\n\n", labelStyle.Render("✓"), filepath.Join(userConfigDir, "config.yaml"))
	fmt.Println(labelStyle.Render("Running connectivity & sandbox self-test (lnta doctor)..."))
	return runDoctor(cmd)
}
