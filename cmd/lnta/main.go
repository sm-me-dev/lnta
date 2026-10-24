package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	lnta "github.com/sm-me/lnta"
	"github.com/sm-me/lnta/internal/agent"
	"github.com/sm-me/lnta/internal/audit"
	"github.com/sm-me/lnta/internal/fingerprint"
	"github.com/sm-me/lnta/internal/mcp"
	"github.com/sm-me/lnta/internal/packs"
	"github.com/sm-me/lnta/internal/sandbox"
	"github.com/sm-me/lnta/internal/shell"
	"github.com/sm-me/lnta/internal/transport"
	"github.com/sm-me/lnta/internal/ui"
)

var (
	userConfigDir  string
	explainMode    bool
	dryRunMode     bool
	commandOnly    bool
	jsonOutput     bool
	sshTarget      string
	localModelFlag string

	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	labelStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	mutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
)

var chatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Start an interactive chat session",
	Long:  "Start an interactive multi-turn chat session preserving conversation history and active Run ID snapshots.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runChat()
	},
}

var undoCmd = &cobra.Command{
	Use:   "undo [run_id]",
	Short: "Undo a previous run by run id (defaults to the most recent run)",
	Long: `Undo a previous run by run id. If no run_id is provided, reverts the most recent run.

Use --interactive (-i) to launch the Time Machine TUI for selecting which run to undo.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		interactive, _ := cmd.Flags().GetBool("interactive")
		if interactive {
			return ui.RunTimeMachineForUndo()
		}
		runID := ""
		if len(args) == 1 {
			runID = args[0]
		} else {
			runID = latestRunID()
			if runID == "" {
				return fmt.Errorf("no run snapshots found; specify a run_id: lnta undo <run_id>")
			}
			fmt.Printf("No run_id specified; reverting most recent run %q\n", runID)
		}
		if err := sandbox.RollbackRun(runID); err != nil {
			return fmt.Errorf("undo %q: %w", runID, err)
		}
		fmt.Printf("undone run %q\n", runID)
		return nil
	},
}

var sessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "Launch interactive Time Machine TUI to browse past runs",
	Long: `Launch the Time Machine TUI for browsing, inspecting, and rolling back past lnta runs.

The TUI shows a fuzzy-searchable list of past runs with their timestamps, prompts,
instruction packs, and status icons (✓ verified, ✗ failed, ↩ rolled back).

Key bindings:
  ↑/↓/j/k    Navigate the run list
  /          Filter runs by prompt or pack
  Tab        Switch between left (list) and right (detail) panes
  Enter/u    Roll back the selected run
  r          Resume an interactive chat session (planned)
  d          Export run as Markdown report and shell script
  q/Ctrl+C   Quit`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ui.RunTimeMachine()
	},
}

// ollamaBaseURL is the OpenAI-compatible endpoint exposed by a local Ollama server.
const ollamaBaseURL = "http://127.0.0.1:11434/v1"

var modelsCmd = &cobra.Command{
	Use:   "models",
	Short: "List configured remote models and auto-discovered local Ollama models",
	Long: `List the currently configured remote LLM models and auto-discover local Ollama models
	running at http://127.0.0.1:11434/api/tags.

Use --local flag with a prompt to force 100% offline execution via the best detected local model.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := agent.LoadConfig()
		if err != nil {
			// Config may fail without an API key; that's OK for listing local models.
			cfg = nil
		}

		fmt.Println("Configured remote models:")
		if cfg != nil {
			fmt.Printf("  Model: %s (BaseURL: %s)\n", cfg.Model, cfg.BaseURL)
		} else {
			fmt.Println("  (no remote config — API key not set)")
		}

		fmt.Println("\nAuto-discovered local Ollama models:")
		discovered, hasToolCalling, discErr := agent.DiscoverLocalOllama()
		if discErr != nil {
			fmt.Printf("  Ollama discovery failed: %v (ensure Ollama is running at http://127.0.0.1:11434/)\n", discErr)
		} else if len(discovered) > 0 {
			for _, m := range discovered {
				tc := ""
				if hasToolCalling {
					tc = " [tool-calling]"
				}
				fmt.Printf("  - %s (size: %d bytes)%s\n", m.ID, m.Size, tc)
			}
		} else {
			fmt.Println("  No local Ollama models discovered (ensure Ollama is running at http://127.0.0.1:11434/)")
		}

		// If --local flag was provided with a prompt, run 100% offline via Ollama.
		if localModelFlag != "" {
			return runLocalOllama(localModelFlag, commandOnly)
		}

		return nil
	},
}

// runLocalOllama executes a prompt 100% offline using the best detected local
// Ollama model. It never contacts a remote LLM provider.
func runLocalOllama(prompt string, commandOnly bool) error {
	discovered, _, err := agent.DiscoverLocalOllama()
	if err != nil {
		return fmt.Errorf("ollama discovery failed: %w. Start Ollama at http://127.0.0.1:11434/", err)
	}
	if len(discovered) == 0 {
		return fmt.Errorf("no local Ollama models discovered — start Ollama and pull a model (e.g. qwen2.5-coder)")
	}

	// Select the best model: prefer known tool-calling models, then first available.
	preferred := []string{"qwen2.5-coder", "llama3.3", "mistral", "codellama", "deepseek-coder"}
	selected := discovered[0].ID
	for _, pref := range preferred {
		for _, m := range discovered {
			if m.ID == pref || strings.HasPrefix(m.ID, pref+":") {
				selected = m.ID
				break
			}
		}
		if selected != discovered[0].ID {
			break
		}
	}

	if !commandOnly && !jsonOutput {
		fmt.Printf("Offline mode: using local Ollama model %s\n", selected)
		fmt.Printf("Prompt: %s\n\n", prompt)
	}

	sys, err := fingerprint.Fingerprint()
	if err != nil {
		return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("fingerprint: %w", err))
	}

	router, err := packs.NewRouter(lnta.EmbeddedPacks, "packs/*.md", userConfigDir)
	if err != nil {
		return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("load packs: %w", err))
	}
	packs.SetDefaultRouter(router)

	selectedPacks, err := router.SelectPacks(prompt, sys)
	if err != nil {
		return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("route: %w", err))
	}
	pack := selectedPacks[0]

	// Display environment-specific warnings.
	if !commandOnly && !jsonOutput {
		for _, w := range packs.PackEnvironmentWarnings(pack, sys) {
			fmt.Printf("[env-warning] %s\n", w)
		}
	}

	if !commandOnly && !jsonOutput {
		fmt.Println(ui.StatusLine(pack.ID, "Planning (offline)", "", false))
		fmt.Println()
	}

	// Build an OpenAI-compatible client pointed at local Ollama (no API key needed).
	client, err := agent.NewOllamaClient(selected)
	if err != nil {
		return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("ollama client: %w", err))
	}

	runID := nextRunID()
	exec := transport.NewLocalExecutor(runID, ".", pack.AllowedPaths)

	opts := []agent.Option{
		agent.WithRunID(runID),
		agent.WithCWD("."),
		agent.WithApprove(approveMutation("local")),
		agent.WithConfig(&agent.Config{Model: selected, BaseURL: ollamaBaseURL}),
		agent.WithDryRun(dryRunMode),
		agent.WithExecutor(exec),
	}
	if explainMode {
		opts = append(opts, agent.WithAllowedTools([]string{"inspect_system", "complete_task"}))
	}

	o := agent.New(client, router, opts...)

	ctx, cancel := agent.WithSignalCancellation()
	defer cancel()

	result, runErr := o.Run(ctx, prompt, "", commandOnly || jsonOutput)
	summary := o.RunSummary()

	exitCode := agent.DetermineExitCode(runErr, result, summary)
	if summary != nil {
		summary.ExitCode = exitCode
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if summary != nil {
			_ = enc.Encode(summary)
		} else {
			_ = enc.Encode(map[string]interface{}{
				"run_id":    runID,
				"prompt":    prompt,
				"exit_code": exitCode,
				"error":     result,
			})
		}
		if exitCode != agent.ExitCodeSuccess {
			return agent.NewExitError(exitCode, runErr)
		}
		return nil
	}

	if runErr != nil {
		return agent.NewExitError(exitCode, runErr)
	}

	if !commandOnly {
		fmt.Println(renderResult(result, o.RunID(), pack))
	} else {
		cmd := extractVerifiedCommand(result)
		if cmd != "" {
			fmt.Println(cmd)
		}
	}

	if exitCode != agent.ExitCodeSuccess {
		return agent.NewExitError(exitCode, nil)
	}
	return nil
}

var packsCmd = &cobra.Command{
	Use:   "packs",
	Short: "Manage instruction packs",
}

var packsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List loaded instruction packs",
	RunE: func(cmd *cobra.Command, args []string) error {
		router, err := packs.NewRouter(lnta.EmbeddedPacks, "packs/*.md", userConfigDir)
		if err != nil {
			return fmt.Errorf("load packs: %w", err)
		}
		for _, p := range router.AllPacks() {
			fmt.Printf("%-32s %s\n", p.ID, p.Name)
		}
		return nil
	},
}

var packsValidateCmd = &cobra.Command{
	Use:   "validate [path]",
	Short: "Validate instruction pack syntax and structure",
	Long: `Validate instruction pack files for correct frontmatter, glob patterns,
required binaries, and executable context_cmd/verify_cmd commands.

If PATH is not provided, validates embedded packs.
If PATH is a directory, validates all *.md files in it.
If PATH is a file, validates that specific pack.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		config := packs.DefaultValidatorConfig()
		config.CheckBinaries, _ = cmd.Flags().GetBool("check-binaries")
		config.RunContextCmd, _ = cmd.Flags().GetBool("run-context-cmd")
		config.StrictMode, _ = cmd.Flags().GetBool("strict")

		var results []packs.ValidationResult
		var err error

		if len(args) == 0 {
			// Validate embedded packs
			results, err = packs.ValidateEmbeddedPacks(lnta.EmbeddedPacks, "packs/*.md", config)
			if err != nil {
				return fmt.Errorf("validate embedded packs: %w", err)
			}
		} else {
			path := args[0]
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("stat %s: %w", path, err)
			}
			if info.IsDir() {
				results, err = packs.ValidateDirectory(path, config)
				if err != nil {
					return fmt.Errorf("validate directory: %w", err)
				}
			} else {
				result, err := packs.ValidatePack(path, config)
				if err != nil {
					return fmt.Errorf("validate pack: %w", err)
				}
				results = []packs.ValidationResult{result}
			}
		}

		jsonOutput, _ := cmd.Flags().GetBool("json")
		if jsonOutput {
			output, err := packs.FormatValidationResultsJSON(results)
			if err != nil {
				return fmt.Errorf("format JSON: %w", err)
			}
			fmt.Println(output)
		} else {
			fmt.Print(packs.FormatValidationResults(results, config))
		}

		// Exit with error code if any pack is invalid
		hasInvalid := false
		for _, r := range results {
			if !r.Valid {
				hasInvalid = true
				break
			}
		}
		if hasInvalid {
			if config.StrictMode {
				os.Exit(1)
			}
			return fmt.Errorf("one or more packs failed validation")
		}

		return nil
	},
}

func init() {
	packsCmd.AddCommand(packsListCmd)
	packsCmd.AddCommand(packsValidateCmd)
}

func init() {
	packsValidateCmd.Flags().Bool("check-binaries", true, "Check if required_bins exist in PATH")
	packsValidateCmd.Flags().Bool("run-context-cmd", false, "Execute context_cmd in sandbox to validate (requires bwrap/Landlock)")
	packsValidateCmd.Flags().Bool("strict", false, "Treat warnings as errors and exit with non-zero code on validation failure")
	packsValidateCmd.Flags().Bool("json", false, "Output results as JSON")
}

func init() {
	undoCmd.Flags().BoolP("interactive", "i", false, "Launch interactive Time Machine TUI to select run to undo")
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run system health and configuration diagnostics",
	Long: `Performs diagnostic checks on the LNTA environment including:
- LLM API configuration and connectivity
- Kernel sandbox status (bwrap, AppArmor, Landlock)
- Installed validator binaries`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDoctor(cmd)
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

var doctorVerbose bool
var doctorFix bool

func init() {
	doctorCmd.Flags().BoolVar(&doctorVerbose, "verbose", false, "Verbose output")
	doctorCmd.Flags().BoolVar(&doctorFix, "generate-apparmor", false, "Generate AppArmor profile for bwrap")
}

var sandboxExecCmd = &cobra.Command{
	Use:    "__sandbox_exec",
	Short:  "Internal: Landlock sandbox executor (do not call directly)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sandbox.LandlockExecCommand(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return nil
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

var initCmd = &cobra.Command{
	Use:   "init <zsh|bash|fish>",
	Short: "Generate shell integration script for terminal prompt enhancement",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		shellName := args[0]
		script, err := shell.GenerateInitScript(shellName, lnta.Version)
		if err != nil {
			return fmt.Errorf("generate init script: %w", err)
		}
		fmt.Print(script)
		return nil
	},
}

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Automatically capture and attempt to fix the last failed command",
	RunE: func(cmd *cobra.Command, args []string) error {
		lastCmd := os.Getenv("_LNTA_LAST_CMD")
		lastExit := os.Getenv("_LNTA_LAST_EXIT")

		if lastCmd == "" || lastExit == "" {
			fmt.Println("No previous command to fix. Run a command first.")
			os.Exit(1)
		}

		// Parse exit code
		exitCode := 0
		fmt.Sscanf(lastExit, "%d", &exitCode)

		// For now, we'll just run the standard prompt with a fix context
		// In the future, this could re-run in sandbox and construct FixContext
		fixPrompt := fmt.Sprintf("The command %q failed with exit code %d. Please diagnose and propose a fix.", lastCmd, exitCode)

		return runPrompt(cmd, []string{fixPrompt})
	},
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run the MCP server (JSON-RPC 2.0 over stdio)",
	Long: `Start the Model Context Protocol (MCP) server over stdio.
This allows LNTA to be used as an MCP backend for tools like Claude Code, Cursor, or OpenCode.

The server exposes these tools:
- lnta_inspect_sandboxed: Execute read-only commands in a sandbox
- lnta_get_pack_runbook: Get an instruction pack by ID
- lnta_verify_task: Run a pack's verify_cmd with a target`,
	RunE: func(cmd *cobra.Command, args []string) error {
		server, err := mcp.NewServer(userConfigDir, lnta.EmbeddedPacks)
		if err != nil {
			return fmt.Errorf("create MCP server: %w", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Handle signals
		sigCtx, sigCancel := signal.NotifyContext(ctx, os.Interrupt)
		defer sigCancel()

		return server.Run(sigCtx)
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func main() {
	// Kill any tracked child process groups on exit (Ctrl-C / cancellation)
	// so bwrap/ssh/mutate children cannot outlive the CLI (H5).
	defer sandbox.KillAllChildren()

	if err := rootCmd.Execute(); err != nil {
		var exitErr *agent.ExitError
		if errors.As(err, &exitErr) {
			if !jsonOutput && exitErr.Err != nil {
				fmt.Fprintln(os.Stderr, exitErr.Err)
			}
			os.Exit(exitErr.Code)
		}
		if !jsonOutput {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(agent.ExitCodeGeneralError)
	}
}

var rootCmd = &cobra.Command{
	Use:   "lnta [prompt]",
	Short: "LNTA — Linux Natural-Language Terminal Assistant",
	Long: `LNTA grounds LLM actions in local system truth.

Use "lnta <prompt>" for one-shot execution.
Use "lnta --explain <prompt>" for Explain Mode (no state mutation possible).
Use "lnta --dry-run <prompt>" to inspect proposed diffs without writing.
Use "lnta chat" for an interactive multi-turn session.
Use "lnta undo [run_id]" to revert a previous run.
Use "lnta undo -i" to interactively select a run to undo.
Use "lnta sessions" to browse past runs in the Time Machine TUI.
Use "lnta init <zsh|bash|fish>" to generate shell integration.
Use "lnta fix" to automatically fix the last failed command.
Use "lnta models" to list configured remote models and auto-discovered local Ollama models.
Use "lnta --local <prompt>" to force 100% offline execution via the best detected local Ollama model.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		return runPrompt(cmd, args)
	},
	SilenceUsage:  true,
	SilenceErrors: true,
	Args:          cobra.ArbitraryArgs,
}

func init() {
	home, _ := os.UserHomeDir()
	userConfigDir = filepath.Join(home, ".config", "lnta")
	rootCmd.PersistentFlags().StringVar(&userConfigDir, "config", userConfigDir,
		"user config directory (default ~/.config/lnta)")
	rootCmd.PersistentFlags().BoolVar(&explainMode, "explain", false,
		"Explain Mode: disables write_scoped_file and mutate_system so no state can be mutated")
	rootCmd.PersistentFlags().BoolVar(&dryRunMode, "dry-run", false,
		"Dry-run mode: print proposed file diffs and commands, block all writes")
	rootCmd.PersistentFlags().BoolVar(&commandOnly, "command-only", false,
		"Output only the verified command (for shell widgets)")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false,
		"Output structured RunSummary (plan, diffs, verification receipt, exit code) as clean JSON to stdout")
	rootCmd.PersistentFlags().StringVar(&sshTarget, "ssh", "",
		"Execute on remote host via SSH (format: user@host[:port])")
	rootCmd.PersistentFlags().StringVar(&localModelFlag, "local", "",
		"Force 100% offline execution via the best detected local Ollama model. "+
			"Optionally provide a prompt to run immediately with the local model.")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		ui.EnforceColorProfile()
	}

	rootCmd.Version = lnta.Version
	rootCmd.SetVersionTemplate("LNTA version {{.Version}}\n")

	rootCmd.AddCommand(chatCmd)
	rootCmd.AddCommand(undoCmd)
	rootCmd.AddCommand(sessionsCmd)
	rootCmd.AddCommand(packsCmd)
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(fixCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(modelsCmd)

	// Hidden command for Landlock sandbox self-re-exec
	rootCmd.AddCommand(sandboxExecCmd)
}

// runPrompt runs one-shot execution mode through the agent orchestrator.
func runPrompt(cmd *cobra.Command, args []string) error {
	prompt := strings.Join(args, " ")

	// --local forces 100% offline execution via the best detected local Ollama model.
	if localModelFlag != "" {
		return runLocalOllama(prompt, commandOnly)
	}

	// Detect pipe on stdin early
	stdinIsPipe := shell.IsStdinPipe()
	var pipeContext string
	if stdinIsPipe {
		ctx, _, err := shell.ReadPipeContext(os.Stdin)
		if err != nil {
			return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("read pipe context: %w", err))
		}
		pipeContext = ctx
	}

	sys, err := fingerprint.Fingerprint()
	if err != nil {
		return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("fingerprint: %w", err))
	}

	router, err := packs.NewRouter(lnta.EmbeddedPacks, "packs/*.md", userConfigDir)
	if err != nil {
		return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("load packs: %w", err))
	}
	packs.SetDefaultRouter(router)

	selected, err := router.SelectPacks(prompt, sys)
	if err != nil {
		return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("route: %w", err))
	}
	pack := selected[0]

	// Display environment-specific warnings (WSL2, container, headless SSH).
	if !commandOnly && !jsonOutput {
		for _, w := range packs.PackEnvironmentWarnings(pack, sys) {
			fmt.Printf("[env-warning] %s\n", w)
		}
	}

	// Compact status line at the start of execution.
	if !commandOnly && !jsonOutput {
		fmt.Println(ui.StatusLine(pack.ID, "Planning", "", false))
		fmt.Println()
	}

	// Build the orchestrator backed by a real LLM client.
	cfg, err := agent.LoadConfigDir(userConfigDir)
	if err != nil {
		if errors.Is(err, agent.ErrNoAPIKey) || strings.Contains(err.Error(), "no LLM API key configured") {
			// Auto-launch interactive setup wizard if running interactively on a terminal
			if !jsonOutput && !commandOnly && !stdinIsPipe && term.IsTerminal(os.Stdin.Fd()) {
				fmt.Println("No API key configured. Starting interactive setup wizard...")
				if serr := runSetup(cmd); serr != nil {
					return serr
				}
				cfg, err = agent.LoadConfigDir(userConfigDir)
				if err != nil {
					return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("config error after setup: %w", err))
				}
			} else {
				return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("no LLM API key configured: run 'lnta setup' or set LNTA_API_KEY"))
			}
		} else {
			return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("config: %w", err))
		}
	}

	client, err := agent.NewOpenAIClient(cfg)
	if err != nil {
		return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("llm client: %w", err))
	}

	runID := nextRunID()

	// Set up executor (local or SSH)
	var executor transport.TargetExecutor
	if sshTarget != "" {
		executor, err = transport.NewSSHExecutor(sshTarget, runID, ".")
		if err != nil {
			return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("create SSH executor: %w", err))
		}
		defer executor.Close()

		// Preflight: fingerprint remote host
		ctx := context.Background()
		if err := executor.Preflight(ctx); err != nil {
			return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("SSH preflight: %w", err))
		}

		// Display remote fingerprint for user confirmation
		if fp := executor.RemoteFingerprint(); fp != nil && !commandOnly && !jsonOutput {
			fmt.Printf("Connected to %s (%s %s)\n", sshTarget, fp.OSRelease["ID"], fp.OSRelease["VERSION_ID"])
			fmt.Println()
		}
	} else {
		executor = transport.NewLocalExecutor(runID, ".", pack.AllowedPaths)
	}

	// One approval function for every path (piped or interactive stdin).
	approveFn := approveMutation(executor.TargetID())

	opts := []agent.Option{
		agent.WithRunID(runID),
		agent.WithCWD("."),
		agent.WithApprove(approveFn),
		agent.WithConfig(cfg),
		agent.WithDryRun(dryRunMode),
		agent.WithExecutor(executor),
	}
	if explainMode {
		// Explain Mode: physically remove write_scoped_file and mutate_system so
		// the model cannot mutate state at the harness level.
		opts = append(opts, agent.WithAllowedTools([]string{"inspect_system", "complete_task"}))
	}

	o := agent.New(client, router, opts...)

	ctx, cancel := agent.WithSignalCancellation()
	defer cancel()

	result, runErr := o.Run(ctx, prompt, pipeContext, commandOnly || jsonOutput)
	summary := o.RunSummary()

	// Determine deterministic exit code
	exitCode := agent.DetermineExitCode(runErr, result, summary)
	if summary != nil {
		summary.ExitCode = exitCode
	}

	// Trigger lightweight automatic storage garbage collection in background
	if cfg != nil {
		go audit.AutoGC(cfg.GCMaxRuns, cfg.GCMaxMB)
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if summary != nil {
			_ = enc.Encode(summary)
		} else {
			_ = enc.Encode(map[string]interface{}{
				"run_id":    runID,
				"prompt":    prompt,
				"exit_code": exitCode,
				"error":     result,
			})
		}
		if exitCode != agent.ExitCodeSuccess {
			return agent.NewExitError(exitCode, runErr)
		}
		return nil
	}

	if runErr != nil {
		return agent.NewExitError(exitCode, runErr)
	}

	if !commandOnly {
		fmt.Println(renderResult(result, o.RunID(), pack))
	} else {
		// In --command-only mode, extract and print only the verified command
		cmd := extractVerifiedCommand(result)
		if cmd != "" {
			fmt.Println(cmd)
		}
	}

	if exitCode != agent.ExitCodeSuccess {
		return agent.NewExitError(exitCode, nil)
	}
	return nil
}

// extractVerifiedCommand extracts the verified command from the result for --command-only mode.
func extractVerifiedCommand(result string) string {
	// The result should contain the verified command from complete_task
	// Look for patterns in the result
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "TASK_COMPLETE:") {
			// The summary might contain the command, but we want just the command
			// In practice, the pack's verify_cmd or the agent should output just the command
			// For now, return empty to indicate we need the agent to output the command
			continue
		}
	}
	return ""
}

// nextRunID returns a deterministic run identifier for this invocation.
func nextRunID() string {
	return "run-" + time.Now().UTC().Format("20060102T150405")
}

// renderResult renders the orchestrator outcome and a Verification Receipt.
func renderResult(result string, runID string, pack packs.Pack) string {
	var b strings.Builder

	status := ui.ReceiptFailed
	changedPaths := []string{}
	var results []ui.VerificationResult

	if strings.Contains(result, "TASK_COMPLETE") {
		status = ui.ReceiptCompleted
		for _, line := range strings.Split(result, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "verified_targets:") {
				targets := strings.TrimSpace(strings.TrimPrefix(line, "verified_targets:"))
				if targets != "" {
					changedPaths = strings.Split(targets, ",")
					for i := range changedPaths {
						changedPaths[i] = strings.TrimSpace(changedPaths[i])
					}
				}
			}
		}
		results = append(results, ui.VerificationResult{
			Command:  pack.VerifyCmd,
			ExitCode: 0,
			Output:   "verification gate passed",
		})
	} else if strings.Contains(result, "HARNESS_VERIFICATION_FAILED") {
		status = ui.ReceiptFailed
		exitCode := 1
		outputMsg := "verification gate failed"
		for _, line := range strings.Split(result, "\n") {
			if idx := strings.Index(line, "verify_cmd exited "); idx != -1 {
				var code int
				if n, _ := fmt.Sscanf(line[idx:], "verify_cmd exited %d", &code); n == 1 {
					exitCode = code
				}
			}
		}
		results = append(results, ui.VerificationResult{
			Command:  pack.VerifyCmd,
			ExitCode: exitCode,
			Output:   outputMsg,
		})
	}

	b.WriteString(titleStyle.Render("## Result"))
	b.WriteString("\n")
	b.WriteString(result)
	b.WriteString("\n\n")
	b.WriteString(ui.VerificationReceipt(status, runID, changedPaths, results))
	b.WriteString("\n")
	b.WriteString(mutedStyle.Render("Hint: Run 'lnta undo <run_id>' to revert a previous run."))
	return b.String()
}

// approveMutation is the single mutate_system approval callback for every
// invocation path (piped or interactive stdin). It renders a high-visibility
// huh.Confirm on /dev/tty showing the exact target, command, cwd, and risk
// level, with all display text sanitized against control-char and bidi
// spoofing. On any error (including no controlling terminal / CI) it denies.
func approveMutation(target string) agent.ApproveFunc {
	return func(command, cwd, riskLevel, reason string) bool {
		desc := fmt.Sprintf("target:  %s\ncommand: %s\ncwd:     %s\nreason:  %s",
			target,
			shell.SanitizeForDisplay(command),
			shell.SanitizeForDisplay(cwd),
			shell.SanitizeForDisplay(reason),
		)
		if riskLevel == sandbox.RiskCriticalDestructive.String() {
			challenge := sandbox.GenerateChallengeCode()
			ok, err := shell.ConfirmChallengeWithTTY(fmt.Sprintf("mutate_system (%s risk)", riskLevel), desc, challenge)
			if err != nil {
				fmt.Fprintf(os.Stderr, "approval error: %v\n", err)
				return false
			}
			return ok
		}
		ok, err := shell.ConfirmWithTTY(fmt.Sprintf("mutate_system (%s risk)", riskLevel), desc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "approval error: %v\n", err)
			return false
		}
		return ok
	}
}

// snapshotRoot mirrors sandbox.snapshotRoot (unexported) so the CLI can list runs.
func snapshotRoot() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".local", "share", "lnta", "snapshots")
	}
	return filepath.Join(home, ".local", "share", "lnta", "snapshots")
}

// latestRunID returns the most recent run snapshot directory name, or "".
func latestRunID() string {
	root := snapshotRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	var latest string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() > latest {
			latest = e.Name()
		}
	}
	return latest
}

// runChat starts an interactive multi-turn REPL.
func runChat() error {
	fmt.Println("LNTA interactive chat. Type your prompt, or 'exit'/'quit' to leave.")
	fmt.Println("Commands: /undo <run_id> | /packs | /exit")
	fmt.Println()
	for {
		fmt.Print("lnta> ")
		var input string
		if _, err := fmt.Scanln(&input); err != nil {
			fmt.Println()
			return nil
		}
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		if input == "/exit" || input == "exit" || input == "quit" {
			fmt.Println("goodbye.")
			return nil
		}
		if input == "/packs" {
			router, _ := packs.NewRouter(lnta.EmbeddedPacks, "packs/*.md", userConfigDir)
			for _, p := range router.AllPacks() {
				fmt.Printf("  %-32s %s\n", p.ID, p.Name)
			}
			continue
		}
		if strings.HasPrefix(input, "/undo ") {
			runID := strings.TrimSpace(strings.TrimPrefix(input, "/undo"))
			if err := sandbox.RollbackRun(runID); err != nil {
				fmt.Printf("undo failed: %v\n", err)
			} else {
				fmt.Printf("undone run %q\n", runID)
			}
			continue
		}
		if err := runPromptArgs(input); err != nil {
			fmt.Printf("error: %v\n", err)
		}
		fmt.Println()
	}
}

// runPromptArgs runs a single prompt within the chat session.
func runPromptArgs(prompt string) error {
	sys, err := fingerprint.Fingerprint()
	if err != nil {
		return fmt.Errorf("fingerprint: %w", err)
	}
	router, err := packs.NewRouter(lnta.EmbeddedPacks, "packs/*.md", userConfigDir)
	if err != nil {
		return fmt.Errorf("load packs: %w", err)
	}
	packs.SetDefaultRouter(router)
	selected, err := router.SelectPacks(prompt, sys)
	if err != nil {
		return fmt.Errorf("route: %w", err)
	}
	pack := selected[0]

	// Display environment-specific warnings (WSL2, container, headless SSH).
	for _, w := range packs.PackEnvironmentWarnings(pack, sys) {
		fmt.Printf("[env-warning] %s\n", w)
	}

	fmt.Println(ui.StatusLine(pack.ID, "Running", "", false))
	cfg, err := agent.LoadConfig()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	client, err := agent.NewOpenAIClient(cfg)
	if err != nil {
		return fmt.Errorf("llm client: %w", err)
	}
	o := agent.New(client, router,
		agent.WithRunID(nextRunID()),
		agent.WithCWD("."),
		agent.WithApprove(approveMutation("local")),
		agent.WithConfig(cfg),
		agent.WithDryRun(dryRunMode),
	)
	ctx, cancel := agent.WithSignalCancellation()
	defer cancel()
	result, err := o.Run(ctx, prompt, "", false)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	fmt.Println(renderResult(result, o.RunID(), pack))
	return nil
}

func runDoctor(cmd *cobra.Command) error {
	fmt.Println(titleStyle.Render("## LNTA Doctor"))
	fmt.Println()

	checks := []struct {
		name string
		fn   func() error
	}{
		{"LLM Configuration", checkLLMConfig},
		{"LLM Connectivity", checkLLMConnectivity},
		{"Kernel Sandbox", checkKernelSandbox},
		{"Validator Binaries", checkValidators},
	}

	allPassed := true
	for _, c := range checks {
		fmt.Printf("  %s %s... ", labelStyle.Render("▶"), c.name)
		err := c.fn()
		if err != nil {
			fmt.Println(mutedStyle.Render("FAIL"))
			if doctorVerbose {
				fmt.Printf("    %s\n", mutedStyle.Render(err.Error()))
			}
			allPassed = false
		} else {
			fmt.Println(labelStyle.Render("OK"))
		}
	}

	if doctorFix {
		fmt.Println()
		fmt.Println(titleStyle.Render("## AppArmor Profile for bwrap"))
		fmt.Println()
		fmt.Println(generateAppArmorProfile())
	}

	fmt.Println()
	if allPassed {
		fmt.Println(labelStyle.Render("All checks passed"))
	} else {
		fmt.Println(mutedStyle.Render("Some checks failed — run with --verbose for details"))
	}

	return nil
}

func checkLLMConfig() error {
	cfg, err := agent.LoadConfigDir(userConfigDir)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	isOllama := strings.Contains(cfg.BaseURL, "11434")
	if cfg.APIKey == "" && !isOllama {
		return errors.New("LNTA_API_KEY not set")
	}
	if cfg.BaseURL == "" {
		return errors.New("LNTA_BASE_URL not set")
	}
	if doctorVerbose {
		keyDisplay := "(none/local)"
		if cfg.APIKey != "" {
			keyDisplay = fmt.Sprintf("%s... (len=%d)", cfg.APIKey[:min(8, len(cfg.APIKey))], len(cfg.APIKey))
		}
		fmt.Printf("    API Key: %s\n", keyDisplay)
		fmt.Printf("    Base URL: %s\n", cfg.BaseURL)
		fmt.Printf("    Model: %s\n", cfg.Model)
	}
	return nil
}

func checkLLMConnectivity() error {
	cfg, err := agent.LoadConfigDir(userConfigDir)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	isOllama := strings.Contains(cfg.BaseURL, "11434")
	if (cfg.APIKey == "" && !isOllama) || cfg.BaseURL == "" {
		return errors.New("API key or base URL not configured")
	}

	// Quick HTTP request to check endpoint reachability
	client := &http.Client{Timeout: 5 * time.Second}
	targetURL := strings.TrimSuffix(cfg.BaseURL, "/") + "/models"
	if isOllama {
		targetURL = "http://127.0.0.1:11434/api/tags"
	}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", cfg.BaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}
	if doctorVerbose {
		fmt.Printf("    Endpoint: %s (status %d)\n", cfg.BaseURL, resp.StatusCode)
	}
	return nil
}

func checkKernelSandbox() error {
	// Check bwrap binary
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("bwrap not found in PATH")
	}
	if doctorVerbose {
		fmt.Printf("    bwrap: %s\n", bwrapPath)
	}

	// Check AppArmor userns restriction
	apparmorRestrict, err := readSysctl("kernel.apparmor_restrict_unprivileged_userns")
	if err == nil {
		if doctorVerbose {
			fmt.Printf("    kernel.apparmor_restrict_unprivileged_userns: %s\n", apparmorRestrict)
		}
		if strings.TrimSpace(apparmorRestrict) == "1" {
			return fmt.Errorf("AppArmor userns restriction enabled (value=1) — bwrap will be blocked")
		}
	} else if doctorVerbose {
		fmt.Printf("    kernel.apparmor_restrict_unprivileged_userns: unreadable (%v)\n", err)
	}

	// Test bwrap probe
	if err := sandboxProbeBwrap(); err != nil {
		if errors.Is(err, sandbox.ErrBwrapBlocked) {
			return fmt.Errorf("bwrap probe blocked by AppArmor: %w", err)
		}
		if errors.Is(err, sandbox.ErrBwrapNotFound) {
			return fmt.Errorf("bwrap not found: %w", err)
		}
		return fmt.Errorf("bwrap probe failed: %w", err)
	}
	if doctorVerbose {
		fmt.Printf("    bwrap probe: OK\n")
	}

	// Check Landlock availability
	if err := sandbox.LandlockProbe(); err != nil {
		if doctorVerbose {
			fmt.Printf("    Landlock: unavailable (%v)\n", err)
		}
		return fmt.Errorf("Landlock unavailable: %w", err)
	}
	if doctorVerbose {
		fmt.Printf("    Landlock: available\n")
	}

	return nil
}

func sandboxProbeBwrap() error {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return sandbox.ErrBwrapNotFound
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, bwrapPath, "--ro-bind", "/", "/", "--", "true")
	c.Stdin = nil
	c.Stdout = nil
	c.Stderr = nil
	if err := c.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 126 || exitErr.ExitCode() == 127 {
				return sandbox.ErrBwrapBlocked
			}
		}
		return err
	}
	return nil
}

func checkValidators() error {
	validators := []string{
		"desktop-file-validate",
		"systemd-analyze",
		"shellcheck",
		"ufw",
		"ss",
	}
	var missing []string
	for _, v := range validators {
		if _, err := exec.LookPath(v); err != nil {
			missing = append(missing, v)
		} else if doctorVerbose {
			fmt.Printf("    %s: found\n", v)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing validators: %s", strings.Join(missing, ", "))
	}
	return nil
}

func readSysctl(key string) (string, error) {
	data, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func generateAppArmorProfile() string {
	return `# Allow unprivileged user namespaces for bwrap
# Install to: /etc/apparmor.d/bwrap
# Then run: sudo apparmor_parser -r /etc/apparmor.d/bwrap

abi <abi/4.0>,
include <tunables/global>

profile bwrap flags=(unconfined) {
  userns,

  # Site-specific additions and overrides. See local/README for details.
  include if exists <local/bwrap>
}
`
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}