package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	lnta "github.com/sm-me/lnta"
	"github.com/sm-me/lnta/internal/fingerprint"
	"github.com/sm-me/lnta/internal/packs"
	"github.com/sm-me/lnta/internal/sandbox"
)

var (
	userConfigDir string
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	labelStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	mutedStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "lnta [prompt]",
	Short: "LNTA — Linux Natural-Language Terminal Assistant",
	Long: `LNTA grounds LLM actions in local system truth.

Use "lnta <prompt>" to route a request to the matching instruction pack(s),
gather ground-truth context, and show what would be done.

Use "lnta chat" for an interactive session.`,
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

	rootCmd.AddCommand(chatCmd)
	rootCmd.AddCommand(undoCmd)
	rootCmd.AddCommand(packsCmd)
}

// runPrompt routes a free-form prompt to instruction packs and prints results.
func runPrompt(cmd *cobra.Command, args []string) error {
	prompt := strings.Join(args, " ")

	sys, err := fingerprint.Fingerprint()
	if err != nil {
		return fmt.Errorf("fingerprint: %w", err)
	}

	router, err := packs.NewRouter(lnta.EmbeddedPacks, "packs/*.md", userConfigDir)
	if err != nil {
		return fmt.Errorf("load packs: %w", err)
	}
	packs.SetDefaultRouter(router)

	selected, err := packs.SelectPacks(prompt, sys)
	if err != nil {
		return fmt.Errorf("route: %w", err)
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("## System Context"))
	b.WriteString("\n")
	b.WriteString(sys.String())
	b.WriteString("\n\n")
	b.WriteString(labelStyle.Render(fmt.Sprintf("## Matched Pack (%d)", len(selected))))
	b.WriteString("\n")
	for _, p := range selected {
		b.WriteString(fmt.Sprintf("- %s (%s)\n  source: %s\n", p.Name, p.ID, p.Source()))
		if len(p.RequiredBins) > 0 {
			b.WriteString(fmt.Sprintf("  required_bins: %v\n", p.RequiredBins))
			missing := p.MissingBins(sys)
			if len(missing) > 0 {
				b.WriteString(fmt.Sprintf("  missing_bins: %v\n", missing))
			}
		}
		if p.ContextCmd != "" {
			b.WriteString(fmt.Sprintf("  context_cmd: %s\n", p.ContextCmd))
		}
		if p.VerifyCmd != "" {
			b.WriteString(fmt.Sprintf("  verify_cmd: %s\n", p.VerifyCmd))
		}
	}
	b.WriteString("\n")
	b.WriteString(bodyOf(selected...))
	b.WriteString(mutedStyle.Render("\n---\nLNTA Phase 1 scaffold: no system mutation was performed."))

	fmt.Print(b.String())
	return nil
}

// bodyOf joins the markdown bodies of the given packs.
func bodyOf(ps ...packs.Pack) string {
	var b strings.Builder
	for i, p := range ps {
		if i > 0 {
			b.WriteString("\n---\n\n")
		}
		b.WriteString(p.Body)
	}
	return b.String()
}

var chatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Start an interactive chat session",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("interactive chat not yet implemented in this phase")
		fmt.Println("Use: lnta <your prompt>")
		return nil
	},
}

var undoCmd = &cobra.Command{
	Use:   "undo <run_id>",
	Short: "Undo a previous run by run id",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		runID := args[0]
		if err := sandbox.RollbackRun(runID); err != nil {
			return fmt.Errorf("undo %q: %w", runID, err)
		}
		fmt.Printf("undone run %q\n", runID)
		return nil
	},
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

func init() {
	packsCmd.AddCommand(packsListCmd)
}
