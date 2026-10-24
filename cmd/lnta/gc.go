package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sm-me-dev/lnta/internal/agent"
	"github.com/sm-me-dev/lnta/internal/audit"
)

var (
	gcKeepLast int
)

var gcCmd = &cobra.Command{
	Use:   "gc",
	Short: "Clean old run snapshots and rotate audit logs",
	Long: `Garbage collects old run snapshots and rotates large audit log files.
Snapshots are pruned according to --keep-last (default 100 or config.yaml) and
cumulative disk storage limits (default 100MB). Audit logs above 10MB are rotated.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := agent.LoadConfigDir(userConfigDir)
		keepLast := gcKeepLast
		maxMB := 100
		if cfg != nil {
			if keepLast <= 0 && cfg.GCMaxRuns > 0 {
				keepLast = cfg.GCMaxRuns
			}
			if cfg.GCMaxMB > 0 {
				maxMB = cfg.GCMaxMB
			}
		}
		if keepLast <= 0 {
			keepLast = 100
		}

		res, err := audit.RunGC(audit.GCOptions{
			KeepLast: keepLast,
			MaxBytes: int64(maxMB) * 1024 * 1024,
		})
		if err != nil {
			return agent.NewExitError(agent.ExitCodeGeneralError, fmt.Errorf("gc failed: %w", err))
		}

		fmt.Println(audit.FormatGCResult(res))
		return nil
	},
}

func init() {
	gcCmd.Flags().IntVar(&gcKeepLast, "keep-last", 0, "Number of most recent snapshots to keep (defaults to config or 100)")
	rootCmd.AddCommand(gcCmd)
}
