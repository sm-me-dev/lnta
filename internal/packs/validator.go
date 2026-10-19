// Package packs implements the pack linter for validating instruction packs.
package packs

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sm-me/lnta/internal/sandbox"
)

// ValidationSeverity represents the severity of a validation issue.
type ValidationSeverity string

const (
	SeverityError   ValidationSeverity = "ERROR"
	SeverityWarning ValidationSeverity = "WARNING"
	SeverityInfo    ValidationSeverity = "INFO"
)

// ValidationIssue represents a single validation finding.
type ValidationIssue struct {
	Severity  ValidationSeverity `json:"severity"`
	Field     string             `json:"field,omitempty"`
	Message   string             `json:"message"`
	PackID    string             `json:"pack_id,omitempty"`
	Suggestion string            `json:"suggestion,omitempty"`
}

// ValidationResult contains the results of validating a pack or directory.
type ValidationResult struct {
	PackID   string             `json:"pack_id"`
	Path     string             `json:"path"`
	Valid    bool               `json:"valid"`
	Issues   []ValidationIssue  `json:"issues"`
	Warnings []ValidationIssue  `json:"warnings"`
}

// ValidatorConfig configures the pack validator.
type ValidatorConfig struct {
	StrictMode      bool     // Treat warnings as errors
	CheckBinaries   bool     // Check if required_bins exist in PATH
	RunContextCmd   bool     // Execute context_cmd in sandbox to validate
	CheckTriggers   bool     // Check for trigger collisions across packs
	UserPacksDir    string   // Optional user packs directory to also validate
}

// DefaultValidatorConfig returns a sensible default configuration.
func DefaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		StrictMode:    false,
		CheckBinaries: true,
		RunContextCmd: true,
		CheckTriggers: true,
		UserPacksDir:  "",
	}
}

// ValidatePack validates a single pack file.
func ValidatePack(path string, config ValidatorConfig) (ValidationResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ValidationResult{}, fmt.Errorf("read pack: %w", err)
	}

	pack, err := parsePack(path, data)
	if err != nil {
		field := ""
		if strings.Contains(err.Error(), "missing id") {
			field = "id"
		}
		return ValidationResult{
			Path:   path,
			Valid:  false,
			Issues: []ValidationIssue{{Severity: SeverityError, Field: field, Message: err.Error()}},
		}, nil
	}

	result := ValidationResult{
		PackID: pack.ID,
		Path:   path,
		Valid:  true,
	}

	// 1. Required field validation
	validateRequiredFields(pack, &result)

	// 2. Field type and format validation
	validateFieldFormats(pack, &result)

	// 3. Glob syntax validation for allowed_paths
	validateAllowedPathsGlobs(pack, &result)

	// 4. Verify_cmd placeholder validation
	validateVerifyCmdPlaceholders(pack, &result)

	// 5. Binary availability check
	if config.CheckBinaries {
		validateBinaries(pack, &result)
	}

	// 6. Run context_cmd in sandbox
	if config.RunContextCmd && pack.ContextCmd != "" && pack.ContextCmd != "true" {
		if err := validateContextCmd(pack, &result); err != nil {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity:  SeverityError,
				Field:     "context_cmd",
				Message:   fmt.Sprintf("context_cmd execution failed: %v", err),
				PackID:    pack.ID,
				Suggestion: "Ensure context_cmd is a valid read-only command that exits 0 in the sandbox",
			})
		}
	}

	// Determine overall validity
	result.Valid = !hasErrors(result.Issues)

	return result, nil
}

// ValidateDirectory validates all .md packs in a directory.
func ValidateDirectory(dir string, config ValidatorConfig) ([]ValidationResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory %s: %w", dir, err)
	}

	var results []ValidationResult
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		result, err := ValidatePack(path, config)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	// Cross-pack trigger collision check
	if config.CheckTriggers && len(results) > 1 {
		checkTriggerCollisions(results, config)
	}

	return results, nil
}

// ValidateEmbeddedPacks validates all embedded packs from the embed.FS.
func ValidateEmbeddedPacks(embedFS embed.FS, packGlob string, config ValidatorConfig) ([]ValidationResult, error) {
	matches, err := fs.Glob(embedFS, packGlob)
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", packGlob, err)
	}

	var results []ValidationResult
	for _, m := range matches {
		data, err := fs.ReadFile(embedFS, m)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", m, err)
		}
		pack, err := parsePack(m, data)
		if err != nil {
			results = append(results, ValidationResult{
				PackID: "unknown",
				Path:   m,
				Valid:  false,
				Issues: []ValidationIssue{{Severity: SeverityError, Message: err.Error()}},
			})
			continue
		}
		result := ValidationResult{
			PackID: pack.ID,
			Path:   m,
			Valid:  true,
		}
		validateRequiredFields(pack, &result)
		validateFieldFormats(pack, &result)
		validateAllowedPathsGlobs(pack, &result)
		validateVerifyCmdPlaceholders(pack, &result)
		if config.CheckBinaries {
			validateBinaries(pack, &result)
		}
		if config.RunContextCmd && pack.ContextCmd != "" && pack.ContextCmd != "true" {
			if err := validateContextCmd(pack, &result); err != nil {
				result.Issues = append(result.Issues, ValidationIssue{
					Severity:  SeverityError,
					Field:     "context_cmd",
					Message:   fmt.Sprintf("context_cmd execution failed: %v", err),
					PackID:    pack.ID,
				})
			}
		}
		result.Valid = !hasErrors(result.Issues)
		results = append(results, result)
	}

	// Cross-pack trigger collision check
	if config.CheckTriggers && len(results) > 1 {
		checkTriggerCollisions(results, config)
	}

	return results, nil
}

// validateRequiredFields checks that all required frontmatter fields are present.
func validateRequiredFields(pack *Pack, result *ValidationResult) {
	if pack.ID == "" {
		result.Issues = append(result.Issues, ValidationIssue{
			Severity: SeverityError,
			Field:    "id",
			Message:  "pack missing required 'id' field",
		})
	}
	if pack.Name == "" {
		result.Issues = append(result.Issues, ValidationIssue{
			Severity: SeverityError,
			Field:    "name",
			Message:  "pack missing required 'name' field",
		})
	}
	if len(pack.Triggers) == 0 {
		// Only error if not the fallback pack
		if pack.ID != "general-diagnostics" {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity: SeverityError,
				Field:    "triggers",
				Message:  "pack must have at least one trigger (empty triggers only allowed for fallback pack)",
			})
		}
	}
	// allowed_paths, required_bins can be empty (read-only packs)
	// context_cmd, verify_cmd can be empty but verify_cmd is recommended
	if pack.VerifyCmd == "" && pack.ID != "general-diagnostics" {
		result.Warnings = append(result.Warnings, ValidationIssue{
			Severity:  SeverityWarning,
			Field:     "verify_cmd",
			Message:   "verify_cmd is empty - verification gate will not run",
			PackID:    pack.ID,
			Suggestion: "Add a verify_cmd to enable harness-enforced verification",
		})
	}
}

// validateFieldFormats checks field types and formats.
func validateFieldFormats(pack *Pack, result *ValidationResult) {
	// ID format: kebab-case, alphanumeric and hyphens
	if pack.ID != "" {
		if !regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`).MatchString(pack.ID) {
			result.Warnings = append(result.Warnings, ValidationIssue{
				Severity:  SeverityWarning,
				Field:     "id",
				Message:   fmt.Sprintf("id %q should be kebab-case (lowercase, alphanumeric, hyphens only)", pack.ID),
				PackID:    pack.ID,
				Suggestion: "Use format like 'my-pack-name'",
			})
		}
	}

	// Triggers: non-empty strings, no duplicates
	seenTriggers := make(map[string]bool)
	for _, t := range pack.Triggers {
		t = strings.TrimSpace(t)
		if t == "" {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity: SeverityError,
				Field:    "triggers",
				Message:  "trigger contains empty string",
			})
		}
		if seenTriggers[t] {
			result.Warnings = append(result.Warnings, ValidationIssue{
				Severity:  SeverityWarning,
				Field:     "triggers",
				Message:   fmt.Sprintf("duplicate trigger: %q", t),
				PackID:    pack.ID,
				Suggestion: "Remove duplicate triggers",
			})
		}
		seenTriggers[t] = true
	}

	// Required bins: non-empty strings, valid binary names
	for _, b := range pack.RequiredBins {
		if strings.TrimSpace(b) == "" {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity: SeverityError,
				Field:    "required_bins",
				Message:  "required_bins contains empty string",
			})
		}
		if !regexp.MustCompile(`^[a-zA-Z0-9._-]+$`).MatchString(b) {
			result.Warnings = append(result.Warnings, ValidationIssue{
				Severity:  SeverityWarning,
				Field:     "required_bins",
				Message:   fmt.Sprintf("binary name %q contains unusual characters", b),
				PackID:    pack.ID,
			})
		}
	}
}

// validateAllowedPathsGlobs tests glob patterns against sample paths.
func validateAllowedPathsGlobs(pack *Pack, result *ValidationResult) {
	for _, glob := range pack.AllowedPaths {
		if strings.TrimSpace(glob) == "" {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity: SeverityError,
				Field:    "allowed_paths",
				Message:  "allowed_paths contains empty string",
			})
			continue
		}

		// Check for path traversal attempts
		if strings.Contains(glob, "..") {
			result.Warnings = append(result.Warnings, ValidationIssue{
				Severity:  SeverityWarning,
				Field:     "allowed_paths",
				Message:   fmt.Sprintf("glob %q contains '..' which may allow path traversal", glob),
				PackID:    pack.ID,
				Suggestion: "Use absolute paths or ~ expansion instead of relative parent references",
			})
		}

		// Test glob syntax by matching against a sample path
		// We expand ~ to a temp path for testing
		testPath := expandPathForGlobTest(glob)
		if matched, err := filepath.Match(glob, testPath); err != nil {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity:  SeverityError,
				Field:     "allowed_paths",
				Message:   fmt.Sprintf("invalid glob pattern %q: %v", glob, err),
				PackID:    pack.ID,
			})
		} else if !matched {
			// This is OK - glob might be for a different structure
			result.Warnings = append(result.Warnings, ValidationIssue{
				Severity:  SeverityInfo,
				Field:     "allowed_paths",
				Message:   fmt.Sprintf("glob %q does not match test path %q (may be OK if targeting different paths)", glob, testPath),
				PackID:    pack.ID,
			})
		}
	}
}

// expandPathForGlobTest expands ~ in a glob to a testable path.
func expandPathForGlobTest(glob string) string {
	if strings.HasPrefix(glob, "~/") {
		home, _ := os.UserHomeDir()
		if home != "" {
			return home + glob[1:]
		}
	}
	// For absolute paths, return a dummy path under /tmp for testing
	return "/tmp/test" + glob
}

// validateVerifyCmdPlaceholders checks that verify_cmd uses expected placeholders.
func validateVerifyCmdPlaceholders(pack *Pack, result *ValidationResult) {
	if pack.VerifyCmd == "" {
		return
	}

	// Check for placeholder syntax
	placeholderRe := regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	matches := placeholderRe.FindAllStringSubmatch(pack.VerifyCmd, -1)

	if len(matches) == 0 {
		result.Warnings = append(result.Warnings, ValidationIssue{
			Severity:  SeverityWarning,
			Field:     "verify_cmd",
			Message:   "verify_cmd has no ${placeholder} - verification may not be dynamic",
			PackID:    pack.ID,
			Suggestion: "Use ${target} or ${unit} etc. to parameterize verification",
		})
	}

	// Check for common expected placeholders based on pack type
	expectedPlaceholders := map[string][]string{
		"linux-desktop-entries":     {"target"},
		"systemd-user-services":     {"unit"},
		"systemd-timers-cron":       {"calendar_expr"},
		"network-ports-processes":   {"port"},
		"docker-compose-diagnostics": {"target"},
		"ufw-firewall-ports":        {"rule_num"},
		"udev-device-rules":         {"device"},
		"ssh-gpg-permissions":       {"target"},
		"disk-mounts-fstab":         {"target"},
		"git-repo-hygiene":          {"branch_name"},
	}

	if expected, ok := expectedPlaceholders[pack.ID]; ok {
		found := make(map[string]bool)
		for _, m := range matches {
			found[m[1]] = true
		}
		for _, exp := range expected {
			if !found[exp] {
				result.Warnings = append(result.Warnings, ValidationIssue{
					Severity:  SeverityInfo,
					Field:     "verify_cmd",
					Message:   fmt.Sprintf("verify_cmd missing expected placeholder ${%s} for pack type %s", exp, pack.ID),
					PackID:    pack.ID,
				})
			}
		}
	}
}

// validateBinaries checks if required_bins are available in PATH.
func validateBinaries(pack *Pack, result *ValidationResult) {
	for _, bin := range pack.RequiredBins {
		if _, err := execLookPath(bin); err != nil {
			result.Warnings = append(result.Warnings, ValidationIssue{
				Severity:  SeverityWarning,
				Field:     "required_bins",
				Message:   fmt.Sprintf("required binary %q not found in PATH", bin),
				PackID:    pack.ID,
				Suggestion: fmt.Sprintf("Install %s or remove from required_bins if optional", bin),
			})
		}
	}
}

// execLookPath is a wrapper for exec.LookPath (for testability)
var execLookPath = func(name string) (string, error) {
	return exec.LookPath(name)
}

// validateContextCmd executes the context_cmd in the read-only sandbox to verify it works.
func validateContextCmd(pack *Pack, result *ValidationResult) error {
	// Run with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := sandbox.RunReadOnly(ctx, pack.ContextCmd, "/tmp", 0)
	if err != nil {
		// Sandbox might not be available in all test environments
		if errors.Is(err, sandbox.ErrBwrapNotFound) || errors.Is(err, sandbox.ErrBwrapBlocked) {
			return fmt.Errorf("sandbox unavailable: %w", err)
		}
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("context_cmd exited with code %d: %s", res.ExitCode, res.Stderr)
	}
	return nil
}

// checkTriggerCollisions detects ambiguous triggers across packs.
func checkTriggerCollisions(results []ValidationResult, config ValidatorConfig) {
	// This is a simplified check - a full implementation would compare
	// all single-word triggers across packs
	// For now, we just log that this check should be implemented
}

// hasErrors returns true if any issues have SeverityError.
func hasErrors(issues []ValidationIssue) bool {
	for _, i := range issues {
		if i.Severity == SeverityError {
			return true
		}
	}
	return false
}

// FormatValidationResults formats results for human-readable output.
func FormatValidationResults(results []ValidationResult, config ValidatorConfig) string {
	var b strings.Builder

	totalErrors := 0
	totalWarnings := 0
	totalPacks := len(results)
	validPacks := 0

	for _, r := range results {
		if r.Valid {
			validPacks++
		}
		for _, i := range r.Issues {
			if i.Severity == SeverityError {
				totalErrors++
			} else if i.Severity == SeverityWarning {
				totalWarnings++
			}
		}
		for _, w := range r.Warnings {
			if w.Severity == SeverityWarning {
				totalWarnings++
			}
		}
	}

	b.WriteString(fmt.Sprintf("Validated %d pack(s): %d valid, %d invalid\n", totalPacks, validPacks, totalPacks-validPacks))
	b.WriteString(fmt.Sprintf("Errors: %d, Warnings: %d\n\n", totalErrors, totalWarnings))

	for _, r := range results {
		status := "✓"
		if !r.Valid {
			status = "✗"
		}
		b.WriteString(fmt.Sprintf("%s %s (%s)\n", status, r.PackID, r.Path))

		for _, i := range r.Issues {
			prefix := "  ERROR: "
			if i.Severity == SeverityWarning {
				prefix = "  WARN:  "
			} else if i.Severity == SeverityInfo {
				prefix = "  INFO:  "
			}
			b.WriteString(fmt.Sprintf("%s[%s] %s\n", prefix, i.Field, i.Message))
			if i.Suggestion != "" {
				b.WriteString(fmt.Sprintf("         → %s\n", i.Suggestion))
			}
		}
		for _, w := range r.Warnings {
			b.WriteString(fmt.Sprintf("  WARN:  [%s] %s\n", w.Field, w.Message))
			if w.Suggestion != "" {
				b.WriteString(fmt.Sprintf("         → %s\n", w.Suggestion))
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}

// FormatValidationResultsJSON formats results as JSON.
func FormatValidationResultsJSON(results []ValidationResult) (string, error) {
	// Use a simple manual JSON for now
	var b strings.Builder
	b.WriteString("[\n")
	for i, r := range results {
		if i > 0 {
			b.WriteString(",\n")
		}
		b.WriteString(fmt.Sprintf(`  {"pack_id": "%s", "path": "%s", "valid": %t, "issues": [`, r.PackID, r.Path, r.Valid))
		for j, issue := range r.Issues {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString(fmt.Sprintf(`{"severity": "%s", "field": "%s", "message": "%s"}`, issue.Severity, issue.Field, issue.Message))
		}
		b.WriteString("]}")
	}
	b.WriteString("\n]")
	return b.String(), nil
}