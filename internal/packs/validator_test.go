// Package packs implements the pack linter for validating instruction packs.
package packs

import (
	"embed"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed testdata/*.md
var validatorTestEmbedFS embed.FS

func TestValidateEmbeddedPacks(t *testing.T) {
	config := DefaultValidatorConfig()
	config.CheckBinaries = false // Don't check binaries in test environment
	config.RunContextCmd = false // Don't run context_cmd in test environment

	results, err := ValidateEmbeddedPacks(validatorTestEmbedFS, "testdata/*.md", config)
	if err != nil {
		t.Fatalf("ValidateEmbeddedPacks: %v", err)
	}

	// All test packs should pass validation
	if len(results) != 4 {
		t.Fatalf("expected 4 test packs, got %d", len(results))
	}

	for _, r := range results {
		if !r.Valid {
			t.Errorf("pack %s should be valid but got errors: %v", r.PackID, r.Issues)
		}
	}
}

func TestValidatePack_InvalidFrontmatter(t *testing.T) {
	// Test with missing id
	invalidPack := `---
name: Test Pack
triggers:
  - test
---
Body`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid.md")
	if err := os.WriteFile(tmpFile, []byte(invalidPack), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	config := DefaultValidatorConfig()
	result, err := ValidatePack(tmpFile, config)
	if err != nil {
		t.Fatalf("ValidatePack: %v", err)
	}

	if result.Valid {
		t.Error("expected pack to be invalid (missing id)")
	}

	found := false
	for _, i := range result.Issues {
		if i.Field == "id" && i.Severity == SeverityError {
			found = true
		}
	}
	if !found {
		t.Error("expected ERROR on missing id field")
	}
}

func TestValidatePack_DuplicateTriggers(t *testing.T) {
	pack := `---
id: test-dup
name: Test Duplicate
triggers:
  - foo
  - foo
  - bar
allowed_paths: []
required_bins: []
context_cmd: true
verify_cmd: true
---
Body`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "dup.md")
	if err := os.WriteFile(tmpFile, []byte(pack), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	config := DefaultValidatorConfig()
	result, err := ValidatePack(tmpFile, config)
	if err != nil {
		t.Fatalf("ValidatePack: %v", err)
	}

	// Should be valid but with warning
	if !result.Valid {
		t.Error("expected pack to be valid despite duplicate triggers")
	}

	found := false
	for _, w := range result.Warnings {
		if w.Field == "triggers" && w.Severity == SeverityWarning && strings.Contains(w.Message, "duplicate") {
			found = true
		}
	}
	if !found {
		t.Error("expected WARNING on duplicate triggers")
	}
}

func TestValidatePack_InvalidGlob(t *testing.T) {
	pack := `---
id: test-glob
name: Test Glob
triggers:
  - test
allowed_paths:
  - "invalid[glob"
required_bins: []
context_cmd: true
verify_cmd: true
---
Body`
	tmpDir := t.TempDir()
tmpFile := filepath.Join(tmpDir, "glob.md")
	if err := os.WriteFile(tmpFile, []byte(pack), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	config := DefaultValidatorConfig()
	result, err := ValidatePack(tmpFile, config)
	if err != nil {
		t.Fatalf("ValidatePack: %v", err)
	}

	found := false
	for _, i := range result.Issues {
		if i.Field == "allowed_paths" && i.Severity == SeverityError {
			found = true
		}
	}
	if !found {
		t.Error("expected ERROR on invalid glob pattern")
	}
}

func TestValidatePack_MissingVerifyCmdPlaceholder(t *testing.T) {
	pack := `---
id: test-verify
name: Test Verify
triggers:
  - test
allowed_paths: []
required_bins: []
context_cmd: true
verify_cmd: echo "no placeholder here"
---
Body`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "verify.md")
	if err := os.WriteFile(tmpFile, []byte(pack), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	config := DefaultValidatorConfig()
	result, err := ValidatePack(tmpFile, config)
	if err != nil {
		t.Fatalf("ValidatePack: %v", err)
	}

	// Should be valid but with warning
	if !result.Valid {
		t.Error("expected pack to be valid")
	}

	found := false
	for _, w := range result.Warnings {
		if w.Field == "verify_cmd" && w.Severity == SeverityWarning && strings.Contains(w.Message, "placeholder") {
			found = true
		}
	}
	if !found {
		t.Error("expected WARNING on missing placeholder in verify_cmd")
	}
}

func TestValidatePack_IDFormat(t *testing.T) {
	pack := `---
id: Invalid_ID_Format
name: Test ID
triggers:
  - test
allowed_paths: []
required_bins: []
context_cmd: true
verify_cmd: true
---
Body`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "id.md")
	if err := os.WriteFile(tmpFile, []byte(pack), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	config := DefaultValidatorConfig()
	result, err := ValidatePack(tmpFile, config)
	if err != nil {
		t.Fatalf("ValidatePack: %v", err)
	}

	// Should be valid but with warning
	if !result.Valid {
		t.Error("expected pack to be valid")
	}

	found := false
	for _, w := range result.Warnings {
		if w.Field == "id" && w.Severity == SeverityWarning && strings.Contains(w.Message, "kebab-case") {
			found = true
		}
	}
	if !found {
		t.Error("expected WARNING on non-kebab-case id")
	}
}

func TestValidateDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Valid pack
	validPack := `---
id: valid-pack
name: Valid Pack
triggers:
  - valid
allowed_paths: []
required_bins: []
context_cmd: true
verify_cmd: true
---
Body`
	if err := os.WriteFile(filepath.Join(tmpDir, "valid.md"), []byte(validPack), 0o644); err != nil {
		t.Fatalf("write valid pack: %v", err)
	}

	// Invalid pack (missing id)
	invalidPack := `---
name: Invalid Pack
triggers:
  - invalid
allowed_paths: []
required_bins: []
context_cmd: true
verify_cmd: true
---
Body`
	if err := os.WriteFile(filepath.Join(tmpDir, "invalid.md"), []byte(invalidPack), 0o644); err != nil {
		t.Fatalf("write invalid pack: %v", err)
	}

	config := DefaultValidatorConfig()
	results, err := ValidateDirectory(tmpDir, config)
	if err != nil {
		t.Fatalf("ValidateDirectory: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	validFound := false
	invalidFound := false
	for _, r := range results {
		if r.PackID == "valid-pack" && r.Valid {
			validFound = true
		}
		if !r.Valid && (r.PackID == "unknown" || r.PackID == "") {
			invalidFound = true
		}
	}

	if !validFound {
		t.Error("expected valid-pack to be valid")
	}
	if !invalidFound {
		t.Error("expected invalid pack to be invalid")
	}
}

func TestFormatValidationResults(t *testing.T) {
	results := []ValidationResult{
		{
			PackID: "test-pack",
			Path:   "/path/to/test.md",
			Valid:  true,
			Issues: []ValidationIssue{},
			Warnings: []ValidationIssue{
				{Severity: SeverityWarning, Field: "verify_cmd", Message: "missing placeholder"},
			},
		},
		{
			PackID: "invalid-pack",
			Path:   "/path/to/invalid.md",
			Valid:  false,
			Issues: []ValidationIssue{
				{Severity: SeverityError, Field: "id", Message: "missing id"},
			},
			Warnings: []ValidationIssue{},
		},
	}

	config := DefaultValidatorConfig()
	output := FormatValidationResults(results, config)

	if !strings.Contains(output, "test-pack") {
		t.Error("output should contain test-pack")
	}
	if !strings.Contains(output, "invalid-pack") {
		t.Error("output should contain invalid-pack")
	}
	if !strings.Contains(output, "ERROR") {
		t.Error("output should contain ERROR")
	}
	if !strings.Contains(output, "WARN") {
		t.Error("output should contain WARN")
	}
}

func TestValidatePack_BinaryCheck(t *testing.T) {
	pack := `---
id: test-bins
name: Test Bins
triggers:
  - test
allowed_paths: []
required_bins:
  - git
  - nonexistent-binary-12345
context_cmd: true
verify_cmd: true
---
Body`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "bins.md")
	if err := os.WriteFile(tmpFile, []byte(pack), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	config := DefaultValidatorConfig()
	config.CheckBinaries = true
	config.RunContextCmd = false

	result, err := ValidatePack(tmpFile, config)
	if err != nil {
		t.Fatalf("ValidatePack: %v", err)
	}

	// Should be valid but with warning about missing binary
	if !result.Valid {
		t.Error("expected pack to be valid despite missing binary (warning only)")
	}

	found := false
	for _, w := range result.Warnings {
		if w.Field == "required_bins" && w.Severity == SeverityWarning && strings.Contains(w.Message, "nonexistent-binary-12345") {
			found = true
		}
	}
	if !found {
		t.Error("expected WARNING on missing binary")
	}
}