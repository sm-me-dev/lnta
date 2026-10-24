package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sm-me-dev/lnta/internal/audit"
	"github.com/zalando/go-keyring"
)

func TestEnforceStrictFilePermissions(t *testing.T) {
	tempDir := t.TempDir()
	insecureFile := filepath.Join(tempDir, "config.yaml")

	// Create file with 0644 permissions (group/world-readable)
	if err := os.WriteFile(insecureFile, []byte("model: gpt-4o-mini\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Capture stderr to verify warning output
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	err := EnforceStrictFilePermissions(insecureFile)

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("EnforceStrictFilePermissions returned error: %v", err)
	}

	// Verify security warning printed
	warningOutput := buf.String()
	if warningOutput == "" {
		t.Error("expected security warning to be printed to stderr, got none")
	}

	// Verify file mode changed to 0600
	fi, err := os.Stat(insecureFile)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected permissions to be 0600, got %04o", perm)
	}

	// Running again on 0600 file should NOT print a warning
	r2, w2, _ := os.Pipe()
	os.Stderr = w2

	err = EnforceStrictFilePermissions(insecureFile)

	w2.Close()
	os.Stderr = oldStderr

	var buf2 bytes.Buffer
	_, _ = io.Copy(&buf2, r2)

	if err != nil {
		t.Fatalf("EnforceStrictFilePermissions on 0600 returned error: %v", err)
	}
	if buf2.String() != "" {
		t.Errorf("expected no warning for already secure file, got: %s", buf2.String())
	}
}

func TestOSKeyringSaveAndLoad(t *testing.T) {
	// Initialize mock keyring
	keyring.MockInit()

	testKey := "sk-test-keyring-1234567890abcdef"
	if err := keyring.Set(KeyringServiceName, KeyringUserKey, testKey); err != nil {
		t.Fatalf("keyring.Set failed: %v", err)
	}

	got, err := keyring.Get(KeyringServiceName, KeyringUserKey)
	if err != nil {
		t.Fatalf("keyring.Get failed: %v", err)
	}
	if got != testKey {
		t.Errorf("expected %q, got %q", testKey, got)
	}

	// Test LoadSecret picks it up
	loaded, err := LoadSecret()
	if err != nil {
		t.Fatalf("LoadSecret failed: %v", err)
	}
	if loaded != testKey {
		t.Errorf("LoadSecret expected %q, got %q", testKey, loaded)
	}
}

func TestCredentialsFallbackWhenKeyringFails(t *testing.T) {
	// Mock keyring to fail so fallback to credentials file occurs
	keyring.MockInitWithError(errors.New("dbus secret service unavailable in headless environment"))

	tempDir := t.TempDir()
	testKey := "sk-test-credentials-fallback-key"

	// Save secret to custom directory
	if err := SaveSecretToDir(tempDir, testKey); err != nil {
		t.Fatalf("SaveSecretToDir failed: %v", err)
	}

	// Verify credentials file was created with 0600 permissions
	credPath := filepath.Join(tempDir, credentialsFileName)
	fi, err := os.Stat(credPath)
	if err != nil {
		t.Fatalf("stat credentials file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected credentials file permissions to be 0600, got %04o", perm)
	}

	// Test loading secret from directory
	loaded, err := LoadSecretFromDir(tempDir)
	if err != nil {
		t.Fatalf("LoadSecretFromDir failed: %v", err)
	}
	if loaded != testKey {
		t.Errorf("expected loaded key %q, got %q", testKey, loaded)
	}

	// Test loading config with LoadConfigDir
	cfg, err := LoadConfigDir(tempDir)
	if err != nil {
		t.Fatalf("LoadConfigDir failed: %v", err)
	}
	if cfg.APIKey != testKey {
		t.Errorf("expected cfg.APIKey %q, got %q", testKey, cfg.APIKey)
	}
}

func TestCredentialsFilePermissionEnforcementOnRead(t *testing.T) {
	tempDir := t.TempDir()
	credPath := filepath.Join(tempDir, credentialsFileName)

	// Create credentials file with 0644
	if err := os.WriteFile(credPath, []byte("api_key: sk-perm-test-12345\n"), 0o644); err != nil {
		t.Fatalf("write credentials file: %v", err)
	}

	// Reading credentials must fix permissions to 0600
	key, err := LoadCredentialsFile(credPath)
	if err != nil {
		t.Fatalf("LoadCredentialsFile failed: %v", err)
	}
	if key != "sk-perm-test-12345" {
		t.Errorf("expected key 'sk-perm-test-12345', got %q", key)
	}

	fi, err := os.Stat(credPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected credentials permissions to be chmodded to 0600, got %04o", perm)
	}
}

func TestDeterministicExitCodes(t *testing.T) {
	// Test 0 = Completed & Verified
	summaryVerified := &audit.RunSummary{
		Status: audit.RunStatusVerified,
	}
	if code := DetermineExitCode(nil, "TASK_COMPLETE: all good", summaryVerified); code != ExitCodeSuccess {
		t.Errorf("expected ExitCodeSuccess (0), got %d", code)
	}

	// Test 2 = Verification Failed
	summaryFailedVerify := &audit.RunSummary{
		Status: audit.RunStatusFailed,
		VerificationReceipt: []audit.VerificationRecord{
			{Command: "verify_cmd", ExitCode: 1, Passed: false},
		},
	}
	if code := DetermineExitCode(nil, "HARNESS_VERIFICATION_FAILED: check failed", summaryFailedVerify); code != ExitCodeVerificationFailed {
		t.Errorf("expected ExitCodeVerificationFailed (2), got %d", code)
	}

	// Test 3 = User Cancelled / Approval Denied
	if code := DetermineExitCode(context.Canceled, "", nil); code != ExitCodeUserCancelled {
		t.Errorf("expected ExitCodeUserCancelled (3) for context.Canceled, got %d", code)
	}
	if code := DetermineExitCode(errors.New("user did not approve mutate_system"), "", nil); code != ExitCodeUserCancelled {
		t.Errorf("expected ExitCodeUserCancelled (3) for approval denied, got %d", code)
	}
	if code := DetermineExitCode(nil, "MUTATE_BLOCKED: user did not approve mutate_system (risk: high)", nil); code != ExitCodeUserCancelled {
		t.Errorf("expected ExitCodeUserCancelled (3) for MUTATE_BLOCKED result, got %d", code)
	}

	// Test 4 = Sandbox / Environment Error
	if code := DetermineExitCode(errors.New("bwrap: failed to create namespace: permission denied"), "", nil); code != ExitCodeSandboxError {
		t.Errorf("expected ExitCodeSandboxError (4) for bwrap error, got %d", code)
	}
	if code := DetermineExitCode(errors.New("landlock restrict failed: system not supported"), "", nil); code != ExitCodeSandboxError {
		t.Errorf("expected ExitCodeSandboxError (4) for landlock error, got %d", code)
	}

	// Test 1 = General / Execution Error
	if code := DetermineExitCode(errors.New("unexpected network timeout connecting to api"), "", nil); code != ExitCodeGeneralError {
		t.Errorf("expected ExitCodeGeneralError (1) for general error, got %d", code)
	}

	// Test ExitError wrapper
	ee := NewExitError(ExitCodeVerificationFailed, errors.New("custom verify error"))
	if ee.ExitCode() != 2 {
		t.Errorf("expected ExitCode 2, got %d", ee.ExitCode())
	}
	if code := DetermineExitCode(ee, "", nil); code != 2 {
		t.Errorf("expected DetermineExitCode on ExitError to yield 2, got %d", code)
	}
}

func TestConfigFilePermissionEnforcementOnLoad(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, configFileName)

	content := "base_url: https://api.openai.com/v1\nmodel: gpt-4o-mini\napi_key: sk-config-key\ngc_max_runs: 50\ngc_max_mb: 200\n"
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadConfigDir(tempDir)
	if err != nil {
		t.Fatalf("LoadConfigDir failed: %v", err)
	}

	if cfg.GCMaxRuns != 50 {
		t.Errorf("expected GCMaxRuns 50, got %d", cfg.GCMaxRuns)
	}
	if cfg.GCMaxMB != 200 {
		t.Errorf("expected GCMaxMB 200, got %d", cfg.GCMaxMB)
	}

	// Verify file mode changed from 0644 to 0600
	fi, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected config.yaml permissions to be 0600, got %04o", perm)
	}
}

