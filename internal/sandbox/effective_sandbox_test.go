package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEffectiveSandboxCredentialAndFilesystemRestrictions(t *testing.T) {
	root := sandboxTempDir(t)
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	const projectSecret = "LNTA_PROJECT_SENTINEL_CREDENTIAL_93821"
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(projectSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "public.txt"), []byte("public-project-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	home := sandboxTempDir(t)
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const homeSecret = "LNTA_HOME_SENTINEL_CREDENTIAL_28417"
	if err := os.WriteFile(filepath.Join(sshDir, "sentinel"), []byte(homeSecret), 0o600); err != nil {
		t.Fatal(err)
	}

	requireLandlock := os.Getenv("LNTA_REQUIRE_LANDLOCK") == "1"
	bwrapErr := probeBwrap()
	backend := "bubblewrap"
	if requireLandlock {
		if bwrapErr == nil {
			t.Fatal("expected restricted host policy to block Bubblewrap")
		}
		if err := ProbeLandlockExecution(3 * time.Second); err != nil {
			t.Fatalf("required Landlock fallback is not operational: %v", err)
		}
		backend = "landlock"
	} else if bwrapErr != nil {
		if err := ProbeLandlockExecution(3 * time.Second); err != nil {
			t.Skipf("no operational sandbox backend: Bubblewrap: %v; Landlock: %v", bwrapErr, err)
		}
		backend = "landlock"
	}
	t.Logf("effective sandbox backend: %s", backend)

	hostWrite := filepath.Join(root, "host-write")
	command := "printf 'PUBLIC='; cat public.txt; printf '\\nPROJECT_SECRET='; cat ../.env; " +
		"printf '\\nHOME_SECRET='; cat \"$HOME/.ssh/sentinel\"; printf '\\n'; printf blocked > " + shellQuote(hostWrite)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := RunReadOnlyProjectEnv(ctx, command, root, nested, 10*time.Second, nil)
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("sandbox execution failed before command completion: %v", err)
		}
	}
	combined := res.Stdout + res.Stderr
	if !strings.Contains(combined, "public-project-data") {
		t.Fatalf("sandbox could not read permitted project data: %q", res.Stdout)
	}
	if strings.Contains(combined, projectSecret) || strings.Contains(combined, homeSecret) {
		t.Fatalf("sandbox exposed a sentinel credential")
	}
	if _, statErr := os.Stat(hostWrite); !os.IsNotExist(statErr) {
		t.Fatalf("sandbox wrote to the host project: %v", statErr)
	}
}

func sandboxTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".lnta-sandbox-test-")
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(abs) })
	if err := os.Mkdir(filepath.Join(abs, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	return abs
}
