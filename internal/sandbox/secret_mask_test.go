package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectSecretScanCoversIgnoredDirectoriesAndBothBackends(t *testing.T) {
	project := t.TempDir()
	home := t.TempDir() // deliberately differs from the project root
	secrets := []string{
		filepath.Join(project, "vendor", ".env.production"),
		filepath.Join(project, "node_modules", "pkg", ".npmrc"),
		filepath.Join(project, ".git", "credentials.json"),
	}
	for _, p := range secrets {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("credential"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := maskProjectSecrets(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(secrets) {
		t.Fatalf("found %d secrets, want %d: %v", len(got), len(secrets), got)
	}
	args, err := bwrapArgs(home, project, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if !hasArgSequence(args, "--ro-bind", "/dev/null", secret) {
			t.Errorf("Bubblewrap args do not mask %q", secret)
		}
	}
	cfg, err := buildLandlockConfig(project, project, home, t.TempDir(), "true", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if containsPath(cfg.ROFiles, secret) || containsPath(cfg.RODirs, secret) {
			t.Errorf("Landlock grants credential path %q", secret)
		}
	}
}

func TestNestedCWDScansParentProjectSecretsForBothBackends(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "packages", "app", "src")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, ".env.production")
	if err := os.WriteFile(secret, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolvedRoot, resolvedCWD, err := resolveProjectAndCWD(root, nested)
	if err != nil {
		t.Fatal(err)
	}
	args, err := bwrapArgs(t.TempDir(), resolvedRoot, resolvedCWD, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasArgSequence(args, "--ro-bind", "/dev/null", secret) {
		t.Fatalf("bwrap did not mask parent secret %q", secret)
	}
	cfg, err := buildLandlockConfig(resolvedRoot, resolvedCWD, t.TempDir(), t.TempDir(), "true", nil)
	if err != nil {
		t.Fatal(err)
	}
	if containsPath(cfg.ROFiles, secret) || containsPath(cfg.RODirs, secret) {
		t.Fatalf("Landlock grants parent secret %q", secret)
	}
	if !containsPath(cfg.RWFiles, "/dev/null") {
		t.Fatal("expected standard null device grant")
	}
}

func TestResolveProjectRootFindsGitDirectoryAndWorktreeFile(t *testing.T) {
	for _, marker := range []string{"directory", "file"} {
		t.Run(marker, func(t *testing.T) {
			root := t.TempDir()
			child := filepath.Join(root, "nested", "src")
			if err := os.MkdirAll(child, 0o700); err != nil {
				t.Fatal(err)
			}
			git := filepath.Join(root, ".git")
			if marker == "directory" {
				if err := os.Mkdir(git, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(git, []byte("gitdir: ../.git/worktrees/x"), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := ResolveProjectRoot(child)
			if err != nil {
				t.Fatal(err)
			}
			if got != root {
				t.Fatalf("ResolveProjectRoot() = %q, want %q", got, root)
			}
		})
	}
}

func TestResolveProjectAndCWDRejectsOutsideAndSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "inside")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if _, _, err := resolveProjectAndCWD(root, outside); err == nil || !strings.Contains(err.Error(), "outside project root") {
		t.Fatalf("outside cwd accepted: %v", err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveProjectAndCWD(root, link); err == nil || !strings.Contains(err.Error(), "outside project root") {
		t.Fatalf("symlink escape accepted: %v", err)
	}
	if _, _, err := resolveProjectAndCWD(root, inside); err != nil {
		t.Fatalf("nested cwd rejected: %v", err)
	}
	odd := filepath.Join(root, "space [and] unicode-λ")
	if err := os.Mkdir(odd, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, got, err := resolveProjectAndCWD(root, odd); err != nil || got != odd {
		t.Fatalf("unusual in-root path rejected: cwd=%q err=%v", got, err)
	}
	sibling := root + "-sibling"
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveProjectAndCWD(root, sibling); err == nil {
		t.Fatal("sibling with matching string prefix accepted as inside root")
	}
}

func TestProjectSecretScanFailsAtDepthAndEntryLimits(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		root := t.TempDir()
		deep := root
		for range 33 {
			deep = filepath.Join(deep, "a")
		}
		if err := os.MkdirAll(deep, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(deep, ".env"), []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := maskProjectSecrets(root); err == nil || !strings.Contains(err.Error(), "depth limit") {
			t.Fatalf("incomplete depth scan accepted: %v", err)
		}
	})
	t.Run("credential directory", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, ".env", "nested"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := maskProjectSecrets(root); err == nil || !strings.Contains(err.Error(), "credential-named directory") {
			t.Fatalf("credential-named directory was not rejected: %v", err)
		}
	})
	t.Run("entries", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i <= 5000; i++ {
			if err := os.WriteFile(filepath.Join(root, filepath.Base(strings.Repeat("x", 1))+string(rune(0x1000+i))), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := maskProjectSecrets(root); err == nil || !strings.Contains(err.Error(), "entry limit") {
			t.Fatalf("incomplete entry scan accepted: %v", err)
		}
	})
}

func TestProjectSecretScanFailsClosedOnSymlinks(t *testing.T) {
	tests := []struct {
		name string
		link func(root, outside string) error
	}{
		{name: "secret file", link: func(root, outside string) error { return os.Symlink(outside, filepath.Join(root, ".env")) }},
		{name: "external file alias", link: func(root, outside string) error { return os.Symlink(outside, filepath.Join(root, "notes.txt")) }},
		{name: "directory", link: func(root, outside string) error {
			return os.Symlink(filepath.Dir(outside), filepath.Join(root, "linked"))
		}},
		{name: "dangling", link: func(root, _ string) error { return os.Symlink("missing-target", filepath.Join(root, "dangling")) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root, outside := t.TempDir(), filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tc.link(root, outside); err != nil {
				t.Fatal(err)
			}
			if _, err := maskProjectSecrets(root); err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("symlink scan did not fail closed: %v", err)
			}
			if _, err := bwrapArgs(t.TempDir(), root, root, nil); err == nil {
				t.Fatal("Bubblewrap args accepted incomplete symlink scan")
			}
			if _, err := buildLandlockConfig(root, root, t.TempDir(), t.TempDir(), "true", nil); err == nil {
				t.Fatal("Landlock config accepted incomplete symlink scan")
			}
		})
	}
}

func TestLandlockAllowlistScanHonorsResourceBounds(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "entry"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := landlockConfig{}
	err := grantTree(&cfg, dir, map[string]bool{}, map[string]bool{dir: true}, &landlockTreeScan{entries: maxLandlockTreeEntries}, 0)
	if err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatalf("Landlock allowlist scan did not stop at the entry limit: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "incomplete") {
		t.Fatalf("bounded scan failure was not explicit: %v", err)
	}
}

func TestLandlockCarvesCredentialPathsFromContainingReadRoot(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "project", ".env")
	if err := os.MkdirAll(filepath.Dir(secret), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	deny := map[string]bool{secret: true}
	ancestors := map[string]bool{root: true, filepath.Join(root, "project"): true}
	cfg := landlockConfig{}
	if err := grantLandlockRoot(&cfg, root, deny, ancestors, &landlockTreeScan{}); err != nil {
		t.Fatal(err)
	}
	if containsPath(cfg.RODirs, root) || containsPath(cfg.ROFiles, secret) {
		t.Fatalf("containing read root bypasses credential deny: dirs=%v files=%v", cfg.RODirs, cfg.ROFiles)
	}
}

func hasArgSequence(args []string, sequence ...string) bool {
	for i := 0; i+len(sequence) <= len(args); i++ {
		match := true
		for j := range sequence {
			if args[i+j] != sequence[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func containsPath(paths []string, path string) bool {
	for _, p := range paths {
		if p == path {
			return true
		}
	}
	return false
}
