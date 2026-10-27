package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProjectSecretScanCoversIgnoredDirectoriesAndBothBackends(t *testing.T) {
	project := t.TempDir()
	home := t.TempDir() // deliberately differs from the project root
	secrets := []string{
		filepath.Join(project, "vendor", ".env.production"),
		filepath.Join(project, "node_modules", "pkg", ".npmrc"),
		filepath.Join(project, ".git", "credentials.json"),
		filepath.Join(project, ".hidden", "generated", "service-account.json"),
		filepath.Join(project, "generated", "artifacts", "terraform.tfvars"),
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

func TestHostBwrapArgsSkipProjectScanButKeepHostSecretMasks(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "unsafe-link")); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	args, err := bwrapArgs(home, "", root, nil)
	if err != nil {
		t.Fatalf("host sandbox argument construction scanned the project tree: %v", err)
	}
	if !hasArgSequence(args, "--tmpfs", sshDir) {
		t.Fatalf("host sandbox did not retain the standard home credential mask: %v", args)
	}
	cfg, err := buildLandlockConfig("", root, home, t.TempDir(), "true", nil)
	if err != nil {
		t.Fatalf("host Landlock configuration scanned the project tree: %v", err)
	}
	if !containsPath(cfg.RODirs, root) {
		t.Fatalf("host Landlock configuration did not allow the selected working directory: %v", cfg.RODirs)
	}
	if _, err := bwrapArgs(home, root, root, nil); !errors.Is(err, ErrSecretScanIncomplete) {
		t.Fatalf("project sandbox did not retain fail-closed symlink handling: %v", err)
	}
	if _, err := buildLandlockConfig(root, root, home, t.TempDir(), "true", nil); !errors.Is(err, ErrSecretScanIncomplete) {
		t.Fatalf("project Landlock configuration did not retain fail-closed symlink handling: %v", err)
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
	t.Run("maximum child depth", func(t *testing.T) {
		root, nested := t.TempDir(), ""
		for range maxProjectScanDepth {
			nested = filepath.Join(nested, "a")
		}
		deep := filepath.Join(root, nested)
		if err := os.MkdirAll(deep, 0o700); err != nil {
			t.Fatal(err)
		}
		secret := filepath.Join(deep, ".env")
		if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := maskProjectSecrets(root)
		if err != nil || len(got) != 1 || got[0] != secret {
			t.Fatalf("maximum configured depth failed: paths=%v err=%v", got, err)
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
	t.Run("more than five thousand entries", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i < 5_001; i++ {
			if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("entry-%05d", i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		secret := filepath.Join(root, ".env")
		if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := maskProjectSecrets(root)
		if err != nil || len(got) != 1 || got[0] != secret {
			t.Fatalf("large project scan failed or missed credentials: paths=%v err=%v", got, err)
		}
		partial, err := scanProjectSecrets(root, maxProjectScanDepth, 5_000, maxProjectSecretPaths, maxProjectSecretPathBytes)
		if err == nil || !strings.Contains(err.Error(), "entry limit") || partial != nil {
			t.Fatalf("budget-plus-one scan returned partial credentials: paths=%v err=%v", partial, err)
		}
	})
}

func TestProjectSecretScanRejectsSecretBudgetsWithoutPartialResults(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		maxSecrets   int
		maxPathBytes int
		want         string
	}{
		{name: "path count", maxSecrets: 0, maxPathBytes: maxProjectSecretPathBytes, want: "secret path limit"},
		{name: "path bytes", maxSecrets: maxProjectSecretPaths, maxPathBytes: 1, want: "secret path byte limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanProjectSecrets(root, maxProjectScanDepth, maxProjectScanEntries, tc.maxSecrets, tc.maxPathBytes)
			if err == nil || !strings.Contains(err.Error(), tc.want) || got != nil {
				t.Fatalf("budget exhaustion returned partial results: paths=%v err=%v", got, err)
			}
		})
	}
}

func TestProjectSecretScanEntryBudgetRefusesConfiguredBudgetPlusOne(t *testing.T) {
	budget := projectSecretScanBudget{entries: maxProjectScanEntries - 1, maxEntries: maxProjectScanEntries}
	if err := budget.addEntry(); err != nil {
		t.Fatalf("last configured entry was rejected: %v", err)
	}
	if err := budget.addEntry(); err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatalf("configured entry budget-plus-one was accepted: %v", err)
	}
}

func TestProjectSecretScanStopsAtConfiguredSecretPathLimit(t *testing.T) {
	root := t.TempDir()
	for index := 0; index <= maxProjectSecretPaths; index++ {
		dir := filepath.Join(root, fmt.Sprintf("secret-%04d", index))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".env"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := maskProjectSecrets(root)
	if err == nil || !strings.Contains(err.Error(), "secret path limit") || got != nil {
		t.Fatalf("secret path budget-plus-one was accepted: paths=%v err=%v", got, err)
	}
}

func TestProjectSecretScanStopsAtConfiguredPathByteLimit(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, strings.Repeat("p", 220))
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxProjectSecretPaths; index++ {
		dir := filepath.Join(parent, fmt.Sprintf("d%04d", index))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".env"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := maskProjectSecrets(root)
	if err == nil || !strings.Contains(err.Error(), "secret path byte limit") || got != nil {
		t.Fatalf("secret path byte budget was accepted: paths=%v err=%v", got, err)
	}
}

func TestProjectSecretScanRejectsUnknownAndUnreadableEntries(t *testing.T) {
	t.Run("unknown special file", func(t *testing.T) {
		root := t.TempDir()
		if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := maskProjectSecrets(root); err == nil || !strings.Contains(err.Error(), "unsupported project entry type") || got != nil {
			t.Fatalf("special entry was accepted: paths=%v err=%v", got, err)
		}
	})
	t.Run("unreadable directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can bypass directory read permissions")
		}
		root := t.TempDir()
		blocked := filepath.Join(root, "blocked")
		if err := os.Mkdir(blocked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })
		if got, err := maskProjectSecrets(root); err == nil || got != nil {
			t.Fatalf("unreadable tree was accepted: paths=%v err=%v", got, err)
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

func TestProjectSecretScanConcurrentTreeChangesRemainBounded(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(outside, []byte("harmless concurrent scan sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed := filepath.Join(root, "changing-entry")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Remove(changed)
			if i%2 == 0 {
				_ = os.Symlink(outside, changed)
			} else {
				_ = os.WriteFile(changed, []byte("ordinary file"), 0o600)
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})

	for i := 0; i < 100; i++ {
		paths, err := maskProjectSecrets(root)
		if err != nil {
			// Concurrent disappearance and symlink discovery both fail closed.
			continue
		}
		for _, path := range paths {
			if !pathWithin(path, root) {
				t.Fatalf("scanner returned a path outside the project: %q", path)
			}
		}
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

func TestLandlockConfigurationBudgetsRejectBeforeAddingRules(t *testing.T) {
	pathScan := &landlockTreeScan{pathBytes: maxLandlockPathBytes - 1}
	var paths []string
	if err := pathScan.addRule(&paths, "/tmp"); err == nil || len(paths) != 0 {
		t.Fatalf("path budget accepted an over-budget rule: paths=%v err=%v", paths, err)
	}
	ruleScan := &landlockTreeScan{rules: maxLandlockRules}
	if err := ruleScan.addRule(&paths, "/tmp"); err == nil || len(paths) != 0 {
		t.Fatalf("rule budget accepted an over-budget rule: paths=%v err=%v", paths, err)
	}
	entryScan := &landlockTreeScan{}
	parent := unix.Stat_t{Dev: 1, Ino: 2}
	if err := entryScan.addEntry(parent, "entry"); err != nil {
		t.Fatal(err)
	}
	if err := entryScan.addEntry(parent, "entry"); err != nil || entryScan.entries != 1 {
		t.Fatalf("same directory entry was counted more than once: entries=%d err=%v", entryScan.entries, err)
	}
}

func TestLandlockConfigurationRejectsOversizedSerializedJSON(t *testing.T) {
	encodedConfig := landlockConfig{
		RODirs: []string{"/tmp/<λ>"},
		Cwd:    "/tmp/\xff",
		Cmd:    "printf '\u2028'",
		Env:    []string{"KEY=value&more"},
	}
	raw, err := json.Marshal(encodedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got := estimateLandlockJSONBytes(encodedConfig); got != len(raw) {
		t.Fatalf("serialized size estimate=%d, actual=%d", got, len(raw))
	}
	cfg := landlockConfig{Cwd: "/", Cmd: strings.Repeat("<", maxLandlockConfigBytes/6+1)}
	if err := validateLandlockConfigBudget(cfg); err == nil || !strings.Contains(err.Error(), "serialized JSON limit") {
		t.Fatalf("oversized Landlock configuration was accepted: %v", err)
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
