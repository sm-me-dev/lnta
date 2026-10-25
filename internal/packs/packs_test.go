package packs

import (
	"embed"
	"os"
	"path/filepath"
	"testing"

	"github.com/sm-me-dev/lnta/internal/fingerprint"
)

func TestRouterRejectsDuplicateUserPackIDs(t *testing.T) {
	dir := t.TempDir()
	content := "---\nid: duplicate\nname: Duplicate\ntriggers: [test]\nallowed_paths: []\nverify_cmd: 'test -f \"${target}\"'\n---\nbody\n"
	for _, name := range []string{"one.md", "two.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewRouter(testEmbedFS, "testdata/*.md", dir); err == nil {
		t.Fatal("duplicate user pack IDs were accepted")
	}
}

//go:embed testdata/*.md
var testEmbedFS embed.FS

func TestSelectPacksDesktopEntries(t *testing.T) {
	r, err := NewRouter(testEmbedFS, "testdata/*.md", "")
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	sys := fingerprint.SystemContext{Binaries: map[string]bool{}}
	selected, err := r.SelectPacks("create a .desktop launcher for my app", sys)
	if err != nil {
		t.Fatalf("SelectPacks: %v", err)
	}
	if len(selected) == 0 {
		t.Fatal("expected at least one pack selected")
	}
	found := false
	for _, p := range selected {
		if p.ID == "linux-desktop-entries" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected linux-desktop-entries pack, got %v", selected)
	}
}

func TestSelectPacksSystemdUser(t *testing.T) {
	r, err := NewRouter(testEmbedFS, "testdata/*.md", "")
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	sys := fingerprint.SystemContext{Binaries: map[string]bool{"systemctl": true}}
	selected, err := r.SelectPacks("create a user-level systemd service", sys)
	if err != nil {
		t.Fatalf("SelectPacks: %v", err)
	}
	found := false
	for _, p := range selected {
		if p.ID == "systemd-user-services" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected systemd-user-services pack, got %v", selected)
	}
}

func TestSelectPacksNetworkPorts(t *testing.T) {
	r, err := NewRouter(testEmbedFS, "testdata/*.md", "")
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	sys := fingerprint.SystemContext{Binaries: map[string]bool{"ss": true}}
	selected, err := r.SelectPacks("what is listening on port 8080", sys)
	if err != nil {
		t.Fatalf("SelectPacks: %v", err)
	}
	found := false
	for _, p := range selected {
		if p.ID == "network-ports-processes" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected network-ports-processes pack, got %v", selected)
	}
}

func TestSelectPacksFallbackGeneralDiagnostics(t *testing.T) {
	r, err := NewRouter(testEmbedFS, "testdata/*.md", "")
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	sys := fingerprint.SystemContext{}
	selected, err := r.SelectPacks("asdfghjkl qwertyuiop zxcvbnm", sys)
	if err != nil {
		t.Fatalf("SelectPacks: %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("expected exactly one fallback pack, got %d", len(selected))
	}
	if selected[0].ID != "general-diagnostics" {
		t.Fatalf("expected general-diagnostics fallback, got %s", selected[0].ID)
	}
}

func TestSelectPacksRespectsMaxTwo(t *testing.T) {
	r, err := NewRouter(testEmbedFS, "testdata/*.md", "")
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	sys := fingerprint.SystemContext{}
	// A prompt touching many topics.
	selected, err := r.SelectPacks("desktop systemd network port process service", sys)
	if err != nil {
		t.Fatalf("SelectPacks: %v", err)
	}
	if len(selected) > 2 {
		t.Fatalf("expected at most 2 packs, got %d", len(selected))
	}
}

func TestParsePackFrontmatter(t *testing.T) {
	data := []byte(`---
id: test-pack
name: Test Pack
triggers:
  - foo bar
  - baz
allowed_paths:
  - "~/.config/lnta/*.md"
required_bins:
  - git
context_cmd: echo hi
verify_cmd: test -f ${target}
---
# Body here

Some markdown.
`)
	p, err := parsePack("test.md", data)
	if err != nil {
		t.Fatalf("parsePack: %v", err)
	}
	if p.ID != "test-pack" {
		t.Errorf("id = %q, want %q", p.ID, "test-pack")
	}
	if p.Name != "Test Pack" {
		t.Errorf("name = %q, want %q", p.Name, "Test Pack")
	}
	if len(p.Triggers) != 2 || p.Triggers[0] != "foo bar" || p.Triggers[1] != "baz" {
		t.Errorf("triggers = %v", p.Triggers)
	}
	if len(p.AllowedPaths) != 1 || p.AllowedPaths[0] == "~/.config/lnta/*.md" {
		t.Errorf("allowed_paths not expanded: %v", p.AllowedPaths)
	}
	if len(p.RequiredBins) != 1 || p.RequiredBins[0] != "git" {
		t.Errorf("required_bins = %v", p.RequiredBins)
	}
	if p.ContextCmd != "echo hi" {
		t.Errorf("context_cmd = %q", p.ContextCmd)
	}
	if p.VerifyCmd != "test -f ${target}" {
		t.Errorf("verify_cmd = %q", p.VerifyCmd)
	}
	if !stringsContains(p.Body, "# Body here") {
		t.Errorf("body not captured: %q", p.Body)
	}
}

func TestAllBinsAvailable(t *testing.T) {
	p := Pack{RequiredBins: []string{"git", "ss"}}
	ctx := fingerprint.SystemContext{Binaries: map[string]bool{"git": true, "ss": true}}
	if !p.AllBinsAvailable(ctx) {
		t.Error("expected all bins available")
	}
	ctx2 := fingerprint.SystemContext{Binaries: map[string]bool{"git": true}}
	if p.AllBinsAvailable(ctx2) {
		t.Error("expected missing bin")
	}
	if got := p.MissingBins(ctx2); len(got) != 1 || got[0] != "ss" {
		t.Errorf("missing bins = %v", got)
	}
}

func stringsContains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
