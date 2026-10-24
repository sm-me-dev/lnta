// Package packs implements Executable Instruction Packs: markdown files with
// YAML frontmatter that describe a capability, its trigger keywords, the paths
// it is allowed to touch, required binaries, and commands to gather ground
// truth (context_cmd) and to verify completion (verify_cmd).
//
// A Local Intent Router scores packs against a user prompt using tokenized
// keyword + bigram matching and selects the best match(es).
package packs

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/adrg/frontmatter"
	"github.com/sm-me-dev/lnta/internal/fingerprint"
)

// ErrNoPack is returned when no pack matches and there is no fallback.
var ErrNoPack = errors.New("no instruction pack matched")

// defaultScoreThreshold is the minimum score for a pack to be considered a
// match. A score of 0 means no trigger matched.
const defaultScoreThreshold = 1

// maxSelected is the maximum number of packs returned by the router.
const maxSelected = 2

// Pack is a single executable instruction pack.
type Pack struct {
	ID           string   `yaml:"id" json:"id"`
	Name         string   `yaml:"name" json:"name"`
	Triggers     []string `yaml:"triggers" json:"triggers"`
	AllowedPaths []string `yaml:"allowed_paths" json:"allowed_paths"`
	RequiredBins []string `yaml:"required_bins" json:"required_bins"`
	ContextCmd   string   `yaml:"context_cmd" json:"context_cmd"`
	VerifyCmd    string   `yaml:"verify_cmd" json:"verify_cmd"`

	// Body is the markdown body following the frontmatter. Not part of YAML.
	Body string `yaml:"-" json:"-"`

	// source is the origin ("embedded:<file>" or "user:<file>") for debugging.
	source string
}

// Router holds the loaded pack registry and performs intent routing.
type Router struct {
	packs []Pack
	byID  map[string]*Pack
}

// NewRouter builds a Router from embedded packs (embed.FS) and an optional
// user override directory (~/.config/lnta/packs/). User packs with the same
// id as an embedded pack take precedence. `packGlob` selects which embedded
// files to load (e.g. "packs/*.md" in production, "testdata/*.md" in tests).
func NewRouter(embedFS embed.FS, packGlob string, userDir string) (*Router, error) {
	loaded, err := loadEmbedded(embedFS, packGlob)
	if err != nil {
		return nil, fmt.Errorf("load embedded packs: %w", err)
	}

	if userDir != "" {
		userPacks, err := loadDir(userDir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("load user packs from %s: %w", userDir, err)
		}
		// Override embedded packs by id.
		byID := make(map[string]*Pack, len(loaded))
		for i := range loaded {
			byID[loaded[i].ID] = &loaded[i]
		}
		for i := range userPacks {
			byID[userPacks[i].ID] = &userPacks[i]
		}
		loaded = packsFromMap(byID)
	}

	r := &Router{
		packs: loaded,
		byID:  make(map[string]*Pack, len(loaded)),
	}
	for i := range loaded {
		r.byID[loaded[i].ID] = &loaded[i]
	}
	return r, nil
}

// packsFromMap converts a map to a deterministic slice sorted by id.
func packsFromMap(m map[string]*Pack) []Pack {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Pack, 0, len(m))
	for _, id := range ids {
		out = append(out, *m[id])
	}
	return out
}

// loadEmbedded reads all *.md packs from the embed.FS under packGlob.
func loadEmbedded(embedFS embed.FS, packGlob string) ([]Pack, error) {
	matches, err := fs.Glob(embedFS, packGlob)
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)

	var packs []Pack
	for _, m := range matches {
		data, err := fs.ReadFile(embedFS, m)
		if err != nil {
			return nil, err
		}
		p, err := parsePack(m, data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", m, err)
		}
		packs = append(packs, *p)
	}
	return packs, nil
}

// loadDir reads all *.md packs from a filesystem directory.
func loadDir(dir string) ([]Pack, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var packs []Pack
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		p, err := parsePack(path, data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		packs = append(packs, *p)
	}
	return packs, nil
}

// parsePack splits frontmatter from body and decodes the schema.
func parsePack(source string, data []byte) (*Pack, error) {
	p := &Pack{source: source}
	rest, err := frontmatter.Parse(strings.NewReader(string(data)), p)
	if err != nil {
		return nil, err
	}
	p.Body = strings.TrimSpace(string(rest))
	if p.ID == "" {
		return nil, errors.New("pack missing id")
	}
	if p.Name == "" {
		p.Name = p.ID
	}
	// Expand ~ in allowed paths.
	for i, ap := range p.AllowedPaths {
		p.AllowedPaths[i] = expandPath(ap)
	}
	return p, nil
}

// ParsePackForTest is a test helper that parses a pack without requiring embed.FS.
// It's exported so other packages can use it in tests.
func ParsePackForTest(source string, data []byte) (*Pack, error) {
	return parsePack(source, data)
}

// expandPath replaces a leading ~ with the HOME directory.
func expandPath(p string) string {
	if strings.HasPrefix(p, "~") {
		home := os.Getenv("HOME")
		if home == "" {
			if u, err := os.UserHomeDir(); err == nil {
				home = u
			}
		}
		if home != "" {
			p = home + p[1:]
		}
	}
	return p
}

// Source returns the pack origin.
func (p Pack) Source() string { return p.source }

// AllBinsAvailable reports whether every required binary is present in the
// given fingerprint context.
func (p Pack) AllBinsAvailable(ctx fingerprint.SystemContext) bool {
	for _, bin := range p.RequiredBins {
		if !ctx.Binaries[bin] {
			return false
		}
	}
	return true
}

// MissingBins returns the required binaries not present in the context.
func (p Pack) MissingBins(ctx fingerprint.SystemContext) []string {
	var missing []string
	for _, bin := range p.RequiredBins {
		if !ctx.Binaries[bin] {
			missing = append(missing, bin)
		}
	}
	return missing
}

// SelectPacks scores all packs against the prompt and returns the best match
// (top 1–2 above threshold). Falls back to the general-diagnostics pack if no
// pack scores above zero.
func (r *Router) SelectPacks(prompt string, sys fingerprint.SystemContext) ([]Pack, error) {
	if len(r.packs) == 0 {
		return nil, ErrNoPack
	}

	promptTokens := tokenize(prompt)
	promptBigrams := bigramSet(promptTokens)

	type scored struct {
		pack Pack
		score int
	}
	scoredPacks := make([]scored, 0, len(r.packs))
	for _, p := range r.packs {
		s := scorePack(p, promptTokens, promptBigrams)
		if s >= defaultScoreThreshold {
			scoredPacks = append(scoredPacks, scored{pack: p, score: s})
		}
	}

	// Deterministic ordering: score desc, then id asc.
	sort.SliceStable(scoredPacks, func(i, j int) bool {
		if scoredPacks[i].score != scoredPacks[j].score {
			return scoredPacks[i].score > scoredPacks[j].score
		}
		return scoredPacks[i].pack.ID < scoredPacks[j].pack.ID
	})

	selected := make([]Pack, 0, maxSelected)
	for i := 0; i < len(scoredPacks) && len(selected) < maxSelected; i++ {
		selected = append(selected, scoredPacks[i].pack)
	}

	if len(selected) == 0 {
		// Fallback to general diagnostics.
		if fb, ok := r.byID["general-diagnostics"]; ok {
			return []Pack{*fb}, nil
		}
		return nil, ErrNoPack
	}
	return selected, nil
}

// scorePack computes a deterministic match score for a pack against the
// prompt. Single-word triggers add weight when present; multi-word triggers
// add weight when the full phrase (all consecutive bigrams) appears.
func scorePack(p Pack, promptTokens []string, promptBigrams map[string]bool) int {
	score := 0
	for _, trigger := range p.Triggers {
		t := strings.ToLower(strings.TrimSpace(trigger))
		if t == "" {
			continue
		}
		tTokens := tokenize(t)
		if len(tTokens) == 0 {
			continue
		}
		if len(tTokens) == 1 {
			if tokenSet(promptTokens)[tTokens[0]] {
				score += 2
			}
			continue
		}
		// Multi-word: require all consecutive bigrams of the trigger to appear.
		tBigrams := bigrams(tTokens)
		allPresent := true
		for _, bg := range tBigrams {
			key := bg[0] + " " + bg[1]
			if !promptBigrams[key] {
				allPresent = false
				break
			}
		}
		if allPresent {
			score += 3
		}
	}
	return score
}

// tokenize lowercases and splits on non-alphanumeric runs.
func tokenize(s string) []string {
	s = strings.ToLower(s)
	var tokens []string
	var cur strings.Builder
	for _, r := range s {
		if isAlnum(r) {
			cur.WriteRune(r)
		} else {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func isAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

// tokenSet returns a set of tokens.
func tokenSet(tokens []string) map[string]bool {
	m := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		m[t] = true
	}
	return m
}

// bigrams returns consecutive pairs from tokens.
func bigrams(tokens []string) [][2]string {
	if len(tokens) < 2 {
		return nil
	}
	out := make([][2]string, 0, len(tokens)-1)
	for i := 0; i < len(tokens)-1; i++ {
		out = append(out, [2]string{tokens[i], tokens[i+1]})
	}
	return out
}

// bigramSet returns a set of "w1 w2" bigram strings.
func bigramSet(tokens []string) map[string]bool {
	m := make(map[string]bool, len(tokens))
	for _, bg := range bigrams(tokens) {
		m[bg[0]+" "+bg[1]] = true
	}
	return m
}

// --- context_cmd / verify_cmd runners ---

var (
	// defaultRouter is the process-wide router used by the free SelectPacks.
	defaultRouter *Router
	defaultMu     sync.Mutex
)

// SetDefaultRouter installs the process-wide router (called from main).
func SetDefaultRouter(r *Router) {
	defaultMu.Lock()
	defaultRouter = r
	defaultMu.Unlock()
}

// SelectPacks is the package-level entry point matching the required
// signature SelectPacks(prompt string, sys SystemContext) ([]Pack, error).
// It uses the process-wide router installed via SetDefaultRouter.
func SelectPacks(prompt string, sys fingerprint.SystemContext) ([]Pack, error) {
	defaultMu.Lock()
	r := defaultRouter
	defaultMu.Unlock()
	if r == nil {
		return nil, ErrNoPack
	}
	return r.SelectPacks(prompt, sys)
}

// PackByID returns the pack with the given id, or nil.
func (r *Router) PackByID(id string) *Pack {
	if p, ok := r.byID[id]; ok {
		return p
	}
	return nil
}

// PackEnvironmentWarnings returns environment-specific warnings for the given
// pack when run in the described system context. It checks required binaries
// against environment capabilities (e.g. systemd availability in WSL2 or
// rootless containers) and suggests container-native alternatives where
// applicable.
func PackEnvironmentWarnings(p Pack, ctx fingerprint.SystemContext) []string {
	var warnings []string

	// If the pack requires systemctl/systemd-analyze but systemd is not
	// available (WSL2 without systemd=true, or rootless container without
	// systemd as PID 1), warn and suggest container-native alternatives.
	needsSystemd := false
	for _, bin := range p.RequiredBins {
		if bin == "systemctl" || bin == "systemd-analyze" || bin == "loginctl" {
			needsSystemd = true
			break
		}
	}

	if needsSystemd && !ctx.SystemdEnabled {
		warnings = append(warnings,
			"pack requires systemd binaries (systemctl/systemd-analyze/loginctl) but systemd is not available in this environment")
		if ctx.IsContainer {
			warnings = append(warnings,
				"rootless container without systemd: use `docker ps`/`podman ps` instead of `systemctl status`, `docker logs`/`podman logs` instead of `journalctl`, and `docker exec`/`podman exec` instead of `systemctl start/stop`")
		}
		if ctx.IsWSL2 {
			warnings = append(warnings,
				"WSL2 without systemd=true in /etc/wsl.conf: systemctl will fail; add `systemd=true` to /etc/wsl.conf and restart the WSL2 instance, or use `service` / `wsl.exe` directly")
		}
		if !ctx.IsContainer && !ctx.IsWSL2 {
			warnings = append(warnings,
				"systemd is not running as PID 1; systemctl operations will fail with \"System has not been booted with systemd\"")
		}
	}

	// WSL2-specific desktop-entry warning.
	if p.ID == "linux-desktop-entries" && ctx.IsWSL2 {
		warnings = append(warnings,
			"WSL2 desktop-entry packs: prefer `wslview` over `xdg-open` for launching .desktop files; WSLg may be required for GUI display")
	}

	// Container-specific docker-compose warning.
	if p.ID == "docker-compose-diagnostics" && ctx.IsContainer && ctx.ContainerRuntime != "docker" {
		warnings = append(warnings,
			"docker-compose pack selected in a non-Docker container runtime: docker socket may not be mounted; use the matching container runtime CLI instead")
	}

	return warnings
}

// AllPacks returns all loaded packs (sorted by id).
func (r *Router) AllPacks() []Pack {
	out := make([]Pack, len(r.packs))
	copy(out, r.packs)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// placeholder regexp for future placeholder rendering in verify_cmd.
var placeholderRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// RenderVerifyCmd replaces ${var} placeholders in the verify command.
func RenderVerifyCmd(cmd string, vars map[string]string) string {
	return placeholderRe.ReplaceAllStringFunc(cmd, func(match string) string {
		name := match[2 : len(match)-1] // strip ${ }
		if v, ok := vars[name]; ok {
			return v
		}
		return match
	})
}
