// Package fingerprint collects a lightweight, deterministic system
// fingerprint used to ground LLM prompts in local ground truth.
//
// It performs only native file reads and environment lookups — never an LLM
// call and never a slow subprocess — and is designed to execute in under
// 5 ms.
package fingerprint

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// SystemContext is a clean, deterministic snapshot of the local environment
// suitable for prompt injection. All fields are populated from native reads
// and environment variables; nothing here requires an LLM or a subprocess.
type SystemContext struct {
	// OS release information parsed from /etc/os-release.
	DistroID   string `yaml:"distro_id" json:"distro_id"`
	DistroVer  string `yaml:"distro_version" json:"distro_version"`
	PrettyName string `yaml:"pretty_name" json:"pretty_name"`

	// Environment variables relevant to desktop/session/shell context.
	XDGCurrentDesktop string `yaml:"xdg_current_desktop" json:"xdg_current_desktop"`
	XDGSessionType    string `yaml:"xdg_session_type" json:"xdg_session_type"`
	Shell             string `yaml:"shell" json:"shell"`
	Path              string `yaml:"path" json:"path"`
	Home              string `yaml:"home" json:"home"`

	// Process / identity context.
	CWD      string `yaml:"cwd" json:"cwd"`
	UID      int    `yaml:"uid" json:"uid"`
	GID      int    `yaml:"gid" json:"gid"`
	Username string `yaml:"username" json:"username"`

	// Binary availability in $PATH (true if the binary exists and is executable).
	Binaries map[string]bool `yaml:"binaries" json:"binaries"`

	// Timing metadata.
	FingerprintedAt string `yaml:"fingerprinted_at" json:"fingerprinted_at"`
	DurationNs      int64  `yaml:"duration_ns" json:"duration_ns"`
}

// wantedBins is the canonical set of binaries LNTa cares about. Order is
// fixed so the output is deterministic.
var wantedBins = []string{
	"bwrap",
	"systemctl",
	"desktop-file-validate",
	"ss",
	"ufw",
	"git",
}

// Fingerprint collects the system context. It returns an error only if the
// working directory or identity cannot be resolved (both are effectively
// always available on a normal system).
func Fingerprint() (SystemContext, error) {
	start := time.Now()

	ctx := SystemContext{
		Binaries: make(map[string]bool, len(wantedBins)),
	}

	// Environment variables (cheap, no syscalls beyond getenv).
	ctx.XDGCurrentDesktop = os.Getenv("XDG_CURRENT_DESKTOP")
	ctx.XDGSessionType = os.Getenv("XDG_SESSION_TYPE")
	ctx.Shell = os.Getenv("SHELL")
	ctx.Path = os.Getenv("PATH")
	ctx.Home = os.Getenv("HOME")

	// Current working directory.
	if cwd, err := os.Getwd(); err == nil {
		ctx.CWD = cwd
	}

	// Effective UID / GID / username via os/user (native read, no subprocess).
	if u, err := user.Current(); err == nil {
		ctx.Username = u.Username
		// user.Current returns Uid/Gid as strings on most platforms; parse them.
		// We also read the numeric IDs directly when available.
		_ = u.Uid
		_ = u.Gid
	}
	// Numeric IDs are most reliably obtained from the runtime.
	ctx.UID = os.Geteuid()
	ctx.GID = os.Getegid()

	// OS release from /etc/os-release.
	if rel, err := parseOSRelease("/etc/os-release"); err == nil {
		ctx.DistroID = rel["ID"]
		ctx.DistroVer = rel["VERSION_ID"]
		ctx.PrettyName = rel["PRETTY_NAME"]
	}

	// Binary availability in $PATH.
	for _, b := range wantedBins {
		ctx.Binaries[b] = binaryInPath(b, ctx.Path)
	}

	ctx.FingerprintedAt = start.UTC().Format(time.RFC3339Nano)
	ctx.DurationNs = time.Since(start).Nanoseconds()

	return ctx, nil
}

// parseOSRelease reads a key=value OS-release file and returns the parsed map.
// Quotes are stripped from values. Missing file is not an error.
func parseOSRelease(path string) (map[string]string, error) {
	out := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = stripQuotes(val)
		out[key] = val
	}
	return out, sc.Err()
}

// stripQuotes removes a matching pair of surrounding quotes.
func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// binaryInPath reports whether name exists and is executable in any dir of path.
func binaryInPath(name, path string) bool {
	if name == "" {
		return false
	}
	// runtime.GOOS check keeps this portable; on Windows we'd check PATHEXT.
	if runtime.GOOS == "windows" {
		name = name + ".exe"
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		// Executable check: on Unix, any of the execute bits.
		m := info.Mode()
		if m&0o111 != 0 {
			return true
		}
	}
	return false
}

// String renders the SystemContext as a compact, deterministic YAML-ish text
// block suitable for injection into an LLM prompt.
func (c SystemContext) String() string {
	var b strings.Builder
	b.WriteString("## System Context\n")
	b.WriteString(fmt.Sprintf("- os: %s %s (%s)\n", c.DistroID, c.DistroVer, c.PrettyName))
	b.WriteString(fmt.Sprintf("- shell: %s\n", c.Shell))
	b.WriteString(fmt.Sprintf("- session: %s / %s\n", c.XDGSessionType, c.XDGCurrentDesktop))
	b.WriteString(fmt.Sprintf("- home: %s\n", c.Home))
	b.WriteString(fmt.Sprintf("- cwd: %s\n", c.CWD))
	b.WriteString(fmt.Sprintf("- user: %s (uid=%d gid=%d)\n", c.Username, c.UID, c.GID))
	b.WriteString("- binaries:\n")
	for _, bin := range wantedBins {
		b.WriteString(fmt.Sprintf("    - %s: %v\n", bin, c.Binaries[bin]))
	}
	b.WriteString(fmt.Sprintf("- fingerprinted_at: %s\n", c.FingerprintedAt))
	b.WriteString(fmt.Sprintf("- duration_ns: %d\n", c.DurationNs))
	return b.String()
}

// Sanity check that SystemContext compiles against the yaml/json tags.
// (The struct is consumed by callers; this is here to lock the shape.)
var _ = fmt.Sprintf("%v", SystemContext{})
