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

	// Environment detection flags.
	// IsWSL2 detects the Windows Subsystem for Linux 2 environment.
	// Checks /proc/sys/fs/binfmt_misc/WSLInterop or "microsoft" in /proc/version.
	IsWSL2 bool `yaml:"is_wsl2" json:"is_wsl2"`
	// IsContainer detects Docker/Podman container environments.
	// Checks /.dockerenv or /run/.containerenv existence.
	IsContainer bool `yaml:"is_container" json:"is_container"`
	// IsHeadlessSSH detects headless SSH sessions.
	// SSH_CONNECTION present without DISPLAY/WAYLAND_DISPLAY.
	IsHeadlessSSH bool `yaml:"is_headless_ssh" json:"is_headless_ssh"`
	// SystemdEnabled indicates whether systemd is enabled (WSL2 specific).
	// Checks /etc/wsl.conf for systemd=true.
	SystemdEnabled bool `yaml:"systemd_enabled" json:"systemd_enabled"`
	// ContainerRuntime identifies the container runtime if in a container.
	// "docker" or "podman" or "".
	ContainerRuntime string `yaml:"container_runtime" json:"container_runtime"`

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

// Test-only path overrides for environment detection. Defaults point to the
// real system paths; tests can override them to point at temp files.
var (
	wslInteropPath   = "/proc/sys/fs/binfmt_misc/WSLInterop"
	procVersionPath  = "/proc/version"
	dockerEnvPath    = "/.dockerenv"
	containerEnvPath = "/run/.containerenv"
	wslConfPath      = "/etc/wsl.conf"
)

// detectWSL2 checks whether the current environment is WSL2.
// It checks /proc/sys/fs/binfmt_misc/WSLInterop existence or "microsoft" in /proc/version.
func detectWSL2() bool {
	// Check /proc/sys/fs/binfmt_misc/WSLInterop
	if _, err := os.Stat(wslInteropPath); err == nil {
		return true
	}
	// Check /proc/version for microsoft (case-insensitive; WSL2 reports
	// "Microsoft" with a capital M).
	ver, err := os.ReadFile(procVersionPath)
	if err == nil && strings.Contains(strings.ToLower(string(ver)), "microsoft") {
		return true
	}
	return false
}

// detectContainer checks whether the current environment is a Docker/Podman container.
// It checks /.dockerenv or /run/.containerenv existence.
func detectContainer() bool {
	if _, err := os.Stat(dockerEnvPath); err == nil {
		return true
	}
	if _, err := os.Stat(containerEnvPath); err == nil {
		return true
	}
	return false
}

// detectHeadlessSSH detects whether we're in a headless SSH session.
// SSH_CONNECTION present without DISPLAY/WAYLAND_DISPLAY.
func detectHeadlessSSH() bool {
	sshConn := os.Getenv("SSH_CONNECTION")
	if sshConn == "" {
		return false
	}
	display := os.Getenv("DISPLAY")
	wayland := os.Getenv("WAYLAND_DISPLAY")
	// Headless if no display server available
	return display == "" && wayland == ""
}

// detectSystemd checks if systemd is enabled in WSL2 environment.
// Reads /etc/wsl.conf for systemd setting.
func detectSystemd() bool {
	data, err := os.ReadFile(wslConfPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "systemd=true")
}

// ContainerRuntime identifies the container runtime if in a container.
// "docker" or "podman" or "".
func ContainerRuntime() string {
	if detectContainer() {
		// Check for docker binary in PATH
		if binaryInPath("docker", "") {
			return "docker"
		}
		// Check for podman binary in PATH
		if binaryInPath("podman", "") {
			return "podman"
		}
	}
	return ""
}

// parseOSRelease reads a key=value OS-release file and returns the parsed map.
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

// Fingerprint collects the system context. It returns an error only if the
// working directory or identity cannot be resolved (both are effectively
// always available on a normal system).
func Fingerprint() (SystemContext, error) {
	start := time.Now()

	// Get user info first (outside struct init)
	var username string
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	// Initialize all fields
	ctx := SystemContext{
		Binaries: make(map[string]bool, len(wantedBins)),
		// Environment detection flags default to false
		IsWSL2:         false,
		IsContainer:    false,
		IsHeadlessSSH:  false,
		SystemdEnabled: false,
		ContainerRuntime: "",
		// Environment variables (cheap, no syscalls beyond getenv).
		XDGCurrentDesktop: os.Getenv("XDG_CURRENT_DESKTOP"),
		XDGSessionType:    os.Getenv("XDG_SESSION_TYPE"),
		Shell:             os.Getenv("SHELL"),
		Path:              os.Getenv("PATH"),
		Home:              os.Getenv("HOME"),
		// Process / identity context.
		CWD:      "",
		UID:      os.Geteuid(),
		GID:      os.Getegid(),
		Username: username,
	}
	// Populate CWD from os.Getwd() if available
	if cwd, err := os.Getwd(); err == nil {
		ctx.CWD = cwd
	}

	// OS release from /etc/os-release
	if rel, err := parseOSRelease("/etc/os-release"); err == nil {
		ctx.DistroID = rel["ID"]
		ctx.DistroVer = rel["VERSION_ID"]
		ctx.PrettyName = rel["PRETTY_NAME"]
	}

	// Binary availability in $PATH
	for _, b := range wantedBins {
		ctx.Binaries[b] = binaryInPath(b, ctx.Path)
	}

	ctx.FingerprintedAt = start.UTC().Format(time.RFC3339Nano)
	ctx.DurationNs = time.Since(start).Nanoseconds()

	// Add environment detection flags
	ctx.IsWSL2 = detectWSL2()
	ctx.IsContainer = detectContainer()
	ctx.IsHeadlessSSH = detectHeadlessSSH()
	ctx.SystemdEnabled = detectSystemd()
	ctx.ContainerRuntime = ContainerRuntime()

	return ctx, nil
}

// String renders the SystemContext as a compact, deterministic YAML-ish text
// block suitable for injection into an LLM prompt.
func (c SystemContext) String() string {
	var b strings.Builder
	b.WriteString("## System Context\n")
	fmt.Fprintf(&b, "- os: %s %s (%s)\n", c.DistroID, c.DistroVer, c.PrettyName)
	fmt.Fprintf(&b, "- shell: %s\n", c.Shell)
	fmt.Fprintf(&b, "- session: %s / %s\n", c.XDGSessionType, c.XDGCurrentDesktop)
	fmt.Fprintf(&b, "- home: %s\n", c.Home)
	fmt.Fprintf(&b, "- cwd: %s\n", c.CWD)
	fmt.Fprintf(&b, "- user: %s (uid=%d gid=%d)\n", c.Username, c.UID, c.GID)
	b.WriteString("- binaries:\n")
	for _, bin := range wantedBins {
		fmt.Fprintf(&b, "    - %s: %v\n", bin, c.Binaries[bin])
	}
	fmt.Fprintf(&b, "- fingerprinted_at: %s\n", c.FingerprintedAt)
	fmt.Fprintf(&b, "- duration_ns: %d\n", c.DurationNs)
	b.WriteString(c.environmentConstraints())
	return b.String()
}

// environmentConstraints returns environment-specific constraint guidance
// for WSL2, container, and headless SSH sessions. This is injected into the
// system prompt so the LLM knows what capabilities and limitations apply.
func (c SystemContext) environmentConstraints() string {
	var b strings.Builder

	// --- WSL2 constraints ---
	if c.IsWSL2 {
		b.WriteString("\n## Environment: WSL2 (Windows Subsystem for Linux 2)\n")
		b.WriteString("- systemd: ")
		if c.SystemdEnabled {
			b.WriteString("enabled (systemd=true in /etc/wsl.conf — systemctl is usable)\n")
		} else {
			b.WriteString("NOT enabled (systemd=true missing in /etc/wsl.conf — systemctl will fail; use service commands or wsl.exe directly)\n")
		}
		b.WriteString("- desktop integration: wslview / WSLg may be available for launching GUI apps; prefer wslview over xdg-open for .desktop files\n")
		b.WriteString("- note: systemd-dependent operations (systemctl, loginctl, journalctl --user) may not work unless systemd=true is set in /etc/wsl.conf and the WSL2 instance was restarted\n")
	}

	// --- Container constraints ---
	if c.IsContainer {
		b.WriteString("\n## Environment: Container (" + c.containerRuntimeLabel() + ")\n")
		if c.SystemdEnabled {
			b.WriteString("- systemd: available in container\n")
		} else {
			b.WriteString("- systemd: NOT available (rootless container without systemd as PID 1 — systemctl will fail with \"System has not been booted with systemd\")\n")
			b.WriteString("- container-native alternatives: use `docker ps`/`podman ps` instead of `systemctl status`, use `docker logs`/`podman logs` instead of `journalctl`, use `docker exec`/`podman exec` instead of `systemctl start/stop`\n")
			b.WriteString("- avoid systemd-dependent packs; prefer container runtime APIs and read-only filesystem inspection\n")
		}
	}

	// --- Headless SSH constraints ---
	if c.IsHeadlessSSH {
		b.WriteString("\n## Environment: Headless SSH Session\n")
		b.WriteString("- SSH_CONNECTION present, no DISPLAY/WAYLAND_DISPLAY — no graphical session available\n")
		b.WriteString("- desktop-entry packs (.desktop files) can be written and validated but GUI launch via wslview/xdg-open will not work\n")
		b.WriteString("- prefer read-only inspection (inspect_system) over GUI-dependent operations\n")
	}

	return b.String()
}

// containerRuntimeLabel returns a human-readable label for the container runtime.
func (c SystemContext) containerRuntimeLabel() string {
	switch c.ContainerRuntime {
	case "docker":
		return "Docker"
	case "podman":
		return "Podman"
	default:
		return "OCI container"
	}
}

// Sanity check that SystemContext compiles against the yaml/json tags.
// (The struct is consumed by callers; this is here to lock the shape.)
var _ = fmt.Sprintf("%v", SystemContext{})