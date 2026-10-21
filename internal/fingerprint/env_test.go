package fingerprint

import (
	"os"
	"strings"
	"testing"
)

// TestDetectWSL2 verifies WSL2 environment detection via both
// /proc/sys/fs/binfmt_misc/WSLInterop and "microsoft" in /proc/version.
func TestDetectWSL2(t *testing.T) {
	// Save and restore real paths.
	origInterop := wslInteropPath
	origVersion := procVersionPath
	defer func() {
		wslInteropPath = origInterop
		procVersionPath = origVersion
	}()

	// Not WSL2 by default (paths don't exist in test env).
	wslInteropPath = "/nonexistent/wslinterop"
	procVersionPath = "/nonexistent/version"
	if detectWSL2() {
		t.Error("expected detectWSL2() to return false when neither path exists")
	}

	// WSLInterop exists -> WSL2.
	dir := t.TempDir()
	wslInteropPath = dir
	if !detectWSL2() {
		t.Error("expected detectWSL2() to return true when WSLInterop path exists")
	}

	// "microsoft" in /proc/version -> WSL2.
	wslInteropPath = "/nonexistent/wslinterop"
	verFile := filepathJoin(dir, "version")
	if err := os.WriteFile(verFile, []byte("Linux version 5.15.0 (Microsoft)"), 0o644); err != nil {
		t.Fatalf("write version file: %v", err)
	}
	procVersionPath = verFile
	if !detectWSL2() {
		t.Error("expected detectWSL2() to return true when /proc/version contains microsoft")
	}

	// Case-insensitive microsoft check.
	if err := os.WriteFile(verFile, []byte("Linux version 5.15.0 (microsoft)"), 0o644); err != nil {
		t.Fatalf("write version file: %v", err)
	}
	if !detectWSL2() {
		t.Error("expected detectWSL2() to return true for lowercase microsoft")
	}
}

// TestDetectContainer verifies container environment detection via
// /.dockerenv and /run/.containerenv.
func TestDetectContainer(t *testing.T) {
	origDocker := dockerEnvPath
	origContainer := containerEnvPath
	defer func() {
		dockerEnvPath = origDocker
		containerEnvPath = origContainer
	}()

	// Neither path exists -> not a container.
	dockerEnvPath = "/nonexistent/dockerenv"
	containerEnvPath = "/nonexistent/containerenv"
	if detectContainer() {
		t.Error("expected detectContainer() to return false when neither path exists")
	}

	// /.dockerenv exists -> container (Docker).
	dir := t.TempDir()
	dockerEnvPath = dir
	if !detectContainer() {
		t.Error("expected detectContainer() to return true when /.dockerenv exists")
	}

	// /run/.containerenv exists -> container (Podman).
	dockerEnvPath = "/nonexistent/dockerenv"
	ctrFile := filepathJoin(dir, "containerenv")
	if err := os.WriteFile(ctrFile, []byte{}, 0o644); err != nil {
		t.Fatalf("write containerenv file: %v", err)
	}
	containerEnvPath = ctrFile
	if !detectContainer() {
		t.Error("expected detectContainer() to return true when /run/.containerenv exists")
	}
}

// TestDetectHeadlessSSH verifies headless SSH session detection via env vars.
func TestDetectHeadlessSSH(t *testing.T) {
	origSSH := os.Getenv("SSH_CONNECTION")
	origDisplay := os.Getenv("DISPLAY")
	origWayland := os.Getenv("WAYLAND_DISPLAY")
	defer func() {
		_ = os.Setenv("SSH_CONNECTION", origSSH)
		_ = os.Setenv("DISPLAY", origDisplay)
		_ = os.Setenv("WAYLAND_DISPLAY", origWayland)
	}()

	// No SSH_CONNECTION -> not headless SSH.
	_ = os.Unsetenv("SSH_CONNECTION")
	_ = os.Setenv("DISPLAY", ":0")
	if detectHeadlessSSH() {
		t.Error("expected detectHeadlessSSH() to return false without SSH_CONNECTION")
	}

	// SSH_CONNECTION with DISPLAY -> not headless (has graphical session).
	_ = os.Setenv("SSH_CONNECTION", "10.0.0.1 1234 10.0.0.2 5678")
	_ = os.Setenv("DISPLAY", ":0")
	if detectHeadlessSSH() {
		t.Error("expected detectHeadlessSSH() to return false when DISPLAY is set")
	}

	// SSH_CONNECTION with WAYLAND_DISPLAY -> not headless.
	_ = os.Unsetenv("DISPLAY")
	_ = os.Setenv("WAYLAND_DISPLAY", "wayland-0")
	if detectHeadlessSSH() {
		t.Error("expected detectHeadlessSSH() to return false when WAYLAND_DISPLAY is set")
	}

	// SSH_CONNECTION with no display -> headless SSH.
	_ = os.Unsetenv("DISPLAY")
	_ = os.Unsetenv("WAYLAND_DISPLAY")
	if !detectHeadlessSSH() {
		t.Error("expected detectHeadlessSSH() to return true for headless SSH")
	}
}

// TestDetectSystemd verifies systemd detection via /etc/wsl.conf.
func TestDetectSystemd(t *testing.T) {
	origConf := wslConfPath
	defer func() { wslConfPath = origConf }()

	// No wsl.conf -> systemd not enabled.
	wslConfPath = "/nonexistent/wsl.conf"
	if detectSystemd() {
		t.Error("expected detectSystemd() to return false when /etc/wsl.conf is missing")
	}

	// wsl.conf without systemd=true -> not enabled.
	dir := t.TempDir()
	confFile := filepathJoin(dir, "wsl.conf")
	if err := os.WriteFile(confFile, []byte("[boot]\n"), 0o644); err != nil {
		t.Fatalf("write wsl.conf: %v", err)
	}
	wslConfPath = confFile
	if detectSystemd() {
		t.Error("expected detectSystemd() to return false when systemd=true is not set")
	}

	// wsl.conf with systemd=true -> enabled.
	if err := os.WriteFile(confFile, []byte("[boot]\nsystemd=true\n"), 0o644); err != nil {
		t.Fatalf("write wsl.conf: %v", err)
	}
	if !detectSystemd() {
		t.Error("expected detectSystemd() to return true when systemd=true is set")
	}
}

// TestContainerRuntime verifies container runtime detection returns empty
// when not in a container (binaryInPath with empty path never finds binaries).
func TestContainerRuntime(t *testing.T) {
	origDocker := dockerEnvPath
	origContainer := containerEnvPath
	defer func() {
		dockerEnvPath = origDocker
		containerEnvPath = origContainer
	}()

	// Not a container -> empty runtime.
	dockerEnvPath = "/nonexistent/dockerenv"
	containerEnvPath = "/nonexistent/containerenv"
	if got := ContainerRuntime(); got != "" {
		t.Errorf("expected empty container runtime, got %q", got)
	}

	// Container detected but no runtime binary in PATH (empty path) -> "".
	dockerEnvPath = t.TempDir()
	containerEnvPath = "/nonexistent/containerenv"
	if got := ContainerRuntime(); got != "" {
		t.Errorf("expected empty container runtime when no binary found, got %q", got)
	}
}

// TestStringIncludesEnvironmentConstraints verifies String() includes
// WSL2, container, and headless SSH constraint sections.
func TestStringIncludesEnvironmentConstraints(t *testing.T) {
	ctx := SystemContext{
		DistroID:      "ubuntu",
		DistroVer:     "22.04",
		PrettyName:    "Ubuntu 22.04 LTS",
		Shell:         "/bin/bash",
		Home:          "/home/user",
		CWD:           "/home/user",
		Username:      "user",
		UID:           1000,
		GID:           1000,
		IsWSL2:        true,
		SystemdEnabled: false,
		Binaries:      map[string]bool{"systemctl": true},
	}
	s := ctx.String()
	if !strings.Contains(s, "Environment: WSL2") {
		t.Error("expected String() to include WSL2 environment section")
	}
	if !strings.Contains(s, "systemd=true") {
		t.Error("expected String() to mention systemd=true for WSL2")
	}
	if !strings.Contains(s, "wslview") {
		t.Error("expected String() to mention wslview for WSL2 desktop integration")
	}

	// Container without systemd.
	ctx2 := SystemContext{
		DistroID:       "alpine",
		DistroVer:      "3.18",
		PrettyName:     "Alpine Linux 3.18",
		Shell:          "/bin/sh",
		Home:           "/root",
		CWD:            "/root",
		Username:       "root",
		UID:            0,
		GID:            0,
		IsContainer:    true,
		ContainerRuntime: "podman",
		SystemdEnabled: false,
		Binaries:       map[string]bool{"systemctl": false},
	}
	s2 := ctx2.String()
	if !strings.Contains(s2, "Environment: Container") {
		t.Error("expected String() to include Container environment section")
	}
	if !strings.Contains(s2, "container-native alternatives") {
		t.Error("expected String() to mention container-native alternatives")
	}

	// Headless SSH.
	ctx3 := SystemContext{
		DistroID:   "debian",
		DistroVer:  "12",
		PrettyName: "Debian 12",
		Shell:      "/bin/bash",
		Home:       "/home/user",
		CWD:        "/home/user",
		Username:   "user",
		UID:        1000,
		GID:        1000,
		IsHeadlessSSH: true,
		Binaries:    map[string]bool{},
	}
	s3 := ctx3.String()
	if !strings.Contains(s3, "Environment: Headless SSH Session") {
		t.Error("expected String() to include Headless SSH environment section")
	}
}

// filepathJoin is a small helper to join dir + filename (avoids path import in test).
func filepathJoin(dir, file string) string {
	if dir == "" {
		return file
	}
	if strings.HasSuffix(dir, "/") {
		return dir + file
	}
	return dir + "/" + file
}
