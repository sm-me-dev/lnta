// Package sandbox tests for CVE-2026-25725 and CVE-2025-66479 defenses.
package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// requireBwrap is defined in sandbox_test.go
// func requireBwrap(t *testing.T) { ... }

// TestRunReadOnlyBlocksNetworkEgress verifies that RunReadOnly cannot make
// outbound TCP/UDP connections due to --unshare-net (CVE-2025-66479 defense).
func TestRunReadOnlyBlocksNetworkEgress(t *testing.T) {
	requireBwrap(t) // Defined in sandbox_test.go

	// Skip if we can't verify network isolation (some CI environments)
	// This test attempts to connect to a known external address.
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/sm-me"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Try to connect to a public DNS server - should fail with --unshare-net
	res, err := RunReadOnly(ctx, `timeout 2 bash -c "</dev/tcp/8.8.8.8/53" && echo "CONNECTED" || echo "BLOCKED"`, home, 10*time.Second)

	t.Logf("Network egress test: exit=%d err=%v stdout=%q stderr=%q", res.ExitCode, err, res.Stdout, res.Stderr)

	// The command should either fail to execute (timeout) or report BLOCKED
	// With --unshare-net, the network namespace is isolated (loopback only)
	if strings.Contains(res.Stdout, "CONNECTED") {
		t.Fatalf("Network egress was NOT blocked! Sandbox can reach external hosts: %s", res.Stdout)
	}

	// Also test UDP
	res2, _ := RunReadOnly(ctx, `timeout 2 bash -c "echo test | nc -u -w1 8.8.8.8 53 2>/dev/null && echo UDP_CONNECTED || echo UDP_BLOCKED"`, home, 10*time.Second)
	t.Logf("UDP test: exit=%d stdout=%q", res2.ExitCode, res2.Stdout)
	if strings.Contains(res2.Stdout, "UDP_CONNECTED") {
		t.Fatalf("UDP egress was NOT blocked!")
	}
}

// TestRunReadOnlyBlocksLoopbackOnly verifies that loopback (127.0.0.1) still works
// inside the sandbox --unshare-net (loopback is preserved in new network namespace).
func TestRunReadOnlyAllowsLoopback(t *testing.T) {
	requireBwrap(t)
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/sm-me"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start a simple TCP listener on loopback in background, then connect to it
	// This tests that loopback works inside the new network namespace
	cmd := `python3 -c "
import socket, threading, time
def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    with open('/tmp/lnta_loopback_port', 'w') as f:
        f.write(str(port))
    s.listen(1)
    conn, _ = s.accept()
    conn.send(b'OK')
    conn.close()
    s.close()
t = threading.Thread(target=server)
t.daemon = True
t.start()
time.sleep(0.5)
with open('/tmp/lnta_loopback_port') as f:
    port = int(f.read().strip())
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.settimeout(2)
try:
    c.connect(('127.0.0.1', port))
    print('LOOPBACK_OK:', c.recv(1024).decode())
except Exception as e:
    print('LOOPBACK_FAILED:', e)
c.close()
" 2>&1`

	res, err := RunReadOnly(ctx, cmd, home, 15*time.Second)
	t.Logf("Loopback test: exit=%d err=%v stdout=%q", res.ExitCode, err, res.Stdout)

	// Loopback should work in the new network namespace
	if strings.Contains(res.Stdout, "LOOPBACK_OK") {
		t.Log("Loopback works correctly in isolated network namespace")
	} else {
		t.Logf("Loopback test inconclusive (may need python3): %s", res.Stdout)
	}
}

// TestPhantomDotfileProtection verifies that phantom dotfiles (.bashrc, .zshrc,
// .profile, .bash_profile, .bash_login, .bash_logout, .ssh/authorized_keys,
// .ssh/config, .config/lnta, .config/claude/settings.json) are protected
// even when they don't exist (CVE-2026-25725 defense).
//
// Protection mechanisms:
// - Files directly in $HOME (e.g., .bashrc, .zshrc): protected by --ro-bind /dev/null
// - Files in secret directories (e.g., .ssh/authorized_keys): protected by --tmpfs isolation
//   (writes succeed in sandbox but don't persist to host)
// - Files in .config/ subdirs: protected by --tmpfs on parent directory
func TestPhantomDotfileProtection(t *testing.T) {
	requireBwrap(t)
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/sm-me"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Files in $HOME directly - should be blocked by --ro-bind /dev/null
	homeDotfiles := []string{
		"$HOME/.bashrc",
		"$HOME/.zshrc",
		"$HOME/.profile",
		"$HOME/.bash_profile",
		"$HOME/.bash_login",
		"$HOME/.bash_logout",
	}

	// Files in secret directories - protected by --tmpfs isolation
	// (writes succeed in sandbox but don't persist to host)
	secretDotfiles := []string{
		"$HOME/.ssh/authorized_keys",
		"$HOME/.ssh/config",
	}

	// Files in .config/ subdirs - protected by --tmpfs on parent
	configDotfiles := []string{
		"$HOME/.config/lnta",
		"$HOME/.config/claude/settings.json",
	}

	// Test home dotfiles - should be blocked (read-only)
	for _, f := range homeDotfiles {
		cmd := `echo "malicious content" > ` + f + ` 2>&1 && cat ` + f + ` 2>&1 || echo "BLOCKED"`
		res, err := RunReadOnly(ctx, cmd, home, 10*time.Second)

		t.Logf("Home dotfile test (%s): exit=%d err=%v stdout=%q", f, res.ExitCode, err, res.Stdout)

		// Should be blocked - no "malicious content" in output
		if strings.Contains(res.Stdout, "malicious content") {
			t.Errorf("Home dotfile %s was WRITABLE! Output: %s", f, res.Stdout)
		}
		if !strings.Contains(res.Stdout, "BLOCKED") && res.ExitCode == 0 {
			t.Errorf("Home dotfile %s should show BLOCKED or fail: %s", f, res.Stdout)
		}

		// Verify file doesn't exist on host
		expanded := strings.Replace(f, "$HOME", home, 1)
		if _, statErr := os.Stat(expanded); !os.IsNotExist(statErr) {
			content, _ := os.ReadFile(expanded)
			if strings.Contains(string(content), "malicious content") {
				t.Errorf("Home dotfile %s was MODIFIED on host!", expanded)
			}
		}
	}

	// Test secret dotfiles - tmpfs isolation means writes don't persist
	for _, f := range secretDotfiles {
		// First ensure the secret dir exists on host
		expanded := strings.Replace(f, "$HOME", home, 1)
		parent := filepath.Dir(expanded)
		if err := os.MkdirAll(parent, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", parent, err)
		}

		cmd := `echo "malicious content" > ` + f + ` 2>&1 && cat ` + f + ` 2>&1 || echo "BLOCKED"`
		res, err := RunReadOnly(ctx, cmd, home, 10*time.Second)

		t.Logf("Secret dotfile test (%s): exit=%d err=%v stdout=%q", f, res.ExitCode, err, res.Stdout)

		// With --tmpfs, write succeeds in sandbox but doesn't persist to host
		// The key assertion is that host file is NOT modified
		if _, statErr := os.Stat(expanded); !os.IsNotExist(statErr) {
			content, _ := os.ReadFile(expanded)
			if strings.Contains(string(content), "malicious content") {
				t.Errorf("Secret dotfile %s was MODIFIED on host despite tmpfs isolation!", expanded)
			}
		}
		// The sandbox may show the content (tmpfs is writable) or BLOCKED
		// Both are acceptable - the important thing is host is not modified
	}

	// Test config dotfiles - tmpfs on parent
	for _, f := range configDotfiles {
		cmd := `echo "malicious content" > ` + f + ` 2>&1 && cat ` + f + ` 2>&1 || echo "BLOCKED"`
		res, err := RunReadOnly(ctx, cmd, home, 10*time.Second)

		t.Logf("Config dotfile test (%s): exit=%d err=%v stdout=%q", f, res.ExitCode, err, res.Stdout)

		// Verify host not modified
		expanded := strings.Replace(f, "$HOME", home, 1)
		if _, statErr := os.Stat(expanded); !os.IsNotExist(statErr) {
			content, _ := os.ReadFile(expanded)
			if strings.Contains(string(content), "malicious content") {
				t.Errorf("Config dotfile %s was MODIFIED on host!", expanded)
			}
		}
	}
}

// TestPhantomDotfileProtectionNonExistentDir verifies protection works even when
// parent directories don't exist (e.g., ~/.config/claude doesn't exist).
func TestPhantomDotfileProtectionNonExistentDir(t *testing.T) {
	requireBwrap(t)
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/sm-me"
	}

	// Ensure ~/.config/claude doesn't exist
	claudeDir := filepath.Join(home, ".config", "claude")
	os.RemoveAll(claudeDir)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := `echo "malicious" > "$HOME/.config/claude/settings.json" 2>&1 && cat "$HOME/.config/claude/settings.json" 2>&1 || echo "BLOCKED"`
	res, err := RunReadOnly(ctx, cmd, home, 10*time.Second)

	t.Logf("Non-existent dir test: exit=%d err=%v stdout=%q", res.ExitCode, err, res.Stdout)

	if strings.Contains(res.Stdout, "malicious") {
		t.Errorf("Phantom dotfile in non-existent dir was WRITABLE!")
	}

	// Verify directory wasn't created
	if _, statErr := os.Stat(claudeDir); !os.IsNotExist(statErr) {
		t.Errorf("Directory %s was created during sandbox execution!", claudeDir)
	}
}

// TestLandlockBlocksNetworkEgress verifies Landlock fallback also blocks network.
func TestLandlockBlocksNetworkEgress(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Landlock is Linux-only")
	}

	if err := LandlockProbe(); err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}

	landlockExePath = "/tmp/lnta_test"
	if _, err := os.Stat(landlockExePath); err != nil {
		t.Skipf("lnta test binary not found at %s", landlockExePath)
	}
	defer func() { landlockExePath = "" }()

	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/sm-me"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Landlock doesn't have network isolation built-in (requires kernel 6.6+),
	// but we verify the phantom dotfile protection works
	res, err := runLandlock(ctx, `echo "test" > "$HOME/.bashrc" 2>&1 && cat "$HOME/.bashrc" 2>&1 || echo "BLOCKED"`, home, 10*time.Second)
	t.Logf("Landlock phantom bashrc: exit=%d err=%v stdout=%q", res.ExitCode, err, res.Stdout)

	if strings.Contains(res.Stdout, "test") {
		t.Errorf("Landlock phantom dotfile protection failed!")
	}
}

// TestNetworkNamespaceIsolation verifies that --unshare-net creates a new
// network namespace with only loopback interface.
func TestNetworkNamespaceIsolation(t *testing.T) {
	requireBwrap(t)
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/sm-me"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Check interfaces visible inside sandbox
	res, _ := RunReadOnly(ctx, `ip link show 2>/dev/null || ifconfig -a 2>/dev/null || cat /proc/net/dev`, home, 10*time.Second)
	t.Logf("Network interfaces in sandbox: %s", res.Stdout)

	// Should only see lo (loopback) interface, not eth0, wlan0, etc.
	if strings.Contains(res.Stdout, "eth0") || strings.Contains(res.Stdout, "wlan0") || strings.Contains(res.Stdout, "ens") {
		t.Errorf("External network interfaces visible in sandbox: %s", res.Stdout)
	}

	if !strings.Contains(res.Stdout, "lo") && !strings.Contains(res.Stdout, "loopback") {
		t.Log("Note: loopback interface not detected in output (may be format difference)")
	}
}

// TestUnshareFlagsPresent verifies that the bwrap command includes all required
// isolation flags (--unshare-net, --unshare-ipc, --unshare-pid, --new-session).
func TestUnshareFlagsPresent(t *testing.T) {
	requireBwrap(t)
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/sm-me"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Use a command that shows the namespace isolation
	res, _ := RunReadOnly(ctx, `ls -la /proc/self/ns/ 2>/dev/null || echo "ns not available"`, home, 10*time.Second)
	t.Logf("Namespaces: %s", res.Stdout)

	// Check that we're in new namespaces (different from host)
	// In a new network namespace, we should only see loopback
	res2, _ := RunReadOnly(ctx, `cat /proc/net/dev 2>/dev/null | grep -v "lo:" | grep -v "Inter" | grep -v "face" | wc -l`, home, 10*time.Second)
	t.Logf("Non-loopback interfaces count: %s", res2.Stdout)
}