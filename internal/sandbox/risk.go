// Package sandbox provides risk classification for mutate_system commands.
// This implements the Semantic Blast-Radius Classifier for Phase 9.
package sandbox

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"
)

// RiskLevel represents the blast-radius risk tier of a mutate_system command.
type RiskLevel string

const (
	// RiskLowMutation - Scoped user-space changes (e.g., systemctl --user daemon-reload).
	// Uses standard [y/N] prompt.
	RiskLowMutation RiskLevel = "LOW_MUTATION"

	// RiskElevatedMutation - Package installation (apt, dnf, pacman), sudo usage,
	// service restarts (systemctl restart), permission changes (chmod/chown).
	// Renders a yellow warning banner highlighting affected system components + [y/N] (default N).
	RiskElevatedMutation RiskLevel = "ELEVATED_MUTATION"

	// RiskCriticalDestructive - Matches destructive patterns (rm -rf, find -delete,
	// dd if=, mkfs, fdisk, parted, ufw --force reset, iptables -F, crontab -r,
	// dropping databases, or writing to /boot or /etc/shadow).
	// Anti-Fatigue Challenge Gate: disables simple [y/N] and ignores --yes flags.
	// Requires typing a random 4-character confirmation code or target path basename.
	RiskCriticalDestructive RiskLevel = "CRITICAL_DESTRUCTIVE"
)

// String returns the string representation of the risk level.
func (r RiskLevel) String() string {
	return string(r)
}

// RiskClassification contains the risk assessment for a command.
type RiskClassification struct {
	Level       RiskLevel
	Reason      string            // Human-readable explanation
	Affected    []string          // System components affected
	Challenge   string            // Challenge code for CRITICAL_DESTRUCTIVE (empty otherwise)
	RequireCode bool              // Whether challenge code is required
}

// Destructive patterns that trigger CRITICAL_DESTRUCTIVE classification.
// These are compiled regex patterns for efficient matching.
var destructivePatterns = []*regexp.Regexp{
	// rm -rf / rm -fr / rm -Rf variations (flexible spacing)
	regexp.MustCompile(`(?i)\brm\s+(-[rfFR]+|-r\s+-f|-f\s+-r)\b`),
	// find ... -delete / find ... -exec rm
	regexp.MustCompile(`(?i)\bfind\s+.*\s+-delete\b`),
	regexp.MustCompile(`(?i)\bfind\s+.*\s+-exec\s+rm\b`),
	// dd if= (disk destruction)
	regexp.MustCompile(`(?i)\bdd\s+.*\bif\s*=`),
	// mkfs / mkfs.* (filesystem creation)
	regexp.MustCompile(`(?i)\bmkfs(\.\w+)?\b`),
	// fdisk / parted (partition manipulation)
	regexp.MustCompile(`(?i)\b(fdisk|parted)\b`),
	// ufw --force reset / ufw disable
	regexp.MustCompile(`(?i)\bufw\s+.*(--force\s+reset|disable)\b`),
	// iptables -F / iptables --flush
	regexp.MustCompile(`(?i)\biptables\s+.*(-F|--flush)\b`),
	// crontab -r (removes all crontabs)
	regexp.MustCompile(`(?i)\bcrontab\s+-r\b`),
	// Drop database commands
	regexp.MustCompile(`(?i)\bdrop\s+(database|schema|table)\b`),
	// shred / wipefs
	regexp.MustCompile(`(?i)\b(shred|wipefs)\b`),
	// mv /dev/null over critical files
	regexp.MustCompile(`(?i)\bmv\s+/dev/null\s+`),
	// > /dev/sda / > /dev/nvme (raw disk writes)
	regexp.MustCompile(`>\s*/dev/(sd|nvme|vd|hd|xvd)[a-z]`),
	// chattr +i (immutable flag on critical files)
	regexp.MustCompile(`(?i)\bchattr\s+\+i\b`),
}

// Elevated patterns that trigger ELEVATED_MUTATION classification.
var elevatedPatterns = []*regexp.Regexp{
	// Package managers
	regexp.MustCompile(`(?i)\b(apt|apt-get|dnf|yum|pacman|zypper|apk)\s+(install|remove|purge|upgrade|dist-upgrade|-S|-R|-U)\b`),
	// sudo usage
	regexp.MustCompile(`(?i)\bsudo\b`),
	// systemctl restart / start / stop / enable / disable (system services)
	regexp.MustCompile(`(?i)\bsystemctl\s+(restart|start|stop|enable|disable|reload|mask|unmask)\b`),
	// service command
	regexp.MustCompile(`(?i)\bservice\s+\w+\s+(restart|start|stop|reload)\b`),
	// chmod / chown on system directories
	regexp.MustCompile(`(?i)\b(chmod|chown)\s+.*\s+(/etc|/usr|/bin|/sbin|/lib|/boot|/root)\b`),
	// mount / umount
	regexp.MustCompile(`(?i)\b(mount|umount)\b`),
	// useradd / usermod / userdel / groupadd / groupmod / groupdel
	regexp.MustCompile(`(?i)\b(useradd|usermod|userdel|groupadd|groupmod|groupdel)\b`),
	// passwd
	regexp.MustCompile(`(?i)\bpasswd\b`),
	// ufw enable / allow / deny (non-destructive firewall changes)
	regexp.MustCompile(`(?i)\bufw\s+(enable|allow|deny|delete|limit|reject)\b`),
	// iptables -A / -I / -D (non-flush rules)
	regexp.MustCompile(`(?i)\biptables\s+.*(-A|-I|-D)\b`),
	// systemd service file writes
	regexp.MustCompile(`(?i)\btee\s+/etc/systemd/system/`),
	// kernel parameter changes
	regexp.MustCompile(`(?i)\bsysctl\s+-w\b`),
}

// Critical paths that trigger CRITICAL_DESTRUCTIVE when written to.
var criticalPaths = []string{
	"/boot/",
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"/etc/fstab",
	"/etc/crypttab",
	"/proc/",
	"/sys/",
	"/dev/mem",
	"/dev/kmem",
	"/dev/port",
}

// classifyDestructive checks if command matches any destructive pattern.
func classifyDestructive(cmd string) (bool, string) {
	for _, pattern := range destructivePatterns {
		if pattern.MatchString(cmd) {
			return true, pattern.String()
		}
	}
	// Check for writes to critical paths
	for _, path := range criticalPaths {
		if strings.Contains(cmd, path) {
			// Heuristic: check if it's a write operation (>, >>, tee, sed -i, etc.)
			writePatterns := []string{">", ">>", "tee ", "sed -i", "awk -i", "perl -pi", "cp ", "mv ", "dd "}
			for _, wp := range writePatterns {
				if strings.Contains(cmd, wp) {
					return true, fmt.Sprintf("write to critical path %s", path)
				}
			}
		}
	}
	return false, ""
}

// classifyElevated checks if command matches any elevated pattern.
func classifyElevated(cmd string) (bool, string) {
	for _, pattern := range elevatedPatterns {
		if pattern.MatchString(cmd) {
			return true, pattern.String()
		}
	}
	return false, ""
}

// generateChallengeCode generates a random 4-character alphanumeric code.
func generateChallengeCode() string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // No confusing chars: 0,O,1,I
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// Fallback if crypto/rand fails (should not happen)
		return "ABCD"
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}

// ClassifyRisk analyzes a mutate_system command and returns its risk classification.
func ClassifyRisk(command string) RiskClassification {
	cmd := strings.TrimSpace(command)

	// Check for CRITICAL_DESTRUCTIVE first (highest priority)
	if destructive, pattern := classifyDestructive(cmd); destructive {
		code := generateChallengeCode()
		return RiskClassification{
			Level:       RiskCriticalDestructive,
			Reason:      fmt.Sprintf("Command matches destructive pattern: %s", pattern),
			Affected:    []string{"Filesystem integrity", "System bootability", "Data persistence"},
			Challenge:   code,
			RequireCode: true,
		}
	}

	// Check for ELEVATED_MUTATION
	if elevated, pattern := classifyElevated(cmd); elevated {
		return RiskClassification{
			Level:       RiskElevatedMutation,
			Reason:      fmt.Sprintf("Command matches elevated privilege pattern: %s", pattern),
			Affected:    []string{"System packages", "System services", "User accounts", "Firewall rules"},
			Challenge:   "",
			RequireCode: false,
		}
	}

	// Default to LOW_MUTATION
	return RiskClassification{
		Level:       RiskLowMutation,
		Reason:      "Command appears to be a scoped user-space operation",
		Affected:    []string{"User session", "User configuration"},
		Challenge:   "",
		RequireCode: false,
	}
}

// ValidateChallengeCode checks if the user-provided code matches the expected challenge.
func ValidateChallengeCode(expected, provided string) bool {
	return strings.EqualFold(strings.TrimSpace(expected), strings.TrimSpace(provided))
}