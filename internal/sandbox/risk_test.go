// Package sandbox tests for the Semantic Blast-Radius Classifier.
package sandbox

import (
	"strings"
	"testing"
)

func TestClassifyRiskCriticalDestructive(t *testing.T) {
	testCases := []struct {
		name     string
		command  string
		level    RiskLevel
		contains string // Should contain in reason
	}{
		{
			name:     "rm -rf root",
			command:  "rm -rf /",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "rm -rf var lib",
			command:  "rm -rf /var/lib/mysql",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "rm -fr variant",
			command:  "rm -fr /home/user/data",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "find -delete",
			command:  "find /var -name '*.log' -delete",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "find -exec rm",
			command:  "find /tmp -type f -exec rm {} \\;",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "dd if=/dev/zero",
			command:  "dd if=/dev/zero of=/dev/sda bs=1M",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "mkfs.ext4",
			command:  "mkfs.ext4 /dev/sdb1",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "mkfs.xfs",
			command:  "mkfs.xfs /dev/nvme0n1",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "fdisk",
			command:  "fdisk /dev/sda",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "parted",
			command:  "parted /dev/sda mklabel gpt",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "ufw --force reset",
			command:  "ufw --force reset",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "ufw disable",
			command:  "ufw disable",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "iptables -F",
			command:  "iptables -F",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "iptables --flush",
			command:  "iptables --flush",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "crontab -r",
			command:  "crontab -r",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "drop database",
			command:  "DROP DATABASE production;",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "drop table",
			command:  "DROP TABLE users;",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "write to /boot",
			command:  "echo 'bad' > /boot/grub/grub.cfg",
			level:    RiskCriticalDestructive,
			contains: "critical path",
		},
		{
			name:     "write to /etc/shadow",
			command:  "echo 'root:*:12345::::::' > /etc/shadow",
			level:    RiskCriticalDestructive,
			contains: "critical path",
		},
		{
			name:     "write to /etc/passwd",
			command:  "echo 'evil::0:0::/root:/bin/bash' >> /etc/passwd",
			level:    RiskCriticalDestructive,
			contains: "critical path",
		},
		{
			name:     "write to /etc/sudoers",
			command:  "tee /etc/sudoers <<< 'ALL ALL=(ALL) NOPASSWD:ALL'",
			level:    RiskCriticalDestructive,
			contains: "critical path",
		},
		{
			name:     "shred",
			command:  "shred -n 3 /dev/sda",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "wipefs",
			command:  "wipefs -a /dev/sdb",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "mv /dev/null over critical",
			command:  "mv /dev/null /etc/passwd",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "raw disk write redirect",
			command:  "cat /dev/zero > /dev/sda",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
		{
			name:     "chattr +i",
			command:  "chattr +i /etc/passwd",
			level:    RiskCriticalDestructive,
			contains: "destructive pattern",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			classification := ClassifyRisk(tc.command)
			if classification.Level != tc.level {
				t.Errorf("Expected %s, got %s. Reason: %s", tc.level, classification.Level, classification.Reason)
			}
			if !strings.Contains(classification.Reason, tc.contains) {
				t.Errorf("Reason should contain %q, got: %s", tc.contains, classification.Reason)
			}
			if classification.Level == RiskCriticalDestructive {
				if classification.Challenge == "" {
					t.Error("CRITICAL_DESTRUCTIVE should have a challenge code")
				}
				if len(classification.Challenge) != 4 {
					t.Errorf("Challenge code should be 4 chars, got %d: %s", len(classification.Challenge), classification.Challenge)
				}
				if !classification.RequireCode {
					t.Error("CRITICAL_DESTRUCTIVE should require challenge code")
				}
			}
		})
	}
}

func TestClassifyRiskElevatedMutation(t *testing.T) {
	testCases := []struct {
		name     string
		command  string
		level    RiskLevel
		contains string
	}{
		{
			name:     "apt install",
			command:  "apt install nginx",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "apt-get install",
			command:  "apt-get install -y docker.io",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "dnf install",
			command:  "dnf install httpd",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "pacman install",
			command:  "pacman -S --needed vim",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "sudo command",
			command:  "sudo systemctl restart nginx",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "systemctl restart",
			command:  "systemctl restart sshd",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "systemctl enable",
			command:  "systemctl enable docker",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "service restart",
			command:  "service nginx restart",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "chmod on /etc",
			command:  "chmod 777 /etc/passwd",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "chown on /usr",
			command:  "chown root:root /usr/bin/custom",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "mount",
			command:  "mount /dev/sdb1 /mnt",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "useradd",
			command:  "useradd -m newuser",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "passwd",
			command:  "passwd root",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "ufw allow",
			command:  "ufw allow 80/tcp",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "iptables -A",
			command:  "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "tee systemd service",
			command:  "tee /etc/systemd/system/myapp.service <<'EOF'\n[Service]\nExecStart=/usr/bin/myapp\nEOF",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
		{
			name:     "sysctl -w",
			command:  "sysctl -w net.ipv4.ip_forward=1",
			level:    RiskElevatedMutation,
			contains: "elevated",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			classification := ClassifyRisk(tc.command)
			if classification.Level != tc.level {
				t.Errorf("Expected %s, got %s. Reason: %s", tc.level, classification.Level, classification.Reason)
			}
			if !strings.Contains(strings.ToLower(classification.Reason), strings.ToLower(tc.contains)) {
				t.Errorf("Reason should contain %q, got: %s", tc.contains, classification.Reason)
			}
			if classification.Level == RiskElevatedMutation {
				if classification.RequireCode {
					t.Error("ELEVATED_MUTATION should NOT require challenge code")
				}
				if classification.Challenge != "" {
					t.Error("ELEVATED_MUTATION should not have challenge code")
				}
			}
		})
	}
}

func TestClassifyRiskLowMutation(t *testing.T) {
	testCases := []struct {
		name    string
		command string
		level   RiskLevel
	}{
		{
			name:    "systemctl --user daemon-reload",
			command: "systemctl --user daemon-reload",
			level:   RiskLowMutation,
		},
		{
			name:    "user-space config write",
			command: "echo 'export PATH=$PATH:/custom' >> ~/.bashrc",
			level:   RiskLowMutation,
		},
		{
			name:    "mkdir in home",
			command: "mkdir -p ~/projects/new",
			level:   RiskLowMutation,
		},
		{
			name:    "git clone in home",
			command: "git clone https://github.com/user/repo ~/repo",
			level:   RiskLowMutation,
		},
		{
			name:    "npm install local",
			command: "npm install lodash",
			level:   RiskLowMutation,
		},
		{
			name:    "python pip install --user",
			command: "pip install --user requests",
			level:   RiskLowMutation,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			classification := ClassifyRisk(tc.command)
			if classification.Level != tc.level {
				t.Errorf("Expected %s, got %s. Reason: %s", tc.level, classification.Level, classification.Reason)
			}
			if classification.Level == RiskLowMutation {
				if classification.RequireCode {
					t.Error("LOW_MUTATION should NOT require challenge code")
				}
				if classification.Challenge != "" {
					t.Error("LOW_MUTATION should not have challenge code")
				}
			}
		})
	}
}

func TestValidateChallengeCode(t *testing.T) {
	// Valid case-insensitive match
	if !ValidateChallengeCode("ABCD", "abcd") {
		t.Error("Case-insensitive match should work")
	}
	if !ValidateChallengeCode("ABCD", "ABCD") {
		t.Error("Exact match should work")
	}
	if !ValidateChallengeCode("ABCD", "  ABCD  ") {
		t.Error("Whitespace-trimmed match should work")
	}

	// Invalid cases
	if ValidateChallengeCode("ABCD", "ABCE") {
		t.Error("Wrong code should fail")
	}
	if ValidateChallengeCode("ABCD", "") {
		t.Error("Empty code should fail")
	}
	if ValidateChallengeCode("ABCD", "ABC") {
		t.Error("Partial code should fail")
	}
}

func TestChallengeCodeGeneration(t *testing.T) {
	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		classification := ClassifyRisk("rm -rf /test")
		code := classification.Challenge
		if len(code) != 4 {
			t.Errorf("Code length should be 4, got %d: %s", len(code), code)
		}
		// Check only valid chars (no 0, O, 1, I)
		for _, c := range code {
			if strings.ContainsRune("0O1I", c) {
				t.Errorf("Code should not contain confusing chars, got: %s", code)
			}
		}
		codes[code] = true
	}
	// Should have good entropy (very unlikely to have collisions in 100 samples)
	if len(codes) < 90 {
		t.Logf("Warning: only %d unique codes out of 100 (entropy may be low)", len(codes))
	}
}

func TestRiskClassificationFields(t *testing.T) {
	classification := ClassifyRisk("rm -rf /var/lib/docker")

	if classification.Level != RiskCriticalDestructive {
		t.Fatalf("Expected CRITICAL_DESTRUCTIVE, got %s", classification.Level)
	}

	if len(classification.Affected) == 0 {
		t.Error("Affected components should not be empty for CRITICAL_DESTRUCTIVE")
	}

	expectedComponents := []string{"Filesystem integrity", "System bootability", "Data persistence"}
	for _, expected := range expectedComponents {
		found := false
		for _, actual := range classification.Affected {
			if strings.Contains(actual, expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected affected component containing %q", expected)
		}
	}
}

func TestRiskLevelString(t *testing.T) {
	if RiskLowMutation.String() != "LOW_MUTATION" {
		t.Error("RiskLowMutation.String() failed")
	}
	if RiskElevatedMutation.String() != "ELEVATED_MUTATION" {
		t.Error("RiskElevatedMutation.String() failed")
	}
	if RiskCriticalDestructive.String() != "CRITICAL_DESTRUCTIVE" {
		t.Error("RiskCriticalDestructive.String() failed")
	}
}