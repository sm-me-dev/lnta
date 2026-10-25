package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sm-me-dev/lnta/internal/sandbox"
)

func TestDiagnoseBwrapProbeBranches(t *testing.T) {
	tests := []struct {
		name         string
		probe        sandbox.BwrapProbe
		err          error
		apparmor     string
		userns       string
		usernsErr    error
		usernsMax    string
		usernsMaxErr error
		profiles     []string
		profileErr   error
		want         string
		mustNotHave  string
	}{
		{name: "missing", err: sandbox.ErrBwrapNotFound, want: "missing from PATH"},
		{name: "user namespaces disabled", probe: sandbox.BwrapProbe{ExitStatus: 1, Stderr: "uid map denied"}, err: sandbox.ErrBwrapBlocked, userns: "0", want: "unprivileged user namespaces are disabled"},
		{name: "user namespace limit disabled", probe: sandbox.BwrapProbe{ExitStatus: 1, Stderr: "uid map denied"}, err: sandbox.ErrBwrapBlocked, usernsErr: os.ErrNotExist, usernsMax: "0", want: "user.max_user_namespaces=0"},
		{name: "timeout", probe: sandbox.BwrapProbe{TimedOut: true, Duration: 3 * time.Second}, err: sandbox.ErrBwrapBlocked, want: "timed out"},
		{name: "sysctl is not diagnosis", probe: sandbox.BwrapProbe{ExitStatus: 1, Stderr: "loopback setup failed"}, err: sandbox.ErrBwrapBlocked, apparmor: "1", usernsErr: os.ErrNotExist, profileErr: os.ErrPermission, want: "sysctl alone does not identify", mustNotHave: "blocked by AppArmor"},
		{name: "readable policy", probe: sandbox.BwrapProbe{ExitStatus: 1}, err: sandbox.ErrBwrapBlocked, profiles: []string{"bwrap-userns-restrict (enforce)"}, want: "bwrap-userns-restrict"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := diagnoseBwrapProbe(tc.probe, tc.err, tc.apparmor, tc.userns, tc.usernsErr, tc.usernsMax, tc.usernsMaxErr, tc.profiles, tc.profileErr).Error()
			if !strings.Contains(got, tc.want) {
				t.Fatalf("diagnosis %q does not contain %q", got, tc.want)
			}
			if tc.mustNotHave != "" && strings.Contains(got, tc.mustNotHave) {
				t.Fatalf("diagnosis %q contains unsupported conclusion %q", got, tc.mustNotHave)
			}
		})
	}
	if !errors.Is(diagnoseBwrapProbe(sandbox.BwrapProbe{}, sandbox.ErrBwrapNotFound, "", "", nil, "", nil, nil, nil), sandbox.ErrBwrapNotFound) {
		t.Fatal("missing-bwrap diagnostic did not preserve its cause")
	}
}

func TestGenerateAppArmorProfilePrintsGuidanceOnly(t *testing.T) {
	got := generateAppArmorProfile()
	for _, want := range []string{"sudo aa-status", "sudo journalctl -k", "lnta doctor --verbose", "bwrap-userns-restrict"} {
		if !strings.Contains(got, want) {
			t.Errorf("guidance missing %q", want)
		}
	}
	for _, forbidden := range []string{"profile bwrap", "apparmor_parser", "sudo tee", "userns,"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("guidance contains policy or mutating command %q", forbidden)
		}
	}
}

func TestBwrapAttachmentStatus(t *testing.T) {
	for _, tc := range []struct {
		label string
		want  string
	}{
		{label: "", want: "not observed"},
		{label: "unconfined", want: "no confined label observed"},
		{label: "bwrap-userns-restrict (enforce)", want: "confined label observed"},
	} {
		if got := bwrapAttachmentStatus(tc.label); !strings.Contains(got, tc.want) {
			t.Errorf("bwrapAttachmentStatus(%q) = %q; want substring %q", tc.label, got, tc.want)
		}
	}
}

func TestPackageHooksDoNotChangeAppArmorPolicy(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, name := range []string{"postinstall.sh", "preremove.sh", "postremove.sh"} {
		body, err := os.ReadFile(filepath.Join(root, "scripts", "deb", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"apparmor_parser", "/etc/apparmor.d", "rm -f"} {
			if strings.Contains(string(body), forbidden) {
				t.Errorf("%s contains system AppArmor mutation %q", name, forbidden)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(root, "scripts", "apparmor-profile")); !os.IsNotExist(err) {
		t.Fatalf("retired AppArmor profile artifact still exists (stat err: %v)", err)
	}
}
