package main

import (
	"errors"
	"os"
	"os/exec"
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
		{name: "explicit apparmor denial", probe: sandbox.BwrapProbe{ExitStatus: 1, Stderr: `apparmor="DENIED" operation="userns_create"`}, err: sandbox.ErrBwrapBlocked, want: "explicit AppArmor denial"},
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

func TestSelectSandboxBackend(t *testing.T) {
	tests := []struct {
		name        string
		probe       sandbox.BwrapProbe
		bwrapErr    error
		landlockErr error
		wantBackend string
		wantStatus  string
	}{
		{name: "bwrap operational", probe: sandbox.BwrapProbe{ExitStatus: 0}, landlockErr: sandbox.ErrLandlockUnavailable, wantBackend: "bwrap", wantStatus: "Bubblewrap available and operational"},
		{name: "landlock fallback", probe: sandbox.BwrapProbe{ExitStatus: 1}, bwrapErr: sandbox.ErrBwrapBlocked, wantBackend: "landlock", wantStatus: "Landlock fallback operational"},
		{name: "neither", probe: sandbox.BwrapProbe{ExitStatus: 1}, bwrapErr: sandbox.ErrBwrapBlocked, landlockErr: sandbox.ErrLandlockUnavailable, wantStatus: "neither supported confined backend"},
		{name: "indeterminate", probe: sandbox.BwrapProbe{ExitStatus: -1}, bwrapErr: errors.New("probe setup failed"), landlockErr: errors.New("launcher unavailable"), wantStatus: "cannot be determined reliably"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backend, status, err := selectSandboxBackend(tc.probe, tc.bwrapErr, tc.landlockErr)
			if tc.wantBackend != "" && (err != nil || backend != tc.wantBackend) {
				t.Fatalf("got backend=%q status=%q err=%v", backend, status, err)
			}
			if tc.wantBackend == "" && err == nil {
				t.Fatalf("expected unavailable status, got %q", status)
			}
			if !strings.Contains(status, tc.wantStatus) {
				t.Fatalf("status %q does not include %q", status, tc.wantStatus)
			}
		})
	}
}

func TestDoctorExitStatusTracksRequiredSandboxCapability(t *testing.T) {
	if err := doctorSandboxExitError(nil); err != nil {
		t.Fatalf("operational supported backend should allow doctor success: %v", err)
	}
	want := errors.New("no supported sandbox backend")
	if err := doctorSandboxExitError(want); !errors.Is(err, want) {
		t.Fatalf("unavailable sandbox did not produce doctor failure: %v", err)
	}
}

func TestDoctorNeverPrintsAPIKeyMaterial(t *testing.T) {
	secret := "sensitive-prefix-and-rest"
	if got := doctorKeyDisplay(secret); got != "configured" || strings.Contains(got, secret) || strings.Contains(got, secret[:8]) {
		t.Fatalf("doctor exposed API key material: %q", got)
	}
	if got := doctorKeyDisplay(""); got != "(none/local)" {
		t.Fatalf("unexpected empty API key status: %q", got)
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
	config, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "scripts/apparmor-profile") || strings.Contains(string(config), "/etc/apparmor.d/bwrap") {
		t.Fatal("GoReleaser still references retired distro AppArmor policy")
	}
}

func TestPackagingInputValidationFailsWhenHookMissing(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".goreleaser.yaml"), []byte("nfpms: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Join(root, "scripts", "deb")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"postinstall.sh", "preremove.sh", "postremove.sh"} {
		if err := os.WriteFile(filepath.Join(hooks, name), []byte("#!/bin/sh\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join("..", "..", "scripts", "deb", "validate-inputs.sh")
	cmd := exec.Command("sh", script)
	cmd.Env = append(os.Environ(), "LNTA_REPO_ROOT="+root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("valid packaging inputs rejected: %v: %s", err, out)
	}
	if err := os.Remove(filepath.Join(hooks, "postremove.sh")); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("sh", script)
	cmd.Env = append(os.Environ(), "LNTA_REPO_ROOT="+root)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "required packaging input missing") {
		t.Fatalf("missing required input did not fail visibly: err=%v output=%s", err, out)
	}
}
