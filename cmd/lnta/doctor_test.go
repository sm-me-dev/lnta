package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sm-me-dev/lnta/internal/agent"
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

func TestDoctorChecksClassification(t *testing.T) {
	want := map[string]struct {
		class   doctorClass
		sandbox bool
	}{
		"LLM Configuration":      {doctorRequired, false},
		"LLM Connectivity":       {doctorRequired, false},
		"Kernel Sandbox":         {doctorRequired, true},
		"Validator Binaries":     {doctorRequired, false},
		"Recommended Validators": {doctorOptional, false},
	}
	got := doctorChecks()
	if len(got) != len(want) {
		t.Fatalf("doctorChecks() returned %d checks, want %d", len(got), len(want))
	}
	for _, c := range got {
		w, ok := want[c.name]
		if !ok {
			t.Fatalf("unclassified doctor check %q", c.name)
		}
		if c.class != w.class || c.sandbox != w.sandbox {
			t.Errorf("check %q: class=%v sandbox=%v, want class=%v sandbox=%v", c.name, c.class, c.sandbox, w.class, w.sandbox)
		}
		if c.fn == nil {
			t.Errorf("check %q has no implementation", c.name)
		}
	}
}

func fakeDoctorChecks(config, connectivity, sandboxErr, validators, recommended error) []doctorCheck {
	fn := func(err error) func() error { return func() error { return err } }
	return []doctorCheck{
		{name: "LLM Configuration", class: doctorRequired, fn: fn(config)},
		{name: "LLM Connectivity", class: doctorRequired, fn: fn(connectivity)},
		{name: "Kernel Sandbox", class: doctorRequired, sandbox: true, fn: fn(sandboxErr)},
		{name: "Validator Binaries", class: doctorRequired, fn: fn(validators)},
		{name: "Recommended Validators", class: doctorOptional, fn: fn(recommended)},
	}
}

func TestRunDoctorChecksExitSemantics(t *testing.T) {
	errConfig := errors.New("LNTA_API_KEY not set")
	errConn := errors.New("connect to https://llm.invalid: dial failed")
	errSandbox := errors.New("neither supported confined backend is operational")
	errValidators := errors.New("missing required validators: ss")
	errRecommended := errors.New("recommended validators not found: ufw")

	tests := []struct {
		name        string
		checks      []doctorCheck
		wantCode    int
		wantInErr   []string
		notInErr    []string
		wantOutput  []string
		notInOutput []string
	}{
		{
			name:        "all required pass",
			checks:      fakeDoctorChecks(nil, nil, nil, nil, nil),
			wantCode:    agent.ExitCodeSuccess,
			wantOutput:  []string{"All checks passed"},
			notInOutput: []string{"FAIL", "WARN"},
		},
		{
			name:       "sandbox failure",
			checks:     fakeDoctorChecks(nil, nil, errSandbox, nil, nil),
			wantCode:   agent.ExitCodeSandboxError,
			wantInErr:  []string{"Kernel Sandbox", errSandbox.Error(), "required confined sandbox capability unavailable"},
			wantOutput: []string{"FAIL", "1 required check(s) failed"},
		},
		{
			name:       "LLM configuration failure",
			checks:     fakeDoctorChecks(errConfig, nil, nil, nil, nil),
			wantCode:   agent.ExitCodeGeneralError,
			wantInErr:  []string{"LLM Configuration", errConfig.Error()},
			notInErr:   []string{"Kernel Sandbox"},
			wantOutput: []string{"FAIL"},
		},
		{
			name:      "required connectivity failure",
			checks:    fakeDoctorChecks(nil, errConn, nil, nil, nil),
			wantCode:  agent.ExitCodeGeneralError,
			wantInErr: []string{"LLM Connectivity", errConn.Error()},
		},
		{
			name:      "missing required validator binaries",
			checks:    fakeDoctorChecks(nil, nil, nil, errValidators, nil),
			wantCode:  agent.ExitCodeGeneralError,
			wantInErr: []string{"Validator Binaries", errValidators.Error()},
		},
		{
			name:        "optional failure only",
			checks:      fakeDoctorChecks(nil, nil, nil, nil, errRecommended),
			wantCode:    agent.ExitCodeSuccess,
			wantOutput:  []string{"WARN", "All required checks passed", "1 optional check(s)"},
			notInOutput: []string{"FAIL", "required check(s) failed"},
		},
		{
			name:       "multiple required failures keep every diagnostic",
			checks:     fakeDoctorChecks(errConfig, errConn, nil, errValidators, nil),
			wantCode:   agent.ExitCodeGeneralError,
			wantInErr:  []string{errConfig.Error(), errConn.Error(), errValidators.Error()},
			wantOutput: []string{"3 required check(s) failed"},
		},
		{
			name:      "sandbox plus another required failure reports sandbox code",
			checks:    fakeDoctorChecks(errConfig, nil, errSandbox, nil, nil),
			wantCode:  agent.ExitCodeSandboxError,
			wantInErr: []string{errConfig.Error(), errSandbox.Error()},
		},
		{
			name:       "mixed required and optional failures",
			checks:     fakeDoctorChecks(errConfig, nil, nil, nil, errRecommended),
			wantCode:   agent.ExitCodeGeneralError,
			wantInErr:  []string{errConfig.Error()},
			notInErr:   []string{errRecommended.Error()},
			wantOutput: []string{"FAIL", "WARN", "1 required check(s) failed"},
		},
		{
			name: "informational failure never affects exit status",
			checks: []doctorCheck{
				{name: "Required OK", class: doctorRequired, fn: func() error { return nil }},
				{name: "Info Only", class: doctorInformational, fn: func() error { return errors.New("fyi") }},
			},
			wantCode:    agent.ExitCodeSuccess,
			wantOutput:  []string{"INFO", "All required checks passed"},
			notInOutput: []string{"FAIL"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var terse, verbose bytes.Buffer
			terseErr := runDoctorChecks(&terse, tc.checks, false)
			verboseErr := runDoctorChecks(&verbose, tc.checks, true)

			code := 0
			if terseErr != nil {
				code = exitCodeForError(terseErr)
			}
			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d (err=%v)", code, tc.wantCode, terseErr)
			}
			if (terseErr == nil) != (verboseErr == nil) {
				t.Fatalf("verbose and non-verbose disagree: terse=%v verbose=%v", terseErr, verboseErr)
			}
			if terseErr != nil {
				if exitCodeForError(verboseErr) != code || terseErr.Error() != verboseErr.Error() {
					t.Fatalf("verbose changed failure semantics: %v vs %v", terseErr, verboseErr)
				}
				for _, want := range tc.wantInErr {
					if !strings.Contains(terseErr.Error(), want) {
						t.Errorf("error %q does not contain %q", terseErr, want)
					}
				}
				for _, bad := range tc.notInErr {
					if strings.Contains(terseErr.Error(), bad) {
						t.Errorf("error %q unexpectedly contains %q", terseErr, bad)
					}
				}
			}
			for _, want := range tc.wantOutput {
				if !strings.Contains(terse.String(), want) {
					t.Errorf("output missing %q:\n%s", want, terse.String())
				}
			}
			for _, bad := range tc.notInOutput {
				if strings.Contains(terse.String(), bad) {
					t.Errorf("output unexpectedly contains %q:\n%s", bad, terse.String())
				}
			}
			// The summary must agree with the exit status.
			if code == 0 && strings.Contains(terse.String(), "required check(s) failed") {
				t.Errorf("summary reports failure but exit status is success:\n%s", terse.String())
			}
			if code != 0 && strings.Contains(terse.String(), "All checks passed") {
				t.Errorf("summary reports success but exit status is %d:\n%s", code, terse.String())
			}
		})
	}
}

func TestDoctorCLIExitHelper(t *testing.T) {
	if os.Getenv("LNTA_DOCTOR_CHILD") != "1" {
		return
	}
	mode := os.Getenv("LNTA_DOCTOR_CASE")
	checks := fakeDoctorChecks(nil, nil, nil, nil, nil)
	switch mode {
	case "required":
		checks = fakeDoctorChecks(errors.New("injected config failure"), nil, nil, nil, nil)
	case "sandbox":
		checks = fakeDoctorChecks(nil, nil, errors.New("injected sandbox failure"), nil, nil)
	case "optional":
		checks = fakeDoctorChecks(nil, nil, nil, nil, errors.New("injected optional warning"))
	}
	doctorChecksOverride = checks
	args := []string{"doctor"}
	if os.Getenv("LNTA_DOCTOR_VERBOSE") == "1" {
		args = append(args, "--verbose")
	}
	rootCmd.SetArgs(args)
	main() // exercises Cobra and the real process exit-code handler
}

func TestDoctorCLIUsesExactProcessExitCodes(t *testing.T) {
	tests := []struct {
		name       string
		want       int
		diagnostic string
		summary    string
	}{
		{name: "required", want: 1, diagnostic: "injected config failure", summary: "1 required check(s) failed"},
		{name: "sandbox", want: 4, diagnostic: "injected sandbox failure", summary: "1 required check(s) failed"},
		{name: "optional", want: 0, diagnostic: "injected optional warning", summary: "All required checks passed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outputs := make([]string, 2)
			for i, verbose := range []bool{false, true} {
				cmd := exec.Command(os.Args[0], "-test.run=^TestDoctorCLIExitHelper$")
				cmd.Env = append(os.Environ(), "LNTA_DOCTOR_CHILD=1", "LNTA_DOCTOR_CASE="+tc.name)
				if verbose {
					cmd.Env = append(cmd.Env, "LNTA_DOCTOR_VERBOSE=1")
				}
				out, err := cmd.CombinedOutput()
				outputs[i] = string(out)
				code := 0
				if err != nil {
					var exitErr *exec.ExitError
					if !errors.As(err, &exitErr) {
						t.Fatalf("child process error: %v\n%s", err, out)
					}
					code = exitErr.ExitCode()
				}
				if code != tc.want {
					t.Errorf("verbose=%v exit=%d want %d; output:\n%s", verbose, code, tc.want, out)
				}
				if !strings.Contains(string(out), tc.summary) {
					t.Errorf("verbose=%v missing summary %q:\n%s", verbose, tc.summary, out)
				}
				if (tc.name != "optional" || verbose) && !strings.Contains(string(out), tc.diagnostic) {
					t.Errorf("verbose=%v missing diagnostic %q:\n%s", verbose, tc.diagnostic, out)
				}
			}
			for _, phrase := range []string{"injected config failure", "injected sandbox failure"} {
				if strings.Contains(outputs[0], phrase) != strings.Contains(outputs[1], phrase) {
					t.Errorf("verbose mode changed diagnostic presence for %q", phrase)
				}
			}
			if tc.name == "optional" && strings.Contains(outputs[0], tc.diagnostic) {
				t.Fatal("terse optional warning unexpectedly exposed its detail")
			}
		})
	}
}

func TestDoctorFailureErrorsKeepCauses(t *testing.T) {
	cause := errors.New("underlying cause")
	err := runDoctorChecks(&bytes.Buffer{}, fakeDoctorChecks(nil, nil, cause, nil, nil), false)
	if !errors.Is(err, cause) {
		t.Fatalf("doctor error does not wrap the check's cause: %v", err)
	}
	if got := exitCodeForError(errors.New("plain error")); got != agent.ExitCodeGeneralError {
		t.Fatalf("plain errors must exit %d, got %d", agent.ExitCodeGeneralError, got)
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
