package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sm-me-dev/lnta/internal/audit"
)

// Deterministic CLI exit codes for scripting and CI pipelines:
//
//	0 = Completed & Verified
//	1 = General / Execution Error
//	2 = Verification Failed
//	3 = User Cancelled / Approval Denied
//	4 = Sandbox / Environment Error
//	5 = Blocked before completion
//	6 = Completed without verification
const (
	ExitCodeSuccess            = 0
	ExitCodeGeneralError       = 1
	ExitCodeVerificationFailed = 2
	ExitCodeUserCancelled      = 3
	ExitCodeSandboxError       = 4
	ExitCodeBlocked            = 5
	ExitCodeUnverified         = 6
)

// ExitCoder is implemented by errors that carry a specific process exit code.
type ExitCoder interface {
	ExitCode() int
}

// ExitError represents an error associated with a specific CLI exit code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit code %d", e.Code)
}

func (e *ExitError) Unwrap() error {
	return e.Err
}

func (e *ExitError) ExitCode() int {
	return e.Code
}

// NewExitError creates a new ExitError with the given code and underlying error.
func NewExitError(code int, err error) *ExitError {
	return &ExitError{Code: code, Err: err}
}

// DetermineExitCode inspects execution error, result string, and run summary to return
// the deterministic exit code according to CLI standards:
//
//	0: Completed & Verified
//	1: General / Execution Error
//	2: Verification Failed
//	3: User Cancelled / Approval Denied
//	4: Sandbox / Environment Error
//	5: Blocked before completion
//	6: Completed without verification
func DetermineExitCode(err error, result string, summary *audit.RunSummary) int {
	if err != nil {
		var exitCoder ExitCoder
		if errors.As(err, &exitCoder) {
			return exitCoder.ExitCode()
		}
		if errors.Is(err, context.Canceled) ||
			strings.Contains(err.Error(), "context canceled") ||
			strings.Contains(err.Error(), "canceled") ||
			strings.Contains(err.Error(), "cancelled") {
			return ExitCodeUserCancelled
		}
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "approval denied") ||
			strings.Contains(errStr, "user did not approve") ||
			strings.Contains(errStr, "cancelled by user") ||
			strings.Contains(errStr, "canceled by user") {
			return ExitCodeUserCancelled
		}
		if strings.Contains(errStr, "bwrap") ||
			strings.Contains(errStr, "landlock") ||
			strings.Contains(errStr, "sandbox") ||
			strings.Contains(errStr, "apparmor") {
			return ExitCodeSandboxError
		}
		if strings.Contains(errStr, "verification") ||
			strings.Contains(errStr, "harness_verification_failed") {
			return ExitCodeVerificationFailed
		}
		return ExitCodeGeneralError
	}

	if strings.Contains(result, "MUTATE_BLOCKED: user did not approve") ||
		strings.Contains(result, "approval error") {
		return ExitCodeUserCancelled
	}
	if strings.Contains(result, "HARNESS_VERIFICATION_FAILED") || strings.Contains(result, "HARNESS_VERIFICATION_UNAVAILABLE") {
		return ExitCodeVerificationFailed
	}
	if strings.HasPrefix(result, "INSPECT_BLOCKED:") || strings.HasPrefix(result, "TASK_BLOCKED:") {
		return ExitCodeBlocked
	}
	if strings.HasPrefix(result, "TASK_COMPLETE_UNVERIFIED:") {
		return ExitCodeUnverified
	}

	if summary != nil {
		if summary.Status == audit.RunStatusCompleted || summary.Status == audit.RunStatusVerified {
			return ExitCodeSuccess
		}
		if summary.Status == audit.RunStatusNotRequired {
			return ExitCodeSuccess
		}
		if summary.Status == audit.RunStatusBlocked {
			return ExitCodeBlocked
		}
		if summary.Status == audit.RunStatusCompletedUnverified {
			return ExitCodeUnverified
		}
		if summary.Status == audit.RunStatusFailed {
			errStr := strings.ToLower(summary.Error)
			if strings.Contains(errStr, "cancel") ||
				strings.Contains(errStr, "approval") ||
				strings.Contains(errStr, "denied") {
				return ExitCodeUserCancelled
			}
			if strings.Contains(errStr, "bwrap") ||
				strings.Contains(errStr, "sandbox") ||
				strings.Contains(errStr, "landlock") ||
				strings.Contains(errStr, "apparmor") {
				return ExitCodeSandboxError
			}
			if len(summary.VerificationReceipt) > 0 {
				lastReceipt := summary.VerificationReceipt[len(summary.VerificationReceipt)-1]
				if !lastReceipt.Passed || lastReceipt.ExitCode != 0 {
					return ExitCodeVerificationFailed
				}
			}
			if summary.Error != "" {
				return ExitCodeGeneralError
			}
			return ExitCodeVerificationFailed
		}
	}

	if strings.Contains(result, "TASK_COMPLETE:") {
		return ExitCodeSuccess
	}

	return ExitCodeGeneralError
}
