package ui

import (
	"strings"
	"testing"
)

func TestVerificationReceiptOutcomeLabels(t *testing.T) {
	for _, tc := range []struct {
		status ReceiptStatus
		label  string
	}{
		{ReceiptCompleted, "COMPLETED"},
		{ReceiptUnverified, "COMPLETED — NOT VERIFIED"},
		{ReceiptBlocked, "BLOCKED"},
	} {
		receipt := VerificationReceipt(tc.status, "run-test", nil, nil)
		if !strings.Contains(receipt, tc.label) {
			t.Errorf("receipt for %q missing label %q", tc.status, tc.label)
		}
		if tc.status != ReceiptCompleted && strings.Contains(receipt, "verification gate passed") {
			t.Errorf("receipt for %q falsely claims verification passed", tc.status)
		}
	}
}
