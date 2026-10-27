package main

import (
	"strings"
	"testing"

	"github.com/sm-me-dev/lnta/internal/packs"
)

func TestRenderResultDoesNotCertifyUnverifiedOrBlockedOutcomes(t *testing.T) {
	pack := packs.Pack{VerifyCmd: "true"}
	for _, tc := range []struct {
		result string
		status string
	}{
		{"TASK_COMPLETE_UNVERIFIED: findings\nverification_status: NOT_REQUIRED", "COMPLETED — NOT VERIFIED"},
		{"INSPECT_BLOCKED: unsafe project entry", "BLOCKED"},
	} {
		rendered := renderResult(tc.result, "run-test", pack)
		if !strings.Contains(rendered, tc.status) {
			t.Errorf("rendered result missing %q: %s", tc.status, rendered)
		}
		if strings.Contains(rendered, "verification gate passed") {
			t.Errorf("rendered result falsely claims verification passed: %s", rendered)
		}
	}
}

func TestNextRunIDIsUniqueWithinChatSession(t *testing.T) {
	first := nextRunID()
	second := nextRunID()
	if first == second || !strings.HasPrefix(first, "run-") || !strings.HasPrefix(second, "run-") {
		t.Fatalf("run ids are not unique: %q, %q", first, second)
	}
}
