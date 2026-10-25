package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestProcessLifecycleDetailsAreBoundedAndPrivate(t *testing.T) {
	started := time.Now().Add(-23 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := processStartDetails("mutate_system", 1234)
	complete := processCompletionDetails("mutate_system", "1234", started, ctx, 0, 15, 7)
	for key, want := range map[string]string{"role": "mutate_system", "pid": "1234", "pgid": "1234"} {
		if start[key] != want {
			t.Errorf("start details[%q]=%q want %q", key, start[key], want)
		}
	}
	for key, want := range map[string]string{
		"role": "mutate_system", "pid": "1234", "pgid": "1234", "exit_status": "0",
		"canceled": "false", "timed_out": "false", "stdout_bytes": "15", "stderr_bytes": "7",
	} {
		if complete[key] != want {
			t.Errorf("completion details[%q]=%q want %q", key, complete[key], want)
		}
	}
	if _, ok := complete["elapsed_ms"]; !ok {
		t.Fatal("completion details missing elapsed time")
	}
	for _, details := range []map[string]string{start, complete} {
		for key := range details {
			if strings.Contains(key, "command") || strings.Contains(key, "output") || strings.Contains(key, "prompt") || strings.Contains(key, "env") {
				t.Errorf("unexpected private lifecycle field %q", key)
			}
		}
	}
}

func TestProcessLifecycleDetailsMarkTimeout(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	details := processCompletionDetails("bwrap", "55", time.Now(), ctx, 137, 0, 32)
	if details["canceled"] != "true" || details["timed_out"] != "true" {
		t.Fatalf("timeout flags missing: %#v", details)
	}
}
