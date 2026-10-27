package agent

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

type trackingProcFS struct {
	fs.FS
	opened []string
}

func (f *trackingProcFS) Open(name string) (fs.File, error) {
	f.opened = append(f.opened, name)
	return f.FS.Open(name)
}

func syntheticStat(pid int, name string, rssPages int) string {
	fields := make([]string, 22)
	fields[0] = "S"
	for i := 1; i < len(fields); i++ {
		fields[i] = "0"
	}
	fields[21] = fmt.Sprint(rssPages)
	return fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(fields, " "))
}

func TestCollectHostMemoryFSUsesOnlyMeminfoAndStat(t *testing.T) {
	proc := &trackingProcFS{FS: fstest.MapFS{
		"meminfo":     {Data: []byte("MemTotal: 1024000 kB\nMemAvailable: 512000 kB\nSwapTotal: 1048576 kB\nSwapFree: 524288 kB\n")},
		"100/stat":    {Data: []byte(syntheticStat(100, "worker (pool)", 4))},
		"101/stat":    {Data: []byte(syntheticStat(101, "worker (pool)", 2))},
		"42/status":   {Data: []byte("Name: vanished\n")},
		"43/stat":     {Data: []byte("malformed process stat\n")},
		"100/cmdline": {Data: []byte("private argument secret")},
		"100/environ": {Data: []byte("PRIVATE=secret")},
	}}

	report, err := collectHostMemoryFS(proc, 1024*1024)
	if err != nil {
		t.Fatalf("collectHostMemoryFS: %v", err)
	}
	for _, want := range []string{
		"Memory: total=1000.0 MiB used=500.0 MiB available=500.0 MiB",
		"Swap: total=1024.0 MiB used=512.0 MiB free=512.0 MiB",
		"100\t4.0 MiB\t\"worker (pool)\"",
		"Grouped RSS by process name:",
		"6.0 MiB\t\"worker (pool)\"",
		"Skipped inaccessible or malformed process entries: 2",
		"no process was changed",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "private argument secret") || strings.Contains(report, "PRIVATE=secret") {
		t.Fatal("report exposed process arguments or environment data")
	}
	for _, opened := range proc.opened {
		if strings.HasSuffix(opened, "/cmdline") || strings.HasSuffix(opened, "/environ") {
			t.Fatalf("collector read forbidden proc file %q", opened)
		}
	}
}

func TestCollectHostMemoryFSRejectsIncompleteMeminfo(t *testing.T) {
	proc := fstest.MapFS{"meminfo": {Data: []byte("MemTotal: broken kB\n")}}
	if _, err := collectHostMemoryFS(proc, 4096); err == nil || !strings.Contains(err.Error(), "malformed /proc/meminfo") {
		t.Fatalf("expected malformed meminfo error, got %v", err)
	}
}

func TestInspectHostRAMDoesNotRequireProjectExecutor(t *testing.T) {
	result, err := inspectSystem(context.Background(), mustMarshal(map[string]any{
		"scope": "host", "query": "ram", "reason": "diagnose memory",
	}), ToolDeps{ProjectRoot: "/project/with/symlink"})
	if err != nil || !strings.Contains(result, "Scope: host") || !strings.Contains(result, "Grouped RSS by process name:") {
		t.Fatalf("result=%q error=%v", result, err)
	}
}
