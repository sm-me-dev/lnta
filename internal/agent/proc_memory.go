package agent

import (
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
)

type processMemory struct {
	PID      int
	Name     string
	RSSBytes uint64
}

type memoryTotals struct {
	MemTotal     uint64
	MemAvailable uint64
	SwapTotal    uint64
	SwapFree     uint64
}

func collectHostMemory(procRoot string) (string, error) {
	return collectHostMemoryFS(os.DirFS(procRoot), uint64(os.Getpagesize()))
}

func collectHostMemoryFS(proc fs.FS, pageSize uint64) (string, error) {
	if pageSize == 0 {
		return "", fmt.Errorf("invalid system page size")
	}
	meminfo, err := fs.ReadFile(proc, "meminfo")
	if err != nil {
		return "", fmt.Errorf("read /proc/meminfo: %w", err)
	}
	totals, err := parseMemoryTotals(string(meminfo))
	if err != nil {
		return "", err
	}
	entries, err := fs.ReadDir(proc, ".")
	if err != nil {
		return "", fmt.Errorf("list /proc: %w", err)
	}

	processes := make([]processMemory, 0, len(entries))
	skipped := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		data, err := fs.ReadFile(proc, entry.Name()+"/stat")
		if err != nil {
			skipped++
			continue
		}
		process, ok := parseProcessStat(string(data), pid, pageSize)
		if !ok {
			skipped++
			continue
		}
		processes = append(processes, process)
	}
	sort.Slice(processes, func(i, j int) bool {
		if processes[i].RSSBytes != processes[j].RSSBytes {
			return processes[i].RSSBytes > processes[j].RSSBytes
		}
		return processes[i].PID < processes[j].PID
	})

	byName := make(map[string]uint64)
	for _, process := range processes {
		byName[process.Name] += process.RSSBytes
	}
	groups := make([]processMemory, 0, len(byName))
	for name, rss := range byName {
		groups = append(groups, processMemory{Name: name, RSSBytes: rss})
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].RSSBytes != groups[j].RSSBytes {
			return groups[i].RSSBytes > groups[j].RSSBytes
		}
		return groups[i].Name < groups[j].Name
	})

	var b strings.Builder
	fmt.Fprintf(&b, "Scope: host (read-only /proc query)\n")
	fmt.Fprintf(&b, "Memory: total=%s used=%s available=%s\n",
		formatKiB(totals.MemTotal),
		formatKiB(totals.MemTotal-totals.MemAvailable),
		formatKiB(totals.MemAvailable))
	usedSwap := uint64(0)
	if totals.SwapFree <= totals.SwapTotal {
		usedSwap = totals.SwapTotal - totals.SwapFree
	}
	fmt.Fprintf(&b, "Swap: total=%s used=%s free=%s\n",
		formatKiB(totals.SwapTotal), formatKiB(usedSwap), formatKiB(totals.SwapFree))
	b.WriteString("Processes by RSS (PID, RSS, name):\n")
	const maxProcessRows = 50
	for i, process := range processes {
		if i == maxProcessRows {
			fmt.Fprintf(&b, "... %d more process(es) omitted\n", len(processes)-i)
			break
		}
		fmt.Fprintf(&b, "%d\t%s\t%q\n", process.PID, formatMiB(process.RSSBytes), process.Name)
	}
	b.WriteString("Grouped RSS by process name:\n")
	for i, group := range groups {
		if i == maxProcessRows {
			fmt.Fprintf(&b, "... %d more process group(s) omitted\n", len(groups)-i)
			break
		}
		fmt.Fprintf(&b, "%s\t%q\n", formatMiB(group.RSSBytes), group.Name)
	}
	if skipped > 0 {
		fmt.Fprintf(&b, "Skipped inaccessible or malformed process entries: %d\n", skipped)
	}
	b.WriteString("Recommendation only: review the largest RSS consumers; no process was changed.\n")
	return b.String(), nil
}

func parseMemoryTotals(data string) (memoryTotals, error) {
	values := make(map[string]uint64, 4)
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		switch key {
		case "MemTotal", "MemAvailable", "SwapTotal", "SwapFree":
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return memoryTotals{}, fmt.Errorf("malformed /proc/meminfo field %s", key)
			}
			values[key] = value
		}
	}
	for _, key := range []string{"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"} {
		if _, ok := values[key]; !ok {
			return memoryTotals{}, fmt.Errorf("missing /proc/meminfo field %s", key)
		}
	}
	if values["MemAvailable"] > values["MemTotal"] || values["SwapFree"] > values["SwapTotal"] {
		return memoryTotals{}, fmt.Errorf("inconsistent /proc/meminfo totals")
	}
	return memoryTotals{
		MemTotal: values["MemTotal"], MemAvailable: values["MemAvailable"],
		SwapTotal: values["SwapTotal"], SwapFree: values["SwapFree"],
	}, nil
}

func parseProcessStat(data string, pid int, pageSize uint64) (processMemory, bool) {
	open := strings.IndexByte(data, '(')
	close := strings.LastIndexByte(data, ')')
	if open < 0 || close <= open || close+1 >= len(data) {
		return processMemory{}, false
	}
	name := data[open+1 : close]
	fields := strings.Fields(data[close+1:])
	const rssFieldAfterComm = 21 // /proc/<pid>/stat field 24; field 3 starts at index 0.
	if name == "" || len(fields) <= rssFieldAfterComm {
		return processMemory{}, false
	}
	pages, err := strconv.ParseInt(fields[rssFieldAfterComm], 10, 64)
	if err != nil || pages < 0 || uint64(pages) > ^uint64(0)/pageSize {
		return processMemory{}, false
	}
	return processMemory{PID: pid, Name: name, RSSBytes: uint64(pages) * pageSize}, true
}

func formatMiB(bytes uint64) string {
	return fmt.Sprintf("%.1f MiB", float64(bytes)/(1024*1024))
}

func formatKiB(kib uint64) string {
	return fmt.Sprintf("%.1f MiB", float64(kib)/1024)
}
