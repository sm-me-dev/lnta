package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func BenchmarkLandlockProjectFixtures(b *testing.B) {
	fixtures := []struct {
		name          string
		entries       int
		build         func(string) error
		budgetFailure string
	}{
		{name: "realistic-165k", entries: 165_000, build: makeRealisticLandlockFixture},
		{name: "high-fanout", entries: 230_001, build: makeHighFanoutLandlockFixture, budgetFailure: "path byte limit"},
		{name: "long-path", entries: 33, build: makeLongPathLandlockFixture},
		{name: "credential-heavy", entries: 8_193, build: makeCredentialHeavyLandlockFixture, budgetFailure: "secret path byte limit"},
	}
	for _, fixture := range fixtures {
		b.Run(fixture.name, func(b *testing.B) {
			root, err := os.MkdirTemp("/tmp", "lnta-bench-")
			if err != nil {
				b.Fatal(err)
			}
			defer os.RemoveAll(root)
			if err := fixture.build(root); err != nil {
				b.Fatal(err)
			}
			tmp, err := os.MkdirTemp("/tmp", "lnta-bench-tmp-")
			if err != nil {
				b.Fatal(err)
			}
			defer os.RemoveAll(tmp)
			b.ReportAllocs()
			b.ResetTimer()
			started := time.Now()
			var rules, configBytes int
			for range b.N {
				cfg, err := buildLandlockConfig(root, root, "", tmp, "true", nil)
				if fixture.budgetFailure != "" {
					if err == nil || !strings.Contains(err.Error(), fixture.budgetFailure) {
						b.Fatalf("expected %q budget refusal, got %v", fixture.budgetFailure, err)
					}
					continue
				}
				if err != nil {
					b.Fatal(err)
				}
				rules = len(cfg.RODirs) + len(cfg.ROFiles) + len(cfg.ReadDirOnly) + len(cfg.RWDirs) + len(cfg.RWFiles)
				raw, err := json.Marshal(cfg)
				if err != nil {
					b.Fatal(err)
				}
				configBytes = len(raw)
			}
			b.StopTimer()
			b.ReportMetric(float64(fixture.entries), "entries/fixture")
			b.ReportMetric(float64(time.Since(started).Microseconds())/float64(b.N)/1000, "elapsed-ms/op")
			if fixture.budgetFailure != "" {
				b.ReportMetric(1, "budget-reject/op")
			} else {
				b.ReportMetric(float64(rules), "rules/op")
				b.ReportMetric(float64(configBytes), "config-B/op")
			}
			var usage unix.Rusage
			if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err == nil {
				b.ReportMetric(float64(usage.Maxrss)/1024, "peak-RSS-MiB")
			}
		})
	}
}

func makeRealisticLandlockFixture(root string) error {
	for directoryIndex := 0; directoryIndex < 33; directoryIndex++ {
		directory := filepath.Join(root, fmt.Sprintf("pkg%02d", directoryIndex))
		if err := os.Mkdir(directory, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(directory, ".env"), nil, 0o600); err != nil {
			return err
		}
		for fileIndex := 0; fileIndex < 4_998; fileIndex++ {
			name := fmt.Sprintf("f%x", directoryIndex*4_998+fileIndex)
			if err := os.WriteFile(filepath.Join(directory, name), nil, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

func makeHighFanoutLandlockFixture(root string) error {
	if err := os.WriteFile(filepath.Join(root, ".env"), nil, 0o600); err != nil {
		return err
	}
	for index := 0; index < 230_000; index++ {
		name := fmt.Sprintf("file-%07x", index)
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func makeLongPathLandlockFixture(root string) error {
	path := root
	for range maxProjectScanDepth {
		path = filepath.Join(path, strings.Repeat("x", 100))
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(path, ".env"), nil, 0o600)
}

func makeCredentialHeavyLandlockFixture(root string) error {
	longParent := filepath.Join(root, strings.Repeat("p", 245))
	if err := os.Mkdir(longParent, 0o700); err != nil {
		return err
	}
	for index := 0; index < maxProjectSecretPaths; index++ {
		directory := filepath.Join(longParent, fmt.Sprintf("d%04d", index))
		if err := os.Mkdir(directory, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(directory, ".env"), nil, 0o600); err != nil {
			return err
		}
	}
	return nil
}
