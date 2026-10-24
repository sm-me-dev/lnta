package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestCompareSemVer(t *testing.T) {
	tests := []struct {
		current  string
		latest   string
		expected int // -1 if current < latest (update available), 0 if equal, 1 if current > latest
		wantErr  bool
	}{
		{"0.1.0", "0.2.0", -1, false},
		{"v0.1.0", "0.2.0", -1, false},
		{"0.2.0", "0.1.0", 1, false},
		{"0.1.0", "0.1.0", 0, false},
		{"v0.1.0", "v0.1.0", 0, false},
		{"0.9.0", "0.10.0", -1, false},
		{"0.10.0", "0.9.0", 1, false},
		{"0.1.0-rc1", "0.1.0", -1, false},
		{"0.1.0", "0.1.0-rc1", 1, false},
		{"dev", "0.1.0", -1, false},
		{"", "0.1.0", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.current+"_vs_"+tt.latest, func(t *testing.T) {
			got, err := compareSemVer(tt.current, tt.latest)
			if (err != nil) != tt.wantErr {
				t.Fatalf("compareSemVer(%q, %q) error = %v, wantErr %v", tt.current, tt.latest, err, tt.wantErr)
			}
			if got != tt.expected {
				t.Errorf("compareSemVer(%q, %q) = %d, want %d", tt.current, tt.latest, got, tt.expected)
			}
		})
	}
}

func TestParseChecksums(t *testing.T) {
	checksumsData := `
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  lnta_0.1.0_linux_amd64.tar.gz
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad lnta_0.1.0_linux_arm64.tar.gz
`
	// Match double-space line
	hash, err := parseChecksums(checksumsData, "lnta_0.1.0_linux_amd64.tar.gz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedAmd64 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hash != expectedAmd64 {
		t.Errorf("expected %s, got %s", expectedAmd64, hash)
	}

	// Match single-space line
	hash, err = parseChecksums(checksumsData, "lnta_0.1.0_linux_arm64.tar.gz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedArm64 := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if hash != expectedArm64 {
		t.Errorf("expected %s, got %s", expectedArm64, hash)
	}

	// Missing asset
	_, err = parseChecksums(checksumsData, "nonexistent.tar.gz")
	if err == nil {
		t.Errorf("expected error for nonexistent asset, got nil")
	}
}

func TestVerifySHA256(t *testing.T) {
	data := []byte("hello lnta self-update")
	h := sha256.Sum256(data)
	correctHash := hex.EncodeToString(h[:])

	// Correct hash should pass
	if err := verifySHA256(bytes.NewReader(data), correctHash); err != nil {
		t.Errorf("expected valid checksum to pass, got: %v", err)
	}

	// Wrong hash should fail
	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := verifySHA256(bytes.NewReader(data), wrongHash); err == nil {
		t.Errorf("expected corrupted checksum to fail, got nil")
	}
}

func TestExtractBinaryFromTarGz(t *testing.T) {
	// Create mock .tar.gz in memory
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	binaryContent := []byte("#!/bin/sh\necho 'mock lnta binary'\n")
	header := &tar.Header{
		Name: "lnta",
		Mode: 0755,
		Size: int64(len(binaryContent)),
	}
	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf("failed to write tar header: %v", err)
	}
	if _, err := tw.Write(binaryContent); err != nil {
		t.Fatalf("failed to write tar body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}

	tmpDir := t.TempDir()
	extractedPath := filepath.Join(tmpDir, "lnta")

	err := extractBinaryFromTarGz(bytes.NewReader(buf.Bytes()), "lnta", extractedPath)
	if err != nil {
		t.Fatalf("failed to extract binary: %v", err)
	}

	readBack, err := os.ReadFile(extractedPath)
	if err != nil {
		t.Fatalf("failed to read extracted binary: %v", err)
	}
	if !bytes.Equal(readBack, binaryContent) {
		t.Errorf("extracted content does not match: expected %q, got %q", binaryContent, readBack)
	}

	// Verify permissions
	info, err := os.Stat(extractedPath)
	if err != nil {
		t.Fatalf("failed to stat extracted binary: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Errorf("expected executable permissions, got mode: %v", info.Mode())
	}
}

func TestDetectPackageManagerNonExistent(t *testing.T) {
	managed, pkgManager := detectPackageManager("/nonexistent/dummy/path/to/lnta")
	if managed {
		t.Errorf("expected nonexistent path to not be package-managed, got managed by %s", pkgManager)
	}
}
