package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	lnta "github.com/sm-me-dev/lnta"
	"github.com/sm-me-dev/lnta/internal/sandbox"
)

var (
	selfUpdateCheckOnly bool
	selfUpdateForce     bool
)

const (
	defaultGitHubRepo      = "sm-me-dev/lnta"
	releaseKeyFingerprint  = "45BFE7B566C24F984EF00F6AEE0178A118050BDB"
	maxUpdateArtifactBytes = 100 << 20
)

//go:embed release-key.asc
var releasePublicKey embed.FS

var selfUpdateCmd = &cobra.Command{
	Use:     "self-update",
	Aliases: []string{"upgrade"},
	Short:   "Update LNTA to the latest official release",
	Long: `Check for new releases on GitHub and update standalone installations in place.

If LNTA was installed via a system package manager (e.g. APT on Ubuntu/Debian),
this command detects the package ownership and instructs you to use your
system's native package manager to prevent state conflicts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSelfUpdate(cmd.Context(), selfUpdateCheckOnly, selfUpdateForce)
	},
}

func init() {
	selfUpdateCmd.Flags().BoolVar(&selfUpdateCheckOnly, "check", false,
		"Check for available updates without applying them")
	selfUpdateCmd.Flags().BoolVar(&selfUpdateForce, "force", false,
		"Force re-download and re-install even if already on the latest version")
}

// detectPackageManager checks whether the binary at binaryPath is managed by APT, RPM, or Pacman.
func detectPackageManager(ctx context.Context, binaryPath string) (bool, string) {
	if _, err := os.Stat(binaryPath); err != nil {
		return false, ""
	}

	// 1. Check dpkg (APT)
	if _, err := exec.LookPath("dpkg"); err == nil {
		if _, _, err := runUpdateCommand(ctx, "package_owner_check", "dpkg", []string{"-S", binaryPath}, nil); err == nil {
			return true, "APT"
		}
	}

	// 2. Check rpm (Fedora/RHEL/openSUSE)
	if _, err := exec.LookPath("rpm"); err == nil {
		if _, _, err := runUpdateCommand(ctx, "package_owner_check", "rpm", []string{"-qf", binaryPath}, nil); err == nil {
			return true, "RPM/DNF"
		}
	}

	// 3. Check pacman (Arch Linux)
	if _, err := exec.LookPath("pacman"); err == nil {
		if _, _, err := runUpdateCommand(ctx, "package_owner_check", "pacman", []string{"-Qo", binaryPath}, nil); err == nil {
			return true, "Pacman"
		}
	}

	return false, ""
}

func runUpdateCommand(parent context.Context, role, executable string, args []string, stdin io.Reader) (string, string, error) {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdin = stdin
	sandbox.ConfigureProcessGroup(cmd)
	stdout := sandbox.NewCappedBuffer(16*1024, 256*1024, cancel)
	stderr := sandbox.NewCappedBuffer(16*1024, 256*1024, cancel)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	started, err := sandbox.StartChild(role, cmd)
	if err != nil {
		return "", "", err
	}
	err = sandbox.WaitChild(role, cmd, started, ctx, stdout, stderr)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return stdout.Render(), stderr.Render(), err
}

// compareSemVer compares two semantic version strings.
// Returns -1 if current < latest (update available), 0 if equal, 1 if current > latest.
func compareSemVer(current, latest string) (int, error) {
	c := strings.TrimPrefix(strings.TrimSpace(current), "v")
	l := strings.TrimPrefix(strings.TrimSpace(latest), "v")

	// If current is dev/none/empty, latest always counts as an update.
	if c == "" || c == "dev" || c == "none" || c == "unknown" {
		return -1, nil
	}
	if l == "" || l == "dev" || l == "none" || l == "unknown" {
		return 0, nil
	}

	cParts, cPre := splitPreRelease(c)
	lParts, lPre := splitPreRelease(l)

	// Compare major.minor.patch
	maxLen := len(cParts)
	if len(lParts) > maxLen {
		maxLen = len(lParts)
	}

	for i := 0; i < maxLen; i++ {
		var cNum, lNum int
		var err error
		if i < len(cParts) {
			cNum, err = strconv.Atoi(cParts[i])
			if err != nil {
				return 0, fmt.Errorf("invalid current version number %q: %w", cParts[i], err)
			}
		}
		if i < len(lParts) {
			lNum, err = strconv.Atoi(lParts[i])
			if err != nil {
				return 0, fmt.Errorf("invalid latest version number %q: %w", lParts[i], err)
			}
		}

		if cNum < lNum {
			return -1, nil
		}
		if cNum > lNum {
			return 1, nil
		}
	}

	// Numerical versions match, compare pre-releases
	if cPre == "" && lPre != "" {
		// e.g. 0.1.0 is newer than 0.1.0-rc1
		return 1, nil
	}
	if cPre != "" && lPre == "" {
		// e.g. 0.1.0-rc1 is older than 0.1.0
		return -1, nil
	}
	if cPre < lPre {
		return -1, nil
	}
	if cPre > lPre {
		return 1, nil
	}

	return 0, nil
}

func splitPreRelease(v string) ([]string, string) {
	idx := strings.Index(v, "-")
	var pre string
	if idx >= 0 {
		pre = v[idx+1:]
		v = v[:idx]
	}
	parts := strings.Split(v, ".")
	return parts, pre
}

// parseChecksums finds the SHA-256 hash for targetAsset in checksums.txt data.
func parseChecksums(checksumsData, targetAsset string) (string, error) {
	lines := strings.Split(checksumsData, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			hash := fields[0]
			filename := strings.TrimPrefix(fields[1], "*")
			if filename == targetAsset {
				return strings.ToLower(hash), nil
			}
		}
	}
	return "", fmt.Errorf("checksum for asset %q not found in checksums.txt", targetAsset)
}

// verifySHA256 verifies that the content read from r produces expectedHash.
func verifySHA256(r io.Reader, expectedHash string) error {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return fmt.Errorf("calculate sha256: %w", err)
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expectedHash) {
		return fmt.Errorf("SHA-256 checksum mismatch: expected %s, got %s", expectedHash, actual)
	}
	return nil
}

// extractBinaryFromTarGz extracts the named binary from a .tar.gz reader and writes it to destPath.
func extractBinaryFromTarGz(r io.Reader, binaryName, destPath string) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		if filepath.Base(header.Name) == binaryName && header.Typeflag == tar.TypeReg {
			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("create output file %s: %w", destPath, err)
			}
			written, err := io.Copy(outFile, io.LimitReader(tr, maxUpdateArtifactBytes+1))
			if err != nil {
				outFile.Close()
				return fmt.Errorf("write extracted binary: %w", err)
			}
			if written > maxUpdateArtifactBytes {
				outFile.Close()
				return fmt.Errorf("extracted binary exceeds %d-byte limit", maxUpdateArtifactBytes)
			}
			outFile.Close()
			return nil
		}
	}

	return fmt.Errorf("binary %q not found in archive", binaryName)
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

func fetchLatestRelease(repo string) (*githubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "lnta-self-update/"+lnta.Version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch release metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no published releases found yet on https://github.com/%s", repo)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status %s (%d)", resp.Status, resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release metadata: %w", err)
	}
	return &rel, nil
}

func downloadURLToBytes(url string) ([]byte, error) {
	return downloadURLToBytesLimit(url, maxUpdateArtifactBytes)
}

func downloadURLToBytesLimit(url string, limit int64) ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read download %s: %w", url, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("download %s exceeds %d-byte limit", url, limit)
	}
	return data, nil
}

func verifyReleaseChecksums(ctx context.Context, checksums, signature []byte) error {
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		return fmt.Errorf("gpg is required to verify release signature: %w", err)
	}
	gpgvPath, err := exec.LookPath("gpgv")
	if err != nil {
		return fmt.Errorf("gpgv is required to verify release signature: %w", err)
	}
	key, err := releasePublicKey.ReadFile("release-key.asc")
	if err != nil {
		return fmt.Errorf("read embedded release key: %w", err)
	}
	fingerprintOutput, _, err := runUpdateCommand(ctx, "update_gpg_fingerprint", gpgPath, []string{"--batch", "--show-keys", "--with-colons"}, strings.NewReader(string(key)))
	if err != nil {
		return fmt.Errorf("inspect embedded release key: %w", err)
	}
	var fingerprint string
	for _, line := range strings.Split(string(fingerprintOutput), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "fpr" {
			fingerprint = fields[9]
			break
		}
	}
	if fingerprint != releaseKeyFingerprint {
		return fmt.Errorf("embedded release key fingerprint mismatch")
	}
	tmpDir, err := os.MkdirTemp("", "lnta-update-verify-*")
	if err != nil {
		return fmt.Errorf("create signature verification directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	keyPath := filepath.Join(tmpDir, "release-key.gpg")
	if _, output, err := runUpdateCommand(ctx, "update_gpg_dearmor", gpgPath, []string{"--batch", "--dearmor", "--output", keyPath}, strings.NewReader(string(key))); err != nil {
		return fmt.Errorf("prepare embedded release key: %w: %s", err, strings.TrimSpace(string(output)))
	}
	checksumsPath := filepath.Join(tmpDir, "checksums.txt")
	signaturePath := filepath.Join(tmpDir, "checksums.txt.sig")
	if err := os.WriteFile(checksumsPath, checksums, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		return err
	}
	if _, output, err := runUpdateCommand(ctx, "update_gpg_verify", gpgvPath, []string{"--keyring", keyPath, signaturePath, checksumsPath}, nil); err != nil {
		return fmt.Errorf("release checksum signature verification failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runSelfUpdate(ctx context.Context, checkOnly, force bool) error {
	// 1. Locate current running binary
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable path: %w", err)
	}
	evalPath, err := filepath.EvalSymlinks(execPath)
	if err != nil {
		evalPath = execPath
	}

	// 2. Package manager ownership check
	if isManaged, pkgManager := detectPackageManager(ctx, evalPath); isManaged {
		switch pkgManager {
		case "APT":
			fmt.Println("lnta is managed by APT.")
			fmt.Println("Run 'sudo apt update && sudo apt upgrade lnta' to update.")
		case "RPM/DNF":
			fmt.Println("lnta is managed by RPM/DNF.")
			fmt.Println("Run 'sudo dnf upgrade lnta' to update.")
		case "Pacman":
			fmt.Println("lnta is managed by Pacman.")
			fmt.Println("Run 'sudo pacman -Syu lnta' to update.")
		default:
			fmt.Printf("lnta is managed by system package manager (%s).\n", pkgManager)
			fmt.Println("Please update LNTA using your system package manager.")
		}
		return nil
	}

	// 3. Query latest GitHub release
	fmt.Printf("Checking for updates (current version: %s)...\n", lnta.Version)
	rel, err := fetchLatestRelease(defaultGitHubRepo)
	if err != nil {
		return fmt.Errorf("check latest release: %w", err)
	}

	latestVersion := strings.TrimPrefix(rel.TagName, "v")
	cmp, err := compareSemVer(lnta.Version, latestVersion)
	if err != nil {
		return fmt.Errorf("compare versions: %w", err)
	}

	if cmp >= 0 && !force {
		fmt.Printf("lnta is already up to date (%s).\n", lnta.Version)
		return nil
	}

	if checkOnly {
		fmt.Printf("Update available: %s -> %s\n", lnta.Version, rel.TagName)
		fmt.Println("Run 'lnta self-update' to install the new version.")
		return nil
	}

	// 4. Check write permissions to destination directory/file
	testFile, err := os.OpenFile(evalPath, os.O_WRONLY, 0)
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("permission denied writing to %s; run 'sudo lnta self-update'", evalPath)
		}
	} else {
		testFile.Close()
	}

	// 5. Detect architecture and target asset
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("unsupported system architecture: %s", arch)
	}

	targetAssetName := fmt.Sprintf("lnta_%s_linux_%s.tar.gz", latestVersion, arch)
	var assetURL string
	var checksumsURL string
	var signatureURL string

	for _, a := range rel.Assets {
		if a.Name == targetAssetName {
			assetURL = a.BrowserDownloadURL
		}
		if a.Name == "checksums.txt" {
			checksumsURL = a.BrowserDownloadURL
		}
		if a.Name == "checksums.txt.sig" {
			signatureURL = a.BrowserDownloadURL
		}
	}

	if assetURL == "" {
		return fmt.Errorf("release %s does not contain matching asset %q", rel.TagName, targetAssetName)
	}
	if checksumsURL == "" {
		return fmt.Errorf("release %s is missing checksums.txt", rel.TagName)
	}
	if signatureURL == "" {
		return fmt.Errorf("release %s is missing the signed checksum file", rel.TagName)
	}

	// 6. Download checksums.txt and find expected hash
	fmt.Println("Fetching release checksums...")
	checksumsBytes, err := downloadURLToBytesLimit(checksumsURL, 1<<20)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}
	signatureBytes, err := downloadURLToBytesLimit(signatureURL, 1<<20)
	if err != nil {
		return fmt.Errorf("download checksum signature: %w", err)
	}
	if err := verifyReleaseChecksums(ctx, checksumsBytes, signatureBytes); err != nil {
		return err
	}

	expectedHash, err := parseChecksums(string(checksumsBytes), targetAssetName)
	if err != nil {
		return fmt.Errorf("parse checksum: %w", err)
	}

	// 7. Download tarball asset
	fmt.Printf("Downloading %s (%s)...\n", targetAssetName, rel.TagName)
	tarballBytes, err := downloadURLToBytes(assetURL)
	if err != nil {
		return fmt.Errorf("download asset: %w", err)
	}

	// 8. Verify SHA-256 hash
	fmt.Println("Verifying SHA-256 checksum...")
	if err := verifySHA256(strings.NewReader(string(tarballBytes)), expectedHash); err != nil {
		return err
	}

	// 9. Extract binary to temp file in the SAME directory as the binary (ensures same filesystem for atomic rename)
	destDir := filepath.Dir(evalPath)
	tempFile, err := os.CreateTemp(destDir, ".lnta-update-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary update binary: %w", err)
	}
	tempPath := tempFile.Name()
	tempFile.Close()
	defer os.Remove(tempPath) // Cleaned up if rename fails

	fmt.Println("Extracting binary...")
	if err := extractBinaryFromTarGz(strings.NewReader(string(tarballBytes)), "lnta", tempPath); err != nil {
		return err
	}

	if err := os.Chmod(tempPath, 0755); err != nil {
		return fmt.Errorf("set executable permissions: %w", err)
	}
	if err := validateUpdateBinary(tempPath); err != nil {
		return err
	}
	if f, err := os.OpenFile(tempPath, os.O_RDWR, 0); err != nil {
		return fmt.Errorf("open staged update for sync: %w", err)
	} else if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync staged update: %w", err)
	} else {
		_ = f.Close()
	}

	// 10. Atomically replace existing binary
	if err := os.Rename(tempPath, evalPath); err != nil {
		return fmt.Errorf("atomically replace %s: %w", evalPath, err)
	}
	if dir, err := os.Open(destDir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}

	fmt.Printf("Successfully updated lnta from %s to %s at %s\n", lnta.Version, rel.TagName, evalPath)
	return nil
}

func validateUpdateBinary(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open staged update binary: %w", err)
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return fmt.Errorf("staged update binary is incomplete: %w", err)
	}
	if magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		return fmt.Errorf("staged update is not a Linux ELF binary")
	}
	return nil
}
