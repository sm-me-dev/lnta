package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
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
)

var (
	selfUpdateCheckOnly bool
	selfUpdateForce     bool
)

const (
	defaultGitHubRepo = "sm-me-dev/lnta"
)

var selfUpdateCmd = &cobra.Command{
	Use:     "self-update",
	Aliases: []string{"upgrade"},
	Short:   "Update LNTA to the latest official release",
	Long: `Check for new releases on GitHub and update standalone installations in place.

If LNTA was installed via a system package manager (e.g. APT on Ubuntu/Debian),
this command detects the package ownership and instructs you to use your
system's native package manager to prevent state conflicts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSelfUpdate(selfUpdateCheckOnly, selfUpdateForce)
	},
}

func init() {
	selfUpdateCmd.Flags().BoolVar(&selfUpdateCheckOnly, "check", false,
		"Check for available updates without applying them")
	selfUpdateCmd.Flags().BoolVar(&selfUpdateForce, "force", false,
		"Force re-download and re-install even if already on the latest version")
}

// detectPackageManager checks whether the binary at binaryPath is managed by APT, RPM, or Pacman.
func detectPackageManager(binaryPath string) (bool, string) {
	if _, err := os.Stat(binaryPath); err != nil {
		return false, ""
	}

	// 1. Check dpkg (APT)
	if _, err := exec.LookPath("dpkg"); err == nil {
		cmd := exec.Command("dpkg", "-S", binaryPath)
		if err := cmd.Run(); err == nil {
			return true, "APT"
		}
	}

	// 2. Check rpm (Fedora/RHEL/openSUSE)
	if _, err := exec.LookPath("rpm"); err == nil {
		cmd := exec.Command("rpm", "-qf", binaryPath)
		if err := cmd.Run(); err == nil {
			return true, "RPM/DNF"
		}
	}

	// 3. Check pacman (Arch Linux)
	if _, err := exec.LookPath("pacman"); err == nil {
		cmd := exec.Command("pacman", "-Qo", binaryPath)
		if err := cmd.Run(); err == nil {
			return true, "Pacman"
		}
	}

	return false, ""
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
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("write extracted binary: %w", err)
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
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release metadata: %w", err)
	}
	return &rel, nil
}

func downloadURLToBytes(url string) ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func runSelfUpdate(checkOnly, force bool) error {
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
	if isManaged, pkgManager := detectPackageManager(evalPath); isManaged {
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

	for _, a := range rel.Assets {
		if a.Name == targetAssetName {
			assetURL = a.BrowserDownloadURL
		}
		if a.Name == "checksums.txt" {
			checksumsURL = a.BrowserDownloadURL
		}
	}

	if assetURL == "" {
		return fmt.Errorf("release %s does not contain matching asset %q", rel.TagName, targetAssetName)
	}
	if checksumsURL == "" {
		return fmt.Errorf("release %s is missing checksums.txt", rel.TagName)
	}

	// 6. Download checksums.txt and find expected hash
	fmt.Println("Fetching release checksums...")
	checksumsBytes, err := downloadURLToBytes(checksumsURL)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
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

	// 10. Atomically replace existing binary
	if err := os.Rename(tempPath, evalPath); err != nil {
		return fmt.Errorf("atomically replace %s: %w", evalPath, err)
	}

	fmt.Printf("Successfully updated lnta from %s to %s at %s\n", lnta.Version, rel.TagName, evalPath)
	return nil
}
