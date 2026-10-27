#!/bin/sh
# Generate GitHub Pages index.html landing page for LNTA APT repository
# Usage: scripts/apt/generate-index.sh <VERSION> <OUTPUT_DIR>

set -eu

VERSION="${1:-0.1.6}"
OUTPUT_DIR="${2:-.}"
TARGET_FILE="${OUTPUT_DIR}/index.html"

mkdir -p "${OUTPUT_DIR}"

cat <<'EOF' > "${TARGET_FILE}"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LNTA — Official APT Repository</title>
  <meta name="description" content="Official Debian/Ubuntu APT repository for LNTA (Linux Natural-Language Terminal Assistant).">
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --card-border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --green: #2ea043;
      --code-bg: #1f242c;
      --code-border: #383e47;
      --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      line-height: 1.6;
      padding: 2rem 1rem;
    }
    .container {
      max-width: 860px;
      margin: 0 auto;
    }
    header {
      text-align: center;
      margin-bottom: 2.5rem;
    }
    .badge-bar {
      display: flex;
      justify-content: center;
      gap: 0.5rem;
      flex-wrap: wrap;
      margin-bottom: 1rem;
    }
    .badge {
      display: inline-block;
      padding: 0.2rem 0.6rem;
      font-size: 0.75rem;
      font-weight: 600;
      border-radius: 20px;
      background: #21262d;
      color: #58a6ff;
      border: 1px solid var(--card-border);
    }
    .badge-green {
      color: #3fb950;
      border-color: #238636;
    }
    h1 {
      font-size: 2.5rem;
      font-weight: 800;
      color: #f0f6fc;
      margin-bottom: 0.5rem;
      letter-spacing: -0.5px;
    }
    .tagline {
      font-size: 1.15rem;
      color: var(--text-muted);
      max-width: 640px;
      margin: 0 auto;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    .card-title {
      font-size: 1.25rem;
      font-weight: 700;
      color: #f0f6fc;
      margin-bottom: 0.75rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .code-block {
      background: var(--code-bg);
      border: 1px solid var(--code-border);
      border-radius: 6px;
      padding: 0.85rem 1rem;
      font-family: var(--font-mono);
      font-size: 0.9rem;
      color: #79c0ff;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      margin-top: 0.5rem;
      margin-bottom: 0.75rem;
    }
    .code-block code {
      font-family: inherit;
    }
    .step-desc {
      font-size: 0.9rem;
      color: var(--text-muted);
      margin-top: 0.5rem;
    }
    details {
      margin-top: 1rem;
      border-top: 1px solid var(--card-border);
      padding-top: 0.75rem;
    }
    summary {
      cursor: pointer;
      color: var(--accent);
      font-weight: 600;
      user-select: none;
    }
    summary:hover {
      text-decoration: underline;
    }
    .downloads-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
      gap: 0.75rem;
      margin-top: 1rem;
    }
    .dl-btn {
      display: block;
      padding: 0.75rem 1rem;
      background: #21262d;
      border: 1px solid var(--card-border);
      border-radius: 6px;
      color: #f0f6fc;
      text-decoration: none;
      font-size: 0.85rem;
      font-family: var(--font-mono);
      transition: all 0.15s ease;
    }
    .dl-btn:hover {
      background: #30363d;
      border-color: #58a6ff;
      color: #58a6ff;
    }
    .dl-btn span {
      display: block;
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-top: 0.2rem;
    }
    footer {
      text-align: center;
      margin-top: 3rem;
      font-size: 0.85rem;
      color: var(--text-muted);
    }
    footer a {
      color: var(--accent);
      text-decoration: none;
    }
    footer a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="badge-bar">
        <span class="badge badge-green">APT Official Repository</span>
        <span class="badge">Debian 12+ / Ubuntu 22.04+ / 24.04 LTS</span>
        <span class="badge">amd64 & arm64</span>
        <span class="badge">Version @@VERSION@@</span>
      </div>
      <h1>LNTA</h1>
      <p class="tagline">Fast, kernel-sandboxed Linux natural-language terminal assistant with atomic rollbacks and offline Ollama reasoning.</p>
    </header>

    <div class="card">
      <div class="card-title">⚡ Instant Installation (Recommended)</div>
      <p class="step-desc">Installs the signing key, adds the APT repository, and installs <code>lnta</code> with automated future upgrades via <code>apt upgrade</code>:</p>
      <div class="code-block"><code>curl -fsSL https://sm-me-dev.github.io/lnta/install-apt.sh | sudo sh</code></div>

      <details>
        <summary>Manual DEB822 Repository & Keyring Setup (Step-by-Step)</summary>
        <div style="margin-top: 0.75rem;">
          <p class="step-desc"><strong>Step 1:</strong> Install the dedicated LNTA Ed25519 repository signing key:</p>
          <div class="code-block"><code>sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://sm-me-dev.github.io/lnta/lnta-archive-keyring.asc | sudo gpg --dearmor -o /etc/apt/keyrings/lnta.gpg
sudo chmod a+r /etc/apt/keyrings/lnta.gpg</code></div>

          <p class="step-desc"><strong>Step 2:</strong> Add the modern DEB822 repository entry:</p>
          <div class="code-block"><code>echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/lnta.gpg] https://sm-me-dev.github.io/lnta stable main" | \
  sudo tee /etc/apt/sources.list.d/lnta.list > /dev/null</code></div>

          <p class="step-desc"><strong>Step 3:</strong> Update cache and install:</p>
          <div class="code-block"><code>sudo apt update && sudo apt install -y lnta</code></div>
        </div>
      </details>
    </div>

    <div class="card">
      <div class="card-title">📦 Direct Downloads (v@@VERSION@@)</div>
      <p class="step-desc">Direct binary and package downloads from GitHub Releases:</p>
      <div class="downloads-grid">
        <a class="dl-btn" href="https://github.com/sm-me-dev/lnta/releases/download/v@@VERSION@@/lnta_@@VERSION@@_linux_amd64.deb">
          lnta_@@VERSION@@_linux_amd64.deb
          <span>Debian / Ubuntu (x86_64)</span>
        </a>
        <a class="dl-btn" href="https://github.com/sm-me-dev/lnta/releases/download/v@@VERSION@@/lnta_@@VERSION@@_linux_arm64.deb">
          lnta_@@VERSION@@_linux_arm64.deb
          <span>Debian / Ubuntu (ARM64)</span>
        </a>
        <a class="dl-btn" href="https://github.com/sm-me-dev/lnta/releases/download/v@@VERSION@@/lnta-@@VERSION@@-1.amd64.rpm">
          lnta-@@VERSION@@-1.amd64.rpm
          <span>Fedora / RHEL / openSUSE</span>
        </a>
        <a class="dl-btn" href="https://github.com/sm-me-dev/lnta/releases/download/v@@VERSION@@/lnta_@@VERSION@@_linux_amd64.tar.gz">
          lnta_@@VERSION@@_linux_amd64.tar.gz
          <span>Standalone Tarball (x86_64)</span>
        </a>
        <a class="dl-btn" href="lnta-archive-keyring.asc">
          lnta-archive-keyring.asc
          <span>Public GPG Signing Key</span>
        </a>
        <a class="dl-btn" href="https://github.com/sm-me-dev/lnta/releases/download/v@@VERSION@@/checksums.txt">
          checksums.txt
          <span>SHA-256 Release Signatures</span>
        </a>
      </div>
    </div>

    <div class="card">
      <div class="card-title">🛡️ Security & Integrity Highlights</div>
      <ul style="padding-left: 1.5rem; color: var(--text-muted); font-size: 0.9rem;">
        <li><strong style="color: var(--text);">Zero Unbounded Bash:</strong> All read inspections execute inside <code>bwrap</code> with <code>--ro-bind / /</code>, empty <code>/tmp</code>, and credential maskings.</li>
        <li><strong style="color: var(--text);">AppArmor & Landlock:</strong> Restricts unprivileged user namespaces on Ubuntu 24.04 LTS and enforces kernel-level filesystem sandboxing.</li>
        <li><strong style="color: var(--text);">Signed InRelease:</strong> The APT repository metadata is cryptographically signed with a dedicated Ed25519 GPG release key.</li>
        <li><strong style="color: var(--text);">Time Machine Rollback:</strong> Every file mutation creates an atomic snapshot before write. Revert anytime with <code>lnta undo</code>.</li>
      </ul>
    </div>

    <footer>
      <p>LNTA is open source under the MIT License • <a href="https://github.com/sm-me-dev/lnta">GitHub Repository</a> • <a href="https://github.com/sm-me-dev/lnta/releases">All Releases</a></p>
    </footer>
  </div>
</body>
</html>
EOF

sed -i "s/@@VERSION@@/${VERSION}/g" "${TARGET_FILE}"
echo "Generated ${TARGET_FILE} for version ${VERSION}"
