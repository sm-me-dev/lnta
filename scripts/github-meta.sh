#!/usr/bin/env bash
# scripts/github-meta.sh
# Sets repository metadata, description, topics, and optionally triggers v0.1.0 release tag
set -euo pipefail

REPO="sm-me-dev/lnta"
DESCRIPTION="Fast, kernel-sandboxed Linux terminal assistant in Go with deterministic verification gates and atomic rollbacks."
HOMEPAGE="https://github.com/sm-me-dev/lnta"
TOPICS="linux,cli,golang,terminal,sysadmin,bubblewrap,landlock,ai-agent,mcp"

echo "==> Configuring repository metadata for ${REPO}..."
if command -v gh >/dev/null 2>&1; then
    gh repo edit "${REPO}" \
        --description "${DESCRIPTION}" \
        --homepage "${HOMEPAGE}" \
        --add-topic "${TOPICS}" \
        --enable-issues \
        --enable-wiki=false
    echo "==> Repository metadata updated successfully."
else
    echo "Warning: GitHub CLI ('gh') is not installed. Skipping remote repo edit." >&2
fi

# Optional release helper
if [ "${1:-}" = "--release" ] || [ "${1:-}" = "release" ]; then
    VERSION="${2:-v0.1.0}"
    echo "==> Creating and pushing release tag ${VERSION}..."
    git tag -a "${VERSION}" -m "Release ${VERSION}"
    git push origin "${VERSION}"
    echo "==> Tag ${VERSION} pushed. Release workflow will trigger automatically."
fi
