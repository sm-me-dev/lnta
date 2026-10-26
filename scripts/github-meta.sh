#!/usr/bin/env bash
# scripts/github-meta.sh
# Sets repository metadata and topics, with an optional explicit release tag
set -euo pipefail

REPO="sm-me-dev/lnta"
DESCRIPTION="Fast, kernel-sandboxed Linux terminal assistant in Go with deterministic verification gates and atomic rollbacks."
HOMEPAGE="https://github.com/sm-me-dev/lnta"
TOPICS="linux,cli,golang,terminal,sysadmin,bubblewrap,landlock,ai-agent,mcp"
RELEASE_VERSION=""
RELEASE_NOTES=""

if [ "${1:-}" = "--release" ] || [ "${1:-}" = "release" ]; then
    RELEASE_VERSION="${2:-}"
    if [[ ! "$RELEASE_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
        echo "Usage: $0 --release vMAJOR.MINOR.PATCH" >&2
        exit 2
    fi
    if git show-ref --verify --quiet "refs/tags/${RELEASE_VERSION}"; then
        echo "Release tag already exists: ${RELEASE_VERSION}" >&2
        exit 2
    fi
    RELEASE_NOTES="$(awk -v version="$RELEASE_VERSION" '
        /^## / {
            if (found) exit
            if (index($0, "## " version " ") == 1) found=1
        }
        found { print }
    ' CHANGELOG.md)"
    if [ -z "$RELEASE_NOTES" ]; then
        echo "No CHANGELOG.md release entry found for ${RELEASE_VERSION}" >&2
        exit 2
    fi
fi

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
    echo "==> Creating and pushing release tag ${RELEASE_VERSION}..."
    git tag -a "$RELEASE_VERSION" -m "$RELEASE_NOTES"
    git push origin "$RELEASE_VERSION"
    echo "==> Tag ${RELEASE_VERSION} pushed. Release workflow will trigger automatically."
fi
