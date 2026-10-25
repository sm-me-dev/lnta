#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/repo"
tar -C "$root" --exclude=.git --exclude=dist -cf - . | tar -C "$tmp/repo" -xf -
missing="$tmp/repo/scripts/deb/postremove.sh"
mv "$missing" "$missing.missing"
log="$tmp/goreleaser.log"
if (cd "$tmp/repo" && "${GORELEASER:-goreleaser}" release --snapshot --clean --skip=sign,publish) >"$log" 2>&1; then
	echo "GoReleaser succeeded with a required packaging input missing" >&2
	exit 1
fi
if ! grep -Fq "required packaging input missing: $missing" "$log"; then
	cat "$log" >&2
	echo "GoReleaser failed without the expected packaging input diagnostic" >&2
	exit 1
fi
echo "GoReleaser failed closed with the missing packaging input diagnostic."
