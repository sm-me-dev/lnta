#!/bin/sh
set -eu

root=${LNTA_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
config="$root/.goreleaser.yaml"
test -f "$config" || { echo "required packaging input missing: $config" >&2; exit 1; }
if grep -Fq 'scripts/apparmor-profile' "$config"; then
	echo "retired AppArmor profile must not be packaged" >&2
	exit 1
fi
for hook in postinstall.sh preremove.sh postremove.sh; do
	path="$root/scripts/deb/$hook"
	test -f "$path" || { echo "required packaging input missing: $path" >&2; exit 1; }
done
