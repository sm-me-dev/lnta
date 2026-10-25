#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
	echo "usage: $0 PACKAGE.deb" >&2
	exit 2
fi
package=$1
contents=$(dpkg-deb --contents "$package")
if printf '%s\n' "$contents" | grep -Eq '(^|[[:space:]])\./etc/apparmor\.d/bwrap$'; then
	echo "package ships retired /etc/apparmor.d/bwrap policy" >&2
	exit 1
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
dpkg-deb --control "$package" "$tmp"
for hook in postinst prerm postrm; do
	path="$tmp/DEBIAN/$hook"
	if [ -f "$path" ] && grep -Eiq 'apparmor_parser|/etc/apparmor\.d|rm[[:space:]]+-f|rmdir' "$path"; then
		echo "package hook $hook can mutate system AppArmor policy" >&2
		exit 1
	fi
done
