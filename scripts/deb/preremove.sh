#!/bin/sh
set -e

if command -v apparmor_parser >/dev/null 2>&1; then
  apparmor_parser -R /etc/apparmor.d/bwrap || true
fi
