#!/bin/sh
set -eu
# Use: sudo /usr/bin/python3.12 -I install.py
exec python3 -I "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/install.py" "$@"
