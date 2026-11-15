#!/usr/bin/env bash
# Validate a native Lookout Debian package without installing or opening it.
set -euo pipefail

if [[ $# -ne 1 || ! -f "$1" ]]; then
    echo "Usage: $0 path/to/lookout.deb" >&2
    exit 2
fi
DEB="$1"
for tool in dpkg-deb desktop-file-validate glib-compile-schemas ldd; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done

[[ "$(dpkg-deb -f "$DEB" Package)" == lookout ]]
[[ "$(dpkg-deb -f "$DEB" Architecture)" == "$(dpkg --print-architecture)" ]]
dpkg-deb --info "$DEB"
ROOT="$(mktemp -d)"
trap 'rm -rf -- "$ROOT"' EXIT
dpkg-deb -x "$DEB" "$ROOT"

APP_ID=io.github.gavindi.Lookout
BIN="$ROOT/usr/bin/lookout"
DESKTOP="$ROOT/usr/share/applications/$APP_ID.desktop"
SCHEMAS="$ROOT/usr/share/glib-2.0/schemas"
test -x "$BIN"
test -s "$DESKTOP"
test -s "$ROOT/usr/share/icons/hicolor/scalable/apps/$APP_ID.svg"
test -s "$ROOT/usr/share/metainfo/$APP_ID.metainfo.xml"
test -s "$SCHEMAS/$APP_ID.gschema.xml"
desktop-file-validate "$DESKTOP"
glib-compile-schemas --strict --dry-run "$SCHEMAS"
LIBS="$(ldd "$BIN")"
printf '%s\n' "$LIBS"
if grep -q 'not found' <<< "$LIBS"; then
    echo "Missing native runtime libraries" >&2
    exit 1
fi
echo "Package content, desktop entry, schema and native libraries verified."
