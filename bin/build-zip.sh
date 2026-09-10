#!/usr/bin/env bash
#
# Build a distributable INI Protector plugin zip, excluding everything listed in
# .distignore so dev-only files (docs, build tooling, VCS) never reach clients.
#
# Usage:
#   bin/build-zip.sh [output_dir]
#
# Default output_dir is the local dist directory. The zip is
# named ini-protector-<version>.zip, where <version> is read from the plugin header.
#
# The zip always contains a single top-level ini-protector/ directory, as WordPress
# expects.

set -euo pipefail

# --- Resolve paths -----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SLUG="ini-protector"
MAIN_FILE="${PLUGIN_DIR}/${SLUG}.php"
DIST_IGNORE="${PLUGIN_DIR}/.distignore"

OUTPUT_DIR="${1:-${PLUGIN_DIR}/dist}"

# --- Read version from the plugin header -------------------------------------
VERSION="$(grep -iE '^\s*\*\s*Version:' "${MAIN_FILE}" | head -1 | sed -E 's/.*Version:\s*//I' | tr -d '\r' | xargs)"
if [[ -z "${VERSION}" ]]; then
	echo "ERROR: could not read Version from ${MAIN_FILE}" >&2
	exit 1
fi

mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"
ZIP_PATH="${OUTPUT_DIR}/${SLUG}-${VERSION}.zip"

# --- Stage a clean copy, honouring .distignore -------------------------------
STAGING="$(mktemp -d)"
trap 'rm -rf "${STAGING}"' EXIT

# rsync uses .distignore as an exclude list (same glob semantics we need).
RSYNC_EXCLUDES=()
if [[ -f "${DIST_IGNORE}" ]]; then
	RSYNC_EXCLUDES+=(--exclude-from="${DIST_IGNORE}")
fi

mkdir -p "${STAGING}/${SLUG}"
rsync -a "${RSYNC_EXCLUDES[@]}" "${PLUGIN_DIR}/" "${STAGING}/${SLUG}/"

# --- Build the zip -----------------------------------------------------------
mkdir -p "${OUTPUT_DIR}"
rm -f "${ZIP_PATH}"
( cd "${STAGING}" && zip -rq "${ZIP_PATH}" "${SLUG}" )

echo "Built: ${ZIP_PATH}"
echo "Version: ${VERSION}"
echo "Contents (top level):"
unzip -l "${ZIP_PATH}" | awk 'NR>3 && $4 != "" {print "  " $4}' | sed -E "s#^  ${SLUG}/##" | grep -vE '^\s*$' | cut -d/ -f1 | sort -u | sed 's/^/  /'
