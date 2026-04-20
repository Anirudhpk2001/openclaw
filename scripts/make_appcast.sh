#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ZIP=${1:?"Usage: $0 OpenClaw-<ver>.zip"}
FEED_URL=${2:-"https://raw.githubusercontent.com/openclaw/openclaw/main/appcast.xml"}
PRIVATE_KEY_FILE=${SPARKLE_PRIVATE_KEY_FILE:-}

find_generate_appcast() {
  if command -v generate_appcast >/dev/null 2>&1; then
    command -v generate_appcast
    return 0
  fi

  find "$ROOT/apps/macos/.build" -type f -path "*/artifacts/sparkle/Sparkle/bin/generate_appcast" -print -quit 2>/dev/null
}

if [[ -z "$PRIVATE_KEY_FILE" ]]; then
  echo "Set SPARKLE_PRIVATE_KEY_FILE to your ed25519 private key (Sparkle)." >&2
  exit 1
fi

# Validate private key file path to prevent path traversal
PRIVATE_KEY_FILE=$(realpath -- "$PRIVATE_KEY_FILE" 2>/dev/null) || {
  echo "Invalid SPARKLE_PRIVATE_KEY_FILE path." >&2
  exit 1
}
if [[ ! -f "$PRIVATE_KEY_FILE" ]]; then
  echo "Private key file not found." >&2
  exit 1
fi

if [[ ! -f "$ZIP" ]]; then
  echo "Zip not found: $ZIP" >&2
  exit 1
fi

# Validate ZIP path to prevent path traversal
ZIP=$(realpath -- "$ZIP" 2>/dev/null) || {
  echo "Invalid zip path." >&2
  exit 1
}

ZIP_DIR=$(cd "$(dirname "$ZIP")" && pwd)
ZIP_NAME=$(basename "$ZIP")
ZIP_BASE="${ZIP_NAME%.zip}"
VERSION=${SPARKLE_RELEASE_VERSION:-}
if [[ -z "$VERSION" ]]; then
  # Accept legacy calver suffixes like -1 and prerelease forms like -beta.1 / .beta.1.
  if [[ "$ZIP_NAME" =~ ^OpenClaw-([0-9]+(\.[0-9]+){1,2}([-.][0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?)\.zip$ ]]; then
    VERSION="${BASH_REMATCH[1]}"
  else
    echo "Could not infer version from $ZIP_NAME; set SPARKLE_RELEASE_VERSION." >&2
    exit 1
  fi
fi

# Validate VERSION contains only safe characters to prevent injection
if [[ ! "$VERSION" =~ ^[0-9A-Za-z._-]+$ ]]; then
  echo "Invalid version string: $VERSION" >&2
  exit 1
fi

# Validate FEED_URL to prevent SSRF - must be https and match expected domain
if [[ ! "$FEED_URL" =~ ^https:// ]]; then
  echo "FEED_URL must use HTTPS." >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
# Restrict permissions on temp directory
chmod 700 "$TMP_DIR"

cleanup() {
  rm -rf "$TMP_DIR"
  if [[ "${KEEP_SPARKLE_NOTES:-0}" != "1" ]]; then
    rm -f "$NOTES_HTML"
  fi
}
trap cleanup EXIT
cp -f "$ZIP" "$TMP_DIR/$ZIP_NAME"
if [[ -f "$ROOT/appcast.xml" ]]; then
  cp -f "$ROOT/appcast.xml" "$TMP_DIR/appcast.xml"
fi

NOTES_HTML="${ZIP_DIR}/${ZIP_BASE}.html"
if [[ -x "$ROOT/scripts/changelog-to-html.sh" ]]; then
  "$ROOT/scripts/changelog-to-html.sh" "$VERSION" >"$NOTES_HTML"
else
  echo "Missing scripts/changelog-to-html.sh; cannot generate HTML release notes." >&2
  exit 1
fi
cp -f "$NOTES_HTML" "$TMP_DIR/${ZIP_BASE}.html"

DOWNLOAD_URL_PREFIX=${SPARKLE_DOWNLOAD_URL_PREFIX:-"https://github.com/openclaw/openclaw/releases/download/v${VERSION}/"}

# Validate DOWNLOAD_URL_PREFIX to prevent SSRF - must use HTTPS
if [[ ! "$DOWNLOAD_URL_PREFIX" =~ ^https:// ]]; then
  echo "DOWNLOAD_URL_PREFIX must use HTTPS." >&2
  exit 1
fi

GENERATE_APPCAST="$(find_generate_appcast)"
if [[ -z "$GENERATE_APPCAST" ]]; then
  echo "generate_appcast not found. Install Sparkle tooling or build the mac app first so SwiftPM emits the Sparkle binaries." >&2
  exit 1
fi

# Validate GENERATE_APPCAST path to prevent path traversal/injection
GENERATE_APPCAST=$(realpath -- "$GENERATE_APPCAST" 2>/dev/null) || {
  echo "Invalid generate_appcast path." >&2
  exit 1
}
if [[ ! -x "$GENERATE_APPCAST" ]]; then
  echo "generate_appcast is not executable." >&2
  exit 1
fi

"$GENERATE_APPCAST" \
  --ed-key-file "$PRIVATE_KEY_FILE" \
  --download-url-prefix "$DOWNLOAD_URL_PREFIX" \
  --embed-release-notes \
  --link "$FEED_URL" \
  "$TMP_DIR"

cp -f "$TMP_DIR/appcast.xml" "$ROOT/appcast.xml"

echo "Appcast generated (appcast.xml). Upload alongside $ZIP at $FEED_URL"