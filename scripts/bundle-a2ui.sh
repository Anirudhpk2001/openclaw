#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Validate ROOT_DIR to prevent path traversal
if [[ "$ROOT_DIR" != /* ]] || [[ "$ROOT_DIR" =~ \.\. ]]; then
  echo "Error: Invalid root directory path" >&2
  exit 1
fi

SCRIPT_PATH="$ROOT_DIR/scripts/bundle-a2ui.mjs"

# Validate the script path exists and is a regular file
if [[ ! -f "$SCRIPT_PATH" ]]; then
  echo "Error: Script not found: $SCRIPT_PATH" >&2
  exit 1
fi

exec node "$SCRIPT_PATH" "$@"