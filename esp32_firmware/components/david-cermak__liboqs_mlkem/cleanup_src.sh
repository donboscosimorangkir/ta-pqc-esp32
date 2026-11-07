#!/usr/bin/env bash

set -euo pipefail

# Remove vendored liboqs + kyber sources deployed by deploy_src.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="$SCRIPT_DIR/src"

echo "[cleanup_src] Cleaning destination: $DEST_DIR"
rm -rf "$DEST_DIR/liboqs" "$DEST_DIR/kyber"

echo "[cleanup_src] Done."
