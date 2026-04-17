#!/usr/bin/env bash
# Usage: ./compile_wireshark.sh input.ksy output.lua
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KSY_FILE="$(realpath "$1")"
OUT_FILE="$(realpath "$2")"

cd "$SCRIPT_DIR/kaitai-to-wireshark"
python3 convert.py "$KSY_FILE" > "$OUT_FILE"
echo "Written: $OUT_FILE"
