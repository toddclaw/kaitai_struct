#!/usr/bin/env bash
# Batch compile all network .ksy files to Wireshark Lua and report results.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KSY_DIR="$SCRIPT_DIR/compiler/kaitai-struct-compiler-0.11/formats/network"
OUT_DIR="$SCRIPT_DIR/batch_output"
mkdir -p "$OUT_DIR"

pass=0
fail=0
failures=()

for ksy in "$KSY_DIR"/*.ksy; do
    name="$(basename "$ksy" .ksy)"
    out="$OUT_DIR/${name}.lua"
    if "$SCRIPT_DIR/compile_wireshark.sh" "$ksy" "$out" 2>/dev/null; then
        echo "PASS  $name"
        ((pass++)) || true
    else
        echo "FAIL  $name"
        failures+=("$name")
        ((fail++)) || true
    fi
done

echo ""
echo "Results: $pass passed, $fail failed out of $((pass + fail)) total"
if [ ${#failures[@]} -gt 0 ]; then
    echo "Failed:"
    for f in "${failures[@]}"; do echo "  - $f"; done
fi
