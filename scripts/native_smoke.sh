#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
PYTHON=${PYTHON:-python3}
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

for cipher in chacha20 speck32_64 threefish256; do
    "$PYTHON" -m fullround_key_recovery.reproduce "$cipher" --mapping-only --pretty
done
