#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
PYTHON=${PYTHON:-python3}
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

case "${1:-}" in
    chacha20|speck32_64|threefish256) cipher=$1 ;;
    *)
        echo "usage: $0 {chacha20|speck32_64|threefish256}" >&2
        exit 2
        ;;
esac

"$PYTHON" -m fullround_key_recovery.reproduce "$cipher" --pretty
