#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="$ROOT/research/experiments/chacha20_round20_w24_causal_ordered_metal_a294.py"
PROTOCOL_SHA256="f49cf71d945c400dfb5302587302e776e2b9aa9dbc4b7b14fb361ed79a8a4c6f"

case "${1:---analyze}" in
  --analyze)
    exec "$PYTHON" "$RUNNER" \
      --analyze \
      --expected-protocol-sha256 "$PROTOCOL_SHA256"
    ;;
  --run)
    exec "$PYTHON" "$RUNNER" \
      --run \
      --expected-protocol-sha256 "$PROTOCOL_SHA256"
    ;;
  *)
    echo "usage: ${0##*/} [--analyze|--run]" >&2
    exit 2
    ;;
esac
