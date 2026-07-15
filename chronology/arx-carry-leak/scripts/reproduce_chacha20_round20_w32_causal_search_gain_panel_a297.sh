#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="$ROOT/research/experiments/chacha20_round20_w32_causal_search_gain_panel_a297.py"
PROTOCOL_SHA256="6c3505606b53d3e3c5680b11142833129bb083313657b83ba027dcd9994bc253"
PREFLIGHT_SHA256="663d90c7d29b928830431510c6e854c7c5206ed79c7bebfa0bade0c69e3d6c07"
RESULT_DIR="$ROOT/research/results/v1/chacha20_round20_w32_causal_search_gain_panel_a297_v1"
TARGETS=(w32_t00 w32_t01 w32_t02 w32_t03)

usage() {
  printf '%s\n' \
    "Usage: $0 --status" \
    "       $0 --measure TARGET_ID" \
    "       $0 --measure-missing" \
    "       $0 --recover"
}

measure() {
  local target="$1"
  "$PYTHON" "$RUNNER" \
    --measure \
    --target-id "$target" \
    --expected-protocol-sha256 "$PROTOCOL_SHA256" \
    --expected-preflight-sha256 "$PREFLIGHT_SHA256"
}

case "${1:-}" in
  --status)
    "$PYTHON" "$RUNNER" --analyze
    ;;
  --measure)
    test "$#" -eq 2 || { usage >&2; exit 2; }
    measure "$2"
    ;;
  --measure-missing)
    test "$#" -eq 1 || { usage >&2; exit 2; }
    for target in "${TARGETS[@]}"; do
      if test -f "$RESULT_DIR/$target.order.json"; then
        printf 'retained %s\n' "$target"
      else
        measure "$target"
      fi
    done
    ;;
  --recover)
    test "$#" -eq 1 || { usage >&2; exit 2; }
    "$PYTHON" "$RUNNER" \
      --recover \
      --expected-protocol-sha256 "$PROTOCOL_SHA256" \
      --expected-preflight-sha256 "$PREFLIGHT_SHA256"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
