#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="$ROOT/research/experiments/chacha20_round20_causal_search_gain_panel_a296.py"
PROTOCOL_SHA256="09c9461eaad32e36e63705aa8b3ebf5054afc861aea519022fdea7f92ac77f64"
PREFLIGHT_SHA256="9f6c506785976a560fc1087f0ac6da4d4fc68c2bfeacaadf79f4a0e154c89adc"
RESULT_DIR="$ROOT/research/results/v1/chacha20_round20_causal_search_gain_panel_a296_v1"
TARGETS=(
  w24_t00 w24_t01 w24_t02 w24_t03
  w28_t00 w28_t01 w28_t02 w28_t03
)

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
