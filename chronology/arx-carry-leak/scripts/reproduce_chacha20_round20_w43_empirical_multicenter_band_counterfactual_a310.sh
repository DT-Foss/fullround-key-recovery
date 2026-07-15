#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="$ROOT/research/experiments/chacha20_round20_w43_empirical_multicenter_band_counterfactual_a310.py"

usage() {
  echo "usage: $0 --analyze | --materialize | --evaluate ORDER_SHA A309_RESULT_SHA" >&2
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

case "$1" in
  --analyze)
    [[ $# -eq 1 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --analyze
    ;;
  --materialize)
    [[ $# -eq 1 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --materialize
    ;;
  --evaluate)
    [[ $# -eq 3 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --evaluate \
      --expected-order-sha256 "$2" \
      --expected-a309-result-sha256 "$3"
    ;;
  *)
    usage
    exit 2
    ;;
esac
