#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="$ROOT/research/experiments/chacha20_round20_w32_dominance_pruned_companion_a303.py"

usage() {
  echo "usage: $0 --analyze | --freeze | --derive-order PROTOCOL_SHA A298_ORDER_SHA | --recover PROTOCOL_SHA ORDER_SHA" >&2
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
  --freeze)
    [[ $# -eq 1 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --freeze
    ;;
  --derive-order)
    [[ $# -eq 3 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --derive-order \
      --expected-protocol-sha256 "$2" \
      --expected-a298-order-sha256 "$3"
    ;;
  --recover)
    [[ $# -eq 3 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --recover \
      --expected-protocol-sha256 "$2" \
      --expected-order-sha256 "$3"
    ;;
  *)
    usage
    exit 2
    ;;
esac
