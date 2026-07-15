#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="$ROOT/research/experiments/chacha20_round20_w43_dominance_pruned_portfolio_a301.py"

usage() {
  echo "usage: $0 --analyze | --freeze A300_PROTOCOL_SHA A300_PREFLIGHT_SHA | --derive-order PROTOCOL_SHA A300_ORDER_SHA | --recover PROTOCOL_SHA ORDER_SHA" >&2
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
    [[ $# -eq 3 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --freeze \
      --expected-a300-protocol-sha256 "$2" \
      --expected-a300-preflight-sha256 "$3"
    ;;
  --derive-order)
    [[ $# -eq 3 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --derive-order \
      --expected-protocol-sha256 "$2" \
      --expected-a300-order-sha256 "$3"
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
