#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="$ROOT/research/experiments/chacha20_round20_w43_width_conditioned_band_portfolio_a309.py"

usage() {
  echo "usage: $0 --analyze | --freeze | --recover PROTOCOL_SHA" >&2
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
  --recover)
    [[ $# -eq 2 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --recover \
      --expected-protocol-sha256 "$2"
    ;;
  *)
    usage
    exit 2
    ;;
esac
