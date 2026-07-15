#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="$ROOT/research/experiments/chacha20_round20_w24_fine_selected_channel_a295.py"

usage() {
  echo "usage: $0 --analyze | --freeze A293_RESULT_SHA | --run PROTOCOL_SHA" >&2
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
    [[ $# -eq 2 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --freeze \
      --expected-a293-result-sha256 "$2"
    ;;
  --run)
    [[ $# -eq 2 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --run \
      --expected-protocol-sha256 "$2"
    ;;
  *)
    usage
    exit 2
    ;;
esac
