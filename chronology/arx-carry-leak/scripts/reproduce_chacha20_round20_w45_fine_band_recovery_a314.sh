#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="$ROOT/research/experiments/chacha20_round20_w45_fine_band_recovery_a314.py"

usage() {
  echo "usage: $0 --analyze | --freeze A311_QUALIFICATION_SHA | --preflight PROTOCOL_SHA | --measure PROTOCOL_SHA PREFLIGHT_SHA | --recover PROTOCOL_SHA PREFLIGHT_SHA ORDER_SHA A311_QUALIFICATION_SHA" >&2
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
      --expected-a311-qualification-sha256 "$2"
    ;;
  --preflight)
    [[ $# -eq 2 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --preflight \
      --expected-protocol-sha256 "$2"
    ;;
  --measure)
    [[ $# -eq 3 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --measure \
      --expected-protocol-sha256 "$2" \
      --expected-preflight-sha256 "$3"
    ;;
  --recover)
    [[ $# -eq 5 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --recover \
      --expected-protocol-sha256 "$2" \
      --expected-preflight-sha256 "$3" \
      --expected-order-sha256 "$4" \
      --expected-a311-qualification-sha256 "$5"
    ;;
  *)
    usage
    exit 2
    ;;
esac
