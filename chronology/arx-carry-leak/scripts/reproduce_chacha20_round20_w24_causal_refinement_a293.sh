#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="$ROOT/research/experiments/chacha20_round20_w24_causal_refinement_a293.py"

usage() {
  echo "usage: $0 --freeze DESIGN_SHA A288_RESULT_SHA | --analyze PROTOCOL_SHA | --run PROTOCOL_SHA" >&2
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

case "$1" in
  --freeze)
    [[ $# -eq 3 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --freeze \
      --expected-design-sha256 "$2" \
      --expected-a288-result-sha256 "$3"
    ;;
  --analyze | --run)
    [[ $# -eq 2 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" "$1" \
      --expected-protocol-sha256 "$2"
    ;;
  *)
    usage
    exit 2
    ;;
esac
