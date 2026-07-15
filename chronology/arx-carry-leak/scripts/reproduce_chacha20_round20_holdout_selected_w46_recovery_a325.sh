#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
RUNNER="$ROOT/research/experiments/chacha20_round20_holdout_selected_w46_recovery_a325.py"

usage() {
  echo "usage: $0 --analyze | --materialize A321_COMMITMENT_SHA A324_QUALIFICATION_SHA | --recover PROTOCOL_SHA A324_QUALIFICATION_SHA" >&2
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
    [[ $# -eq 3 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --materialize \
      --expected-a321-commitment-sha256 "$2" \
      --expected-a324-qualification-sha256 "$3"
    ;;
  --recover)
    [[ $# -eq 3 ]] || { usage; exit 2; }
    exec "$PYTHON" "$RUNNER" --recover \
      --expected-protocol-sha256 "$2" \
      --expected-a324-qualification-sha256 "$3"
    ;;
  *)
    usage
    exit 2
    ;;
esac
