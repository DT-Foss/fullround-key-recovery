#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"
RUNNER="${ROOT}/research/experiments/chacha20_round20_w45_covariance_whitened_atlas_a320.py"

if [[ ! -x "${PYTHON}" ]]; then
  PYTHON="python3"
fi

case "${1:-}" in
  --analyze)
    exec "${PYTHON}" "${RUNNER}" --analyze
    ;;
  --materialize)
    shift
    exec "${PYTHON}" "${RUNNER}" --materialize "$@"
    ;;
  --evaluate)
    shift
    exec "${PYTHON}" "${RUNNER}" --evaluate "$@"
    ;;
  *)
    echo "usage: $0 --analyze | --materialize --expected-a314-order-sha256 SHA | --evaluate --expected-commitment-sha256 SHA --expected-a314-result-sha256 SHA" >&2
    exit 2
    ;;
esac
