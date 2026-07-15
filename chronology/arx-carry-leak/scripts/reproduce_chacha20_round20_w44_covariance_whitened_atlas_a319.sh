#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"
RUNNER="${ROOT}/research/experiments/chacha20_round20_w44_covariance_whitened_atlas_a319.py"

if [[ ! -x "${PYTHON}" ]]; then
  PYTHON="python3"
fi

case "${1:-}" in
  --materialize)
    exec "${PYTHON}" "${RUNNER}" --materialize
    ;;
  --evaluate)
    shift
    exec "${PYTHON}" "${RUNNER}" --evaluate "$@"
    ;;
  --analyze)
    exec "${PYTHON}" "${RUNNER}" --analyze
    ;;
  *)
    echo "usage: $0 --materialize | --evaluate --expected-commitment-sha256 SHA --expected-a313-result-sha256 SHA | --analyze" >&2
    exit 2
    ;;
esac
