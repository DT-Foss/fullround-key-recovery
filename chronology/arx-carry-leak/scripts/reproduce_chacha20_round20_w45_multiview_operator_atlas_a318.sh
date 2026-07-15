#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"
RUNNER="${ROOT}/research/experiments/chacha20_round20_w45_multiview_operator_atlas_a318.py"

if [[ ! -x "${PYTHON}" ]]; then
  echo "missing repository Python: ${PYTHON}" >&2
  exit 1
fi

exec "${PYTHON}" "${RUNNER}" "$@"
