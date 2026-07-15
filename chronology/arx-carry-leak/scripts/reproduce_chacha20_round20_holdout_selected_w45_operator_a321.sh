#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"
RUNNER="${ROOT}/research/experiments/chacha20_round20_holdout_selected_w45_operator_a321.py"

if [[ ! -x "${PYTHON}" ]]; then
  PYTHON="python3"
fi

exec "${PYTHON}" "${RUNNER}" "$@"
