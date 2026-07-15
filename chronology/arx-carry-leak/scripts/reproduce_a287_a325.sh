#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON="$(command -v python3)"
  else
    echo "missing Python interpreter" >&2
    exit 2
  fi
fi

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

"$PYTHON" scripts/verify_hash_manifest.py research/results/v1/A287_A325_SHA256SUMS

TEST_LIST="research/results/v1/A287_A325_TESTS.txt"
mapfile_command=()
while IFS= read -r path; do
  [[ -z "$path" || "$path" == \#* ]] && continue
  mapfile_command+=("$path")
done < "$TEST_LIST"
if [[ "${#mapfile_command[@]}" -eq 0 ]]; then
  echo "empty focused test list: $TEST_LIST" >&2
  exit 2
fi
"$PYTHON" -m pytest -q "${mapfile_command[@]}"

AUDIT="$(mktemp)"
trap 'rm -f "$AUDIT"' EXIT
"$PYTHON" scripts/validate_causal_artifacts.py research/results/v1 > "$AUDIT"
"$PYTHON" - "$AUDIT" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    audit = json.load(handle)

by_name = {row["path"].rsplit("/", 1)[-1]: row for row in audit["artifacts"]}
required = (
    "chacha20_round20_w24_causal_ordered_metal_a294_v1.causal",
    "chacha20_round20_w24_fine_selected_channel_a295_v1.causal",
    "chacha20_round20_causal_search_gain_panel_a296_v1.causal",
    "chacha20_round20_w32_causal_search_gain_panel_a297_v1.causal",
    "chacha20_round20_w32_dominance_pruned_companion_a303_v1.causal",
    "chacha20_round20_w43_grouped_engine_a304_v1.causal",
    "chacha20_round20_w43_a299_grouped_replay_a305_v1.causal",
    "chacha20_round20_w43_width_conditioned_band_portfolio_a309_v1.causal",
    "chacha20_round20_w43_metal_record_v1.causal",
    "chacha20_round20_cross_width_operator_stability_a323_v1.causal",
    "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.causal",
    "chacha20_round20_w44_online_multicenter_counterfactual_a315_v1.causal",
    "chacha20_round20_w44_multiview_operator_atlas_a317_v1.causal",
    "chacha20_round20_w44_covariance_whitened_atlas_a319_v1.causal",
    "chacha20_round20_holdout_selected_w45_operator_a321_order_v1.causal",
)
missing = [name for name in required if name not in by_name]
if missing:
    raise SystemExit(f"missing native Causal readback: {missing}")
if any(by_name[name]["triplets"] < 1 for name in required):
    raise SystemExit("empty native Causal graph in A287--A325 headline set")
print(f"causal artifacts: OK ({audit['validated']} validated)")
PY

echo "A287--A325 cryptanalysis tier: OK"
