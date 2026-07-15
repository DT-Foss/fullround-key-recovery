#!/usr/bin/env python3
"""Prospective A295 fine-reader transfer to the public ChaCha20-R20 W43 holdout."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
REPORTS = RESEARCH / "reports"
ARTIFACTS = RESEARCH / "artifacts/a299_chacha20_r20_w43_fine_transfer"

DESIGN = (
    CONFIGS / "chacha20_round20_w43_fine_selected_channel_transfer_a299_design_v1.json"
)
IMPLEMENTATION_FREEZE = (
    CONFIGS
    / "chacha20_round20_w43_fine_selected_channel_transfer_a299_implementation_freeze_v1.json"
)
IMPLEMENTATION_CORRECTION = (
    CONFIGS
    / "chacha20_round20_w43_fine_selected_channel_transfer_a299_implementation_correction_v2.json"
)
IMPLEMENTATION_CORRECTION_V3 = (
    CONFIGS
    / "chacha20_round20_w43_fine_selected_channel_transfer_a299_implementation_correction_v3.json"
)
A293_RESULT = RESULTS / "chacha20_round20_w24_causal_refinement_a293_v1.json"
A293_CAUSAL = RESULTS / "chacha20_round20_w24_causal_refinement_a293_v1.causal"
A293_RUNNER = RESEARCH / "experiments/chacha20_round20_w24_causal_refinement_a293.py"
A295_RESULT = RESULTS / "chacha20_round20_w24_fine_selected_channel_a295_v1.json"
A295_CAUSAL = RESULTS / "chacha20_round20_w24_fine_selected_channel_a295_v1.causal"
A295_RUNNER = RESEARCH / "experiments/chacha20_round20_w24_fine_selected_channel_a295.py"
A297_RESULT = RESULTS / "chacha20_round20_w32_causal_search_gain_panel_a297_v1.json"
A297_CAUSAL = RESULTS / "chacha20_round20_w32_causal_search_gain_panel_a297_v1.causal"
A297_RUNNER = RESEARCH / "experiments/chacha20_round20_w32_causal_search_gain_panel_a297.py"
W43_PROTOCOL = CONFIGS / "chacha20_round20_w43_metal_record_v1.json"
W43_QUALIFICATION = RESULTS / "chacha20_round20_w43_metal_qualification_v1.json"
W43_RUNNER = RESEARCH / "experiments/chacha20_round20_w43_metal_record.py"
A299_TEST = ROOT / "tests/test_chacha20_round20_w43_fine_selected_channel_transfer_a299.py"

PROTOCOL = CONFIGS / "chacha20_round20_w43_fine_selected_channel_transfer_a299_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w43_fine_selected_channel_transfer_a299_preflight_v1.json"
COARSE = RESULTS / "chacha20_round20_w43_fine_selected_channel_transfer_a299_coarse_v1.json.zst"
ORDER = RESULTS / "chacha20_round20_w43_fine_selected_channel_transfer_a299_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w43_fine_selected_channel_transfer_a299_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = REPORTS / "CHACHA20_ROUND20_W43_FINE_SELECTED_CHANNEL_A299_V1.md"
BUILD = RESEARCH / "build/chacha20_round20_w43_fine_selected_channel_a299"
W43_HELPER_DERIVED = (
    BUILD / "cadical_ranked_variable_prefix_reverse_w43_derived.cpp"
)
W43_HELPER_BINARY = BUILD / "cadical_ranked_variable_prefix_reverse_w43"

DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A299"
DESIGN_SHA256 = "a7876b5a8e61e3a61cfbfcbb9b0ac985f723ebbc40823ce11dbea55bb39f8c36"
W43_PROTOCOL_SHA256 = "fe69f7c4962ed771703c68a1d64c361147a568cabe71d23cc9448fb1bef88de3"
W43_PUBLIC_CHALLENGE_SHA256 = (
    "b7dfe786d4c5f90d190b651701f078f1dadb5ea5972cf46d8f689818e7fdd6d5"
)
W43_QUALIFICATION_SHA256 = (
    "c69c4a63965d22eeeaf92136b9218ae29376f174aa440dd2a7d6b423cae7b369"
)
PRE_REVEAL_IMPLEMENTATION_FREEZE_SHA256 = (
    "7f1208a9ea8c13b6705fcb0254e16a9c3da29e8b7be1e0abb622cb8f8c49a95a"
)
PRE_REVEAL_RUNNER_SHA256 = (
    "dd997a3a73e4df73f75d124417e1d435075dcbac6f844a1a5484353fc3992b23"
)
PRE_REVEAL_TEST_SHA256 = (
    "e9e24113ced6038c4d37dadadb5afcae55e86097ce9cfd3fec0d2dde8ed09553"
)
IMPLEMENTATION_CORRECTION_V2_SHA256 = (
    "6049b632cead5320a6b346beca399435e60ad51b3d4d502aa35fb560e65685ca"
)
CORRECTION_V2_RUNNER_SHA256 = (
    "b049274efd7f5bd8315738feace36a06cd872c6fbebce4940b364c472a0af42e"
)
CORRECTION_V2_TEST_SHA256 = (
    "c5d7ef4d4555d7a0ae6f35a995cd98137ca53021697e42c5a7de2f69bd84a660"
)
WIDTH = 43
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
WORD1_LOW_BITS = 11
CELLS = 1 << PREFIX_BITS
LANES = 8
CELLS_PER_LANE = CELLS // LANES
INNER_GROUP_SIZE = 1 << WORD0_SUFFIX_BITS
OUTER_SLICES = 1 << WORD1_LOW_BITS
GROUP_SIZE = INNER_GROUP_SIZE * OUTER_SLICES
DOMAIN_SIZE = 1 << WIDTH
SECONDS_PER_CELL = 5.0
ZSTD_LEVEL = 10


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A299 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A297 = load_module(A297_RUNNER, "a299_a297_common")
W43 = load_module(W43_RUNNER, "a299_w43_common")
sha256 = A297.sha256
file_sha256 = A297.file_sha256
canonical_bytes = A297.canonical_bytes
canonical_sha256 = A297.canonical_sha256
atomic_bytes = A297.atomic_bytes
atomic_json = A297.atomic_json
relative = A297.relative
path_from_ref = A297.path_from_ref
anchor = A297.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A299 prospective design hash differs")
    value = json.loads(DESIGN.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-fine-selected-channel-transfer-a299-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_while_CHACHA20KR43_complete_domain_execution_and_A293_are_running_before_the_W43_assignment_or_full_domain_result_is_read"
        or value.get("sealed_holdout", {}).get("protocol_sha256")
        != W43_PROTOCOL_SHA256
        or value.get("sealed_holdout", {}).get("public_challenge_sha256")
        != W43_PUBLIC_CHALLENGE_SHA256
        or value.get("information_boundary", {}).get(
            "CHACHA20KR43_checkpoint_candidate_values_read_at_design_freeze"
        )
        is not False
        or value.get("fine_measurement_contract", {}).get("prefix_cells") != CELLS
        or value.get("recovery_contract", {}).get("candidate_group_size")
        != GROUP_SIZE
    ):
        raise RuntimeError("A299 prospective design semantics differ")
    return value


def load_implementation_freeze() -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION_FREEZE) != PRE_REVEAL_IMPLEMENTATION_FREEZE_SHA256:
        raise RuntimeError("A299 pre-reveal implementation freeze hash differs")
    value = json.loads(IMPLEMENTATION_FREEZE.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-fine-selected-channel-transfer-a299-implementation-freeze-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("runner_sha256") != PRE_REVEAL_RUNNER_SHA256
        or value.get("test_sha256") != PRE_REVEAL_TEST_SHA256
        or value.get("W43_protocol_sha256") != W43_PROTOCOL_SHA256
        or value.get("public_challenge_sha256")
        != W43_PUBLIC_CHALLENGE_SHA256
        or value.get("information_boundary", {}).get(
            "W43_complete_domain_result_available_at_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get(
            "W43_checkpoint_candidate_value_read"
        )
        is not False
    ):
        raise RuntimeError("A299 pre-reveal implementation freeze differs")
    return value


def load_implementation_correction() -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION_CORRECTION) != IMPLEMENTATION_CORRECTION_V2_SHA256:
        raise RuntimeError("A299 implementation correction v2 hash differs")
    value = json.loads(IMPLEMENTATION_CORRECTION.read_bytes())
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w43-fine-selected-channel-transfer-a299-implementation-correction-v2"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("parent_implementation_freeze_sha256")
        != PRE_REVEAL_IMPLEMENTATION_FREEZE_SHA256
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("correction_scope")
        != "non_nibble_partial_word_SMT_literal_width_only"
        or value.get("scientific_contract_changed") is not False
        or value.get("runner_sha256") != CORRECTION_V2_RUNNER_SHA256
        or value.get("test_sha256") != CORRECTION_V2_TEST_SHA256
        or boundary.get("W43_checkpoint_or_result_read_by_correction") is not False
        or boundary.get("reader_operator_order_partition_or_recovery_changed")
        is not False
    ):
        raise RuntimeError("A299 implementation correction differs")
    return value


def load_implementation_correction_v3() -> dict[str, Any]:
    value = json.loads(IMPLEMENTATION_CORRECTION_V3.read_bytes())
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w43-fine-selected-channel-transfer-a299-implementation-correction-v3"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("parent_implementation_correction_sha256")
        != IMPLEMENTATION_CORRECTION_V2_SHA256
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("correction_scope")
        != "W43_model_vector_helper_capacity_32_to_64_only"
        or value.get("scientific_contract_changed") is not False
        or value.get("runner_sha256") != file_sha256(Path(__file__))
        or value.get("test_sha256") != file_sha256(A299_TEST)
        or boundary.get("W43_checkpoint_or_result_read_by_correction") is not False
        or boundary.get("reader_operator_order_partition_or_recovery_changed")
        is not False
    ):
        raise RuntimeError("A299 implementation correction v3 differs")
    return value


def correct_non_nibble_known_word_literal(
    formula: str, challenge: Mapping[str, Any], width: int
) -> str:
    """Repair A223's partial-word SMT literal when its width is not a nibble."""
    remainder = width % 32
    if remainder == 0:
        return formula
    known_width = 32 - remainder
    if known_width % 4 == 0:
        return formula
    word = width // 32
    known = int(challenge["known_key_value_words"][word]) >> remainder
    if known >= 1 << known_width:
        raise RuntimeError("A299 partial known-word value exceeds its declared width")
    old = (
        f"(assert (= ((_ extract 31 {remainder}) k{word}) "
        f"#x{known:0{known_width // 4}x}))"
    )
    new = (
        f"(assert (= ((_ extract 31 {remainder}) k{word}) "
        f"#b{known:0{known_width}b}))"
    )
    if formula.count(old) != 1 or new in formula:
        raise RuntimeError("A299 partial known-word SMT literal boundary differs")
    corrected = formula.replace(old, new)
    if corrected.count(new) != 1 or old in corrected:
        raise RuntimeError("A299 partial known-word SMT literal correction failed")
    return corrected


def export_reader_cnf_w43(
    *, a223: Any, config: dict[str, Any], challenge: dict[str, Any]
) -> dict[str, Any]:
    """Use A296's frozen exporter with the width-correct W43 source literal."""
    original = a223._source_formula  # noqa: SLF001

    def corrected_source_formula(
        source_challenge: dict[str, Any], *, width: int
    ) -> str:
        return correct_non_nibble_known_word_literal(
            original(source_challenge, width=width), source_challenge, width
        )

    try:
        a223._source_formula = corrected_source_formula  # noqa: SLF001
        return A297.A296.export_reader_cnf(
            a223=a223,
            config=config,
            identifier="target",
            challenge=challenge,
            width=WIDTH,
        )
    finally:
        a223._source_formula = original  # noqa: SLF001


def compile_w43_helper(
    *,
    output: Path = W43_HELPER_BINARY,
    derived_source: Path = W43_HELPER_DERIVED,
) -> dict[str, Any]:
    """Derive the frozen reverse helper with model-vector capacity for W43."""
    helper = load_module(A293_RUNNER, "a299_a293_helper_locator")
    wrapper = load_module(helper.HELPER_WRAPPER, "a299_w43_helper_build")
    original = wrapper.TRANSFORMATIONS
    capacity_transforms = (
        (
            b"      result.model_one_literals.size() > 32)\n",
            b"      result.model_one_literals.size() > 64)\n",
        ),
        (
            b'        "model-one-literals must contain 9 through 32 literals");\n',
            b'        "model-one-literals must contain 9 through 64 literals");\n',
        ),
    )
    try:
        wrapper.TRANSFORMATIONS = (*original, *capacity_transforms)
        build = wrapper.compile_helper(output=output, derived_source=derived_source)
    finally:
        wrapper.TRANSFORMATIONS = original
    raw = derived_source.read_bytes()
    if any(old in raw for old, _ in capacity_transforms) or any(
        raw.count(new) != 1 for _, new in capacity_transforms
    ):
        raise RuntimeError("A299 W43 helper capacity derivation differs")
    return {
        **build,
        "model_width_max": 64,
        "scientific_solver_semantics_changed": False,
        "capacity_transformation_sha256": sha256(
            b"".join(old + b"\x00" + new + b"\x00" for old, new in capacity_transforms)
        ),
    }


def _reader(path: Path) -> Any:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    return CausalReader(str(path), verify_integrity=True)


def _source_gates(
    expected_a293_result_sha256: str, expected_a295_result_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(A293_RESULT) != expected_a293_result_sha256:
        raise RuntimeError("A299 A293 result hash differs")
    if file_sha256(A295_RESULT) != expected_a295_result_sha256:
        raise RuntimeError("A299 A295 result hash differs")
    a293 = json.loads(A293_RESULT.read_bytes())
    a295 = json.loads(A295_RESULT.read_bytes())
    if (
        a293.get("evidence_stage")
        != "FULLROUND_R20_W24_COMPLETE_CAUSAL_REFINED_BUDGET_BOUNDARY"
        or a293.get("winner") is not None
        or a293.get("coverage", {}).get("executed_prefix_cells") != CELLS
        or a293.get("coverage", {}).get("complete_prefix_cover_if_no_recovery")
        is not True
        or file_sha256(A293_CAUSAL) != a293.get("causal", {}).get("sha256")
    ):
        raise RuntimeError("A299 requires the complete A293 model-free boundary")
    if (
        a295.get("evidence_stage")
        != "FULLROUND_R20_W24_FINE_SELECTED_CHANNEL_ORDERED_RECOVERY_CONFIRMED"
        or a295.get("confirmation") is None
        or a295.get("information_boundary", {}).get("reader_refits") != 0
        or a295.get("information_boundary", {}).get("target_labels_used") != 0
        or file_sha256(A295_CAUSAL) != a295.get("causal", {}).get("sha256")
    ):
        raise RuntimeError("A299 requires the confirmed zero-refit A295 result")
    orbit = a295.get("anchors", {}).get("orbit_source", {})
    expected_orbit_sha = load_design()["source_frontier"][
        "A295_orbit_source_sha256"
    ]
    if orbit.get("sha256") != expected_orbit_sha:
        raise RuntimeError("A299 A295 fine-operator source identity differs")
    anchor(path_from_ref(str(orbit["path"])), expected_orbit_sha)
    a293_reader = _reader(A293_CAUSAL)
    a295_reader = _reader(A295_CAUSAL)
    a297_reader = _reader(A297_CAUSAL)
    if (
        a293_reader.api_id != "a293w24"
        or a295_reader.api_id != "a295w24"
        or a297_reader.api_id != "a297w32"
        or a297_reader._gaps[0].get("expected_object_type")
        != "fine_subprefix_reader_or_prospective_W36_transfer"
    ):
        raise RuntimeError("A299 authentic source Reader chain differs")
    return a293, a295


def _load_public_w43_protocol() -> dict[str, Any]:
    if file_sha256(W43_PROTOCOL) != W43_PROTOCOL_SHA256:
        raise RuntimeError("A299 public W43 protocol hash differs")
    value = W43._load_protocol(W43_PROTOCOL, W43_PROTOCOL_SHA256)  # noqa: SLF001
    if (
        value.get("public_challenge_sha256") != W43_PUBLIC_CHALLENGE_SHA256
        or file_sha256(W43_QUALIFICATION) != W43_QUALIFICATION_SHA256
    ):
        raise RuntimeError("A299 public W43 holdout identity differs")
    return value


def reader_challenge(challenge: Mapping[str, Any]) -> dict[str, Any]:
    """Adapt the public W43 holdout to A223's symbolic-source field names."""
    W43._validate_challenge(challenge)  # noqa: SLF001
    known = [int(value) for value in challenge["known_zeroed_key_words"]]
    return {
        "challenge_id": "a299-reader-view-of-chacha20-r20-w43-fresh-v1",
        "rounds": 20,
        "block_count": 8,
        "counter_schedule": "base_plus_block_index_mod_2^32",
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "unknown_global_bit_interval": [0, WIDTH - 1],
        "unknown_bit_numbering": (
            "little_endian_bit0_upward_across_key_words_k0_through_k7"
        ),
        "unknown_assignment_included": False,
        "unknown_assignment_value_included": False,
        "full_key_included": False,
        "secret_used_only_for_target_construction": True,
        "secret_discarded_after_target_construction": True,
        "known_key_mask_words": [0, 0xFFFFF800, *([0xFFFFFFFF] * 6)],
        "known_key_value_words": known,
        "counter_start": int(challenge["counter_start"]),
        "nonce_words": [int(value) for value in challenge["nonce_words"]],
        "target_words": [
            [int(value) for value in block] for block in challenge["target_words"]
        ],
        "target_block_sha256": list(challenge["target_block_sha256"]),
        "control_target_words": [
            int(value) for value in challenge["control_target_words"]
        ],
        "control_target_block_sha256": challenge[
            "control_target_block_sha256"
        ],
        "source_public_challenge_sha256": W43_PUBLIC_CHALLENGE_SHA256,
    }


def execution_contract() -> dict[str, Any]:
    return {
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward_included": True,
        "unknown_key_bits": WIDTH,
        "known_key_bits": 256 - WIDTH,
        "public_output_blocks": 8,
        "coarse_seed": "unchanged_A297_word0_high8_reader",
        "fine_prefix_coordinates_high_to_low": list(range(31, 19, -1)),
        "fine_prefix_bits": PREFIX_BITS,
        "fine_prefix_cells": CELLS,
        "parallel_retained_state_lanes": LANES,
        "cells_per_lane": CELLS_PER_LANE,
        "seconds_per_cell": SECONDS_PER_CELL,
        "word0_suffix_bits_per_group": WORD0_SUFFIX_BITS,
        "word1_outer_slices_per_group": OUTER_SLICES,
        "candidate_group_size": GROUP_SIZE,
        "complete_residual_domain": DOMAIN_SIZE,
        "reader": "unchanged_A295_frozen_fine_selected_channel",
        "reader_refits": 0,
        "target_labels_used": 0,
        "recovery": (
            "ordered_word0_prefix12_groups_x_complete_word1_low11_slices_then_"
            "dual_independent_eight_block_confirmation"
        ),
    }


def freeze(
    *, expected_a293_result_sha256: str, expected_a295_result_sha256: str
) -> dict[str, Any]:
    if any(
        path.exists()
        for path in (PROTOCOL, PREFLIGHT, COARSE, ORDER, RESULT, CAUSAL, REPORT)
    ) or ARTIFACTS.exists():
        raise FileExistsError("A299 artifacts already exist")
    design = load_design()
    implementation_freeze = load_implementation_freeze()
    implementation_correction = load_implementation_correction()
    implementation_correction_v3 = load_implementation_correction_v3()
    a293, a295 = _source_gates(
        expected_a293_result_sha256, expected_a295_result_sha256
    )
    source = _load_public_w43_protocol()
    challenge = source["challenge"]
    adapted = reader_challenge(challenge)
    a223 = load_module(A297.A223_SOURCE, "a299_a223_freeze")
    formula = correct_non_nibble_known_word_literal(
        A297.A296.b1_formula(a223, adapted, WIDTH), adapted, WIDTH
    )
    if formula.count("(declare-fun k0 () (_ BitVec 32))") != 1 or formula.count(
        "(declare-fun k1 () (_ BitVec 32))"
    ) != 1:
        raise RuntimeError("A299 W43 symbolic reader view differs")
    plan = execution_contract()
    reader_source = Path(inspect.getsourcefile(type(_reader(A297_CAUSAL))) or "")
    payload = {
        "schema": "chacha20-round20-w43-fine-selected-channel-transfer-a299-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": (
            "public_W43_holdout_and_unchanged_two_stage_reader_contract_frozen_"
            "before_A299_CNF_export_measurement_order_or_candidate_discovery"
        ),
        "design": design,
        "implementation_freeze": implementation_freeze,
        "implementation_correction": implementation_correction,
        "implementation_correction_v3": implementation_correction_v3,
        "execution_contract": plan,
        "execution_contract_sha256": canonical_sha256(plan),
        "public_challenge": challenge,
        "public_challenge_sha256": W43_PUBLIC_CHALLENGE_SHA256,
        "reader_challenge": adapted,
        "reader_challenge_sha256": canonical_sha256(adapted),
        "source_results": {
            "A293_result_sha256": expected_a293_result_sha256,
            "A295_result_sha256": expected_a295_result_sha256,
            "A295_rank_analysis": a295["rank_analysis"],
            "A293_coverage": a293["coverage"],
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation_freeze": anchor(IMPLEMENTATION_FREEZE),
            "implementation_correction": anchor(IMPLEMENTATION_CORRECTION),
            "implementation_correction_v3": anchor(IMPLEMENTATION_CORRECTION_V3),
            "W43_protocol": anchor(W43_PROTOCOL, W43_PROTOCOL_SHA256),
            "W43_qualification": anchor(
                W43_QUALIFICATION, W43_QUALIFICATION_SHA256
            ),
            "W43_runner": anchor(W43_RUNNER),
            "A293_result": anchor(A293_RESULT, expected_a293_result_sha256),
            "A293_causal": anchor(A293_CAUSAL),
            "A293_runner": anchor(A293_RUNNER),
            "A295_result": anchor(A295_RESULT, expected_a295_result_sha256),
            "A295_causal": anchor(A295_CAUSAL),
            "A295_runner": anchor(A295_RUNNER),
            "A297_result": anchor(
                A297_RESULT, design["source_frontier"]["A297_result_sha256"]
            ),
            "A297_causal": anchor(
                A297_CAUSAL, design["source_frontier"]["A297_causal_sha256"]
            ),
            "A297_runner": anchor(A297_RUNNER),
            "A296_runner": anchor(A297.A296_RUNNER),
            "A223_source": anchor(A297.A223_SOURCE),
            "A223_config": anchor(A297.A223_CONFIG),
            "A251_wrapper": anchor(A297.A251_WRAPPER),
            "Metal_anchor": anchor(A297.METAL_ANCHOR),
            "CausalReader": anchor(reader_source),
            "runner": anchor(Path(__file__)),
        },
        "information_boundary": {
            "W43_target_is_preexisting_public_holdout": True,
            "W43_assignment_absent_from_source_protocol": True,
            "W43_checkpoint_read": False,
            "W43_complete_domain_result_read": False,
            "W43_confirmation_read": False,
            "target_measurement_or_A299_order_available_at_freeze": False,
            "target_prefix_model_or_A299_filter_outcome_available_at_freeze": False,
            "reader_formula_features_coefficients_and_tiebreak_frozen": True,
            "reader_refits": 0,
            "target_labels_used": 0,
        },
    }
    payload["scientific_design_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "execution_contract": plan,
            "public_challenge_sha256": W43_PUBLIC_CHALLENGE_SHA256,
            "reader_challenge_sha256": payload["reader_challenge_sha256"],
            "information_boundary": payload["information_boundary"],
            "anchors": payload["anchors"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A299 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-fine-selected-channel-transfer-a299-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("execution_contract") != execution_contract()
        or value.get("public_challenge_sha256") != W43_PUBLIC_CHALLENGE_SHA256
        or canonical_sha256(value.get("public_challenge"))
        != W43_PUBLIC_CHALLENGE_SHA256
        or canonical_sha256(value.get("reader_challenge"))
        != value.get("reader_challenge_sha256")
        or value.get("anchors", {}).get("runner", {}).get("sha256")
        != file_sha256(Path(__file__))
    ):
        raise RuntimeError("A299 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    source = _load_public_w43_protocol()
    if source["challenge"] != value["public_challenge"]:
        raise RuntimeError("A299 W43 public challenge copy differs")
    return value


def preflight(expected_protocol_sha256: str) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A299 preflight artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    a223 = load_module(A297.A223_SOURCE, "a299_a223_preflight")
    config = json.loads(A297.A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    original = A297.A296.ARTIFACTS
    try:
        A297.A296.ARTIFACTS = ARTIFACTS / "preflight"
        row = export_reader_cnf_w43(
            a223=a223, config=config, challenge=protocol["reader_challenge"]
        )
    finally:
        A297.A296.ARTIFACTS = original
    mapping = [int(value) for value in row["source_one_literals_bit0_upward"]]
    if len(mapping) != WIDTH or len({abs(value) for value in mapping}) != WIDTH:
        raise RuntimeError("A299 W43 source literal mapping differs")
    coarse_view = [*mapping[:12], *mapping[24:32]]
    row["synthetic_reader_mapping"] = coarse_view
    row["synthetic_reader_mapping_sha256"] = canonical_sha256(coarse_view)
    row["partition_coordinates_high_to_low"] = list(range(31, 19, -1))
    row["coarse_partition_coordinates_high_to_low"] = list(range(31, 23, -1))
    row["diagnostic_model_view_coordinates"] = [*range(12), *range(24, 32)]
    payload = {
        "schema": "chacha20-round20-w43-fine-selected-channel-transfer-a299-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "PUBLIC_W43_TARGET_CNF_AND_WORD0_LITERAL_MAP_FROZEN_BEFORE_ANY_A299_MEASUREMENT"
        ),
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": W43_PUBLIC_CHALLENGE_SHA256,
        "target": row,
        "measurement_started_before_preflight": False,
        "W43_checkpoint_or_result_read": False,
        "preflight_sha256": canonical_sha256(row),
    }
    atomic_json(PREFLIGHT, payload)
    return payload


def load_preflight(
    expected_protocol_sha256: str, expected_preflight_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = load_protocol(expected_protocol_sha256)
    if file_sha256(PREFLIGHT) != expected_preflight_sha256:
        raise RuntimeError("A299 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-fine-selected-channel-transfer-a299-preflight-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("public_challenge_sha256") != W43_PUBLIC_CHALLENGE_SHA256
        or value.get("W43_checkpoint_or_result_read") is not False
    ):
        raise RuntimeError("A299 preflight semantics differ")
    anchor(
        path_from_ref(value["target"]["CNF"]["path"]),
        value["target"]["CNF"]["sha256"],
    )
    return protocol, value


def coarse_measurement(
    protocol: Mapping[str, Any], preflight_value: Mapping[str, Any]
) -> dict[str, Any]:
    a275, model, _a291, indices, helper = A297.A296._reader_stack()  # noqa: SLF001
    wrapper = load_module(A297.A251_WRAPPER, "a299_clause_wrapper")
    row = preflight_value["target"]
    started = time.perf_counter()
    raw_run = wrapper.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["CNF"]["path"]),
        mode="A299_W43_word0_high8_numeric_unlabeled",
        order=[f"{value:08b}" for value in range(256)],
        key_one_literals_bit0_through_bit19=row["synthetic_reader_mapping"],
        conflict_horizons=A297.HORIZONS,
        watchdog_seconds=A297.WATCHDOG_SECONDS,
        external_timeout_seconds=1800.0,
    )
    stable = {
        key: value
        for key, value in raw_run.items()
        if key not in {"command", "process_elapsed_seconds"}
    }
    measurement = {
        "schema": "chacha20-round20-w43-fine-selected-channel-transfer-a299-coarse-measurement-v1",
        "attempt_id": ATTEMPT_ID,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "unknown_key_bits": WIDTH,
        "order_name": "numeric",
        "partition_scope": "key_word0",
        "partition_coordinates_high_to_low": list(range(31, 23, -1)),
        "free_bits_per_cell": WIDTH - 8,
        "run": stable,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "target_label_available_to_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "complete_candidate_cover": len(raw_run["cells"]) == 256,
    }
    matrix = a275._target_feature_matrix(measurement)  # noqa: SLF001
    contributions = a275.standardized_contributions(
        matrix,
        means=model.means,
        scales=model.scales,
        coefficients=model.coefficients,
    )
    scores = contributions[:, indices].sum(axis=1)
    order = a275._candidate_order(scores)  # noqa: SLF001
    if len(order) != 256 or set(order) != set(range(256)):
        raise RuntimeError("A299 coarse order is not an exact cover")
    raw = canonical_bytes(measurement)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    atomic_bytes(COARSE, compressed)
    return {
        "measurement": {
            "path": relative(COARSE),
            "raw_bytes": len(raw),
            "raw_sha256": sha256(raw),
            "compressed_bytes": len(compressed),
            "compressed_sha256": sha256(compressed),
        },
        "score_field": np.asarray(scores, dtype=np.float64).tolist(),
        "score_field_sha256": canonical_sha256(
            np.asarray(scores, dtype=np.float64).tolist()
        ),
        "complete_coarse_order": order,
        "complete_coarse_order_uint8_sha256": sha256(bytes(order)),
        "selected_feature_indices": list(indices),
        "model_refits": 0,
        "target_labels_used": 0,
        "model_free_UNKNOWN_stages": len(stable["stages"]),
    }


def solver_model_permutation() -> list[int]:
    """Map helper-model indices to original assignment coordinates."""
    permutation = [*range(20), *range(32, 43), *range(20, 32)]
    if (
        len(permutation) != WIDTH
        or set(permutation) != set(range(WIDTH))
        or permutation[31:43] != list(range(20, 32))
        or list(reversed(permutation[31:43])) != list(range(31, 19, -1))
    ):
        raise RuntimeError("A299 solver model permutation differs")
    return permutation


def decode_permuted_candidate(candidate: int) -> int:
    if not 0 <= candidate < DOMAIN_SIZE:
        raise ValueError("A299 permuted candidate lies outside W43")
    result = 0
    for permuted_index, original_coordinate in enumerate(solver_model_permutation()):
        result |= ((candidate >> permuted_index) & 1) << original_coordinate
    return result


def fine_lane_plan(
    coarse_order: Sequence[int], preflight_value: Mapping[str, Any]
) -> dict[str, Any]:
    fine = A297.A296.fine_order([int(value) for value in coarse_order])
    if len(fine) != CELLS or set(fine) != set(range(CELLS)):
        raise RuntimeError("A299 coarse-plus-Gray fine seed is not an exact cover")
    source = preflight_value["target"]
    original_mapping = [
        int(value) for value in source["source_one_literals_bit0_upward"]
    ]
    permutation = solver_model_permutation()
    permuted_mapping = [original_mapping[coordinate] for coordinate in permutation]
    arms = []
    active = []
    for lane in range(LANES):
        front = fine[lane::LANES]
        front_set = set(front)
        full = [*front, *[value for value in fine if value not in front_set]]
        prefixes = [f"{value:012b}" for value in full]
        active.extend(front)
        arms.append(
            {
                "arm": f"a299_fine12_lane{lane}",
                "lane": lane,
                "cadical_configuration": "default",
                "cell_order": prefixes,
                "active_prefixes": prefixes[:CELLS_PER_LANE],
                "active_prefixes_uint16be_sha256": sha256(
                    b"".join(value.to_bytes(2, "big") for value in front)
                ),
                "seconds_per_cell": SECONDS_PER_CELL,
                "max_cells": CELLS_PER_LANE,
                "cnf": source["CNF"],
                "model_one_literals_bit0_upward": permuted_mapping,
                "model_index_to_assignment_coordinate": permutation,
            }
        )
    if len(active) != CELLS or set(active) != set(range(CELLS)):
        raise RuntimeError("A299 active lane fronts are not an exact cover")
    return {
        "fine_seed_order": fine,
        "fine_seed_order_uint16be_sha256": sha256(
            b"".join(value.to_bytes(2, "big") for value in fine)
        ),
        "model_index_to_assignment_coordinate": permutation,
        "model_permutation_sha256": canonical_sha256(permutation),
        "arms": arms,
    }


def _trace_rows(directory: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(directory.glob("*.stdout")):
        for line in path.read_text(encoding="ascii").splitlines():
            if line.startswith("PARTITION_RESULT "):
                rows.append(json.loads(line.removeprefix("PARTITION_RESULT ")))
    return rows


def measure(
    *, expected_protocol_sha256: str, expected_preflight_sha256: str
) -> dict[str, Any]:
    if COARSE.exists() or ORDER.exists() or (ARTIFACTS / "fine").exists():
        raise FileExistsError("A299 measurement artifacts already exist")
    protocol, preflight_value = load_preflight(
        expected_protocol_sha256, expected_preflight_sha256
    )
    coarse = coarse_measurement(protocol, preflight_value)
    plan = fine_lane_plan(coarse["complete_coarse_order"], preflight_value)
    helper_build = compile_w43_helper()
    a293 = load_module(A293_RUNNER, "a299_a293_fine_runner")
    original = (
        a293.WIDTH,
        a293.SUFFIX_BITS,
        a293.ARTIFACTS,
        a293.HELPER_BINARY,
    )
    try:
        a293.WIDTH = WIDTH
        a293.SUFFIX_BITS = WIDTH - PREFIX_BITS
        a293.ARTIFACTS = ARTIFACTS / "fine"
        a293.HELPER_BINARY = W43_HELPER_BINARY
        solver_rows, raw_winner = a293.run_partition(
            {"execution_plan": {"arms": plan["arms"]}}
        )
    finally:
        (
            a293.WIDTH,
            a293.SUFFIX_BITS,
            a293.ARTIFACTS,
            a293.HELPER_BINARY,
        ) = original
    winner = None
    if raw_winner is not None:
        permuted_candidate = int(raw_winner["candidate_low24"])
        candidate = decode_permuted_candidate(permuted_candidate)
        prefix = int(raw_winner["prefix12"], 2)
        if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
            raise RuntimeError("A299 decoded symbolic model prefix differs")
        winner = {
            "arm": raw_winner["arm"],
            "candidate": candidate,
            "candidate_hex": f"{candidate:011x}",
            "permuted_candidate": permuted_candidate,
            "prefix12": raw_winner["prefix12"],
            "lane_cell_index": raw_winner["lane_cell_index"],
        }
    traces = _trace_rows(ARTIFACTS / "fine")
    attempted = [str(row["prefix"]) for row in traces]
    if len(attempted) != len(set(attempted)):
        raise RuntimeError("A299 fine trace prefixes overlap")
    fine_readout = None
    if winner is None:
        if (
            len(traces) != CELLS
            or set(attempted) != {f"{value:012b}" for value in range(CELLS)}
            or any(
                row.get("status") != "unknown"
                or row.get("model_bits_bit0_upward") != []
                for row in traces
            )
        ):
            raise RuntimeError("A299 requires a complete model-free fine trace field")
        a295 = load_module(A295_RUNNER, "a299_a295_reader")
        fine_readout = a295.frozen_order(traces)
    trace_anchors = [
        anchor(path)
        for path in sorted((ARTIFACTS / "fine").glob("*"))
        if path.is_file()
    ]
    payload = {
        "schema": "chacha20-round20-w43-fine-selected-channel-transfer-a299-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "W43_DIRECT_FINE_SYMBOLIC_MODEL_DISCOVERED"
            if winner is not None
            else "W43_COMPLETE_MODEL_FREE_FINE_FIELD_AND_ORDER_FROZEN"
        ),
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "public_challenge_sha256": W43_PUBLIC_CHALLENGE_SHA256,
        "coarse_readout": coarse,
        "w43_helper_build": helper_build,
        "fine_lane_plan": {
            "fine_seed_order_uint16be_sha256": plan[
                "fine_seed_order_uint16be_sha256"
            ],
            "model_index_to_assignment_coordinate": plan[
                "model_index_to_assignment_coordinate"
            ],
            "model_permutation_sha256": plan["model_permutation_sha256"],
            "arms": plan["arms"],
        },
        "solver_arms": solver_rows,
        "attempted_prefix_cells": len(attempted),
        "direct_symbolic_winner": winner,
        "fine_readout": fine_readout,
        "trace_artifacts": trace_anchors,
        "information_boundary": {
            "target_key_label_available": False,
            "target_model_used_for_order": False,
            "candidate_filter_outcome_used_for_order": False,
            "W43_checkpoint_read": False,
            "W43_complete_domain_result_read": False,
            "reader_refits": 0,
            "target_labels_used": 0,
            "order_frozen_before_A299_Metal_candidate_discovery": True,
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "coarse_readout": coarse,
            "w43_helper_build": helper_build,
            "solver_arms": solver_rows,
            "direct_symbolic_winner": winner,
            "fine_readout": fine_readout,
            "trace_artifacts": trace_anchors,
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    return payload


def load_order(
    expected_protocol_sha256: str,
    expected_preflight_sha256: str,
    expected_order_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    protocol, preflight_value = load_preflight(
        expected_protocol_sha256, expected_preflight_sha256
    )
    if file_sha256(ORDER) != expected_order_sha256:
        raise RuntimeError("A299 order hash differs")
    value = json.loads(ORDER.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w43-fine-selected-channel-transfer-a299-order-v1"
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("preflight_sha256") != expected_preflight_sha256
        or value.get("public_challenge_sha256") != W43_PUBLIC_CHALLENGE_SHA256
        or (
            value.get("direct_symbolic_winner") is None
            and len(value.get("fine_readout", {}).get("complete_order", []))
            != CELLS
        )
        or value.get("information_boundary", {}).get("W43_checkpoint_read")
        is not False
        or value.get("information_boundary", {}).get(
            "W43_complete_domain_result_read"
        )
        is not False
        or value.get("w43_helper_build", {}).get("model_width_max") != 64
        or value.get("w43_helper_build", {}).get(
            "scientific_solver_semantics_changed"
        )
        is not False
    ):
        raise RuntimeError("A299 order semantics differ")
    for row in value["trace_artifacts"]:
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(COARSE, value["coarse_readout"]["measurement"]["compressed_sha256"])
    helper_build = value["w43_helper_build"]
    anchor(
        Path(helper_build["binary_path"]),
        helper_build["binary_sha256"],
    )
    anchor(
        Path(helper_build["derived_source_path"]),
        helper_build["derived_source_sha256"],
    )
    return protocol, preflight_value, value


def public_hash_order(public_challenge_sha256: str) -> list[int]:
    return A297.public_hash_order(public_challenge_sha256)


def ordered_discovery(
    *, host: Any, challenge: Mapping[str, Any], order: Sequence[int]
) -> dict[str, Any]:
    values = [int(value) for value in order]
    if not values or len(values) != len(set(values)) or any(
        not 0 <= value < CELLS for value in values
    ):
        raise ValueError("A299 prefix order differs")
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    known = challenge["known_zeroed_key_words"]
    counter = int(challenge["counter_start"])
    nonce = challenge["nonce_words"]
    factual: list[int] = []
    controls: list[int] = []
    gpu_seconds = 0.0
    executed_outer_slices = 0
    started = time.perf_counter()
    for group_index, prefix in enumerate(values):
        group_factual: list[int] = []
        first_word0 = prefix << WORD0_SUFFIX_BITS
        for outer in range(OUTER_SLICES):
            host.configure(W43._initial(known, counter, nonce, outer), target, control)  # noqa: SLF001
            observed = host.filter(first_word0, INNER_GROUP_SIZE)
            gpu_seconds += float(observed["gpu_seconds"])
            executed_outer_slices += 1
            group_factual.extend(
                (outer << 32) | int(word0) for word0 in observed["factual"]
            )
            controls.extend(
                (outer << 32) | int(word0) for word0 in observed["control"]
            )
        factual.extend(group_factual)
        if not group_factual:
            continue
        if len(group_factual) != 1:
            raise RuntimeError("A299 prefix group produced multiple factual filters")
        candidate = group_factual[0]
        if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
            raise RuntimeError("A299 candidate word0 prefix differs")
        groups = group_index + 1
        executed = groups * GROUP_SIZE
        return {
            "candidate": candidate,
            "candidate_hex": f"{candidate:011x}",
            "key_word0": candidate & 0xFFFFFFFF,
            "key_word1_low11": candidate >> 32,
            "fine_prefix12": prefix,
            "fine_prefix12_hex": f"{prefix:03x}",
            "Causal_prefix_rank_one_based": groups,
            "executed_prefix_groups": groups,
            "executed_outer_slices": executed_outer_slices,
            "executed_assignments": executed,
            "executed_assignments_upper_bound": executed,
            "complete_domain_assignments": DOMAIN_SIZE,
            "complete_group_execution_before_stop": True,
            "strict_subset_of_complete_domain": groups < CELLS,
            "search_gain_bits": math.log2(CELLS / groups),
            "factual_filter_candidates": factual,
            "matched_control_candidates": len(controls),
            "control_filter_candidates": controls,
            "gpu_seconds": gpu_seconds,
            "volatile_wall_seconds": time.perf_counter() - started,
        }
    raise RuntimeError("A299 exact frozen order exhausted without a factual filter")


def rank_analysis(
    *, discovery: Mapping[str, Any], order_value: Mapping[str, Any], challenge_sha: str
) -> dict[str, Any]:
    prefix = int(discovery["fine_prefix12"])
    primary = (
        [prefix]
        if order_value["direct_symbolic_winner"] is not None
        else [int(value) for value in order_value["fine_readout"]["complete_order"]]
    )
    coarse = A297.A296.fine_order(
        [int(value) for value in order_value["coarse_readout"]["complete_coarse_order"]]
    )
    numeric = list(range(CELLS))
    hashed = public_hash_order(challenge_sha)
    ranks = {
        "A299_fine_selected_channel": primary.index(prefix) + 1,
        "A297_coarse_seed": coarse.index(prefix) + 1,
        "numeric": numeric.index(prefix) + 1,
        "public_hash_control": hashed.index(prefix) + 1,
    }
    return {
        "prefix12": prefix,
        "prefix_ranks_one_based": ranks,
        "assignment_upper_bounds": {
            name: rank * GROUP_SIZE for name, rank in ranks.items()
        },
        "A299_gain_bits_vs_complete_domain": math.log2(
            CELLS / ranks["A299_fine_selected_channel"]
        ),
        "A299_speedup_vs_coarse_seed_rank": (
            ranks["A297_coarse_seed"] / ranks["A299_fine_selected_channel"]
        ),
        "A299_speedup_vs_numeric_rank": (
            ranks["numeric"] / ranks["A299_fine_selected_channel"]
        ),
        "A299_speedup_vs_public_hash_rank": (
            ranks["public_hash_control"] / ranks["A299_fine_selected_channel"]
        ),
        "counterfactual_ranks_computed_after_confirmation": True,
        "controls_triggered_no_duplicate_candidate_execution": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A299:confirmed_fine_reader_W43_recovery"
    writer = CausalWriter(api_id="a299w43")
    writer._rules = []
    writer.add_rule(
        name="word0_coarse_seed_plus_fine_trace_to_W43_order",
        description="The frozen A297 seed and unchanged A295 operator convert the public W43 trace field into a target-label-free word0-prefix order.",
        pattern=["A297_coarse_seed", "A295_fine_operator"],
        conclusion="A299_frozen_W43_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_W43_order_to_confirmed_recovery",
        description="Each prefix expands over all 2^11 outer slices and 2^20 word0 suffixes before dual eight-block confirmation.",
        pattern=["A299_frozen_W43_order", "dual_eight_block_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A297:coarse_W32_reader_boundary",
        mechanism="A297_word0_high8_seed_then_A295_fine_selected_channel_transfer",
        outcome="A299:frozen_W43_word0_prefix_order",
        confidence=1.0,
        source=payload["order_sha256"],
        quantification=json.dumps(payload["rank_analysis"], sort_keys=True),
        evidence=payload["order_sha256"],
        domain="AI-native fine-subprefix ChaCha20-R20 W43 readout",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A299:frozen_W43_word0_prefix_order",
        mechanism="complete_outer11_by_word0_suffix20_group_search_plus_dual_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["confirmation"], sort_keys=True),
        domain="confirmed full-round ChaCha20 W43 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A297:coarse_W32_reader_boundary",
        mechanism="materialized_W32_operator_to_W43_discovery_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A297_A295_A299_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A299 fine-reader W43 recovery",
        entities=[
            "A297:coarse_W32_reader_boundary",
            "A299:frozen_W43_word0_prefix_order",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_W43_replication_or_wider_residual_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the unchanged word0-prefix operator replicate at W43 or widen beyond it?"
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a299w43"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A299 authentic Causal reopen gate failed")
    source = Path(inspect.getsourcefile(CausalReader) or "")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(source),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def recover(
    *,
    expected_protocol_sha256: str,
    expected_preflight_sha256: str,
    expected_order_sha256: str,
    swiftc: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A299 final artifacts already exist")
    protocol, _preflight, order_value = load_order(
        expected_protocol_sha256,
        expected_preflight_sha256,
        expected_order_sha256,
    )
    source_protocol = _load_public_w43_protocol()
    challenge = protocol["public_challenge"]
    executable, build = W43.A184._A181._compile_native(BUILD, swiftc)  # noqa: SLF001
    host = W43.A184.SliceMetalHost(
        executable,
        W43._initial(  # noqa: SLF001
            challenge["known_zeroed_key_words"],
            int(challenge["counter_start"]),
            challenge["nonce_words"],
            0,
        ),
        np.asarray(challenge["target_words"][0], dtype=np.uint32),
        np.asarray(challenge["control_target_words"], dtype=np.uint32),
    )
    try:
        mapping = W43._mapping_gate(  # noqa: SLF001
            host,
            known_zeroed_key_words=challenge["known_zeroed_key_words"],
            counter=int(challenge["counter_start"]),
            nonce_words=challenge["nonce_words"],
        )
        direct = order_value["direct_symbolic_winner"]
        order = (
            [int(direct["prefix12"], 2)]
            if direct is not None
            else [int(value) for value in order_value["fine_readout"]["complete_order"]]
        )
        discovery = ordered_discovery(host=host, challenge=challenge, order=order)
        if direct is not None and int(discovery["candidate"]) != int(
            direct["candidate"]
        ):
            raise RuntimeError("A299 symbolic and Metal candidates differ")
        identity = host.identity
    finally:
        host.close()
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A299 matched one-bit control produced a filter candidate")
    confirmation = W43._confirm(source_protocol, int(discovery["candidate"]))  # noqa: SLF001
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A299 dual independent confirmation failed")
    ranks = rank_analysis(
        discovery=discovery,
        order_value=order_value,
        challenge_sha=W43_PUBLIC_CHALLENGE_SHA256,
    )
    evidence_stage = (
        "FULLROUND_R20_W43_FINE_READER_SYMBOLIC_PLUS_GROUP_RECOVERY_CONFIRMED"
        if order_value["direct_symbolic_winner"] is not None
        else "FULLROUND_R20_W43_FINE_SELECTED_CHANNEL_GROUP_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w43-fine-selected-channel-transfer-a299-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "preflight_sha256": expected_preflight_sha256,
        "order_sha256": expected_order_sha256,
        "public_challenge_sha256": W43_PUBLIC_CHALLENGE_SHA256,
        "native_build": build,
        "metal_identity": identity,
        "mapping_gate": mapping,
        "direct_symbolic_winner": order_value["direct_symbolic_winner"],
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "information_boundary": order_value["information_boundary"],
        "anchors": protocol["anchors"],
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "mapping_gate": mapping,
            "discovery": {
                key: value
                for key, value in discovery.items()
                if not key.startswith("volatile_")
            },
            "metal_identity": identity,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": {
                key: value
                for key, value in discovery.items()
                if not key.startswith("volatile_")
            },
            "rank_analysis": ranks,
            "confirmation": confirmation,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A299 — fine-reader ChaCha20-R20 W43 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Fine prefix rank: **{ranks['prefix_ranks_one_based']['A299_fine_selected_channel']} / 4,096**\n"
            f"- Search gain: **{ranks['A299_gain_bits_vs_complete_domain']:.6f} bits**\n"
            f"- Executed assignments: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W43 assignment: **0x{int(discovery['candidate']):011x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Reader refits / target labels: **0 / 0**\n"
            "- W43 checkpoint/result dependency: **none**\n"
        ).encode()
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "A293_complete": A293_RESULT.exists(),
        "A295_complete": A295_RESULT.exists(),
        "implementation_frozen": IMPLEMENTATION_FREEZE.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "preflight_complete": PREFLIGHT.exists(),
        "order_complete": ORDER.exists(),
        "result_complete": RESULT.exists(),
        "W43_checkpoint_or_result_consulted": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--measure", action="store_true")
    mode.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-a293-result-sha256")
    parser.add_argument("--expected-a295-result-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-preflight-sha256")
    parser.add_argument("--expected-order-sha256")
    parser.add_argument("--swiftc", default="/usr/bin/swiftc")
    args = parser.parse_args()
    if args.analyze:
        output = analyze()
    elif args.freeze:
        if not args.expected_a293_result_sha256 or not args.expected_a295_result_sha256:
            parser.error("--freeze requires both source result hashes")
        value = freeze(
            expected_a293_result_sha256=args.expected_a293_result_sha256,
            expected_a295_result_sha256=args.expected_a295_result_sha256,
        )
        output = {
            "protocol": relative(PROTOCOL),
            "protocol_sha256": file_sha256(PROTOCOL),
            "public_challenge_sha256": value["public_challenge_sha256"],
        }
    else:
        if not args.expected_protocol_sha256:
            parser.error("this mode requires --expected-protocol-sha256")
        if args.preflight:
            value = preflight(args.expected_protocol_sha256)
            output = {
                "preflight": relative(PREFLIGHT),
                "preflight_sha256": file_sha256(PREFLIGHT),
                "evidence_stage": value["evidence_stage"],
            }
        else:
            if not args.expected_preflight_sha256:
                parser.error("--measure/--recover requires --expected-preflight-sha256")
            if args.measure:
                value = measure(
                    expected_protocol_sha256=args.expected_protocol_sha256,
                    expected_preflight_sha256=args.expected_preflight_sha256,
                )
                output = {
                    "order": relative(ORDER),
                    "order_sha256": file_sha256(ORDER),
                    "evidence_stage": value["evidence_stage"],
                    "direct_symbolic_winner": value["direct_symbolic_winner"],
                }
            else:
                if not args.expected_order_sha256:
                    parser.error("--recover requires --expected-order-sha256")
                value = recover(
                    expected_protocol_sha256=args.expected_protocol_sha256,
                    expected_preflight_sha256=args.expected_preflight_sha256,
                    expected_order_sha256=args.expected_order_sha256,
                    swiftc=args.swiftc,
                )
                output = {
                    "result": relative(RESULT),
                    "result_sha256": file_sha256(RESULT),
                    "causal_sha256": value["causal"]["sha256"],
                    "evidence_stage": value["evidence_stage"],
                    "rank_analysis": value["rank_analysis"],
                }
    print(json.dumps(output, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
