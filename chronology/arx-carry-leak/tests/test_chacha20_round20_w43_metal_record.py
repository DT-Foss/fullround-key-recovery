from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research/experiments/chacha20_round20_w43_metal_record.py"
)
SPEC = importlib.util.spec_from_file_location("chacha20_w43_record_test_module", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_reference_gate_matches_rfc8439_and_independent_word_core() -> None:
    gate = MODULE.reference_gate()
    assert gate["rounds"] == 20
    assert gate["feedforward"] is True
    assert gate["output_bits_checked"] == 512
    assert gate["pure_python_exact"] is True
    assert gate["independent_word_reference_exact"] is True


def test_w43_assignment_layout_and_boundaries() -> None:
    known = [0, 0xABCDF800, 1, 2, 3, 4, 5, 6]
    assignment = (0x7FF << 32) | 0xFFFFFFFF
    recovered = MODULE.apply_assignment(known, assignment)
    assert recovered[0] == 0xFFFFFFFF
    assert recovered[1] == 0xABCDFFFF
    assert recovered[2:] == known[2:]
    with pytest.raises(ValueError):
        MODULE.apply_assignment(known, 1 << 43)
    with pytest.raises(ValueError):
        MODULE.apply_assignment([1, *known[1:]], 0)


def test_frozen_challenge_contains_public_relation_but_no_assignment() -> None:
    challenge = MODULE._challenge_from_assignment(
        label="CHACHA20KR43|unit|public",
        assignment=0x543210FEDCB,
    )
    MODULE._validate_challenge(challenge)
    assert challenge["unknown_assignment_included"] is False
    assert "assignment" not in challenge
    assert "secret" not in challenge
    assert "full_key" not in challenge
    assert len(challenge["target_words"]) == 8
    assert all(len(block) == 16 for block in challenge["target_words"])


def test_freeze_and_load_preserve_pre_execution_boundary(tmp_path: Path) -> None:
    qualification = {
        "schema": MODULE.QUALIFICATION_SCHEMA,
        "attempt_id": MODULE.ATTEMPT_ID,
        "qualification_state": "complete_before_production_challenge_generation",
        "selection": {
            "selected_width": 43,
            "logical_candidate_count": 1 << 43,
            "launch_approved": True,
        },
        "production_challenge_generated": False,
    }
    qualification_path = tmp_path / "qualification.json"
    qualification_path.write_text(json.dumps(qualification, sort_keys=True))
    qualification_sha = MODULE._file_sha256(qualification_path)
    protocol_path = tmp_path / "protocol.json"
    frozen = MODULE.freeze_protocol(
        design_path=MODULE.DEFAULT_DESIGN,
        qualification_path=qualification_path,
        expected_qualification_sha256=qualification_sha,
        output=protocol_path,
    )
    protocol_sha = MODULE._file_sha256(protocol_path)
    loaded = MODULE._load_protocol(protocol_path, protocol_sha)
    assert loaded == frozen
    assert loaded["information_boundary"]["fresh_assignment_stored"] is False
    assert "assignment" not in loaded["challenge"]
    assert loaded["execution"]["complete_domain_required"] is True
    assert loaded["execution"]["early_stop_used"] is False


class _FakeHost:
    def __init__(self, factual_assignment: int):
        self.factual_assignment = factual_assignment
        self.outer = 0

    def configure(
        self,
        initial: np.ndarray,
        target: np.ndarray,
        control: np.ndarray,
    ) -> None:
        del target, control
        self.outer = int(initial[5]) & ((1 << MODULE.WORD1_LOW_BITS) - 1)

    def filter(self, first: int, count: int) -> dict[str, object]:
        expected_outer = self.factual_assignment >> MODULE.WORD0_BITS
        expected_inner = self.factual_assignment & MODULE.MASK32
        factual = (
            [expected_inner]
            if self.outer == expected_outer and first <= expected_inner < first + count
            else []
        )
        return {
            "factual": factual,
            "control": [],
            "gpu_seconds": 0.001,
        }


def test_small_complete_domain_enumeration_is_disjoint_and_resumable(
    tmp_path: Path,
) -> None:
    factual_assignment = 777
    challenge = MODULE._challenge_from_assignment(
        label="CHACHA20KR43|unit|enumeration",
        assignment=factual_assignment,
    )
    protocol = {
        "challenge": challenge,
        "public_challenge_sha256": MODULE._canonical_sha256(challenge),
    }
    checkpoint = tmp_path / "checkpoint.json"
    result = MODULE.enumerate_domain(
        host=_FakeHost(factual_assignment),
        protocol=protocol,
        protocol_sha256="a" * 64,
        checkpoint_path=checkpoint,
        resume=False,
        domain_size=1024,
        stream_candidates=64,
    )
    assert result["complete_domain_executed"] is True
    assert result["executed_assignment_count"] == 1024
    assert result["factual_filter_matches"] == [factual_assignment]
    assert result["control_filter_matches"] == []
    resumed = MODULE.enumerate_domain(
        host=_FakeHost(factual_assignment),
        protocol=protocol,
        protocol_sha256="a" * 64,
        checkpoint_path=checkpoint,
        resume=True,
        domain_size=1024,
        stream_candidates=64,
    )
    assert resumed["resumed_assignment_count"] == 1024
    assert resumed["newly_executed_assignment_count"] == 0
    assert resumed["factual_filter_matches"] == [factual_assignment]


def test_authentic_causal_roundtrip_retains_rules_inference_and_gap(
    tmp_path: Path,
) -> None:
    payload = {
        "qualification_sha256": "1" * 64,
        "mapping_gate": {"official_reference_and_Metal_exact": True},
        "execution_sha256": "2" * 64,
        "confirmation_sha256": "3" * 64,
        "execution": {
            "factual_filter_matches": [777],
            "control_filter_matches": [],
        },
        "confirmation": {
            "assignment": 777,
            "all_blocks_match": True,
        },
    }
    path = tmp_path / "w43.causal"
    summary = MODULE.build_causal(
        path=path,
        payload=payload,
        dotcausal_src=MODULE.DEFAULT_DOTCAUSAL_SRC,
    )
    assert summary["api_id"] == "c20kr43"
    assert summary["triplets"] == 7
    assert summary["rules"] == 2
    assert summary["clusters"] == 2
    assert summary["gaps"][0]["expected_object_type"] == (
        "prospectively_selected_strict_subset_of_W43_domain"
    )
