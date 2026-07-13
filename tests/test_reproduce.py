from __future__ import annotations

from pathlib import Path

from fullround_key_recovery.artifacts import load_result
from fullround_key_recovery.reproduce import SPECS, _candidate_output, _retained_targets

ROOT = Path(__file__).parents[1]


def test_reproducer_specs_cover_exact_complete_domains() -> None:
    assert SPECS["chacha20"]["outer_slices"] * 2**32 == 2**40
    assert SPECS["speck32_64"]["outer_slices"] * 2**32 == 2**42
    assert SPECS["threefish256"]["outer_slices"] * 2**32 == 2**38
    assert all((2 ** spec["unknown_bits"]) % spec["stream_candidates"] == 0 for spec in SPECS.values())


def test_reproducer_decodes_every_retained_assignment_independently() -> None:
    for name in SPECS:
        payload = load_result(name, ROOT)
        challenge = payload["public_challenge"]
        assignment = payload["execution"]["factual_full_matches"][0]
        target, control = _retained_targets(name, challenge)
        output = _candidate_output(name, challenge, assignment)
        assert output == target
        assert output != control
