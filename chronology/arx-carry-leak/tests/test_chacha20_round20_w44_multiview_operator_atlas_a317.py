from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_w44_multiview_operator_atlas_a317.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("a317_test_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A317 = load_runner()


def test_confirmed_prototypes_and_target_boundary() -> None:
    design = A317.load_design()
    rows = design["operator_contract"]["confirmed_prototypes"]
    assert [tuple(row["coordinates_one_based"]) for row in rows] == A317.PROTOTYPES
    assert design["information_boundary"]["A313_result_available_at_design_freeze"] is False


def test_multiview_orders_are_exact_and_byte_frozen() -> None:
    value = A317.reconstruct()
    expected = {
        "nearest_prototype_L1": "f6493a2e4c6cafaf7a3353b583e8a3bb4fd057df71fc23e721203d3f2f0c4272",
        "nearest_prototype_Linf": "ebcbc4e1b195f82d4645d280e70e557fdfd0082fde329aaa6d2be90ff282f066",
        "nearest_prototype_squared_L2": "4c625e552d0465caca587a8f0a0d39ae3a5daa658b6727574afaf356eaa9fd2b",
    }
    for metric, digest in expected.items():
        assert value["hashes"][metric] == digest
        assert len(value["atlas"][metric]) == A317.CELLS
        assert set(value["atlas"][metric]) == set(range(A317.CELLS))
    assert value["diversity"]["operator_pairs"] == 21
    assert value["diversity"]["target_labels_used"] == 0


def test_metric_definitions_are_exact() -> None:
    point = (4, 10, 20)
    prototype = (1, 12, 25)
    assert A317._distance(point, prototype, "nearest_prototype_L1") == 10  # noqa: SLF001
    assert A317._distance(point, prototype, "nearest_prototype_Linf") == 5  # noqa: SLF001
    assert A317._distance(point, prototype, "nearest_prototype_squared_L2") == 38  # noqa: SLF001
    with pytest.raises(ValueError):
        A317._distance(point, prototype, "unknown")  # noqa: SLF001
