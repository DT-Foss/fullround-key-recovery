"""Dimension-agnostic XOR-orbit readout for prefix-indexed weak signals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import numpy as np


@dataclass(frozen=True)
class XorOrbit:
    raw_z: np.ndarray
    xor_laplacian: np.ndarray
    xor_gradient_l2: np.ndarray
    xor_gradient_maxabs: np.ndarray


@dataclass(frozen=True)
class ContributionTerm:
    source_feature_index: int
    transform: str
    coefficient: float
    mean: float
    scale: float


# A272's eight prospectively validated positive selected-channel terms.  A
# single measured channel is intentionally reused across the original horizon
# slots; no coefficient is fitted or changed here.
A272_SINGLE_HORIZON_TERMS: Final[tuple[ContributionTerm, ...]] = (
    ContributionTerm(502, "xor_gradient_l2", 0.0010501636320763804, 0.45621808668666164, 1.1381567144243574),
    ContributionTerm(504, "raw_z", 0.011537926479101178, -2.1454192589143161e-16, 0.9999999999999881),
    ContributionTerm(505, "xor_laplacian", 0.010545802277352797, 2.6237692574149207e-18, 1.0081815301110792),
    ContributionTerm(508, "raw_z", 0.004835449400166007, 3.623403660446556e-16, 1.0000000000000047),
    ContributionTerm(509, "xor_laplacian", 0.005339996817035024, -4.336808689942018e-19, 1.0138212253498855),
    ContributionTerm(510, "xor_gradient_l2", 0.006615501694144408, 1.278085743312968, 0.5178748523475099),
    ContributionTerm(511, "xor_gradient_maxabs", 0.008610400087558699, 2.1965947369557046, 0.7501747055099146),
    ContributionTerm(514, "xor_gradient_l2", 0.0027197440972309035, 1.3045396409083105, 0.5488296673908083),
)


def signed_ratio(numerator: np.ndarray, denominator: np.ndarray) -> np.ndarray:
    """Return the scale-free signed ratio used by the trajectory reader."""

    left = np.asarray(numerator, dtype=np.float64)
    right = np.asarray(denominator, dtype=np.float64)
    if left.shape != right.shape or left.ndim != 1:
        raise ValueError("ratio channels must be equal one-dimensional fields")
    if not np.isfinite(left).all() or not np.isfinite(right).all():
        raise ValueError("ratio channels must be finite")
    scale = np.abs(left) + np.abs(right)
    return np.divide(
        left - right,
        scale,
        out=np.zeros_like(left),
        where=scale > 0.0,
    )


def xor_orbit(values: np.ndarray, bits: int) -> XorOrbit:
    """Construct standardized XOR-neighbor transforms on a ``2**bits`` field."""

    field = np.asarray(values, dtype=np.float64)
    size = 1 << bits
    if bits < 1 or field.shape != (size,) or not np.isfinite(field).all():
        raise ValueError("XOR-orbit field must be finite and have length 2**bits")
    mean = float(field.mean())
    scale = float(field.std())
    if scale <= max(1e-12, abs(mean) * 1e-12):
        standardized = np.zeros_like(field)
    else:
        standardized = (field - mean) / scale
    indices = np.arange(size, dtype=np.uint64)
    neighbors = np.stack(
        [standardized[indices ^ (1 << bit)] for bit in range(bits)], axis=1
    )
    differences = standardized[:, None] - neighbors
    return XorOrbit(
        raw_z=standardized,
        xor_laplacian=differences.mean(axis=1),
        xor_gradient_l2=np.sqrt(np.mean(np.square(differences), axis=1)),
        xor_gradient_maxabs=np.max(np.abs(differences), axis=1),
    )


def frozen_a272_single_horizon_score(
    numerator: np.ndarray,
    denominator: np.ndarray,
    *,
    bits: int,
) -> np.ndarray:
    """Apply A272's unchanged positive channel to one prefix-field horizon."""

    orbit = xor_orbit(signed_ratio(numerator, denominator), bits)
    score = np.zeros(1 << bits, dtype=np.float64)
    for term in A272_SINGLE_HORIZON_TERMS:
        values = getattr(orbit, term.transform)
        score += term.coefficient * ((values - term.mean) / term.scale)
    if not np.isfinite(score).all():
        raise RuntimeError("A272 single-horizon score is not finite")
    return score


def descending_order(scores: np.ndarray) -> list[int]:
    """Return a stable descending score order with ascending-index ties."""

    values = np.asarray(scores, dtype=np.float64)
    if values.ndim != 1 or not np.isfinite(values).all():
        raise ValueError("score field must be finite and one-dimensional")
    order = sorted(range(len(values)), key=lambda index: (-float(values[index]), index))
    if len(order) != len(values) or set(order) != set(range(len(values))):
        raise RuntimeError("score order is not an exact permutation")
    return order
