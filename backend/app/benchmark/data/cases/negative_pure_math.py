# Benchmark case: no cryptography whatsoever. Ground-truth: TRUE NEGATIVE.
# The scanner must not fire any finding on this file.
"""Utility functions -- statistics for the internal reporting pipeline."""

from __future__ import annotations

from statistics import mean, stdev


def z_score(sample: list[float], value: float) -> float:
    if len(sample) < 2:
        return 0.0
    m = mean(sample)
    s = stdev(sample)
    return 0.0 if s == 0 else (value - m) / s


def percent_change(before: float, after: float) -> float:
    if before == 0:
        return 0.0
    return (after - before) / before * 100.0
