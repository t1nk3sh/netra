"""Statistical feature engine containing helper functions for feature engineering.

Provides reusable equations for calculating entropy, inter-arrival time
statistics, periodicity, frequency, ratios, and basic aggregates.
"""

from __future__ import annotations

from typing import Sequence, Any
import numpy as np
import scipy.stats


def calculate_entropy(values: Sequence[Any]) -> float:
    """Calculate the Shannon entropy of a sequence of values.

    Args:
        values: Sequence of categories, characters, IPs, ports, etc.

    Returns:
        Shannon entropy in bits (float). Returns 0.0 if sequence is empty.
    """
    if len(values) == 0:
        return 0.0

    _, counts = np.unique(values, return_counts=True)
    probabilities = counts / len(values)
    return float(scipy.stats.entropy(probabilities, base=2))


def calculate_interarrival_statistics(timestamps: Sequence[float]) -> dict[str, float]:
    """Calculate statistics of the inter-arrival gaps between timestamps.

    Args:
        timestamps: Sequence of floating-point timestamps (not necessarily sorted).

    Returns:
        Dict with keys:
            - mean: Mean inter-arrival gap (seconds).
            - std: Standard deviation of gaps.
            - var: Variance of gaps.
            - min: Minimum gap.
            - max: Maximum gap.
            - cv: Coefficient of variation (std / mean).
            - count: Number of gaps calculated.
    """
    default_stats = {
        "mean": 0.0,
        "std": 0.0,
        "var": 0.0,
        "min": 0.0,
        "max": 0.0,
        "cv": 0.0,
        "count": 0,
    }

    if len(timestamps) < 2:
        return default_stats

    sorted_ts = np.sort(np.array(timestamps, dtype=float))
    gaps = np.diff(sorted_ts)

    if len(gaps) == 0:
        return default_stats

    mean_gap = float(np.mean(gaps))
    std_gap = float(np.std(gaps))
    var_gap = float(np.var(gaps))
    min_gap = float(np.min(gaps))
    max_gap = float(np.max(gaps))
    cv_gap = (std_gap / mean_gap) if mean_gap > 0.0 else 0.0

    return {
        "mean": mean_gap,
        "std": std_gap,
        "var": var_gap,
        "min": min_gap,
        "max": max_gap,
        "cv": cv_gap,
        "count": len(gaps),
    }


def calculate_periodicity(timestamps: Sequence[float]) -> float:
    """Calculate a periodicity score for a sequence of events.

    Returns a score between 0.0 and 1.0, where 1.0 indicates perfectly periodic
    events (intervals are identical) and 0.0 indicates highly irregular
    or insufficient events.

    Args:
        timestamps: Sequence of timestamps.

    Returns:
        float score in [0, 1].
    """
    stats = calculate_interarrival_statistics(timestamps)
    if stats["count"] < 3:
        return 0.0

    # A coefficient of variation (CV) close to 0 means the gaps are identical.
    # We formulate: score = 1 / (1 + CV)
    cv = stats["cv"]
    score = 1.0 / (1.0 + cv)

    # Let's also damp the score if the variance is extremely high relative to the mean,
    # or if we have very few samples.
    if cv > 10.0:
        return 0.0

    return float(score)


def calculate_ratios(values: Sequence[float]) -> float:
    """Calculate the ratio of positive elements to total elements.

    Args:
        values: Sequence of numeric values.

    Returns:
        float ratio.
    """
    total = len(values)
    if total == 0:
        return 0.0
    return float(sum(1 for v in values if v > 0) / total)


def calculate_unique_fraction(values: Sequence[Any]) -> float:
    """Calculate the fraction of unique items in a list.

    Args:
        values: Sequence of elements.

    Returns:
        Ratio of unique elements to total elements.
    """
    total = len(values)
    if total == 0:
        return 0.0
    return float(len(set(values)) / total)
