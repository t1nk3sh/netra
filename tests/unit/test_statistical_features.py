"""Unit tests for features/statistical_features.py"""

import pytest

from features.statistical_features import (
    calculate_entropy,
    calculate_interarrival_statistics,
    calculate_periodicity,
    calculate_ratios,
    calculate_unique_fraction,
)


class TestCalculateEntropy:
    def test_empty_sequence(self):
        assert calculate_entropy([]) == 0.0

    def test_single_value(self):
        assert calculate_entropy([1]) == 0.0
        assert calculate_entropy(["a"]) == 0.0

    def test_two_equally_likely_values(self):
        # 1 bit of entropy
        assert calculate_entropy([0, 1]) == pytest.approx(1.0)
        assert calculate_entropy(["a", "b"]) == pytest.approx(1.0)

    def test_four_equally_likely_values(self):
        # 2 bits of entropy
        assert calculate_entropy([1, 2, 3, 4]) == pytest.approx(2.0)

    def test_unevaluated_probabilities(self):
        # [0, 0, 0, 1] -> p(0) = 0.75, p(1) = 0.25
        # Entropy = - (0.75 * log2(0.75) + 0.25 * log2(0.25)) = 0.811
        assert calculate_entropy([0, 0, 0, 1]) == pytest.approx(0.811, abs=0.001)


class TestCalculateInterarrivalStatistics:
    def test_empty_timestamps(self):
        stats = calculate_interarrival_statistics([])
        assert stats["count"] == 0
        assert stats["mean"] == 0.0
        assert stats["cv"] == 0.0

    def test_one_timestamp(self):
        stats = calculate_interarrival_statistics([1.5])
        assert stats["count"] == 0
        assert stats["mean"] == 0.0

    def test_two_timestamps(self):
        stats = calculate_interarrival_statistics([1.0, 3.0])
        assert stats["count"] == 1
        assert stats["mean"] == 2.0
        assert stats["min"] == 2.0
        assert stats["max"] == 2.0
        assert stats["std"] == 0.0
        assert stats["cv"] == 0.0

    def test_multiple_timestamps_regular(self):
        # Timestamps: 0, 2, 4, 6 -> gaps: 2, 2, 2
        stats = calculate_interarrival_statistics([0.0, 4.0, 2.0, 6.0]) # unsorted input
        assert stats["count"] == 3
        assert stats["mean"] == 2.0
        assert stats["std"] == 0.0
        assert stats["min"] == 2.0
        assert stats["max"] == 2.0
        assert stats["cv"] == 0.0

    def test_multiple_timestamps_irregular(self):
        # Timestamps: 0, 1, 3, 6 -> gaps: 1, 2, 3
        # gaps mean = 2.0
        # gaps std = sqrt(((1-2)^2 + (2-2)^2 + (3-2)^2)/3) = sqrt(2/3) ~= 0.81649
        stats = calculate_interarrival_statistics([0.0, 1.0, 3.0, 6.0])
        assert stats["count"] == 3
        assert stats["mean"] == 2.0
        assert stats["std"] == pytest.approx(0.81649, abs=1e-4)
        assert stats["min"] == 1.0
        assert stats["max"] == 3.0
        assert stats["cv"] == pytest.approx(0.81649 / 2.0, abs=1e-4)


class TestCalculatePeriodicity:
    def test_too_few_elements(self):
        assert calculate_periodicity([]) == 0.0
        assert calculate_periodicity([1.0]) == 0.0
        assert calculate_periodicity([1.0, 2.0]) == 0.0  # only 1 gap

    def test_perfectly_periodic(self):
        # gaps: 1.5, 1.5, 1.5 -> std=0, cv=0 -> periodicity = 1.0
        assert calculate_periodicity([0.0, 1.5, 3.0, 4.5]) == pytest.approx(1.0)

    def test_irregular_periodicity(self):
        # gaps: 1, 2, 3 -> mean=2, std=0.81649, cv=0.4082 -> score = 1 / 1.4082 ~= 0.710
        assert calculate_periodicity([0.0, 1.0, 3.0, 6.0]) == pytest.approx(0.710, abs=0.01)


class TestCalculateRatios:
    def test_empty(self):
        assert calculate_ratios([]) == 0.0

    def test_all_positive(self):
        assert calculate_ratios([1, 2.5, 3]) == 1.0

    def test_none_positive(self):
        assert calculate_ratios([0, -1.0, -5]) == 0.0

    def test_mixed(self):
        assert calculate_ratios([0, -1, 3.5, 2.0]) == 0.5


class TestCalculateUniqueFraction:
    def test_empty(self):
        assert calculate_unique_fraction([]) == 0.0

    def test_all_unique(self):
        assert calculate_unique_fraction([1, 2, 3, "a"]) == 1.0

    def test_all_same(self):
        assert calculate_unique_fraction(["a", "a", "a"]) == pytest.approx(1/3)

    def test_mixed(self):
        assert calculate_unique_fraction([1, 2, 1, 3]) == pytest.approx(0.75)
