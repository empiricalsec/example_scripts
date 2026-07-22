"""Tests for the shared row-count validation."""

from __future__ import annotations

from shared.validation import validate_row_count


def test_above_minimum_is_ok():
    assert validate_row_count(600, 500).ok is True


def test_below_minimum_is_not_ok():
    assert validate_row_count(499, 500).ok is False


def test_boundary_is_inclusive():
    assert validate_row_count(500, 500).ok is True


def test_zero_minimum_disables_check():
    assert validate_row_count(0, 0).ok is True


def test_message_mentions_count_and_minimum():
    failed = validate_row_count(4, 500)
    assert "4" in failed.message and "500" in failed.message
    passed = validate_row_count(600, 500)
    assert "600" in passed.message and "OK" in passed.message
