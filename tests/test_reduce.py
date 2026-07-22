"""Tests for the QID posture reduce step (max-across-CVEs + round-half-up)."""

from __future__ import annotations

import pytest

from qualys_client import QidRecord
from scripts.simple_qid_posture_export.reduce import reduce_to_qid_scores, round_half_up


@pytest.mark.parametrize(
    "value, expected",
    [
        (0.0, 0),
        (0.4, 0),
        (0.5, 1),  # half rounds up (not banker's-to-even)
        (1.5, 2),  # half rounds up (banker's would give 2 here too)
        (2.5, 3),  # half rounds up (banker's would give 2)
        (88.49, 88),
        (88.5, 89),
        (99.999, 100),
    ],
)
def test_round_half_up(value, expected):
    assert round_half_up(value) == expected


def test_reduce_uses_max_score_per_qid_then_rounds():
    qid_map = {
        90001: QidRecord(qid=90001, title="A", cves=["CVE-1", "CVE-2"]),
    }
    scores = {"CVE-1": 71.4, "CVE-2": 88.6}  # max is 88.6 -> 89
    assert reduce_to_qid_scores(qid_map, scores) == [(90001, 89)]


def test_reduce_skips_qids_with_no_scored_cve():
    qid_map = {
        90001: QidRecord(qid=90001, title="A", cves=["CVE-1"]),
        90002: QidRecord(qid=90002, title="B (no CVEs)", cves=[]),
        90003: QidRecord(qid=90003, title="C (unscored CVE)", cves=["CVE-UNKNOWN"]),
    }
    scores = {"CVE-1": 50.0}
    assert reduce_to_qid_scores(qid_map, scores) == [(90001, 50)]


def test_reduce_sorts_by_qid_ascending():
    qid_map = {
        90003: QidRecord(qid=90003, title="C", cves=["CVE-3"]),
        90001: QidRecord(qid=90001, title="A", cves=["CVE-1"]),
        90002: QidRecord(qid=90002, title="B", cves=["CVE-2"]),
    }
    scores = {"CVE-1": 10.0, "CVE-2": 20.0, "CVE-3": 30.0}
    assert [qid for qid, _ in reduce_to_qid_scores(qid_map, scores)] == [90001, 90002, 90003]


def test_reduce_empty_when_no_overlap():
    qid_map = {90001: QidRecord(qid=90001, title="A", cves=["CVE-1"])}
    assert reduce_to_qid_scores(qid_map, {"CVE-OTHER": 99.0}) == []
