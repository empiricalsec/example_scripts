"""Tests for the QID <-> high-score-CVE join."""

from __future__ import annotations

from qualys_client import QidRecord

from scripts.qualys_empirical_join.join import join


def test_join_matches_sorts_and_rounds():
    qid_map = {
        200: QidRecord(qid=200, title="B", cves=["CVE-A", "CVE-B"]),
        100: QidRecord(qid=100, title="A", cves=["CVE-C"]),
        300: QidRecord(qid=300, title="C", cves=["CVE-UNSCORED"]),
    }
    hot = {"CVE-A": 71.111181, "CVE-B": 95.0, "CVE-C": 80.0}

    matched = join(qid_map, hot)

    # QID 300 has no CVE in the hot set -> excluded.
    assert [m.qid for m in matched] == [100, 200]  # sorted by QID asc

    # Within a QID, hits are sorted by score desc, and scores are rounded to 4 dp.
    q200 = next(m for m in matched if m.qid == 200)
    assert q200.matched_cves == [
        {"cve": "CVE-B", "global_score": 95.0},
        {"cve": "CVE-A", "global_score": 71.1112},
    ]


def test_join_empty_when_no_overlap():
    qid_map = {1: QidRecord(qid=1, title="x", cves=["CVE-Z"])}
    assert join(qid_map, {"CVE-Y": 90.0}) == []
