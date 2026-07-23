"""Reduce QID -> [CVE] mappings to one rounded score per QID."""

from __future__ import annotations

import math

from qualys_client import QidRecord


def round_half_up(value: float) -> int:
    """Round to the nearest whole number, halves rounding up.

    Python's built-in ``round`` uses banker's rounding (round-half-to-even),
    which surprises users for values like 2.5. Scores here are 0-100, so a plain
    ``floor(value + 0.5)`` gives the expected "nearest whole number" behavior.
    """
    return math.floor(value + 0.5)


def reduce_to_qid_scores(
    qid_map: dict[int, QidRecord], scores: dict[str, float]
) -> list[tuple[int, int]]:
    """One (qid, rounded_score) row per QID, using its highest CVE score.

    Picks the max raw global score across the QID's CVEs that are present in
    ``scores``, then rounds. QIDs with no scored CVE are skipped (there is no
    score to report). Rows are sorted by QID ascending. Matching assumes both
    sides upper-case CVE ids (they do).
    """
    rows: list[tuple[int, int]] = []
    for rec in qid_map.values():
        candidates = [scores[cve] for cve in rec.cves if cve in scores]
        if candidates:
            rows.append((rec.qid, round_half_up(max(candidates))))
    rows.sort(key=lambda r: r[0])
    return rows
