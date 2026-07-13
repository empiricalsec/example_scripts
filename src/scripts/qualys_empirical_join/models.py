"""Join-result models specific to this script."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MatchedQid:
    """A QID that has at least one CVE in the Empirical high-score set."""

    qid: int
    title: str
    matched_cves: list[dict]  # [{"cve": str, "global_score": float}]
