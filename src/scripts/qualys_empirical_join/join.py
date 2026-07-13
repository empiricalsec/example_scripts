"""Join Qualys QID records against the Empirical high-score CVE set."""

from __future__ import annotations

from qualys_client import QidRecord

from .models import MatchedQid


def join(qid_map: dict[int, QidRecord], hot: dict[str, float]) -> list[MatchedQid]:
    """Keep QIDs with >=1 CVE in ``hot``; annotate each hit with its score.

    Hits within a QID are sorted by score (desc); the result is sorted by QID (asc).
    """
    matched: list[MatchedQid] = []
    for rec in qid_map.values():
        hits = [
            {"cve": cve, "global_score": round(hot[cve], 4)}
            for cve in rec.cves
            if cve in hot
        ]
        if hits:
            hits.sort(key=lambda h: h["global_score"], reverse=True)
            matched.append(MatchedQid(qid=rec.qid, title=rec.title, matched_cves=hits))
    matched.sort(key=lambda m: m.qid)
    return matched
