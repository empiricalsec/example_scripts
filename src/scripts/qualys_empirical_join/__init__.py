"""Join Qualys KnowledgeBase QIDs with Empirical Security foundation_v2 model scores.

Produces the set of Qualys QIDs that have at least one associated CVE whose
Empirical foundation_v2 model score is greater than a threshold (default 70), and
writes the result as a gzipped JSON, a CSV, and a tarball bundling both plus a
run manifest.

Strategy
--------
1. Pull the org's QIDs and their QID -> [CVE] mappings from Qualys (Host
   Detection + KnowledgeBase, or the KnowledgeBase alone).
2. Fetch Empirical's complete /api/cves/all score export in one download --
   far cheaper than scoring each Qualys CVE individually -- and keep the
   referenced CVEs with foundation_v2 score > threshold.
3. Keep QIDs with >= 1 CVE in the high-score set.
"""

from __future__ import annotations

from .config import Settings
from .join import join
from .models import MatchedQid
from .output import ReportWriter
from .pipeline import JoinPipeline

__all__ = [
    "JoinPipeline",
    "MatchedQid",
    "ReportWriter",
    "Settings",
    "join",
]
