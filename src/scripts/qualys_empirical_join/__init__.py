"""Join Qualys KnowledgeBase QIDs with Empirical Security foundation_v2 model scores.

Produces the set of Qualys QIDs that have at least one associated CVE whose
Empirical foundation_v2 model score is greater than a threshold (default 70), and
writes the result as a gzipped JSON, a CSV, and a tarball bundling both plus a
run manifest.

Strategy
--------
1. Pull the *set* of all CVEs with foundation_v2 score > threshold from Empirical's
   /api/search endpoint in a single (streamed) query -- far cheaper than
   scoring each Qualys CVE individually.
2. Pull QID -> [CVE] mappings from the Qualys KnowledgeBase API.
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
