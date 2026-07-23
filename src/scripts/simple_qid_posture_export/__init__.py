"""Export the org's live vulnerability posture as one rounded score per QID.

Pulls the set of QIDs currently detected across assets from the Qualys Host
Detection API, maps them to CVEs via the KnowledgeBase, and joins them against
*every* Empirical global-model score (no threshold). Each QID is emitted once,
scored with the highest global score across its CVEs, rounded to the nearest
whole number (0-100).

Strategy
--------
1. Qualys Host Detection -> the deduped set of detected QIDs (live posture).
2. Qualys KnowledgeBase (by ids) -> QID -> [CVE] mappings.
3. Empirical /api/search (``score:>=0``) -> {CVE: global_score(0-100)} for the
   whole scored corpus in one streamed request (no per-CVE calls, no cache).
4. Reduce to one row per QID: round(max score across its scored CVEs).

The ``last_updated_at`` date is intentionally *not* produced here; it is derived
downstream (e.g. by diffing successive daily runs of this export).
"""

from __future__ import annotations

from .config import Settings
from .output import CsvWriter
from .pipeline import PostureExportPipeline, RunResult, build_alerter
from .reduce import reduce_to_qid_scores, round_half_up

__all__ = [
    "CsvWriter",
    "PostureExportPipeline",
    "RunResult",
    "Settings",
    "build_alerter",
    "reduce_to_qid_scores",
    "round_half_up",
]
