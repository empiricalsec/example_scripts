"""End-to-end orchestration: Empirical + Qualys -> join -> written reports."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from empirical_client import EmpiricalClient
from qualys_client import QualysClient

from .config import Settings
from .join import join
from .output import ReportWriter

logger = logging.getLogger("scripts.qualys_empirical_join.pipeline")


class JoinPipeline:
    """Wires the two API clients, the join, and the report writer together.

    Construct directly with ``EmpiricalClient`` / ``QualysClient`` instances
    (convenient for tests), or via :meth:`from_settings` to build them from a
    resolved :class:`~scripts.qualys_empirical_join.config.Settings`.
    """

    def __init__(self, empirical: EmpiricalClient, qualys: QualysClient, settings: Settings):
        self._empirical = empirical
        self._qualys = qualys
        self._settings = settings

    @classmethod
    def from_settings(cls, settings: Settings) -> "JoinPipeline":
        empirical = EmpiricalClient(
            client_id=settings.empirical_client_id,
            client_secret=settings.empirical_client_secret,
        )
        qualys = QualysClient(
            username=settings.qualys_username,
            password=settings.qualys_password,
            base_url=settings.qualys_url,
        )
        return cls(empirical, qualys, settings)

    def run(self) -> dict[str, str]:
        """Execute the full join and write all artifacts; return output paths."""
        s = self._settings

        hot = self._empirical.high_score_cves(s.score_threshold)

        qid_map = self._qualys.knowledge_base(
            id_min=s.id_min,
            id_max=s.id_max,
            batch_size=s.batch_size,
            extra=s.kb_filters,
        )

        matched = join(qid_map, hot)
        logger.info(
            "%d QIDs have >=1 CVE with global score > %s",
            len(matched),
            s.score_threshold,
        )

        manifest = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "qualys_api_url": s.qualys_url,
            "score_threshold": s.score_threshold,
            "id_min": s.id_min,
            "id_max": s.id_max,
            "kb_filters": s.kb_filters,
            "high_score_cve_count": len(hot),
            "qids_scanned": len(qid_map),
            "qids_matched": len(matched),
            "matched_pairs": sum(len(m.matched_cves) for m in matched),
        }

        outputs = ReportWriter(matched, s.out_dir).write_all(manifest)
        logger.info("Wrote:\n  %s", "\n  ".join(outputs.values()))
        return outputs
