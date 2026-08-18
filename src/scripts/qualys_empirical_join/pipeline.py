"""End-to-end orchestration: Qualys QIDs -> Empirical scores -> join -> reports."""

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

        # Qualys first: the org's QIDs determine which CVEs need scoring.
        if s.source == "detection":
            detected = self._qualys.host_detections(extra=s.detection_filters)
            logger.info("Host Detection returned %d unique QIDs", len(detected))
            qid_map = self._qualys.knowledge_base_by_ids(
                detected, batch_size=s.batch_size, extra=s.kb_filters
            )
        else:
            detected = None
            qid_map = self._qualys.knowledge_base(
                id_min=s.id_min,
                id_max=s.id_max,
                batch_size=s.batch_size,
                extra=s.kb_filters,
            )

        referenced = {cve for rec in qid_map.values() for cve in rec.cves}
        logger.info("%d QIDs reference %d unique CVEs", len(qid_map), len(referenced))

        # Score from the complete cves/all export, restricted to the CVEs the
        # org actually has, so the report covers the full posture. (/api/search
        # drops large streamed responses, so it is not used here.)
        all_scores = self._empirical.all_global_scores()
        hot = {
            cve: score
            for cve, score in all_scores.items()
            if cve in referenced and score > s.score_threshold
        }

        matched = join(qid_map, hot)
        logger.info(
            "%d QIDs have >=1 CVE with global score > %s",
            len(matched),
            s.score_threshold,
        )

        now = datetime.now(timezone.utc)
        manifest = {
            "generated_at": now.isoformat(),
            "qualys_api_url": s.qualys_url,
            "source": s.source,
            "score_threshold": s.score_threshold,
            "kb_filters": s.kb_filters,
            "cves_referenced": len(referenced),
            "high_score_cve_count": len(hot),
            "qids_resolved": len(qid_map),
            "qids_matched": len(matched),
            "matched_pairs": sum(len(m.matched_cves) for m in matched),
        }
        if s.source == "detection":
            manifest["asset_groups"] = s.asset_groups
            manifest["detection_filters"] = s.detection_filters
            manifest["qids_detected"] = len(detected)
        else:
            manifest["id_min"] = s.id_min
            manifest["id_max"] = s.id_max

        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        outputs = ReportWriter(matched, s.out_dir, timestamp=stamp).write_all(manifest)
        logger.info("Wrote:\n  %s", "\n  ".join(outputs.values()))
        return outputs
