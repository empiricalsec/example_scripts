"""End-to-end orchestration: detected QIDs + all scores -> reduced CSV."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from empirical_client import EmpiricalClient
from qualys_client import QualysClient

from .config import Settings
from .output import CsvWriter
from .reduce import reduce_to_qid_scores

logger = logging.getLogger("scripts.qid_posture_export.pipeline")


class PostureExportPipeline:
    """Wires the two API clients, the reduce step, and the CSV writer together.

    Construct directly with ``EmpiricalClient`` / ``QualysClient`` instances
    (convenient for tests), or via :meth:`from_settings` to build them from a
    resolved :class:`~scripts.qid_posture_export.config.Settings`.
    """

    def __init__(self, empirical: EmpiricalClient, qualys: QualysClient, settings: Settings):
        self._empirical = empirical
        self._qualys = qualys
        self._settings = settings

    @classmethod
    def from_settings(cls, settings: Settings) -> "PostureExportPipeline":
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

    def run(self) -> str:
        """Fetch, reduce, and write the CSV; return its path."""
        s = self._settings

        detected = self._qualys.host_detections(extra=s.detection_filters)
        logger.info("Host Detection returned %d unique QIDs", len(detected))
        qid_map = self._qualys.knowledge_base_by_ids(detected, batch_size=s.batch_size)

        scores = self._empirical.all_global_scores()

        rows = reduce_to_qid_scores(qid_map, scores)
        logger.info("%d of %d resolved QIDs have >=1 scored CVE", len(rows), len(qid_map))

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = CsvWriter(rows, s.out_dir, timestamp=stamp).write()
        logger.info("Wrote %s", path)
        return path
