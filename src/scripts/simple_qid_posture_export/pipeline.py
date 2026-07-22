"""End-to-end orchestration: detected QIDs + all scores -> reduced CSV."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from empirical_client import EmpiricalClient
from qualys_client import QualysClient
from shared.alerting import AlertError, EmailAlerter
from shared.validation import ValidationResult, validate_row_count

from .config import Settings
from .output import CsvWriter
from .reduce import reduce_to_qid_scores

logger = logging.getLogger("scripts.simple_qid_posture_export.pipeline")


@dataclass(frozen=True)
class RunResult:
    """What a pipeline run produced: the CSV path and its validation outcome."""

    csv_path: str
    validation: ValidationResult


def build_alerter(settings: Settings) -> EmailAlerter | None:
    """Build an email alerter from settings, or ``None`` when alerts are disabled.

    Alerts are enabled purely by the presence of a recipient
    (``settings.alert_email_to``); an empty list means alerts are off.
    """
    if not settings.alert_email_to:
        return None
    return EmailAlerter(
        recipients=list(settings.alert_email_to),
        sender=settings.alert_email_from,
        subject=settings.alert_email_subject,
    )


class PostureExportPipeline:
    """Wires the two API clients, the reduce step, and the CSV writer together.

    Construct directly with ``EmpiricalClient`` / ``QualysClient`` instances
    (convenient for tests), or via :meth:`from_settings` to build them from a
    resolved :class:`~scripts.simple_qid_posture_export.config.Settings`.
    """

    def __init__(
        self,
        empirical: EmpiricalClient,
        qualys: QualysClient,
        settings: Settings,
        alerter: EmailAlerter | None = None,
    ):
        self._empirical = empirical
        self._qualys = qualys
        self._settings = settings
        self._alerter = alerter

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
        return cls(empirical, qualys, settings, build_alerter(settings))

    def run(self) -> RunResult:
        """Fetch, reduce, write the CSV, then validate (alerting on failure)."""
        s = self._settings

        detected = self._qualys.host_detections(extra=s.detection_filters)
        logger.info("Host Detection returned %d unique QIDs", len(detected))
        qid_map = self._qualys.knowledge_base_by_ids(detected, batch_size=s.batch_size)

        scores = self._empirical.all_global_scores()

        rows = reduce_to_qid_scores(qid_map, scores)
        logger.info("%d of %d resolved QIDs have >=1 scored CVE", len(rows), len(qid_map))

        path = CsvWriter(rows, s.out_dir).write()
        logger.info("Wrote %s", path)

        validation = validate_row_count(len(rows), s.min_rows)
        if validation.ok:
            logger.info("Validation passed: %s", validation.message)
        else:
            logger.error("Validation failed: %s", validation.message)
            self._alert(validation, path)

        return RunResult(csv_path=path, validation=validation)

    def _alert(self, validation: ValidationResult, path: str) -> None:
        """Email the validation failure if an alerter is configured (non-fatal)."""
        if self._alerter is None:
            logger.warning(
                "Validation failed but no alert recipient configured; skipping email"
            )
            return

        s = self._settings
        scope = ", ".join(s.asset_groups) if s.asset_groups else "whole org"
        body = (
            f"{validation.message}\n\n"
            f"CSV: {path}\n"
            f"Scope: {scope}\n"
            f"Rows written: {validation.row_count}\n"
            f"Minimum expected: {validation.min_rows}\n"
        )
        try:
            self._alerter.send(body)
        except AlertError as exc:
            logger.error("Email alert failed: %s", exc)
