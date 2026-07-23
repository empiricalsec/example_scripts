"""Tests for PostureExportPipeline wiring (detections -> scores -> CSV)."""

from __future__ import annotations

import csv

import pytest

from qualys_client import QidRecord
from scripts.simple_qid_posture_export.config import Settings
from scripts.simple_qid_posture_export.pipeline import PostureExportPipeline, build_alerter


class _FakeEmpirical:
    def all_global_scores(self) -> dict[str, float]:
        # CVE-2021-2222 scores highest for QID 90001; 90003 has no scored CVE.
        return {"CVE-2021-1111": 71.4, "CVE-2021-2222": 88.6}


class _FakeQualys:
    def __init__(self):
        self.called: list[str] = []
        self.last_detection_extra = None

    def host_detections(self, extra=None, truncation_limit=1000) -> set[int]:
        self.called.append("host_detections")
        self.last_detection_extra = extra
        return {90001, 90003}

    def knowledge_base_by_ids(self, qids, batch_size=1000, extra=None):
        self.called.append("knowledge_base_by_ids")
        return {
            90001: QidRecord(qid=90001, title="A", cves=["CVE-2021-1111", "CVE-2021-2222"]),
            90003: QidRecord(qid=90003, title="C", cves=["CVE-UNSCORED"]),
        }


class _RecordingAlerter:
    def __init__(self):
        self.bodies: list[str] = []

    def send(self, body: str) -> None:
        self.bodies.append(body)


def _settings(tmp_path, **overrides) -> Settings:
    base = dict(
        empirical_client_id="id",
        empirical_client_secret="secret",
        qualys_username="user",
        qualys_password="pass",
        qualys_url="https://qualysapi.example.test",
        batch_size=1000,
        detection_filters={"ag_titles": "Prod Web"},
        asset_groups=["Prod Web"],
        out_dir=str(tmp_path),
        # Default to a trivially-passing threshold; tests raise it to force failure.
        min_rows=1,
        alert_email_to=[],
        alert_email_from=None,
    )
    base.update(overrides)
    return Settings(**base)


def test_pipeline_writes_one_row_per_scored_qid(tmp_path):
    qualys = _FakeQualys()
    settings = _settings(tmp_path)

    result = PostureExportPipeline(_FakeEmpirical(), qualys, settings).run()

    assert qualys.called == ["host_detections", "knowledge_base_by_ids"]
    assert qualys.last_detection_extra == {"ag_titles": "Prod Web"}
    assert result.validation.ok is True

    with open(result.csv_path, newline="", encoding="utf-8") as fh:
        got = list(csv.reader(fh))
    # QID 90001 -> max(71.4, 88.6) -> 89; QID 90003 has no scored CVE -> dropped.
    assert got == [["qid", "score"], ["90001", "89"]]


def test_build_alerter_disabled_without_recipient(tmp_path):
    assert build_alerter(_settings(tmp_path, alert_email_to=[])) is None


def test_build_alerter_enabled_with_recipient(tmp_path):
    settings = _settings(
        tmp_path,
        alert_email_to=["a@x.test", "b@y.test"],
        alert_email_from="from@x.test",
    )
    alerter = build_alerter(settings)
    assert alerter is not None
    assert alerter.recipients == ["a@x.test", "b@y.test"]
    assert alerter.sender == "from@x.test"
    assert alerter.subject == settings.alert_email_subject


def test_validation_fails_below_threshold_and_alerts(tmp_path):
    settings = _settings(tmp_path, min_rows=500)
    alerter = _RecordingAlerter()

    result = PostureExportPipeline(
        _FakeEmpirical(), _FakeQualys(), settings, alerter
    ).run()

    assert result.validation.ok is False
    assert len(alerter.bodies) == 1
    # Body carries the actual row count (1 scored QID here).
    assert "1" in alerter.bodies[0]


def test_validation_pass_does_not_alert(tmp_path):
    settings = _settings(tmp_path, min_rows=1)
    alerter = _RecordingAlerter()

    result = PostureExportPipeline(
        _FakeEmpirical(), _FakeQualys(), settings, alerter
    ).run()

    assert result.validation.ok is True
    assert alerter.bodies == []


def test_validation_failure_without_alerter_is_not_fatal(tmp_path):
    settings = _settings(tmp_path, min_rows=500)

    result = PostureExportPipeline(_FakeEmpirical(), _FakeQualys(), settings).run()

    assert result.validation.ok is False


def test_alert_send_error_is_logged_not_fatal(tmp_path):
    from shared.alerting import AlertError

    class _FailingAlerter:
        def send(self, body: str) -> None:
            raise AlertError("mailx boom")

    settings = _settings(tmp_path, min_rows=500)

    result = PostureExportPipeline(
        _FakeEmpirical(), _FakeQualys(), settings, _FailingAlerter()
    ).run()

    assert result.validation.ok is False


class _FailingEmpirical:
    def all_global_scores(self) -> dict[str, float]:
        raise RuntimeError("cves/all export not ready after 30 attempts")


def test_score_fetch_failure_alerts_and_reraises(tmp_path):
    settings = _settings(tmp_path)
    alerter = _RecordingAlerter()

    pipeline = PostureExportPipeline(
        _FailingEmpirical(), _FakeQualys(), settings, alerter
    )
    with pytest.raises(RuntimeError, match="cves/all export not ready"):
        pipeline.run()

    assert len(alerter.bodies) == 1
    assert "cves/all export" in alerter.bodies[0]


def test_score_fetch_failure_without_alerter_still_reraises(tmp_path):
    settings = _settings(tmp_path)

    pipeline = PostureExportPipeline(_FailingEmpirical(), _FakeQualys(), settings)
    with pytest.raises(RuntimeError, match="cves/all export not ready"):
        pipeline.run()
