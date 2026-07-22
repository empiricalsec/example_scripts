"""Tests for PostureExportPipeline wiring (detections -> scores -> CSV)."""

from __future__ import annotations

import csv

from qualys_client import QidRecord
from scripts.qid_posture_export.config import Settings
from scripts.qid_posture_export.pipeline import PostureExportPipeline


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
    )
    base.update(overrides)
    return Settings(**base)


def test_pipeline_writes_one_row_per_scored_qid(tmp_path):
    qualys = _FakeQualys()
    settings = _settings(tmp_path)

    path = PostureExportPipeline(_FakeEmpirical(), qualys, settings).run()

    assert qualys.called == ["host_detections", "knowledge_base_by_ids"]
    assert qualys.last_detection_extra == {"ag_titles": "Prod Web"}

    with open(path, newline="", encoding="utf-8") as fh:
        got = list(csv.reader(fh))
    # QID 90001 -> max(71.4, 88.6) -> 89; QID 90003 has no scored CVE -> dropped.
    assert got == [["qid", "score"], ["90001", "89"]]
