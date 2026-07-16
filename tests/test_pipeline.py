"""Tests for JoinPipeline source dispatch (detection vs knowledge-base)."""

from __future__ import annotations

import json
import tarfile

from qualys_client import QidRecord
from scripts.qualys_empirical_join.config import Settings
from scripts.qualys_empirical_join.pipeline import JoinPipeline


class _FakeEmpirical:
    def high_score_cves(self, threshold: float) -> dict[str, float]:
        return {"CVE-2021-1111": 95.0}


class _FakeQualys:
    """Records which source method the pipeline invoked."""

    def __init__(self):
        self.called: list[str] = []

    def host_detections(self, extra=None, truncation_limit=1000) -> set[int]:
        self.called.append("host_detections")
        self.last_detection_extra = extra
        return {90001, 90002}

    def knowledge_base_by_ids(self, qids, batch_size=1000, extra=None):
        self.called.append("knowledge_base_by_ids")
        return {90001: QidRecord(qid=90001, title="A", cves=["CVE-2021-1111"])}

    def knowledge_base(self, id_min, id_max, batch_size, extra=None):
        self.called.append("knowledge_base")
        return {90001: QidRecord(qid=90001, title="A", cves=["CVE-2021-1111"])}


def _settings(tmp_path, **overrides) -> Settings:
    base = dict(
        empirical_client_id="id",
        empirical_client_secret="secret",
        qualys_username="user",
        qualys_password="pass",
        qualys_url="https://qualysapi.example.test",
        source="detection",
        id_min=1,
        id_max=100,
        batch_size=1000,
        score_threshold=70.0,
        out_dir=str(tmp_path),
    )
    base.update(overrides)
    return Settings(**base)


def _manifest_from_outputs(outputs: dict[str, str]) -> dict:
    path = next(p for name, p in outputs.items() if name.endswith(".tar.gz"))
    with tarfile.open(path, "r:gz") as tar:
        return json.loads(tar.extractfile("manifest.json").read())


def test_detection_source_uses_host_detections_then_kb_by_ids(tmp_path):
    qualys = _FakeQualys()
    settings = _settings(
        tmp_path,
        source="detection",
        detection_filters={"ag_titles": "Prod Web"},
        asset_groups=["Prod Web"],
    )
    outputs = JoinPipeline(_FakeEmpirical(), qualys, settings).run()

    assert qualys.called == ["host_detections", "knowledge_base_by_ids"]
    assert qualys.last_detection_extra == {"ag_titles": "Prod Web"}

    manifest = _manifest_from_outputs(outputs)
    assert manifest["source"] == "detection"
    assert manifest["qids_detected"] == 2
    assert manifest["asset_groups"] == ["Prod Web"]
    assert "id_min" not in manifest


def test_knowledge_base_source_uses_range_scan(tmp_path):
    qualys = _FakeQualys()
    settings = _settings(tmp_path, source="knowledge-base")
    outputs = JoinPipeline(_FakeEmpirical(), qualys, settings).run()

    assert qualys.called == ["knowledge_base"]

    manifest = _manifest_from_outputs(outputs)
    assert manifest["source"] == "knowledge-base"
    assert manifest["id_min"] == 1 and manifest["id_max"] == 100
    assert "qids_detected" not in manifest
