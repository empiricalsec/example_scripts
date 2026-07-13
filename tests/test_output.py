"""Tests for the ReportWriter artifacts."""

from __future__ import annotations

import csv
import gzip
import json
import tarfile

from scripts.qualys_empirical_join.models import MatchedQid
from scripts.qualys_empirical_join.output import ReportWriter


def _matched() -> list[MatchedQid]:
    return [
        MatchedQid(
            qid=100,
            title="A",
            matched_cves=[
                {"cve": "CVE-B", "global_score": 95.0},
                {"cve": "CVE-A", "global_score": 71.1112},
            ],
        )
    ]


def test_write_all_produces_valid_artifacts(tmp_path):
    manifest = {"score_threshold": 70.0, "qids_matched": 1}
    outputs = ReportWriter(_matched(), str(tmp_path)).write_all(manifest)

    assert set(outputs) == {"results.json.gz", "results.csv", "results.tar.gz"}

    # JSON round-trips and carries the derived count.
    with gzip.open(outputs["results.json.gz"], "rt", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data[0]["qid"] == 100
    assert data[0]["matched_cve_count"] == 2

    # CSV has a header plus one row per QID+CVE pair.
    with open(outputs["results.csv"], newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == ["qid", "title", "cve", "global_score"]
    assert len(rows) == 3  # header + 2 pairs

    # Tarball bundles both files plus the manifest.
    with tarfile.open(outputs["results.tar.gz"], "r:gz") as tar:
        names = set(tar.getnames())
        assert names == {"results.json.gz", "results.csv", "manifest.json"}
        manifest_out = json.loads(tar.extractfile("manifest.json").read())
    assert manifest_out == manifest
