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
    writer = ReportWriter(_matched(), str(tmp_path), timestamp="20260715T153045Z")
    outputs = writer.write_all(manifest)

    # Filenames carry the timestamp so successive runs don't overwrite.
    assert set(outputs) == {
        "results-20260715T153045Z.json.gz",
        "results-20260715T153045Z.csv",
        "results-20260715T153045Z.tar.gz",
    }

    # JSON round-trips and carries the derived count.
    with gzip.open(writer.json_gz_path, "rt", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data[0]["qid"] == 100
    assert data[0]["matched_cve_count"] == 2

    # CSV has a header plus one row per QID+CVE pair.
    with open(writer.csv_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == ["qid", "title", "cve", "global_score"]
    assert len(rows) == 3  # header + 2 pairs

    # Tarball bundles both files plus the manifest.
    with tarfile.open(writer.tarball_path, "r:gz") as tar:
        names = set(tar.getnames())
        assert names == {
            "results-20260715T153045Z.json.gz",
            "results-20260715T153045Z.csv",
            "manifest.json",
        }
        manifest_out = json.loads(tar.extractfile("manifest.json").read())
    assert manifest_out == manifest
