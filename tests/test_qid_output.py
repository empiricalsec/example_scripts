"""Tests for the QID posture CSV writer."""

from __future__ import annotations

import csv
import os

from scripts.simple_qid_posture_export.output import CsvWriter


def test_write_csv_header_and_rows(tmp_path):
    rows = [(90001, 89), (90002, 12)]
    writer = CsvWriter(rows, str(tmp_path), timestamp="20260721T000000Z")

    path = writer.write()

    assert os.path.basename(path) == "qid-posture-20260721T000000Z.csv"
    with open(path, newline="", encoding="utf-8") as fh:
        got = list(csv.reader(fh))
    assert got == [["qid", "score"], ["90001", "89"], ["90002", "12"]]


def test_write_creates_out_dir(tmp_path):
    out_dir = tmp_path / "nested" / "output"
    path = CsvWriter([(1, 0)], str(out_dir), timestamp="20260721T000000Z").write()
    assert os.path.isfile(path)


def test_default_timestamp_in_filename(tmp_path):
    path = CsvWriter([], str(tmp_path)).write()
    name = os.path.basename(path)
    assert name.startswith("qid-posture-") and name.endswith("Z.csv")
