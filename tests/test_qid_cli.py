"""Tests for CLI exit codes (pipeline mocked; no real credentials needed)."""

from __future__ import annotations

import scripts.simple_qid_posture_export.cli as cli
from scripts.simple_qid_posture_export.pipeline import PostureExportPipeline, RunResult
from shared.validation import validate_row_count


class _FakePipeline:
    def __init__(self, ok: bool):
        self._ok = ok

    def run(self) -> RunResult:
        row_count = 500 if self._ok else 1
        return RunResult("some.csv", validate_row_count(row_count, 500))


def _patch(monkeypatch, ok: bool):
    monkeypatch.setattr(cli.Settings, "from_args", staticmethod(lambda args: object()))
    monkeypatch.setattr(
        PostureExportPipeline, "from_settings", staticmethod(lambda settings: _FakePipeline(ok))
    )


def test_main_returns_zero_on_pass(monkeypatch):
    _patch(monkeypatch, ok=True)
    assert cli.main([]) == 0


def test_main_returns_one_on_validation_failure(monkeypatch):
    _patch(monkeypatch, ok=False)
    assert cli.main([]) == 1
