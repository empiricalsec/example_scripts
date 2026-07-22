"""Tests for Settings.from_args env handling (MIN_ROWS parsing)."""

from __future__ import annotations

import pytest

import scripts.simple_qid_posture_export.cli as cli
from scripts.simple_qid_posture_export.config import Settings


def _creds(monkeypatch):
    """Set the required credentials so from_args reaches the min_rows path."""
    for name in (
        "EMPIRICAL_CLIENT_ID",
        "EMPIRICAL_CLIENT_SECRET",
        "QUALYS_USERNAME",
        "QUALYS_PASSWORD",
        "QUALYS_API_URL",
    ):
        monkeypatch.setenv(name, "x")


def test_min_rows_defaults_to_500(monkeypatch):
    _creds(monkeypatch)
    monkeypatch.delenv("MIN_ROWS", raising=False)
    settings = Settings.from_args(cli.parse_args([]))
    assert settings.min_rows == 500


def test_min_rows_reads_env(monkeypatch):
    _creds(monkeypatch)
    monkeypatch.setenv("MIN_ROWS", "0")  # empty check must not swallow a valid 0
    settings = Settings.from_args(cli.parse_args([]))
    assert settings.min_rows == 0


def test_min_rows_cli_overrides_env(monkeypatch):
    _creds(monkeypatch)
    monkeypatch.setenv("MIN_ROWS", "999")
    settings = Settings.from_args(cli.parse_args(["--min-rows", "750"]))
    assert settings.min_rows == 750


def test_min_rows_non_integer_env_exits(monkeypatch):
    _creds(monkeypatch)
    monkeypatch.setenv("MIN_ROWS", "abc")
    with pytest.raises(SystemExit, match="MIN_ROWS must be an integer"):
        Settings.from_args(cli.parse_args([]))
