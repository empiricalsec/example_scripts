"""Tests for the shared mailx email alerter (subprocess mocked)."""

from __future__ import annotations

import subprocess

import pytest

from shared.alerting import DEFAULT_SUBJECT, AlertError, EmailAlerter


def test_send_builds_argv_and_passes_body(monkeypatch):
    calls = {}

    def fake_run(cmd, **kwargs):
        calls["cmd"] = cmd
        calls["kwargs"] = kwargs
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    alerter = EmailAlerter(
        recipients=["a@x.test", "b@y.test"], sender="from@x.test", subject="Subj"
    )
    alerter.send("the body")

    assert calls["cmd"] == [
        "mailx",
        "-s",
        "Subj",
        "-r",
        "from@x.test",
        "a@x.test",
        "b@y.test",
    ]
    assert calls["kwargs"]["input"] == "the body"
    assert calls["kwargs"]["check"] is True


def test_send_omits_sender_flag_when_unset(monkeypatch):
    calls = {}

    def fake_run(cmd, **kwargs):
        calls["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    EmailAlerter(recipients=["a@x.test"]).send("body")

    assert "-r" not in calls["cmd"]
    assert calls["cmd"] == ["mailx", "-s", DEFAULT_SUBJECT, "a@x.test"]


def test_send_raises_alert_error_when_mailx_missing(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("mailx")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(AlertError, match="not found on PATH"):
        EmailAlerter(recipients=["a@x.test"]).send("body")


def test_send_raises_alert_error_on_nonzero_exit(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd, stderr="relay refused")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(AlertError, match="relay refused"):
        EmailAlerter(recipients=["a@x.test"]).send("body")
