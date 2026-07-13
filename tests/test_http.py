"""Tests for the shared HTTP utilities."""

from __future__ import annotations

import logging

import pytest
import requests

from shared.http import (
    check_response,
    is_transient,
    warn_credential_hygiene,
)


def _http_error(status: int) -> requests.HTTPError:
    resp = requests.Response()
    resp.status_code = status
    return requests.HTTPError(response=resp)


@pytest.mark.parametrize(
    "exc, expected",
    [
        (requests.ConnectionError(), True),
        (requests.Timeout(), True),
        (_http_error(500), True),
        (_http_error(503), True),
        (_http_error(429), True),
        (_http_error(401), False),
        (_http_error(404), False),
        (ValueError("nope"), False),
    ],
)
def test_is_transient(exc, expected):
    assert is_transient(exc) is expected


@pytest.mark.parametrize(
    "value, needle",
    [
        ("secret ", "whitespace"),
        ("with\nnewline", "control characters"),
        ("smart“quote", "non-ASCII"),
        ("", "is empty"),
    ],
)
def test_warn_credential_hygiene_flags_and_hides_value(value, needle, caplog):
    with caplog.at_level(logging.WARNING):
        warn_credential_hygiene(value, "SOME_SECRET")
    messages = "\n".join(r.getMessage() for r in caplog.records)
    assert needle in messages
    # The secret itself must never appear in the log output.
    assert value.strip() not in messages or value.strip() == ""


def test_warn_credential_hygiene_clean_value_is_silent(caplog):
    with caplog.at_level(logging.WARNING):
        warn_credential_hygiene("clean-token-123", "SOME_SECRET")
    assert caplog.records == []


def test_check_response_raises_on_error():
    resp = requests.Response()
    resp.status_code = 502
    resp.reason = "Bad Gateway"
    resp.url = "https://example.test"
    with pytest.raises(requests.HTTPError):
        check_response(resp, "context")


def test_check_response_ok_is_silent():
    resp = requests.Response()
    resp.status_code = 200
    check_response(resp, "context")  # must not raise
