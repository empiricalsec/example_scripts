"""Tests for Empirical score extraction and the search parser."""

from __future__ import annotations

import pytest

from empirical_client import EmpiricalClient, extract_global_score


@pytest.mark.parametrize(
    "record, expected",
    [
        ({"scores": {"global": {"score": 0.92}}}, 92.0),  # 0-1 prob -> 0-100
        ({"scores": {"global": {"score": 85}}}, 85.0),  # already 0-100
        ({"score": 0.5}, 50.0),  # flat prob
        ({"score": 73}, 73.0),  # flat 0-100
        ({"scores": {"global": {"score": 1.0}}}, 100.0),  # boundary <= 1.0
        ({"identifier": "CVE-1"}, None),  # no score at all
        ({"scores": {}}, None),  # empty scores
    ],
)
def test_extract_global_score(record, expected):
    assert extract_global_score(record) == expected


class _FakeResponse:
    ok = True

    def __init__(self, lines: list[str]):
        self._lines = lines

    def iter_lines(self, decode_unicode: bool = False):
        yield from self._lines

    def raise_for_status(self):  # pragma: no cover - never called on ok=True
        pass


class _FakeSession:
    def __init__(self, lines: list[str]):
        self._lines = lines
        self.last_params: dict | None = None

    def get(self, url, params=None, headers=None, timeout=None, stream=None):
        self.last_params = params
        return _FakeResponse(self._lines)


def test_high_score_cves_parses_jsonl_and_uppercases(sample_search_jsonl):
    client = EmpiricalClient("id", "secret")
    client._token = "already-have-one"  # skip the token exchange
    client._session = _FakeSession(sample_search_jsonl.split("\n"))

    hot = client.high_score_cves(70)

    assert hot == {"CVE-2021-1111": 92.0, "CVE-2021-2222": 88.0}
    assert client._session.last_params["q"] == "score:>70"
    assert client._session.last_params["scoring_model"] == "global"


def test_all_global_scores_uses_match_all_query(sample_search_jsonl):
    client = EmpiricalClient("id", "secret")
    client._token = "already-have-one"  # skip the token exchange
    client._session = _FakeSession(sample_search_jsonl.split("\n"))

    scores = client.all_global_scores()

    assert scores == {"CVE-2021-1111": 92.0, "CVE-2021-2222": 88.0}
    assert client._session.last_params["q"] == "score:>=0"
    assert client._session.last_params["scoring_model"] == "global"
