"""Tests for Empirical score extraction and the search parser."""

from __future__ import annotations

import io

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


class _FakeGzResponse:
    """Mimics a requests Response for the cves/all poll + download flow."""

    def __init__(self, status_code: int, headers: dict | None = None, raw=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.raw = raw
        self.reason = ""
        self.url = ""
        self.text = ""

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    def raise_for_status(self):  # pragma: no cover - fakes are always ok
        pass

    def __enter__(self):  # real Response is a context manager (closes on exit)
        return self

    def __exit__(self, *exc):
        return False


class _FakeCvesAllSession:
    """Serves N x 202 then a 302 on /api/cves/all, and the gzip on the download URL."""

    DOWNLOAD_URL = "https://storage.example.test/cves-all.jsonl.gz?sig=abc"

    def __init__(self, gz_bytes: bytes, poll_202: int = 0):
        self._gz = gz_bytes
        self._remaining_202 = poll_202
        self.calls: list[dict] = []

    def get(
        self,
        url,
        headers=None,
        timeout=None,
        stream=None,
        allow_redirects=None,
        params=None,
    ):
        self.calls.append(
            {"url": url, "headers": headers or {}, "allow_redirects": allow_redirects}
        )
        if url == self.DOWNLOAD_URL:
            return _FakeGzResponse(200, raw=io.BytesIO(self._gz))
        if self._remaining_202 > 0:
            self._remaining_202 -= 1
            return _FakeGzResponse(202)
        return _FakeGzResponse(302, headers={"Location": self.DOWNLOAD_URL})

    def export_calls(self) -> list[dict]:
        return [c for c in self.calls if c["url"].endswith("/api/cves/all")]

    def download_calls(self) -> list[dict]:
        return [c for c in self.calls if c["url"] == self.DOWNLOAD_URL]


def test_all_global_scores_polls_then_decodes_gzip(sample_cves_all_gz):
    client = EmpiricalClient("id", "secret")
    client._token = "already-have-one"  # skip the token exchange
    client._cves_all_poll_interval = 0  # time.sleep(0) -> instant, no monkeypatch
    session = _FakeCvesAllSession(sample_cves_all_gz, poll_202=2)
    client._session = session

    scores = client.all_global_scores()

    # No-score and no-id records in the corpus are skipped; ids are upper-cased.
    assert scores == {"CVE-2021-1111": 92.0, "CVE-2021-2222": 88.0}
    # Two 202 polls followed by the 302, then a single download.
    assert len(session.export_calls()) == 3
    assert len(session.download_calls()) == 1


def test_cves_all_does_not_send_auth_on_redirect_download(sample_cves_all_gz):
    client = EmpiricalClient("id", "secret")
    client._token = "already-have-one"
    client._cves_all_poll_interval = 0
    session = _FakeCvesAllSession(sample_cves_all_gz, poll_202=1)
    client._session = session

    client.all_global_scores()

    # Poll requests carry the bearer token and never auto-follow the redirect.
    assert all("Authorization" in c["headers"] for c in session.export_calls())
    assert all(c["allow_redirects"] is False for c in session.export_calls())
    # The presigned download must NOT receive the Authorization header.
    assert "Authorization" not in session.download_calls()[0]["headers"]


def test_all_global_scores_raises_when_export_never_ready(sample_cves_all_gz):
    client = EmpiricalClient("id", "secret")
    client._token = "already-have-one"
    client._cves_all_poll_interval = 0
    client._cves_all_max_attempts = 3
    # poll_202 exceeds max attempts, so the export never reaches 302.
    client._session = _FakeCvesAllSession(sample_cves_all_gz, poll_202=99)

    with pytest.raises(RuntimeError, match="not ready after 3 attempts"):
        client.all_global_scores()


def test_await_export_accepts_non_302_redirect():
    """Any 3xx with a Location is the ready signal, not just 302."""
    client = EmpiricalClient("id", "secret")
    client._token = "already-have-one"
    resp = _FakeGzResponse(307, headers={"Location": "https://storage.test/x.gz"})
    client._get_cves_all = lambda: resp

    assert client._await_cves_all_export() == "https://storage.test/x.gz"


def test_await_export_raises_on_redirect_without_location():
    client = EmpiricalClient("id", "secret")
    client._token = "already-have-one"
    client._get_cves_all = lambda: _FakeGzResponse(302, headers={})

    with pytest.raises(RuntimeError, match="without a Location header"):
        client._await_cves_all_export()
