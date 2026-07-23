"""Client for the Empirical Security API."""

from __future__ import annotations

import gzip
import json
import logging
import time

import requests
from requests.auth import HTTPBasicAuth

from shared.http import check_response, with_retry

from .constants import (
    CVES_ALL_DOWNLOAD_TIMEOUT,
    CVES_ALL_MAX_ATTEMPTS,
    CVES_ALL_PATH,
    CVES_ALL_POLL_INTERVAL,
    CVES_ALL_POLL_TIMEOUT,
    EMPIRICAL_BASE,
    FUSIONAUTH_URL,
)

logger = logging.getLogger("empirical_client")


def extract_global_score(record: dict) -> float | None:
    """Pull the global-model score from a search record, normalized to 0-100."""
    score = None
    scores = record.get("scores")
    if isinstance(scores, dict) and isinstance(scores.get("global"), dict):
        score = scores["global"].get("score")
    if score is None:
        score = record.get("score")  # some responses surface a flat score
    if score is None:
        return None
    score = float(score)
    return score * 100 if score <= 1.0 else score  # /api normalizes probs to 0-1


def _record_score(record: dict) -> tuple[str, float] | None:
    """Map one JSONL record to ``(CVE_ID_UPPER, score)`` or ``None`` if unusable."""
    cve = record.get("identifier") or record.get("cve") or record.get("cve_id")
    if not cve:
        return None
    score = extract_global_score(record)
    if score is None:
        return None
    return cve.upper(), score


class EmpiricalClient:
    """Client for the Empirical Security API (OAuth2 client-credentials)."""

    def __init__(self, client_id: str, client_secret: str):
        self._client_id = client_id
        self._client_secret = client_secret
        self._session = requests.Session()
        self._token: str | None = None
        # Bounded polling for the async /api/cves/all export (see all_global_scores).
        self._cves_all_poll_interval = CVES_ALL_POLL_INTERVAL
        self._cves_all_max_attempts = CVES_ALL_MAX_ATTEMPTS

    @with_retry
    def fetch_token(self) -> str:
        """Exchange the client id/secret for a bearer token (JWT)."""
        resp = self._session.post(
            FUSIONAUTH_URL,
            auth=HTTPBasicAuth(self._client_id, self._client_secret),
            data={
                "grant_type": "client_credentials",
                "scope": "target-entity:0c6d5dcc-8bf0-4cd1-bd65-066ef0422369",
            },
            timeout=30,
        )
        check_response(resp, "Empirical token exchange")
        return resp.json()["access_token"]

    def _headers(self) -> dict[str, str]:
        if self._token is None:
            self._token = self.fetch_token()
        return {"Authorization": f"Bearer {self._token}"}

    def high_score_cves(self, threshold: float) -> dict[str, float]:
        """Return {cve_id: global_score(0-100)} for CVEs scoring > threshold."""
        logger.info("Querying Empirical for CVEs with global score > %s", threshold)
        return self._search_scores(f"score:>{threshold}")

    def all_global_scores(self) -> dict[str, float]:
        """Return {cve_id: global_score(0-100)} for the full scored corpus.

        Sources scores from ``GET /api/cves/all`` ("all CVEs in our system"),
        which is guaranteed complete. That endpoint is an async export: it
        returns 202 while the gzipped JSONL file is generated, then 302 with a
        ``Location`` pointing at the ready file (likely presigned storage).
        """
        logger.info("Fetching all global scores from %s", CVES_ALL_PATH)
        download_url = self._await_cves_all_export()
        return self._download_cves_all(download_url)

    def _await_cves_all_export(self) -> str:
        """Poll ``/api/cves/all`` until the export is ready; return its download URL.

        Bounded by ``_cves_all_max_attempts`` so we never loop forever. The 202
        (still generating) and 3xx (ready; the endpoint returns 302) statuses
        both pass ``check_response`` and don't trigger ``with_retry``, so the
        transition is handled here.
        """
        for attempt in range(1, self._cves_all_max_attempts + 1):
            resp = self._get_cves_all()
            # Any 3xx is the "ready" signal (a Location redirect to the file);
            # 202 Accepted means still generating. Anything else is unexpected.
            if 300 <= resp.status_code < 400:
                location = resp.headers.get("Location")
                if not location:
                    raise RuntimeError(
                        f"cves/all returned {resp.status_code} without a Location header"
                    )
                logger.info("cves/all export ready after %d attempt(s)", attempt)
                return location
            if resp.status_code != 202:
                logger.warning(
                    "cves/all returned unexpected status %d; treating as not-ready",
                    resp.status_code,
                )
            # Still generating; wait and re-poll (skip the wait on the final
            # attempt, which would only delay the timeout below).
            if attempt < self._cves_all_max_attempts:
                logger.info(
                    "cves/all export still generating (attempt %d/%d); waiting %ss",
                    attempt,
                    self._cves_all_max_attempts,
                    self._cves_all_poll_interval,
                )
                time.sleep(self._cves_all_poll_interval)
        raise RuntimeError(
            f"cves/all export not ready after {self._cves_all_max_attempts} attempts"
        )

    @with_retry
    def _get_cves_all(self) -> requests.Response:
        """One poll of ``/api/cves/all`` (202 while generating, 302 when ready)."""
        resp = self._session.get(
            f"{EMPIRICAL_BASE}{CVES_ALL_PATH}",
            headers=self._headers(),
            timeout=CVES_ALL_POLL_TIMEOUT,
            allow_redirects=False,  # we follow the 302 ourselves, without auth
        )
        check_response(resp, "Empirical /api/cves/all")
        return resp

    @with_retry
    def _download_cves_all(self, url: str) -> dict[str, float]:
        """Stream-decompress the gzipped JSONL export -> {CVE_ID(upper): score(0-100)}.

        The body is a ``.gz`` file (not ``Content-Encoding: gzip``), so we read
        ``resp.raw`` through ``gzip.GzipFile`` line-by-line rather than using
        ``iter_lines``. No auth header is sent -- ``url`` is a presigned storage
        URL and the session carries no default ``Authorization``.
        """
        scores: dict[str, float] = {}
        # `with resp` releases the connection deterministically even if decoding
        # raises mid-stream (or with_retry re-requests the presigned URL).
        with self._session.get(url, timeout=CVES_ALL_DOWNLOAD_TIMEOUT, stream=True) as resp:
            check_response(resp, "Empirical cves/all download")
            with gzip.GzipFile(fileobj=resp.raw) as gz:
                for raw_line in gz:
                    line = raw_line.decode("utf-8").strip()
                    if not line:
                        continue
                    parsed = _record_score(json.loads(line))
                    if parsed is not None:
                        cve, score = parsed
                        scores[cve] = score
        logger.info("cves/all returned %d scored CVEs", len(scores))
        return scores

    @with_retry
    def _search_scores(self, query: str) -> dict[str, float]:
        """Stream ``/api/search`` for ``query`` -> {CVE_ID(upper): score(0-100)}."""
        resp = self._session.get(
            f"{EMPIRICAL_BASE}/api/search",
            params={
                "q": query,
                "scoring_model": "global",
                "accept": "application/jsonl",
            },
            headers={**self._headers(), "Accept": "application/jsonl"},
            timeout=300,
            stream=True,
        )
        check_response(resp, "Empirical /api/search")

        scores: dict[str, float] = {}
        for line in resp.iter_lines(decode_unicode=True):
            if not line or not line.strip():
                continue
            parsed = _record_score(json.loads(line))
            if parsed is not None:
                cve, score = parsed
                scores[cve] = score
        logger.info("Empirical returned %d scored CVEs for %r", len(scores), query)
        return scores
