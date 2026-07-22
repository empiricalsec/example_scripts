"""Client for the Empirical Security API."""

from __future__ import annotations

import json
import logging

import requests
from requests.auth import HTTPBasicAuth

from shared.http import check_response, with_retry

from .constants import EMPIRICAL_BASE, FUSIONAUTH_URL

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


class EmpiricalClient:
    """Client for the Empirical Security API (OAuth2 client-credentials)."""

    def __init__(self, client_id: str, client_secret: str):
        self._client_id = client_id
        self._client_secret = client_secret
        self._session = requests.Session()
        self._token: str | None = None

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
        """Return {cve_id: global_score(0-100)} for *every* scored CVE (no threshold).

        Uses the ``score:>=0`` match-all query so the caller can look up any CVE's
        score locally. The ``score`` field in the query syntax is on the 0-100
        scale, so ``>=0`` includes the entire scored corpus.
        """
        logger.info("Querying Empirical for all global scores (score:>=0)")
        return self._search_scores("score:>=0")

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
            record = json.loads(line)
            cve = record.get("identifier") or record.get("cve")
            if not cve:
                continue
            score = extract_global_score(record)
            if score is not None:
                scores[cve.upper()] = score
        logger.info("Empirical returned %d scored CVEs for %r", len(scores), query)
        return scores
