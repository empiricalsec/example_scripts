"""Client for the Qualys KnowledgeBase API."""

from __future__ import annotations

import base64
import logging

import requests

from shared.http import check_response, warn_credential_hygiene, with_retry

from .models import QidRecord
from .parsing import parse_kb_xml

logger = logging.getLogger("qualys_client")


class QualysClient:
    """Client for the Qualys KnowledgeBase API (HTTP Basic auth).

    KnowledgeBase is a VM/PC ("FO") API, served from the account's **API Server
    URL** (e.g. https://qualysapi.qg2.apps.qualys.com) on the current
    ``/api/4.0/fo/knowledge_base/vuln/index.php`` endpoint, with the mandatory
    ``X-Requested-With`` header -- NOT the Gateway URL / JWT flow (that is only
    for CSAM, EDR, FIM, Container Security).

    The Basic-auth header is built explicitly with UTF-8 base64 rather than
    ``requests``' HTTPBasicAuth (which uses latin-1), so passwords with special
    characters transmit exactly as stored.
    """

    def __init__(self, username: str, password: str, base_url: str):
        warn_credential_hygiene(username, "QUALYS_USERNAME")
        warn_credential_hygiene(password, "QUALYS_PASSWORD")
        self._username = username
        self._password = password
        self._base = base_url.rstrip("/")
        self._session = requests.Session()

    def _headers(self) -> dict[str, str]:
        raw = f"{self._username}:{self._password}".encode("utf-8")
        return {
            "X-Requested-With": "empirical-join-script",
            "User-Agent": "empirical-join-script/0.1",
            "Authorization": "Basic " + base64.b64encode(raw).decode("ascii"),
        }

    @with_retry
    def _list(self, params: dict[str, str]) -> str:
        resp = self._session.post(
            f"{self._base}/api/4.0/fo/knowledge_base/vuln/index.php",
            data={"action": "list", "details": "Basic", **params},
            headers=self._headers(),
            timeout=300,
        )
        check_response(resp, "Qualys KnowledgeBase list")
        return resp.text

    def knowledge_base(
        self,
        id_min: int,
        id_max: int,
        batch_size: int,
        extra: dict[str, str] | None = None,
    ) -> dict[int, QidRecord]:
        """Fetch QID->record mappings, batched over the QID range."""
        extra = extra or {}
        result: dict[int, QidRecord] = {}
        lo = id_min
        while lo <= id_max:
            hi = min(lo + batch_size - 1, id_max)
            logger.info("Fetching KnowledgeBase QIDs %d-%d", lo, hi)
            xml = self._list({"id_min": str(lo), "id_max": str(hi), **extra})
            batch = parse_kb_xml(xml)
            result.update(batch)
            logger.info("  parsed %d QIDs (running total %d)", len(batch), len(result))
            lo = hi + 1
        return result
