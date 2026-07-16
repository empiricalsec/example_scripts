"""Client for the Qualys KnowledgeBase API."""

from __future__ import annotations

import base64
import logging
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlparse

import requests

from shared.http import check_response, warn_credential_hygiene, with_retry

from .models import QidRecord
from .parsing import parse_detection_xml, parse_kb_xml

logger = logging.getLogger("qualys_client")


class QualysClient:
    """Client for the Qualys VM/PC ("FO") APIs (HTTP Basic auth).

    Covers two data sources, both served from the account's **API Server URL**
    (e.g. https://qualysapi.qg2.apps.qualys.com) with the mandatory
    ``X-Requested-With`` header -- NOT the Gateway URL / JWT flow (that is only
    for CSAM, EDR, FIM, Container Security):

    * KnowledgeBase -- the full vulnerability catalog
      (``/api/4.0/fo/knowledge_base/vuln/index.php``). See :meth:`knowledge_base`
      (range scan) and :meth:`knowledge_base_by_ids` (specific QID set).
    * Host Detection -- the org's live vulnerability posture, i.e. which QIDs are
      currently detected across assets
      (``/api/2.0/fo/asset/host/vm/detection/``). See :meth:`host_detections`.

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

    def knowledge_base_by_ids(
        self,
        qids: Iterable[int],
        batch_size: int = 1000,
        extra: dict[str, str] | None = None,
    ) -> dict[int, QidRecord]:
        """Fetch QID->record mappings for a specific set of QIDs.

        Uses the KnowledgeBase ``ids`` parameter (a comma-separated QID list) so
        only the requested QIDs are fetched -- far cheaper than scanning the full
        id range. The set is sorted and chunked into ``batch_size`` requests to
        keep each request bounded. Empty input makes no HTTP calls.
        """
        extra = extra or {}
        ordered = sorted(set(qids))
        result: dict[int, QidRecord] = {}
        for i in range(0, len(ordered), batch_size):
            chunk = ordered[i : i + batch_size]
            logger.info("Resolving %d QIDs via KnowledgeBase ids param", len(chunk))
            xml = self._list({"ids": ",".join(str(q) for q in chunk), **extra})
            batch = parse_kb_xml(xml)
            result.update(batch)
            logger.info("  parsed %d QIDs (running total %d)", len(batch), len(result))
        return result

    @with_retry
    def _detection_list(self, params: dict[str, str]) -> str:
        resp = self._session.post(
            f"{self._base}/api/2.0/fo/asset/host/vm/detection/",
            data={"action": "list", **params},
            headers=self._headers(),
            timeout=300,
        )
        check_response(resp, "Qualys Host Detection list")
        return resp.text

    def host_detections(
        self,
        extra: dict[str, str] | None = None,
        truncation_limit: int = 1000,
    ) -> set[int]:
        """Return the deduplicated set of QIDs currently detected across assets.

        This is the org's live vulnerability posture. ``extra`` carries optional
        Host Detection filters (e.g. ``status``, ``severities``, ``show_igs``,
        ``ag_titles`` to scope to asset group(s)).

        Follows Qualys pagination: each truncated page carries a ``<WARNING>``
        with the verbatim next-page ``<URL>``; its query string (minus ``action``,
        which :meth:`_detection_list` injects) is replayed as the next request's
        params until no warning remains.
        """
        extra = extra or {}
        params: dict[str, str] = {"truncation_limit": str(truncation_limit), **extra}
        qids: set[int] = set()
        seen_urls: set[str] = set()
        page = 0
        while True:
            page += 1
            logger.info("Fetching Host Detection page %d", page)
            xml = self._detection_list(params)
            batch, next_url = parse_detection_xml(xml)
            qids |= batch
            logger.info(
                "  page %d: %d QIDs (running unique total %d)", page, len(batch), len(qids)
            )
            if not next_url or next_url in seen_urls:
                break
            seen_urls.add(next_url)
            params = {k: v for k, v in parse_qsl(urlparse(next_url).query) if k != "action"}
        return qids
