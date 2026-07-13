"""Verify API connectivity + credentials for both services, without running the
full join.

Runs two independent, read-only checks and prints PASS/FAIL for each:

  1. Empirical  - exchange client id/secret for a JWT, then make one tiny
                  /api/search call (high threshold => small result).
  2. Qualys     - HTTP Basic auth against the KnowledgeBase API for a single
                  small QID window (id_min/id_max), confirming the API Server
                  URL + credentials work.

Nothing is written to disk and no full downloads happen. Exit code is 0 only if
every check that has credentials configured passes.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

import requests

from empirical_client import EmpiricalClient
from qualys_client import QualysClient

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)


def _report_error(exc: Exception) -> None:
    """Print exception detail, including any HTTP response body from the server."""
    print(f"  FAIL: {type(exc).__name__}: {exc}")
    resp = getattr(exc, "response", None)
    if isinstance(resp, requests.Response):
        body = (resp.text or "").strip()
        print(
            f"  response {resp.status_code} {resp.reason}, "
            f"content-type={resp.headers.get('Content-Type', '?')}"
        )
        print(f"  body: {body[:2000] if body else '<empty>'}")


class CredentialChecker:
    """Runs the per-service connectivity checks using only public client APIs."""

    def __init__(self, qualys_url: str | None = None):
        self._qualys_url = qualys_url or os.environ.get("QUALYS_API_URL")

    def check_empirical(self) -> bool:
        print("== Empirical Security ==")
        client_id = os.environ.get("EMPIRICAL_CLIENT_ID")
        client_secret = os.environ.get("EMPIRICAL_CLIENT_SECRET")
        if not client_id or not client_secret:
            print("  SKIP: EMPIRICAL_CLIENT_ID / EMPIRICAL_CLIENT_SECRET not set")
            return True

        client = EmpiricalClient(
            client_id=client_id,
            client_secret=client_secret,
        )
        try:
            token = client.fetch_token()
            print(f"  auth OK (token length {len(token)})")
            # High threshold keeps the response tiny; we only need proof it works.
            hot = client.high_score_cves(95)
            print(f"  search OK ({len(hot)} CVEs with global score > 95)")
            print("  PASS")
            return True
        except Exception as exc:  # noqa: BLE001 - surface any failure to the user
            _report_error(exc)
            return False

    def check_qualys(self) -> bool:
        print("== Qualys KnowledgeBase ==")
        username = os.environ.get("QUALYS_USERNAME")
        password = os.environ.get("QUALYS_PASSWORD")
        base_url = self._qualys_url
        if not username or not password or not base_url:
            print("  SKIP: QUALYS_USERNAME / QUALYS_PASSWORD / QUALYS_API_URL not set")
            return True

        client = QualysClient(username=username, password=password, base_url=base_url)
        try:
            # Smallest possible query: a narrow QID window. Runs exactly one auth
            # attempt (401s are not retried), so it will not lock the account.
            qids = client.knowledge_base(id_min=1, id_max=100, batch_size=100)
            print(f"  auth + KnowledgeBase OK ({len(qids)} QIDs returned for QIDs 1-100)")
            print("  PASS")
            return True
        except Exception as exc:  # noqa: BLE001
            _report_error(exc)
            return False


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only",
        choices=["empirical", "qualys"],
        help="Check only one service (default: both)",
    )
    parser.add_argument(
        "--qualys-url",
        default=os.environ.get("QUALYS_API_URL"),
        help="Qualys API Server URL (or $QUALYS_API_URL)",
    )
    args = parser.parse_args(argv)

    checker = CredentialChecker(qualys_url=args.qualys_url)
    results = []
    if args.only in (None, "empirical"):
        results.append(checker.check_empirical())
    if args.only in (None, "qualys"):
        results.append(checker.check_qualys())

    if all(results):
        print("\nAll configured checks passed.")
        sys.exit(0)
    print("\nOne or more checks FAILED.")
    sys.exit(1)


if __name__ == "__main__":
    main()
