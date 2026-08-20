"""Shared HTTP concerns: retry policy, response checking, credential hygiene."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TypeVar, cast

import requests
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

logger = logging.getLogger("shared.http")

F = TypeVar("F", bound=Callable[..., object])


def is_transient(exc: BaseException) -> bool:
    """Retry only transient failures.

    Never retry 4xx responses -- in particular a 401, since repeatedly replaying
    a bad username/password will lock the Qualys account. Only network hiccups,
    5xx, and 429 (rate limit) are worth retrying.
    """
    # ChunkedEncodingError ("Response ended prematurely") is a mid-stream
    # disconnect; it subclasses RequestException directly, not ConnectionError.
    if isinstance(
        exc,
        (requests.ConnectionError, requests.Timeout, requests.exceptions.ChunkedEncodingError),
    ):
        return True
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        return exc.response.status_code >= 500 or exc.response.status_code == 429
    return False


def with_retry(func: F) -> F:
    """Retry ``func`` on transient failures (network, 5xx, 429) but never 4xx.

    Backs off exponentially up to 5 attempts, then re-raises the last error.
    """
    decorated = retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception(is_transient),
        reraise=True,
    )(func)
    return cast(F, decorated)


def warn_credential_hygiene(value: str, name: str) -> None:
    """Warn about invisible problems in a credential WITHOUT revealing its value.

    A stray trailing newline/space or a non-ASCII "smart quote" pasted into a
    config is a common, silent cause of "valid" credentials being rejected.
    Only boolean properties are reported -- never the secret itself.
    """
    issues = []
    if value != value.strip():
        issues.append("has leading/trailing whitespace")
    if any(ord(c) < 32 for c in value):
        issues.append("contains control characters (e.g. embedded newline)")
    if not value.isascii():
        issues.append("contains non-ASCII characters (e.g. smart quotes)")
    if not value:
        issues.append("is empty")
    if issues:
        logger.warning(
            "%s %s -- this can break authentication (value not shown)",
            name,
            "; ".join(issues),
        )


def check_response(resp: requests.Response, context: str) -> None:
    """Log full response detail on any non-2xx status, then raise HTTPError.

    Qualys and Empirical both return diagnostic bodies (XML/JSON/HTML) even on
    5xx/4xx responses, so surfacing the body is what actually explains failures
    like a 502 Bad Gateway.
    """
    if not resp.ok:
        body = (resp.text or "").strip()
        logger.error(
            "%s failed: HTTP %s %s for %s\n  content-type: %s\n  body: %s",
            context,
            resp.status_code,
            resp.reason,
            resp.url,
            resp.headers.get("Content-Type", "?"),
            body[:2000] if body else "<empty>",
        )
    resp.raise_for_status()
