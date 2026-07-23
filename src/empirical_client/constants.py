"""Empirical Security API endpoints."""

from __future__ import annotations

FUSIONAUTH_URL = "https://empiricalsecurity.fusionauth.io/oauth2/token"
EMPIRICAL_BASE = "https://app.empiricalsecurity.com"

# /api/cves/all is an async export: it returns 202 Accepted while the gzipped
# JSONL file is being generated, then 302 Found with a Location once it's ready.
CVES_ALL_PATH = "/api/cves/all"
CVES_ALL_POLL_INTERVAL = 10  # seconds between export-readiness polls
CVES_ALL_MAX_ATTEMPTS = 30  # bounded: ~5 min before giving up
CVES_ALL_POLL_TIMEOUT = 60  # per poll request
CVES_ALL_DOWNLOAD_TIMEOUT = 300  # the gzip download can be large
