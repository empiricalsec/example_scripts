"""Reusable client for the Empirical Security API."""

from __future__ import annotations

from .client import EmpiricalClient, extract_global_score
from .constants import EMPIRICAL_BASE, FUSIONAUTH_URL

__all__ = [
    "EMPIRICAL_BASE",
    "FUSIONAUTH_URL",
    "EmpiricalClient",
    "extract_global_score",
]
