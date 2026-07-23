"""Cross-cutting, tool-agnostic utilities shared by every client and script."""

from __future__ import annotations

from .alerting import AlertError, EmailAlerter
from .env import require_env
from .http import check_response, is_transient, warn_credential_hygiene, with_retry
from .validation import ValidationResult, validate_row_count

__all__ = [
    "AlertError",
    "EmailAlerter",
    "ValidationResult",
    "check_response",
    "is_transient",
    "require_env",
    "validate_row_count",
    "warn_credential_hygiene",
    "with_retry",
]
