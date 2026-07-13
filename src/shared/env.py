"""Environment-variable helpers shared across scripts."""

from __future__ import annotations

import os


def require_env(name: str, cli_value: str | None = None) -> str:
    """Return a required value from a CLI flag or environment variable.

    Raises SystemExit with an actionable message if neither is set.
    """
    value = cli_value or os.environ.get(name)
    if not value:
        raise SystemExit(
            f"Missing required credential: set ${name} (or pass its CLI flag)"
        )
    return value
