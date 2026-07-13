"""Run configuration for the Qualys <-> Empirical join."""

from __future__ import annotations

from dataclasses import dataclass, field

from shared.env import require_env


@dataclass
class Settings:
    """Resolved run configuration (credentials + query parameters + output).

    Build with :meth:`from_args`, which merges parsed CLI arguments with the
    environment and validates that every required credential is present.
    """

    # Empirical credentials
    empirical_client_id: str
    empirical_client_secret: str

    # Qualys credentials + endpoint
    qualys_username: str
    qualys_password: str
    qualys_url: str

    # Query parameters
    id_min: int
    id_max: int
    batch_size: int
    score_threshold: float
    kb_filters: dict[str, str] = field(default_factory=dict)

    # Output
    out_dir: str = "./output"

    @classmethod
    def from_args(cls, args) -> "Settings":
        """Build settings from parsed argparse ``args`` + environment variables."""
        kb_filters: dict[str, str] = {}
        for flag, param in (
            (args.modified_after, "last_modified_after"),
            (args.modified_before, "last_modified_before"),
            (args.published_after, "published_after"),
            (args.published_before, "published_before"),
        ):
            if flag:
                kb_filters[param] = flag

        return cls(
            empirical_client_id=require_env("EMPIRICAL_CLIENT_ID"),
            empirical_client_secret=require_env("EMPIRICAL_CLIENT_SECRET"),
            qualys_username=require_env("QUALYS_USERNAME"),
            qualys_password=require_env("QUALYS_PASSWORD"),
            qualys_url=require_env("QUALYS_API_URL", args.qualys_url),
            id_min=args.id_min,
            id_max=args.id_max,
            batch_size=args.batch_size,
            score_threshold=args.score_threshold,
            kb_filters=kb_filters,
            out_dir=args.out_dir,
        )
