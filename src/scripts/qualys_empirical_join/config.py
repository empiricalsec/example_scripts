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

    # QID source: "detection" (live Host Detection posture) or "knowledge-base"
    source: str

    # Query parameters
    id_min: int
    id_max: int
    batch_size: int
    score_threshold: float
    kb_filters: dict[str, str] = field(default_factory=dict)
    # Host Detection filters (detection mode), e.g. status/severities/ag_titles
    detection_filters: dict[str, str] = field(default_factory=dict)
    # Asset group titles the detection query is scoped to ([] == whole org)
    asset_groups: list[str] = field(default_factory=list)

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

        detection_filters: dict[str, str] = {}
        for flag, param in (
            (args.status, "status"),
            (args.severities, "severities"),
            (args.show_igs, "show_igs"),
        ):
            if flag:
                detection_filters[param] = flag

        # --asset-group is repeatable and/or comma-separated; flatten to a list.
        asset_groups: list[str] = []
        for raw in args.asset_group or []:
            asset_groups.extend(g.strip() for g in raw.split(",") if g.strip())
        if asset_groups:
            detection_filters["ag_titles"] = ",".join(asset_groups)

        return cls(
            empirical_client_id=require_env("EMPIRICAL_CLIENT_ID"),
            empirical_client_secret=require_env("EMPIRICAL_CLIENT_SECRET"),
            qualys_username=require_env("QUALYS_USERNAME"),
            qualys_password=require_env("QUALYS_PASSWORD"),
            qualys_url=require_env("QUALYS_API_URL", args.qualys_url),
            source=args.source,
            id_min=args.id_min,
            id_max=args.id_max,
            batch_size=args.batch_size,
            score_threshold=args.score_threshold,
            kb_filters=kb_filters,
            detection_filters=detection_filters,
            asset_groups=asset_groups,
            out_dir=args.out_dir,
        )
