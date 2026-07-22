"""Run configuration for the QID posture export."""

from __future__ import annotations

from dataclasses import dataclass, field

from shared.env import require_env


@dataclass
class Settings:
    """Resolved run configuration (credentials + detection scope + output).

    Build with :meth:`from_args`, which merges parsed CLI arguments with the
    environment and validates that every required credential is present. The QID
    source is always the live Host Detection posture, so there is no ``--source``
    or score-threshold knob here (every scored CVE is considered).
    """

    # Empirical credentials
    empirical_client_id: str
    empirical_client_secret: str

    # Qualys credentials + endpoint
    qualys_username: str
    qualys_password: str
    qualys_url: str

    # Query parameters
    batch_size: int
    # Host Detection filters, e.g. status/severities/show_igs/ag_titles
    detection_filters: dict[str, str] = field(default_factory=dict)
    # Asset group titles the detection query is scoped to ([] == whole org)
    asset_groups: list[str] = field(default_factory=list)

    # Output
    out_dir: str = "./output"

    @classmethod
    def from_args(cls, args) -> "Settings":
        """Build settings from parsed argparse ``args`` + environment variables."""
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
            batch_size=args.batch_size,
            detection_filters=detection_filters,
            asset_groups=asset_groups,
            out_dir=args.out_dir,
        )
