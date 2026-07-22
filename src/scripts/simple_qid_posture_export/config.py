"""Run configuration for the QID posture export."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from shared.env import require_env

# Default subject for this script's validation-failure alert emails.
DEFAULT_ALERT_SUBJECT = "simple-qid-posture-export validation failed"


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

    # Validation: flag a run producing fewer than this many rows (<=0 disables)
    min_rows: int = 500

    # Optional email alerts (enabled iff alert_email_to is non-empty)
    alert_email_to: list[str] = field(default_factory=list)
    alert_email_from: str | None = None
    alert_email_subject: str = DEFAULT_ALERT_SUBJECT

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

        # --alert-email-to is repeatable and/or comma-separated; env is a
        # comma-separated fallback. Same flatten idiom as --asset-group.
        alert_email_to: list[str] = []
        raw_recipients = args.alert_email_to or []
        if not raw_recipients and os.environ.get("ALERT_EMAIL_TO"):
            raw_recipients = [os.environ["ALERT_EMAIL_TO"]]
        for raw in raw_recipients:
            alert_email_to.extend(a.strip() for a in raw.split(",") if a.strip())

        if args.min_rows is not None:
            min_rows = args.min_rows
        else:
            raw_min_rows = os.environ.get("MIN_ROWS")
            try:
                min_rows = int(raw_min_rows) if raw_min_rows else 500
            except ValueError:
                raise SystemExit(f"MIN_ROWS must be an integer, got {raw_min_rows!r}")

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
            min_rows=min_rows,
            alert_email_to=alert_email_to,
            alert_email_from=args.alert_email_from or os.environ.get("ALERT_EMAIL_FROM") or None,
            alert_email_subject=os.environ.get("ALERT_EMAIL_SUBJECT") or DEFAULT_ALERT_SUBJECT,
        )
