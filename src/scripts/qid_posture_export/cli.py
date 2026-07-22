"""Command-line entry point for the QID posture export."""

from __future__ import annotations

import argparse
import logging
import os

from . import __doc__ as package_doc
from .config import Settings
from .pipeline import PostureExportPipeline

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=package_doc)
    p.add_argument(
        "--qualys-url",
        default=os.environ.get("QUALYS_API_URL"),
        help="Qualys API Server URL base, e.g. "
        "https://qualysapi.qg2.apps.qualys.com (or $QUALYS_API_URL). "
        "Find yours in the Qualys UI under Help > About.",
    )
    p.add_argument(
        "--asset-group",
        action="append",
        metavar="TITLE",
        help="Scope to asset group title(s) (Qualys ag_titles). Repeatable "
        "and/or comma-separated; omit for whole-org posture. For a title "
        "containing a comma, use repeated --asset-group flags.",
    )
    p.add_argument(
        "--status",
        help="Detection filter: detection status list, e.g. Active,New,Re-Opened",
    )
    p.add_argument("--severities", help="Detection filter: severities, e.g. 4,5")
    p.add_argument("--show-igs", help="Detection filter: include Information Gathered (0/1)")
    p.add_argument(
        "--batch-size",
        type=int,
        default=10_000,
        help="QIDs per KnowledgeBase request (the ids-chunk size)",
    )
    p.add_argument("--out-dir", default="./output", help="Output directory")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    settings = Settings.from_args(args)
    PostureExportPipeline.from_settings(settings).run()


if __name__ == "__main__":
    main()
