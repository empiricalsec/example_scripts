"""Command-line entry point for the Qualys <-> Empirical join."""

from __future__ import annotations

import argparse
import logging
import os

from . import __doc__ as package_doc
from .config import Settings
from .pipeline import JoinPipeline

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
    p.add_argument("--id-min", type=int, default=1, help="Lowest QID to fetch")
    p.add_argument("--id-max", type=int, default=1_000_000, help="Highest QID to fetch")
    p.add_argument(
        "--batch-size", type=int, default=10_000, help="QIDs per KnowledgeBase request"
    )
    p.add_argument("--modified-after", help="KB filter: last_modified_after (YYYY-MM-DD)")
    p.add_argument("--modified-before", help="KB filter: last_modified_before (YYYY-MM-DD)")
    p.add_argument("--published-after", help="KB filter: published_after (YYYY-MM-DD)")
    p.add_argument("--published-before", help="KB filter: published_before (YYYY-MM-DD)")
    p.add_argument(
        "--score-threshold",
        type=float,
        default=70.0,
        help="Global-model score threshold (0-100), exclusive",
    )
    p.add_argument("--out-dir", default="./output", help="Output directory")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    settings = Settings.from_args(args)
    JoinPipeline.from_settings(settings).run()


if __name__ == "__main__":
    main()
