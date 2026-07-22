"""Write the QID posture export to a timestamped CSV."""

from __future__ import annotations

import csv
import os
from datetime import datetime, timezone


def _utc_stamp() -> str:
    """A filesystem-safe UTC timestamp, e.g. 20260715T153045Z."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class CsvWriter:
    """Writes ``(qid, score)`` rows to ``qid-posture-<stamp>.csv``.

    Filenames carry a UTC timestamp so successive runs accumulate rather than
    overwrite. Pass ``timestamp`` to control the stamp; it defaults to now.
    """

    def __init__(
        self, rows: list[tuple[int, int]], out_dir: str, timestamp: str | None = None
    ):
        self._rows = rows
        self._out_dir = out_dir
        stamp = timestamp or _utc_stamp()
        self.csv_name = f"qid-posture-{stamp}.csv"
        self.csv_path = os.path.join(out_dir, self.csv_name)

    def write(self) -> str:
        """Write the CSV; return its path."""
        os.makedirs(self._out_dir, exist_ok=True)
        with open(self.csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["qid", "score"])
            writer.writerows(self._rows)
        return self.csv_path
