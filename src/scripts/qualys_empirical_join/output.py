"""Write join results to disk: gzipped JSON, CSV, and a bundled tarball."""

from __future__ import annotations

import csv
import gzip
import io
import json
import os
import tarfile
from datetime import datetime, timezone

from .models import MatchedQid


def _utc_stamp() -> str:
    """A filesystem-safe UTC timestamp, e.g. 20260715T153045Z."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class ReportWriter:
    """Writes the matched QIDs to disk in every supported artifact format.

    Filenames carry a UTC timestamp (``results-<stamp>.*``) so successive runs
    accumulate rather than overwrite. Pass ``timestamp`` to control the stamp
    (e.g. to align it with the manifest's ``generated_at``); it defaults to now.
    """

    def __init__(self, matched: list[MatchedQid], out_dir: str, timestamp: str | None = None):
        self._matched = matched
        self._out_dir = out_dir
        stamp = timestamp or _utc_stamp()
        self.json_gz_name = f"results-{stamp}.json.gz"
        self.csv_name = f"results-{stamp}.csv"
        self.tarball_name = f"results-{stamp}.tar.gz"
        self.json_gz_path = os.path.join(out_dir, self.json_gz_name)
        self.csv_path = os.path.join(out_dir, self.csv_name)
        self.tarball_path = os.path.join(out_dir, self.tarball_name)

    def write_all(self, manifest: dict) -> dict[str, str]:
        """Write the JSON, CSV, and tarball; return a name->path map of outputs."""
        os.makedirs(self._out_dir, exist_ok=True)
        self.write_json_gz()
        self.write_csv()
        self.write_tarball(manifest)
        return {
            self.json_gz_name: self.json_gz_path,
            self.csv_name: self.csv_path,
            self.tarball_name: self.tarball_path,
        }

    def write_json_gz(self) -> None:
        """One JSON array of QID objects, written to a gzipped file."""
        with gzip.open(self.json_gz_path, "wt", encoding="utf-8") as fh:
            json.dump(
                [
                    {
                        "qid": m.qid,
                        "title": m.title,
                        "matched_cves": m.matched_cves,
                        "matched_cve_count": len(m.matched_cves),
                    }
                    for m in self._matched
                ],
                fh,
                indent=2,
            )

    def write_csv(self) -> None:
        """One row per QID+CVE pair."""
        with open(self.csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["qid", "title", "cve", "global_score"])
            for m in self._matched:
                for hit in m.matched_cves:
                    writer.writerow([m.qid, m.title, hit["cve"], hit["global_score"]])

    def write_tarball(self, manifest: dict) -> None:
        """Bundle the JSON + CSV plus a manifest.json into a .tar.gz."""
        with tarfile.open(self.tarball_path, "w:gz") as tar:
            tar.add(self.json_gz_path, arcname=self.json_gz_name)
            tar.add(self.csv_path, arcname=self.csv_name)
            data = json.dumps(manifest, indent=2).encode("utf-8")
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
