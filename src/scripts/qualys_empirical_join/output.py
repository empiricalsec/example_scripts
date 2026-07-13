"""Write join results to disk: gzipped JSON, CSV, and a bundled tarball."""

from __future__ import annotations

import csv
import gzip
import io
import json
import os
import tarfile

from .models import MatchedQid

JSON_GZ_NAME = "results.json.gz"
CSV_NAME = "results.csv"
TARBALL_NAME = "results.tar.gz"


class ReportWriter:
    """Writes the matched QIDs to disk in every supported artifact format."""

    def __init__(self, matched: list[MatchedQid], out_dir: str):
        self._matched = matched
        self._out_dir = out_dir
        self.json_gz_path = os.path.join(out_dir, JSON_GZ_NAME)
        self.csv_path = os.path.join(out_dir, CSV_NAME)
        self.tarball_path = os.path.join(out_dir, TARBALL_NAME)

    def write_all(self, manifest: dict) -> dict[str, str]:
        """Write the JSON, CSV, and tarball; return a name->path map of outputs."""
        os.makedirs(self._out_dir, exist_ok=True)
        self.write_json_gz()
        self.write_csv()
        self.write_tarball(manifest)
        return {
            JSON_GZ_NAME: self.json_gz_path,
            CSV_NAME: self.csv_path,
            TARBALL_NAME: self.tarball_path,
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
            tar.add(self.json_gz_path, arcname=JSON_GZ_NAME)
            tar.add(self.csv_path, arcname=CSV_NAME)
            data = json.dumps(manifest, indent=2).encode("utf-8")
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
