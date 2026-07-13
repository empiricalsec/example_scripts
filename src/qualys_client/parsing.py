"""Parsing helpers for Qualys KnowledgeBase XML responses."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from .models import QidRecord


def _text(node: ET.Element | None) -> str:
    return (node.text or "").strip() if node is not None else ""


def parse_kb_xml(xml: str) -> dict[int, QidRecord]:
    """Parse the KnowledgeBase XML into {qid: QidRecord}."""
    root = ET.fromstring(xml)
    records: dict[int, QidRecord] = {}
    for vuln in root.iter("VULN"):
        qid_text = _text(vuln.find("QID"))
        if not qid_text:
            continue
        qid = int(qid_text)
        title = _text(vuln.find("TITLE"))
        cves = [
            _text(cve.find("ID")).upper()
            for cve in vuln.iter("CVE")
            if _text(cve.find("ID"))
        ]
        records[qid] = QidRecord(qid=qid, title=title, cves=cves)
    return records
