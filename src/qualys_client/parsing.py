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


def parse_detection_xml(xml: str) -> tuple[set[int], str | None]:
    """Parse one Host Detection page into (detected QIDs, next-page URL or None).

    Walks HOST_LIST_VM_DETECTION_OUTPUT > RESPONSE > HOST_LIST > HOST >
    DETECTION_LIST > DETECTION > QID, collecting every QID as an int and
    deduplicating across hosts/detections. The next-page URL is Qualys's
    verbatim ``RESPONSE/WARNING/URL`` link, present only when the page was
    truncated; it is ``None`` on the final page.
    """
    root = ET.fromstring(xml)
    qids: set[int] = set()
    for det in root.iter("DETECTION"):
        qid_text = _text(det.find("QID"))
        if not qid_text:
            continue
        qids.add(int(qid_text))
    next_url = _text(root.find(".//WARNING/URL")) or None
    return qids, next_url
