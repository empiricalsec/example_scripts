"""Data models for the Qualys KnowledgeBase."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class QidRecord:
    """A single Qualys KnowledgeBase entry: a QID, its title, and its CVEs."""

    qid: int
    title: str
    cves: list[str] = field(default_factory=list)
