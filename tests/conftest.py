"""Shared fixtures + sample API payloads for the test suite."""

from __future__ import annotations

import pytest

# A minimal KnowledgeBase response: two well-formed VULNs (one with two CVEs,
# one with none), plus a malformed entry missing its QID (must be skipped).
SAMPLE_KB_XML = """<?xml version="1.0" encoding="UTF-8"?>
<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
  <RESPONSE>
    <VULN_LIST>
      <VULN>
        <QID>90001</QID>
        <TITLE>Example vulnerability A</TITLE>
        <CVE_LIST>
          <CVE><ID>cve-2021-1111</ID></CVE>
          <CVE><ID>CVE-2021-2222</ID></CVE>
        </CVE_LIST>
      </VULN>
      <VULN>
        <QID>90002</QID>
        <TITLE>Example vulnerability B (no CVEs)</TITLE>
      </VULN>
      <VULN>
        <TITLE>Malformed, missing QID</TITLE>
      </VULN>
    </VULN_LIST>
  </RESPONSE>
</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
"""

# One JSONL record per line, mirroring Empirical's /api/search streamed output.
SAMPLE_SEARCH_JSONL = "\n".join(
    [
        '{"identifier": "cve-2021-1111", "scores": {"global": {"score": 0.92}}}',
        '{"cve": "CVE-2021-2222", "score": 88}',
        '{"identifier": "CVE-2021-3333"}',  # no score -> skipped
        "",  # blank line -> skipped
        '{"score": 90}',  # no identifier -> skipped
    ]
)


@pytest.fixture
def sample_kb_xml() -> str:
    return SAMPLE_KB_XML


@pytest.fixture
def sample_search_jsonl() -> str:
    return SAMPLE_SEARCH_JSONL
