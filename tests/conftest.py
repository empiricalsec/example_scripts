"""Shared fixtures + sample API payloads for the test suite."""

from __future__ import annotations

import gzip

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

# A single Host Detection page: two hosts, QID 90001 detected on both (must dedup),
# host 2 carries an extra QID plus a malformed empty detection (must be skipped).
SAMPLE_DETECTION_XML = """<?xml version="1.0" encoding="UTF-8"?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST>
        <ID>1</ID>
        <DETECTION_LIST>
          <DETECTION><QID>90001</QID><STATUS>Active</STATUS></DETECTION>
          <DETECTION><QID>90002</QID><STATUS>New</STATUS></DETECTION>
        </DETECTION_LIST>
      </HOST>
      <HOST>
        <ID>2</ID>
        <DETECTION_LIST>
          <DETECTION><QID>90001</QID><STATUS>Active</STATUS></DETECTION>
          <DETECTION><QID>90003</QID><STATUS>Re-Opened</STATUS></DETECTION>
          <DETECTION><QID></QID></DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>
"""

# First page of a truncated response: one QID + a WARNING pointing at page 2.
SAMPLE_DETECTION_XML_PAGE1 = """<?xml version="1.0" encoding="UTF-8"?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST><ID>1</ID><DETECTION_LIST>
        <DETECTION><QID>90001</QID></DETECTION>
      </DETECTION_LIST></HOST>
    </HOST_LIST>
    <WARNING>
      <CODE>1980</CODE>
      <TEXT>truncated</TEXT>
      <URL>https://qualysapi.example.test/api/2.0/fo/asset/host/vm/detection/?action=list&amp;id_min=2&amp;truncation_limit=1</URL>
    </WARNING>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>
"""

# Second (final) page: repeats QID 90001 (cross-page dedup) plus a new QID, no WARNING.
SAMPLE_DETECTION_XML_PAGE2 = """<?xml version="1.0" encoding="UTF-8"?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST><ID>2</ID><DETECTION_LIST>
        <DETECTION><QID>90001</QID></DETECTION>
        <DETECTION><QID>90004</QID></DETECTION>
      </DETECTION_LIST></HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>
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
def sample_detection_xml() -> str:
    return SAMPLE_DETECTION_XML


@pytest.fixture
def sample_detection_pages() -> tuple[str, str]:
    return SAMPLE_DETECTION_XML_PAGE1, SAMPLE_DETECTION_XML_PAGE2


@pytest.fixture
def sample_search_jsonl() -> str:
    return SAMPLE_SEARCH_JSONL


# The /api/cves/all export is the same JSONL, delivered as a gzipped (.gz) body.
SAMPLE_CVES_ALL_GZ = gzip.compress(SAMPLE_SEARCH_JSONL.encode("utf-8"))


@pytest.fixture
def sample_cves_all_gz() -> bytes:
    return SAMPLE_CVES_ALL_GZ
