"""Tests for KnowledgeBase XML parsing and batched fetching."""

from __future__ import annotations

from qualys_client import QualysClient, parse_kb_xml


def test_parse_kb_xml(sample_kb_xml):
    records = parse_kb_xml(sample_kb_xml)

    # The malformed VULN (missing QID) is skipped.
    assert set(records) == {90001, 90002}
    assert records[90001].title == "Example vulnerability A"
    # CVE ids are upper-cased regardless of source casing.
    assert records[90001].cves == ["CVE-2021-1111", "CVE-2021-2222"]
    assert records[90002].cves == []


def test_knowledge_base_batches_over_range(monkeypatch):
    client = QualysClient("user", "pass", "https://qualysapi.example.test")

    requested_windows: list[tuple[str, str]] = []

    def fake_list(params):
        requested_windows.append((params["id_min"], params["id_max"]))
        qid = int(params["id_min"])
        return (
            "<OUT><VULN><QID>{}</QID><TITLE>T</TITLE></VULN></OUT>".format(qid)
        )

    monkeypatch.setattr(client, "_list", fake_list)

    result = client.knowledge_base(id_min=1, id_max=25, batch_size=10)

    # 1-10, 11-20, 21-25 => three batches.
    assert requested_windows == [("1", "10"), ("11", "20"), ("21", "25")]
    assert set(result) == {1, 11, 21}


def test_knowledge_base_passes_extra_filters(monkeypatch):
    client = QualysClient("user", "pass", "https://qualysapi.example.test")
    seen: list[dict] = []

    def fake_list(params):
        seen.append(params)
        return "<OUT></OUT>"

    monkeypatch.setattr(client, "_list", fake_list)
    client.knowledge_base(
        id_min=1, id_max=5, batch_size=10, extra={"last_modified_after": "2024-01-01"}
    )

    assert seen[0]["last_modified_after"] == "2024-01-01"
