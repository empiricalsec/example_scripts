"""Tests for KnowledgeBase XML parsing and batched fetching."""

from __future__ import annotations

from qualys_client import QualysClient, parse_detection_xml, parse_kb_xml


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


def test_knowledge_base_by_ids_chunks_and_merges(monkeypatch):
    client = QualysClient("user", "pass", "https://qualysapi.example.test")
    seen_ids: list[str] = []

    def fake_list(params):
        seen_ids.append(params["ids"])
        # Return one VULN per requested QID so results are observable.
        vulns = "".join(
            f"<VULN><QID>{q}</QID><TITLE>T{q}</TITLE></VULN>"
            for q in params["ids"].split(",")
        )
        return f"<OUT>{vulns}</OUT>"

    monkeypatch.setattr(client, "_list", fake_list)

    # Unsorted, duplicated input -> sorted, deduped, chunked by batch_size.
    result = client.knowledge_base_by_ids({90003, 90001, 90002, 90001}, batch_size=2)

    assert seen_ids == ["90001,90002", "90003"]
    assert set(result) == {90001, 90002, 90003}


def test_knowledge_base_by_ids_empty_makes_no_calls(monkeypatch):
    client = QualysClient("user", "pass", "https://qualysapi.example.test")

    def boom(params):
        raise AssertionError("_list should not be called for an empty QID set")

    monkeypatch.setattr(client, "_list", boom)
    assert client.knowledge_base_by_ids([]) == {}


def test_parse_detection_xml(sample_detection_xml):
    qids, next_url = parse_detection_xml(sample_detection_xml)

    # Deduped across hosts (90001 on both); empty <QID> skipped.
    assert qids == {90001, 90002, 90003}
    # No WARNING block -> no next page.
    assert next_url is None


def test_host_detections_paginates(monkeypatch, sample_detection_pages):
    page1, page2 = sample_detection_pages
    client = QualysClient("user", "pass", "https://qualysapi.example.test")

    calls: list[dict] = []
    pages = [page1, page2]

    def fake_detection_list(params):
        calls.append(params)
        return pages.pop(0)

    monkeypatch.setattr(client, "_detection_list", fake_detection_list)

    result = client.host_detections(truncation_limit=1)

    # Two pages consumed; QIDs deduplicated across pages.
    assert result == {90001, 90004}
    assert len(calls) == 2
    # First request carries the initial truncation_limit; no cursor yet.
    assert calls[0]["truncation_limit"] == "1"
    assert "id_min" not in calls[0]
    # Second request replays the WARNING URL's query (action stripped -> re-injected).
    assert calls[1]["id_min"] == "2"
    assert "action" not in calls[1]


def test_host_detections_passes_asset_group_filter(monkeypatch, sample_detection_xml):
    client = QualysClient("user", "pass", "https://qualysapi.example.test")
    seen: list[dict] = []

    def fake_detection_list(params):
        seen.append(params)
        return sample_detection_xml

    monkeypatch.setattr(client, "_detection_list", fake_detection_list)
    client.host_detections(extra={"ag_titles": "Prod Web,DB Tier", "status": "Active"})

    assert seen[0]["ag_titles"] == "Prod Web,DB Tier"
    assert seen[0]["status"] == "Active"
