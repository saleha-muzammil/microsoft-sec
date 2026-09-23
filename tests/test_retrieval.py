"""Retrieval tests.

The property that matters is that retrieval is *optional*: the tool layer must
behave correctly with Azure AI Search absent, misconfigured, or failing, because
the demo cannot depend on a second cloud service being healthy.
"""

from __future__ import annotations

import json

from scuba_oscal.agents.retrieval import SemanticIndex


def test_unconfigured_index_reports_itself_unconfigured(monkeypatch):
    monkeypatch.delenv("AZURE_SEARCH_ENDPOINT", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    assert not SemanticIndex().configured


def test_unconfigured_search_returns_empty_rather_than_raising(monkeypatch):
    monkeypatch.delenv("AZURE_SEARCH_ENDPOINT", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    assert SemanticIndex().search("anything") == []


def test_search_failure_degrades_instead_of_propagating(monkeypatch):
    """A broken search service must not break an answer."""
    index = SemanticIndex(
        endpoint="https://unreachable.search.windows.net",
        embedding_endpoint="https://unreachable.openai.azure.com/",
    )
    assert index.configured
    assert index.search("password spraying") == []


def test_keyword_fallback_still_finds_policies():
    """With semantic retrieval disabled, keyword search must still work."""
    from scuba_oscal.agents.tools import ComplianceTools

    tools = ComplianceTools("data/oscal_out", semantic=False)
    data = json.loads(tools.search_controls("multifactor authentication"))
    assert data["retrieval"] == "keyword"
    assert data["matches"]
    assert any(m["policy_id"].startswith("MS.AAD") for m in data["matches"])


def test_retrieval_mode_is_always_disclosed():
    """Answers should never hide whether they used semantic or keyword search."""
    from scuba_oscal.agents.tools import ComplianceTools

    tools = ComplianceTools("data/oscal_out", semantic=False)
    assert "retrieval" in json.loads(tools.search_controls("mfa"))
