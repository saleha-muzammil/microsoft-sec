"""Tests for how the agents authenticate to Microsoft Foundry.

Two modes exist and the default must never silently change. Keyless (Azure AD)
is preferred because it stores no secret; the API-key path exists only so a
collaborator outside the resource owner's Azure directory can run the agents
without a guest invitation and RBAC propagation.
"""

from __future__ import annotations

import pytest

from scuba_oscal.agents.orchestrator import FoundryConfig

ENDPOINT = "https://example.services.ai.azure.com/api/projects/p"
AOAI = "https://example.openai.azure.com/"


def test_default_is_keyless(monkeypatch):
    """Absent an explicit key, we must use Azure AD and store no secret."""
    monkeypatch.setenv("FOUNDRY_PROJECT_ENDPOINT", ENDPOINT)
    monkeypatch.delenv("FOUNDRY_API_KEY", raising=False)
    config = FoundryConfig.from_env()
    assert not config.uses_key_auth
    assert config.auth_mode.startswith("azure-ad")
    assert config.api_key is None


def test_key_auth_engages_only_when_both_values_present(monkeypatch):
    monkeypatch.setenv("FOUNDRY_PROJECT_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("FOUNDRY_API_KEY", "x")
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    # A key with nowhere to send it is not a usable mode; fall back to Azure AD.
    assert not FoundryConfig.from_env().uses_key_auth

    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", AOAI)
    config = FoundryConfig.from_env()
    assert config.uses_key_auth
    assert config.auth_mode == "api-key"


def test_empty_key_is_treated_as_absent(monkeypatch):
    """.env.example ships FOUNDRY_API_KEY= with no value; that must stay keyless."""
    monkeypatch.setenv("FOUNDRY_PROJECT_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", AOAI)
    monkeypatch.setenv("FOUNDRY_API_KEY", "")
    assert not FoundryConfig.from_env().uses_key_auth


def test_missing_endpoint_raises_a_useful_error(monkeypatch):
    monkeypatch.delenv("FOUNDRY_PROJECT_ENDPOINT", raising=False)
    with pytest.raises(RuntimeError, match="FOUNDRY_PROJECT_ENDPOINT"):
        FoundryConfig.from_env()


def test_no_api_key_is_committed_to_the_repo():
    """The example file must ship a placeholder, never a real value."""
    from pathlib import Path

    example = (Path(__file__).resolve().parents[1] / ".env.example").read_text()
    for line in example.splitlines():
        if line.startswith("FOUNDRY_API_KEY"):
            assert line.split("=", 1)[1].strip() == "", "a key value was committed"
