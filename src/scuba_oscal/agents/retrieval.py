"""Semantic retrieval over SCuBA baselines via Azure AI Search.

Keyword search answers "which policy is MS.AAD.3.1v1?". It does not answer
"how do we stop password spraying?", because the phrase never appears in the
baseline text -- the relevant policies talk about MFA, legacy authentication
and lockout thresholds instead. Vector search closes that gap, which matters
because engineers arrive with a *problem*, not a policy ID.

Two deliberate constraints:

* **Retrieval is never a source of compliance facts.** It returns policy IDs
  and a similarity score. The authoritative requirement, result and mapping are
  then read from the validated OSCAL catalog, exactly as before. A retrieval
  miss can therefore make an answer less complete, but never wrong.
* **It is optional.** If Azure AI Search is not configured or unreachable, the
  caller falls back to keyword search rather than failing. The demo does not
  depend on a second cloud service being healthy.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import cached_property


@dataclass(frozen=True)
class SearchHit:
    policy_id: str
    title: str
    product: str
    criticality: str
    score: float


class SemanticIndex:
    """Thin wrapper over Azure AI Search vector retrieval."""

    def __init__(
        self,
        endpoint: str | None = None,
        index_name: str | None = None,
        embedding_endpoint: str | None = None,
        embedding_model: str | None = None,
    ):
        self.endpoint = endpoint or os.environ.get("AZURE_SEARCH_ENDPOINT", "")
        self.index_name = index_name or os.environ.get("AZURE_SEARCH_INDEX", "scuba-baselines")
        self.embedding_endpoint = embedding_endpoint or os.environ.get("AZURE_OPENAI_ENDPOINT", "")
        self.embedding_model = embedding_model or os.environ.get(
            "FOUNDRY_EMBEDDING_MODEL", "text-embedding-3-large"
        )

    @property
    def configured(self) -> bool:
        return bool(self.endpoint and self.embedding_endpoint)

    @cached_property
    def _credential(self):
        from azure.identity import AzureCliCredential

        return AzureCliCredential()

    @cached_property
    def _search_client(self):
        from azure.search.documents import SearchClient

        return SearchClient(
            endpoint=self.endpoint, index_name=self.index_name, credential=self._credential
        )

    @cached_property
    def _openai_client(self):
        from openai import AzureOpenAI

        token = self._credential.get_token("https://cognitiveservices.azure.com/.default").token
        return AzureOpenAI(
            azure_endpoint=self.embedding_endpoint,
            azure_ad_token=token,
            api_version="2024-10-21",
        )

    def search(self, query: str, limit: int = 8, product: str | None = None) -> list[SearchHit]:
        """Vector search. Returns [] when unavailable, so callers can fall back."""
        if not self.configured:
            return []
        try:
            from azure.search.documents.models import VectorizedQuery

            embedding = (
                self._openai_client.embeddings.create(model=self.embedding_model, input=[query])
                .data[0]
                .embedding
            )
            vector_query = VectorizedQuery(
                vector=embedding, k_nearest_neighbors=limit, fields="embedding"
            )
            results = self._search_client.search(
                search_text=None,
                vector_queries=[vector_query],
                filter=f"product eq '{product.lower()}'" if product else None,
                select=["policy_id", "title", "product", "criticality"],
                top=limit,
            )
            return [
                SearchHit(
                    policy_id=r["policy_id"],
                    title=r["title"],
                    product=r["product"],
                    criticality=r["criticality"],
                    score=float(r.get("@search.score", 0.0)),
                )
                for r in results
            ]
        except Exception:
            # Retrieval is an enhancement, never a dependency. A failure here
            # degrades to keyword search rather than breaking the answer.
            return []
