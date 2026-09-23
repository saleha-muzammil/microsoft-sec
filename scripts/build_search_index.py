#!/usr/bin/env python
"""Build an Azure AI Search vector index over the SCuBA baseline policies.

Why this exists: the built-in `search_controls` tool does keyword matching, so
asking "how do we stop password spraying?" only finds policies containing those
literal words. Vector search understands that the question is about MFA, legacy
authentication and lockout policy even when the wording differs -- which is how
a security engineer actually asks.

The index is deliberately *additive*. Everything still works without it; the
agent falls back to keyword search. Retrieval never becomes a source of
compliance facts either: it returns policy IDs, and the authoritative detail is
then read from the validated OSCAL catalog.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from azure.identity import AzureCliCredential  # noqa: E402
from azure.search.documents import SearchClient  # noqa: E402
from azure.search.documents.indexes import SearchIndexClient  # noqa: E402
from azure.search.documents.indexes.models import (  # noqa: E402
    HnswAlgorithmConfiguration,
    SearchableField,
    SearchField,
    SearchFieldDataType,
    SearchIndex,
    SimpleField,
    VectorSearch,
    VectorSearchProfile,
)
from dotenv import load_dotenv  # noqa: E402
from openai import AzureOpenAI  # noqa: E402

from scuba_oscal.parsers.baselines import parse_baselines  # noqa: E402

load_dotenv(ROOT / ".env")

EMBED_MODEL = os.environ.get("FOUNDRY_EMBEDDING_MODEL", "text-embedding-3-large")
EMBED_DIMS = 3072                      # text-embedding-3-large
INDEX_NAME = os.environ.get("AZURE_SEARCH_INDEX", "scuba-baselines")


def build_index(client: SearchIndexClient) -> None:
    fields = [
        SimpleField(name="id", type=SearchFieldDataType.String, key=True),
        SimpleField(name="policy_id", type=SearchFieldDataType.String, filterable=True),
        SimpleField(name="product", type=SearchFieldDataType.String, filterable=True, facetable=True),
        SimpleField(name="criticality", type=SearchFieldDataType.String, filterable=True, facetable=True),
        SearchableField(name="title", type=SearchFieldDataType.String),
        SearchableField(name="rationale", type=SearchFieldDataType.String),
        SearchableField(name="guidance", type=SearchFieldDataType.String),
        SearchableField(name="mitre", type=SearchFieldDataType.String),
        SearchField(
            name="embedding",
            type=SearchFieldDataType.Collection(SearchFieldDataType.Single),
            searchable=True,
            vector_search_dimensions=EMBED_DIMS,
            vector_search_profile_name="scuba-hnsw",
        ),
    ]
    index = SearchIndex(
        name=INDEX_NAME,
        fields=fields,
        vector_search=VectorSearch(
            algorithms=[HnswAlgorithmConfiguration(name="hnsw-config")],
            profiles=[VectorSearchProfile(name="scuba-hnsw", algorithm_configuration_name="hnsw-config")],
        ),
    )
    client.create_or_update_index(index)
    print(f"  index '{INDEX_NAME}' created/updated")


def main() -> int:
    endpoint = os.environ.get("AZURE_SEARCH_ENDPOINT")
    if not endpoint:
        print("AZURE_SEARCH_ENDPOINT not set — see .env.example")
        return 1

    credential = AzureCliCredential()
    build_index(SearchIndexClient(endpoint=endpoint, credential=credential))

    baselines = parse_baselines(str(ROOT / "data/baselines/ScubaBaselines.json"))
    print(f"  embedding {len(baselines.policies)} policies with {EMBED_MODEL}…")

    token = credential.get_token("https://cognitiveservices.azure.com/.default").token
    openai_client = AzureOpenAI(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        azure_ad_token=token,
        api_version="2024-10-21",
    )

    docs = []
    # Embed the text a person would actually search by: what the policy
    # requires, why it matters, and which techniques it mitigates.
    payloads = [
        f"{p.name}\n\n{p.rationale}\n\n"
        f"MITRE ATT&CK: {', '.join(f'{m.technique_id} {m.name}' for m in p.mitre)}"
        for p in baselines.policies
    ]
    for start in range(0, len(payloads), 64):
        chunk = payloads[start : start + 64]
        response = openai_client.embeddings.create(model=EMBED_MODEL, input=chunk)
        for offset, item in enumerate(response.data):
            policy = baselines.policies[start + offset]
            docs.append(
                {
                    "id": policy.policy_id.replace(".", "_"),
                    "policy_id": policy.policy_id,
                    "product": policy.product,
                    "criticality": policy.criticality,
                    "title": policy.name,
                    "rationale": policy.rationale,
                    "guidance": policy.implementation[:8000],
                    "mitre": ", ".join(f"{m.technique_id} {m.name}" for m in policy.mitre),
                    "embedding": item.embedding,
                }
            )
        print(f"    embedded {min(start + 64, len(payloads))}/{len(payloads)}")

    search_client = SearchClient(endpoint=endpoint, index_name=INDEX_NAME, credential=credential)
    for start in range(0, len(docs), 50):
        search_client.upload_documents(documents=docs[start : start + 50])
    print(f"  uploaded {len(docs)} documents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
