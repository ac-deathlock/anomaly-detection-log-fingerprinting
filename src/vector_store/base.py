"""
src/vector_store/base.py
------------------------
Abstract base class for vector storage backends.

Two concrete implementations exist:
  - DynamoVectorStore  : DynamoDB table + in-process NumPy cosine similarity.
                         Suitable for < ~100k unknowns/day per stream.
  - OpenSearchVectorStore: OpenSearch Serverless k-NN (HNSW).
                           Suitable for high-volume streams.

The active backend is chosen via the VECTOR_BACKEND env var (dynamodb|opensearch).
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class VectorSearchResult:
    id: str
    score: float
    metadata: dict[str, Any] = field(default_factory=dict)


class VectorStore(ABC):

    @abstractmethod
    def upsert(self, id: str, vector: list[float], metadata: dict[str, Any]) -> None:
        """Store or overwrite a vector with associated metadata."""

    @abstractmethod
    def search_similar(
        self,
        vector: list[float],
        top_k: int = 10,
        min_score: float = 0.85,
    ) -> list[VectorSearchResult]:
        """Return the top_k most similar stored vectors with score >= min_score."""

    @abstractmethod
    def fetch_unprocessed(
        self,
        stream_id: str,
        status: str = "UNPROCESSED",
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Return up to *limit* records for *stream_id* with Status == *status*."""

    @abstractmethod
    def update_status(
        self,
        stream_id: str,
        pattern_id: str,
        status: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Update the Status field (and any *extra* attributes) for one record."""

    @abstractmethod
    def list_streams_with_unprocessed(self) -> list[str]:
        """Return distinct StreamIds that have at least one UNPROCESSED record."""
