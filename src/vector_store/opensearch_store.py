"""
src/vector_store/opensearch_store.py
-------------------------------------
OpenSearch Serverless backend using k-NN (HNSW) with cosine similarity.

Required env vars:
  OPENSEARCH_ENDPOINT  e.g. https://abc123.us-east-1.aoss.amazonaws.com
  OPENSEARCH_INDEX     e.g. log-unknown-patterns-prod  (default: log-unknown-patterns)
  OPENSEARCH_REGION    AWS region (default: us-east-1)
  BEDROCK_EMBEDDING_MODEL  used to derive vector dimension at index creation

Index mapping
─────────────
  embedding        knn_vector, dimension=1024 (Titan V2), space_type=cosinesimil
  stream_id        keyword
  message          text
  sanitized_message text
  timestamp        date
  status           keyword
  cluster_id       keyword
"""
import logging
import os
from typing import Any

import boto3
from opensearchpy import OpenSearch, RequestsHttpConnection, AWSV4SignerAuth

from .base import VectorStore, VectorSearchResult

logger = logging.getLogger(__name__)

_EMBEDDING_DIMENSIONS: dict[str, int] = {
    "amazon.titan-embed-text-v2:0": 1024,
    "amazon.titan-embed-text-v1": 1536,
}

_OPENSEARCH_ENDPOINT: str = os.environ.get("OPENSEARCH_ENDPOINT", "")
_OPENSEARCH_INDEX: str = os.environ.get("OPENSEARCH_INDEX", "log-unknown-patterns")
_OPENSEARCH_REGION: str = os.environ.get("OPENSEARCH_REGION", "us-east-1")
_EMBEDDING_MODEL: str = os.environ.get(
    "BEDROCK_EMBEDDING_MODEL", "amazon.titan-embed-text-v2:0"
)


def _get_dimension() -> int:
    return _EMBEDDING_DIMENSIONS.get(_EMBEDDING_MODEL, 1024)


def _build_client() -> OpenSearch:
    credentials = boto3.Session().get_credentials()
    auth = AWSV4SignerAuth(credentials, _OPENSEARCH_REGION, "aoss")
    host = _OPENSEARCH_ENDPOINT.replace("https://", "").replace("http://", "")
    return OpenSearch(
        hosts=[{"host": host, "port": 443}],
        http_auth=auth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection,
        pool_maxsize=20,
    )


_client: OpenSearch | None = None


def _get_client() -> OpenSearch:
    global _client
    if _client is None:
        _client = _build_client()
    return _client


def _ensure_index() -> None:
    client = _get_client()
    if client.indices.exists(index=_OPENSEARCH_INDEX):
        return

    dim = _get_dimension()
    mapping = {
        "settings": {"index.knn": True},
        "mappings": {
            "properties": {
                "embedding": {
                    "type": "knn_vector",
                    "dimension": dim,
                    "method": {
                        "name": "hnsw",
                        "space_type": "cosinesimil",
                        "engine": "nmslib",
                        "parameters": {"ef_construction": 128, "m": 24},
                    },
                },
                "stream_id": {"type": "keyword"},
                "message": {"type": "text"},
                "sanitized_message": {"type": "text"},
                "timestamp": {"type": "date"},
                "status": {"type": "keyword"},
                "cluster_id": {"type": "keyword"},
            }
        },
    }
    client.indices.create(index=_OPENSEARCH_INDEX, body=mapping)
    logger.info("Created OpenSearch index %s with dimension=%d", _OPENSEARCH_INDEX, dim)


class OpenSearchVectorStore(VectorStore):

    def __init__(self) -> None:
        if not _OPENSEARCH_ENDPOINT:
            raise ValueError("OPENSEARCH_ENDPOINT env var is required for opensearch backend")
        _ensure_index()

    def upsert(self, id: str, vector: list[float], metadata: dict[str, Any]) -> None:
        doc = {
            "embedding": vector,
            "stream_id": metadata["stream_id"],
            "message": metadata.get("message", "")[:1024],
            "sanitized_message": metadata.get("sanitized_message", "")[:1024],
            "timestamp": metadata["timestamp"],
            "status": "UNPROCESSED",
        }
        _get_client().index(index=_OPENSEARCH_INDEX, id=id, body=doc, refresh=False)

    def search_similar(
        self,
        vector: list[float],
        top_k: int = 10,
        min_score: float = 0.85,
    ) -> list[VectorSearchResult]:
        query = {
            "size": top_k,
            "min_score": min_score,
            "query": {
                "knn": {
                    "embedding": {
                        "vector": vector,
                        "k": top_k,
                    }
                }
            },
        }
        response = _get_client().search(index=_OPENSEARCH_INDEX, body=query)
        return [
            VectorSearchResult(
                id=hit["_id"],
                score=hit["_score"],
                metadata=hit["_source"],
            )
            for hit in response["hits"]["hits"]
        ]

    def fetch_unprocessed(
        self,
        stream_id: str,
        status: str = "UNPROCESSED",
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        query = {
            "size": limit,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"stream_id": stream_id}},
                        {"term": {"status": status}},
                    ]
                }
            },
        }
        response = _get_client().search(index=_OPENSEARCH_INDEX, body=query)
        return [
            {"PatternId": hit["_id"], **hit["_source"]}
            for hit in response["hits"]["hits"]
        ]

    def update_status(
        self,
        stream_id: str,
        pattern_id: str,
        status: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        doc: dict[str, Any] = {"status": status}
        if extra:
            doc.update(extra)
        _get_client().update(
            index=_OPENSEARCH_INDEX,
            id=pattern_id,
            body={"doc": doc},
        )

    def list_streams_with_unprocessed(self) -> list[str]:
        query = {
            "size": 0,
            "query": {"term": {"status": "UNPROCESSED"}},
            "aggs": {
                "streams": {
                    "terms": {"field": "stream_id", "size": 10000}
                }
            },
        }
        response = _get_client().search(index=_OPENSEARCH_INDEX, body=query)
        buckets = response.get("aggregations", {}).get("streams", {}).get("buckets", [])
        return [b["key"] for b in buckets]
