"""
src/vector_store/factory.py
---------------------------
Returns the active VectorStore implementation based on the VECTOR_BACKEND
environment variable.

  VECTOR_BACKEND=dynamodb   → DynamoVectorStore  (default)
  VECTOR_BACKEND=opensearch → OpenSearchVectorStore
"""
import os

from .base import VectorStore

_instance: VectorStore | None = None


def get_vector_store() -> VectorStore:
    """Return a module-level singleton for the configured backend."""
    global _instance
    if _instance is not None:
        return _instance

    backend = os.environ.get("VECTOR_BACKEND", "dynamodb").lower()
    if backend == "opensearch":
        from .opensearch_store import OpenSearchVectorStore
        _instance = OpenSearchVectorStore()
    else:
        from .dynamo_store import DynamoVectorStore
        _instance = DynamoVectorStore()

    return _instance
