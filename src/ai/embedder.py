"""
src/ai/embedder.py
------------------
Bedrock Titan Text Embeddings wrapper.

Model dimensions:
  amazon.titan-embed-text-v2:0  →  1024  (default)
  amazon.titan-embed-text-v1    →  1536

Env vars:
  BEDROCK_EMBEDDING_MODEL   model ID (default: amazon.titan-embed-text-v2:0)
  BEDROCK_REGION            AWS region (default: us-east-1)
"""
import json
import logging
import os
from typing import Any

import boto3

logger = logging.getLogger(__name__)

EMBEDDING_MODEL: str = os.environ.get(
    "BEDROCK_EMBEDDING_MODEL", "amazon.titan-embed-text-v2:0"
)
EMBEDDING_DIMENSIONS: dict[str, int] = {
    "amazon.titan-embed-text-v2:0": 1024,
    "amazon.titan-embed-text-v1": 1536,
}
# Titan V2 max input ≈ 8192 tokens; ~4 chars/token → truncate at 8000 chars
_MAX_CHARS = 8000

_bedrock = boto3.client(
    "bedrock-runtime",
    region_name=os.environ.get("BEDROCK_REGION", "us-east-1"),
)


def embed(text: str) -> list[float]:
    """
    Return the embedding vector for *text*.

    The input is truncated to _MAX_CHARS before sending to avoid exceeding
    the model's token limit.
    """
    truncated = text[:_MAX_CHARS]
    body = json.dumps({"inputText": truncated})
    response = _bedrock.invoke_model(
        modelId=EMBEDDING_MODEL,
        body=body,
        contentType="application/json",
        accept="application/json",
    )
    result: dict[str, Any] = json.loads(response["body"].read())
    return result["embedding"]


def get_dimension() -> int:
    """Return the vector dimension for the configured embedding model."""
    return EMBEDDING_DIMENSIONS.get(EMBEDDING_MODEL, 1024)
