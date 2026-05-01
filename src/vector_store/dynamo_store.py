"""
src/vector_store/dynamo_store.py
---------------------------------
DynamoDB backend for unknown log pattern storage.

Table schema  (env var UNKNOWN_PATTERNS_TABLE)
──────────────────────────────────────────────
  StreamId   (PK, S)  CloudWatch log group used as profile scope.
  PatternId  (SK, S)  UUID assigned at write time.
  Message    (S)      Raw log message (truncated to 1024 chars).
  SanitizedMessage (S) Sanitized form (truncated to 1024 chars).
  Timestamp  (S)      ISO8601 write time.
  Status     (S)      "UNPROCESSED" | "EMBEDDED" | "PROCESSED"
  Embedding  (B)      little-endian float32 bytes; absent until embed step.
  ClusterId  (S)      Set during cluster step; absent until then.

All queries are by PK=StreamId — no GSI required.
search_similar() is not implemented for this backend; clustering is done
in-process by the enhancement agent using NumPy.
"""
import logging
import os
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr, Key

from .base import VectorStore, VectorSearchResult

logger = logging.getLogger(__name__)

UNKNOWN_PATTERNS_TABLE: str = os.environ.get("UNKNOWN_PATTERNS_TABLE", "")

_dynamodb = boto3.resource("dynamodb")


def _get_table():
    return _dynamodb.Table(UNKNOWN_PATTERNS_TABLE)


class DynamoVectorStore(VectorStore):

    def upsert(self, id: str, vector: list[float], metadata: dict[str, Any]) -> None:
        """Write a new unknown-pattern record. *vector* is stored as raw float32 bytes."""
        import numpy as np

        embedding_bytes = np.array(vector, dtype="<f4").tobytes()
        item: dict[str, Any] = {
            "StreamId": metadata["stream_id"],
            "PatternId": id,
            "Message": metadata.get("message", "")[:1024],
            "SanitizedMessage": metadata.get("sanitized_message", "")[:1024],
            "Timestamp": metadata["timestamp"],
            "Status": "UNPROCESSED",
            "Embedding": embedding_bytes,
        }
        _get_table().put_item(Item=item)

    def search_similar(
        self,
        vector: list[float],
        top_k: int = 10,
        min_score: float = 0.85,
    ) -> list[VectorSearchResult]:
        """Not used for the DynamoDB backend — clustering is done in-process."""
        raise NotImplementedError(
            "search_similar is not supported on DynamoVectorStore. "
            "Use fetch_unprocessed + numpy_cluster instead."
        )

    def fetch_unprocessed(
        self,
        stream_id: str,
        status: str = "UNPROCESSED",
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Query by StreamId (PK) and filter by Status."""
        table = _get_table()
        items: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("StreamId").eq(stream_id),
            "FilterExpression": Attr("Status").eq(status),
        }

        while len(items) < limit:
            response = table.query(**kwargs)
            items.extend(response.get("Items", []))
            last = response.get("LastEvaluatedKey")
            if not last or len(items) >= limit:
                break
            kwargs["ExclusiveStartKey"] = last

        return items[:limit]

    def update_status(
        self,
        stream_id: str,
        pattern_id: str,
        status: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        extra = extra or {}
        set_parts = ["#st = :status"]
        names = {"#st": "Status"}
        values: dict[str, Any] = {":status": status}

        for k, v in extra.items():
            placeholder = f"#attr_{k}"
            val_placeholder = f":val_{k}"
            set_parts.append(f"{placeholder} = {val_placeholder}")
            names[placeholder] = k
            values[val_placeholder] = v

        _get_table().update_item(
            Key={"StreamId": stream_id, "PatternId": pattern_id},
            UpdateExpression="SET " + ", ".join(set_parts),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )

    def list_streams_with_unprocessed(self) -> list[str]:
        """
        Scan for distinct StreamIds with Status=UNPROCESSED.
        One full-table scan per daily run — acceptable for a batch job.
        """
        table = _get_table()
        stream_ids: set[str] = set()
        kwargs: dict[str, Any] = {
            "FilterExpression": Attr("Status").eq("UNPROCESSED"),
            "ProjectionExpression": "StreamId",
        }
        while True:
            response = table.scan(**kwargs)
            for item in response.get("Items", []):
                stream_ids.add(item["StreamId"])
            last = response.get("LastEvaluatedKey")
            if not last:
                break
            kwargs["ExclusiveStartKey"] = last

        return sorted(stream_ids)
