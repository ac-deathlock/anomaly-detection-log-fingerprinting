"""
tests/test_vector_store.py
---------------------------
Unit tests for the DynamoDB vector store backend.
Uses moto to mock DynamoDB — no real AWS calls.

OpenSearch store is not tested here (requires a running OpenSearch service
or a moto implementation that supports AOSS).
"""
import os
import sys
import uuid
from pathlib import Path

import boto3
import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

TABLE_NAME = "test-unknown-patterns"
os.environ["UNKNOWN_PATTERNS_TABLE"] = TABLE_NAME
os.environ["VECTOR_BACKEND"] = "dynamodb"

from moto import mock_aws  # noqa: E402


@pytest.fixture()
def ddb_table():
    with mock_aws():
        client = boto3.resource("dynamodb", region_name="us-east-1")
        table = client.create_table(
            TableName=TABLE_NAME,
            KeySchema=[
                {"AttributeName": "StreamId", "KeyType": "HASH"},
                {"AttributeName": "PatternId", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "StreamId", "AttributeType": "S"},
                {"AttributeName": "PatternId", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


def _make_vector(dim: int = 8) -> list[float]:
    rng = np.random.default_rng(42)
    v = rng.random(dim).astype(np.float32)
    return v.tolist()


def _make_metadata(stream_id: str = "/aws/lambda/app") -> dict:
    from datetime import datetime, timezone
    return {
        "stream_id": stream_id,
        "message": "ERROR something went wrong",
        "sanitized_message": "ERROR something went wrong",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# upsert
# ─────────────────────────────────────────────────────────────────────────────

class TestUpsert:
    def test_item_created_with_unprocessed_status(self, ddb_table):
        from vector_store.dynamo_store import DynamoVectorStore
        store = DynamoVectorStore()
        pid = str(uuid.uuid4())
        store.upsert(pid, _make_vector(), _make_metadata())
        response = ddb_table.get_item(
            Key={"StreamId": "/aws/lambda/app", "PatternId": pid}
        )
        item = response["Item"]
        assert item["Status"] == "UNPROCESSED"
        assert item["StreamId"] == "/aws/lambda/app"
        assert "Embedding" in item

    def test_embedding_stored_as_binary(self, ddb_table):
        from vector_store.dynamo_store import DynamoVectorStore
        from clustering.numpy_cluster import decode_vector

        store = DynamoVectorStore()
        pid = str(uuid.uuid4())
        vector = _make_vector(16)
        store.upsert(pid, vector, _make_metadata())

        item = ddb_table.get_item(
            Key={"StreamId": "/aws/lambda/app", "PatternId": pid}
        )["Item"]
        decoded = decode_vector(bytes(item["Embedding"]))
        np.testing.assert_allclose(decoded, vector, atol=1e-5)

    def test_message_truncated_to_1024(self, ddb_table):
        from vector_store.dynamo_store import DynamoVectorStore
        store = DynamoVectorStore()
        pid = str(uuid.uuid4())
        long_msg = "X" * 2000
        meta = _make_metadata()
        meta["message"] = long_msg
        store.upsert(pid, _make_vector(), meta)
        item = ddb_table.get_item(
            Key={"StreamId": "/aws/lambda/app", "PatternId": pid}
        )["Item"]
        assert len(item["Message"]) == 1024


# ─────────────────────────────────────────────────────────────────────────────
# fetch_unprocessed
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchUnprocessed:
    def _seed(self, ddb_table, stream_id, count, status="UNPROCESSED"):
        from vector_store.dynamo_store import DynamoVectorStore
        store = DynamoVectorStore()
        ids = []
        for _ in range(count):
            pid = str(uuid.uuid4())
            meta = _make_metadata(stream_id)
            store.upsert(pid, _make_vector(), meta)
            if status != "UNPROCESSED":
                store.update_status(stream_id, pid, status)
            ids.append(pid)
        return ids

    def test_returns_unprocessed_for_stream(self, ddb_table):
        from vector_store.dynamo_store import DynamoVectorStore
        store = DynamoVectorStore()
        self._seed(ddb_table, "/aws/lambda/app", 3)
        results = store.fetch_unprocessed("/aws/lambda/app")
        assert len(results) == 3
        assert all(r["Status"] == "UNPROCESSED" for r in results)

    def test_does_not_return_processed_records(self, ddb_table):
        from vector_store.dynamo_store import DynamoVectorStore
        store = DynamoVectorStore()
        self._seed(ddb_table, "/aws/lambda/app", 2, status="PROCESSED")
        results = store.fetch_unprocessed("/aws/lambda/app")
        assert results == []

    def test_does_not_return_other_stream(self, ddb_table):
        from vector_store.dynamo_store import DynamoVectorStore
        store = DynamoVectorStore()
        self._seed(ddb_table, "/aws/lambda/other", 3)
        results = store.fetch_unprocessed("/aws/lambda/app")
        assert results == []

    def test_respects_limit(self, ddb_table):
        from vector_store.dynamo_store import DynamoVectorStore
        store = DynamoVectorStore()
        self._seed(ddb_table, "/aws/lambda/limited", 10)
        results = store.fetch_unprocessed("/aws/lambda/limited", limit=3)
        assert len(results) <= 3


# ─────────────────────────────────────────────────────────────────────────────
# update_status
# ─────────────────────────────────────────────────────────────────────────────

class TestUpdateStatus:
    def test_status_transitions(self, ddb_table):
        from vector_store.dynamo_store import DynamoVectorStore
        store = DynamoVectorStore()
        pid = str(uuid.uuid4())
        store.upsert(pid, _make_vector(), _make_metadata())
        store.update_status("/aws/lambda/app", pid, "EMBEDDED")
        item = ddb_table.get_item(
            Key={"StreamId": "/aws/lambda/app", "PatternId": pid}
        )["Item"]
        assert item["Status"] == "EMBEDDED"

    def test_update_with_extra_attributes(self, ddb_table):
        from vector_store.dynamo_store import DynamoVectorStore
        store = DynamoVectorStore()
        pid = str(uuid.uuid4())
        store.upsert(pid, _make_vector(), _make_metadata())
        store.update_status(
            "/aws/lambda/app", pid, "PROCESSED",
            extra={"ClusterId": "cluster-42"}
        )
        item = ddb_table.get_item(
            Key={"StreamId": "/aws/lambda/app", "PatternId": pid}
        )["Item"]
        assert item["ClusterId"] == "cluster-42"


# ─────────────────────────────────────────────────────────────────────────────
# list_streams_with_unprocessed
# ─────────────────────────────────────────────────────────────────────────────

class TestListStreams:
    def test_returns_streams_with_unprocessed(self, ddb_table):
        from vector_store.dynamo_store import DynamoVectorStore
        store = DynamoVectorStore()
        pid_a = str(uuid.uuid4())
        pid_b = str(uuid.uuid4())
        store.upsert(pid_a, _make_vector(), _make_metadata("/aws/lambda/a"))
        store.upsert(pid_b, _make_vector(), _make_metadata("/aws/lambda/b"))
        streams = store.list_streams_with_unprocessed()
        assert "/aws/lambda/a" in streams
        assert "/aws/lambda/b" in streams

    def test_excludes_fully_processed_streams(self, ddb_table):
        from vector_store.dynamo_store import DynamoVectorStore
        store = DynamoVectorStore()
        pid = str(uuid.uuid4())
        store.upsert(pid, _make_vector(), _make_metadata("/aws/lambda/done"))
        store.update_status("/aws/lambda/done", pid, "PROCESSED")
        streams = store.list_streams_with_unprocessed()
        assert "/aws/lambda/done" not in streams
