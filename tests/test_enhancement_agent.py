"""
tests/test_enhancement_agent.py
--------------------------------
Unit tests for src/handlers/enhancement_agent.py.

AWS calls (DynamoDB, Bedrock) are mocked via moto and unittest.mock.
The tests exercise action dispatch, error handling, and optimistic
concurrency for rule storage.
"""
import json
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import boto3
import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

PROFILES_TABLE = "test-stream-profiles"
PATTERNS_TABLE = "test-unknown-patterns"
os.environ["STREAM_PROFILES_TABLE"] = PROFILES_TABLE
os.environ["UNKNOWN_PATTERNS_TABLE"] = PATTERNS_TABLE
os.environ["VECTOR_BACKEND"] = "dynamodb"

from moto import mock_aws  # noqa: E402


@pytest.fixture()
def aws_tables():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        profiles = ddb.create_table(
            TableName=PROFILES_TABLE,
            KeySchema=[{"AttributeName": "StreamId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "StreamId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        patterns = ddb.create_table(
            TableName=PATTERNS_TABLE,
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
        yield {"profiles": profiles, "patterns": patterns}


def _seed_pattern(patterns_table, stream_id: str, status: str = "UNPROCESSED",
                  with_embedding: bool = False) -> str:
    pid = str(uuid.uuid4())
    item = {
        "StreamId": stream_id,
        "PatternId": pid,
        "Message": f"ERROR sample log for {stream_id}",
        "SanitizedMessage": "ERROR sample log for <STREAM>",
        "Timestamp": "2026-04-30T00:00:00+00:00",
        "Status": status,
    }
    if with_embedding:
        v = np.random.default_rng(42).random(8).astype("<f4")
        item["Embedding"] = v.tobytes()
    patterns_table.put_item(Item=item)
    return pid


# ─────────────────────────────────────────────────────────────────────────────
# Handler dispatch
# ─────────────────────────────────────────────────────────────────────────────

class TestHandlerDispatch:
    def test_unknown_action_raises(self, aws_tables):
        # Reset module singletons before import
        import importlib
        import vector_store.factory as vf
        vf._instance = None

        from handlers.enhancement_agent import handler
        with pytest.raises(ValueError, match="Unknown action"):
            handler({"action": "invalid_action"}, None)

    def test_missing_action_raises(self, aws_tables):
        import vector_store.factory as vf
        vf._instance = None

        from handlers.enhancement_agent import handler
        with pytest.raises(ValueError):
            handler({}, None)


# ─────────────────────────────────────────────────────────────────────────────
# list_streams
# ─────────────────────────────────────────────────────────────────────────────

class TestListStreams:
    def test_returns_streams_with_unprocessed(self, aws_tables):
        import vector_store.factory as vf
        vf._instance = None

        _seed_pattern(aws_tables["patterns"], "/aws/lambda/a")
        _seed_pattern(aws_tables["patterns"], "/aws/lambda/b")

        from handlers.enhancement_agent import handler
        result = handler({"action": "list_streams"}, None)
        assert "/aws/lambda/a" in result["stream_ids"]
        assert "/aws/lambda/b" in result["stream_ids"]
        assert result["total"] == 2

    def test_empty_when_no_unprocessed(self, aws_tables):
        import vector_store.factory as vf
        vf._instance = None

        from handlers.enhancement_agent import handler
        result = handler({"action": "list_streams"}, None)
        assert result["stream_ids"] == []
        assert result["total"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# embed_batch
# ─────────────────────────────────────────────────────────────────────────────

class TestEmbedBatch:
    def test_skips_stream_with_no_unprocessed(self, aws_tables):
        import vector_store.factory as vf
        vf._instance = None

        from handlers.enhancement_agent import handler
        result = handler({"action": "embed_batch", "stream_id": "/aws/lambda/empty"}, None)
        assert result["embedded_count"] == 0

    def test_embeds_and_updates_status(self, aws_tables):
        import vector_store.factory as vf
        vf._instance = None

        stream_id = "/aws/lambda/embed-test"
        _seed_pattern(aws_tables["patterns"], stream_id)

        fake_vector = [0.1] * 1024
        with patch("handlers.enhancement_agent.embed", return_value=fake_vector):
            from handlers.enhancement_agent import handler
            result = handler({"action": "embed_batch", "stream_id": stream_id}, None)

        assert result["embedded_count"] == 1

        # Verify status changed to EMBEDDED in DynamoDB
        items = aws_tables["patterns"].query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("StreamId").eq(stream_id)
        )["Items"]
        assert all(item["Status"] == "EMBEDDED" for item in items)

    def test_failed_embedding_counted_separately(self, aws_tables):
        import vector_store.factory as vf
        vf._instance = None

        stream_id = "/aws/lambda/fail-embed"
        _seed_pattern(aws_tables["patterns"], stream_id)

        with patch("handlers.enhancement_agent.embed", side_effect=RuntimeError("bedrock down")):
            from handlers.enhancement_agent import handler
            result = handler({"action": "embed_batch", "stream_id": stream_id}, None)

        assert result["embedded_count"] == 0
        assert result["failed_count"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# cluster_and_generate
# ─────────────────────────────────────────────────────────────────────────────

class TestClusterAndGenerate:
    def test_skips_stream_with_no_embedded(self, aws_tables):
        import vector_store.factory as vf
        vf._instance = None

        from handlers.enhancement_agent import handler
        result = handler(
            {"action": "cluster_and_generate", "stream_id": "/aws/lambda/no-embedded"},
            None,
        )
        assert result["rules_generated"] == 0
        assert result["processed_count"] == 0

    def test_generates_rule_and_marks_processed(self, aws_tables):
        import vector_store.factory as vf
        vf._instance = None

        stream_id = "/aws/lambda/cluster-test"
        # Seed 3 EMBEDDED records with similar vectors
        v = np.array([1.0, 0.0] * 4, dtype="<f4")
        for _ in range(3):
            pid = _seed_pattern(aws_tables["patterns"], stream_id, status="EMBEDDED",
                                with_embedding=False)
            # Manually set embedding
            aws_tables["patterns"].update_item(
                Key={"StreamId": stream_id, "PatternId": pid},
                UpdateExpression="SET Embedding = :e",
                ExpressionAttributeValues={":e": v.tobytes()},
            )

        fake_rule = {
            "rule_name": "CLUSTER_RULE",
            "pattern": r"sample \w+",
            "replacement": "<TOKEN>",
            "flags": 0,
        }
        with patch("handlers.enhancement_agent.generate_rule", return_value=fake_rule):
            from handlers.enhancement_agent import handler
            result = handler(
                {"action": "cluster_and_generate", "stream_id": stream_id}, None
            )

        assert result["processed_count"] == 3
        # Rule stored in StreamProfile
        profile_item = aws_tables["profiles"].get_item(
            Key={"StreamId": stream_id}
        ).get("Item")
        assert profile_item is not None
        rule_names = [r["rule_name"] for r in profile_item["CustomRules"]]
        assert "CLUSTER_RULE" in rule_names


# ─────────────────────────────────────────────────────────────────────────────
# _store_rules — optimistic concurrency
# ─────────────────────────────────────────────────────────────────────────────

class TestStoreRules:
    def test_creates_new_profile_when_none_exists(self, aws_tables):
        import vector_store.factory as vf
        vf._instance = None

        from handlers.enhancement_agent import _store_rules
        _store_rules("/aws/lambda/new", [{"rule_name": "R1", "pattern": r"\d+", "replacement": "<N>", "flags": 0}])
        item = aws_tables["profiles"].get_item(Key={"StreamId": "/aws/lambda/new"})["Item"]
        assert item["RuleVersion"] == 1
        assert len(item["CustomRules"]) == 1

    def test_does_not_duplicate_rule_names(self, aws_tables):
        import vector_store.factory as vf
        vf._instance = None

        from handlers.enhancement_agent import _store_rules
        rule = {"rule_name": "DUPE", "pattern": r"\d+", "replacement": "<N>", "flags": 0}
        _store_rules("/aws/lambda/dupe", [rule])
        _store_rules("/aws/lambda/dupe", [rule])
        item = aws_tables["profiles"].get_item(Key={"StreamId": "/aws/lambda/dupe"})["Item"]
        rule_names = [r["rule_name"] for r in item["CustomRules"]]
        assert rule_names.count("DUPE") == 1

    def test_bumps_version_on_each_update(self, aws_tables):
        import vector_store.factory as vf
        vf._instance = None

        from handlers.enhancement_agent import _store_rules
        _store_rules("/aws/lambda/versioned", [{"rule_name": "R1", "pattern": r"\d+", "replacement": "<N>", "flags": 0}])
        _store_rules("/aws/lambda/versioned", [{"rule_name": "R2", "pattern": r"[a-z]+", "replacement": "<W>", "flags": 0}])
        item = aws_tables["profiles"].get_item(Key={"StreamId": "/aws/lambda/versioned"})["Item"]
        assert item["RuleVersion"] == 2
        assert len(item["CustomRules"]) == 2
