"""
tests/test_stream_profile.py
-----------------------------
Unit tests for src/analyzer/stream_profile.py.
Uses moto to mock DynamoDB — no real AWS calls.
"""
import os
import re
import sys
import time
from pathlib import Path

import boto3
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

TABLE_NAME = "test-stream-profiles"
os.environ["STREAM_PROFILES_TABLE"] = TABLE_NAME

from moto import mock_aws  # noqa: E402


@pytest.fixture(autouse=True)
def reset_module_state():
    """Re-import stream_profile to clear module-level cache between tests."""
    import importlib
    import analyzer.stream_profile as sp
    sp._cache.clear()
    yield
    sp._cache.clear()


@pytest.fixture()
def ddb_table():
    with mock_aws():
        client = boto3.resource("dynamodb", region_name="us-east-1")
        table = client.create_table(
            TableName=TABLE_NAME,
            KeySchema=[{"AttributeName": "StreamId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "StreamId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


# ─────────────────────────────────────────────────────────────────────────────
# get_profile — fallback behaviour
# ─────────────────────────────────────────────────────────────────────────────

class TestGetProfile:
    def test_missing_profile_returns_default(self, ddb_table):
        from analyzer.stream_profile import get_profile
        profile = get_profile("/aws/lambda/my-app")
        assert profile.source_id == "/aws/lambda/my-app"
        assert profile.base_rules_enabled is True
        assert profile.custom_rules == []
        assert profile.rule_version == 0

    def test_existing_profile_loads_custom_rules(self, ddb_table):
        ddb_table.put_item(Item={
            "StreamId": "/aws/lambda/my-app",
            "CustomRules": [
                {
                    "name": "MY_CUSTOM_RULE",
                    "pattern": r"session-[a-f0-9]+",
                    "replacement": "<SESSION>",
                    "flags": 0,
                }
            ],
            "BaseRulesEnabled": True,
            "RuleVersion": 3,
        })
        from analyzer.stream_profile import get_profile
        profile = get_profile("/aws/lambda/my-app")
        assert len(profile.custom_rules) == 1
        assert profile.custom_rules[0].name == "MY_CUSTOM_RULE"
        assert profile.rule_version == 3

    def test_invalid_regex_in_profile_is_skipped(self, ddb_table):
        ddb_table.put_item(Item={
            "StreamId": "/aws/lambda/bad",
            "CustomRules": [
                {"name": "BAD", "pattern": r"[invalid", "replacement": "x", "flags": 0}
            ],
            "BaseRulesEnabled": True,
            "RuleVersion": 1,
        })
        from analyzer.stream_profile import get_profile
        profile = get_profile("/aws/lambda/bad")
        # Invalid rule should be silently skipped
        assert profile.custom_rules == []

    def test_cache_returns_same_object(self, ddb_table):
        from analyzer.stream_profile import get_profile
        p1 = get_profile("/aws/lambda/cached")
        p2 = get_profile("/aws/lambda/cached")
        assert p1 is p2


# ─────────────────────────────────────────────────────────────────────────────
# sanitize_for_stream
# ─────────────────────────────────────────────────────────────────────────────

class TestSanitizeForStream:
    def test_base_rules_applied_when_no_profile(self, ddb_table):
        from analyzer.stream_profile import sanitize_for_stream
        msg = "ERROR Cannot connect to 10.0.1.5:5432"
        result = sanitize_for_stream(msg, "/aws/lambda/unknown")
        # IPv4 rule should have fired
        assert "<IPv4>" in result.sanitized
        assert "10.0.1.5" not in result.sanitized

    def test_custom_rule_applied_before_base_rules(self, ddb_table):
        ddb_table.put_item(Item={
            "StreamId": "/aws/lambda/app",
            "CustomRules": [
                {
                    "name": "SESSION_ID",
                    "pattern": r"sess-[a-f0-9]{8}",
                    "replacement": "<SESSION>",
                    "flags": 0,
                }
            ],
            "BaseRulesEnabled": True,
            "RuleVersion": 1,
        })
        from analyzer.stream_profile import sanitize_for_stream
        msg = "ERROR User sess-deadbeef not found at 10.0.0.1"
        result = sanitize_for_stream(msg, "/aws/lambda/app")
        assert "<SESSION>" in result.sanitized
        assert "sess-deadbeef" not in result.sanitized
        assert "<IPv4>" in result.sanitized  # base rule also fired
        assert "SESSION_ID" in result.rules_applied

    def test_base_rules_disabled_applies_only_custom(self, ddb_table):
        ddb_table.put_item(Item={
            "StreamId": "/aws/lambda/custom-only",
            "CustomRules": [
                {
                    "name": "TICKET_ID",
                    "pattern": r"TKT-\d+",
                    "replacement": "<TICKET>",
                    "flags": 0,
                }
            ],
            "BaseRulesEnabled": False,
            "RuleVersion": 1,
        })
        from analyzer.stream_profile import sanitize_for_stream
        msg = "ERROR TKT-12345 failed at 10.0.0.1"
        result = sanitize_for_stream(msg, "/aws/lambda/custom-only")
        assert "<TICKET>" in result.sanitized
        # IPv4 base rule should NOT have fired
        assert "10.0.0.1" in result.sanitized

    def test_fingerprint_stable_for_same_message_and_profile(self, ddb_table):
        from analyzer.stream_profile import sanitize_for_stream
        msg = "ERROR connection timeout to 192.168.1.1"
        r1 = sanitize_for_stream(msg, "/aws/lambda/stable")
        r2 = sanitize_for_stream(msg, "/aws/lambda/stable")
        assert r1.fingerprint == r2.fingerprint


# ─────────────────────────────────────────────────────────────────────────────
# invalidate_cache
# ─────────────────────────────────────────────────────────────────────────────

class TestInvalidateCache:
    def test_invalidate_single_stream(self, ddb_table):
        from analyzer.stream_profile import get_profile, invalidate_cache
        p1 = get_profile("/aws/lambda/evict")
        invalidate_cache("/aws/lambda/evict")
        p2 = get_profile("/aws/lambda/evict")
        assert p1 is not p2  # cache miss → new object created

    def test_invalidate_all(self, ddb_table):
        from analyzer.stream_profile import get_profile, invalidate_cache, _cache
        get_profile("/aws/lambda/a")
        get_profile("/aws/lambda/b")
        assert len(_cache) == 2
        invalidate_cache()
        assert len(_cache) == 0
