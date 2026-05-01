"""
src/analyzer/stream_profile.py
-------------------------------
Per-stream rule adapter.

Each CloudWatch log group can have a StreamProfile stored in DynamoDB that
carries a list of custom SanitizationRules specific to that log source.
When sanitize_for_stream() is called, custom rules run first (higher specificity),
then the base RULES list if BaseRulesEnabled is True.

In-memory cache with a 5-minute TTL prevents DynamoDB reads on every event.
If no profile exists, the function gracefully falls back to the base RULES.

DynamoDB table  (env var STREAM_PROFILES_TABLE)
───────────────────────────────────────────────
  StreamId        (PK, S)   CloudWatch log group name used as profile scope.
  CustomRules     (L)       List of rule dicts: {name, pattern, replacement, flags}.
  BaseRulesEnabled (BOOL)   Whether to also apply the 23 base rules (default: true).
  RuleVersion     (N)       Monotonically increasing version; used for optimistic updates.
"""
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

import boto3

from analyzer.sanitizer import RULES, SanitizationRule, FingerprintResult, apply_rules

logger = logging.getLogger(__name__)

STREAM_PROFILES_TABLE: str = os.environ.get("STREAM_PROFILES_TABLE", "")

_dynamodb = boto3.resource("dynamodb")

_CACHE_TTL_SECONDS: float = 300.0  # 5 minutes


@dataclass
class StreamProfile:
    source_id: str
    custom_rules: list[SanitizationRule] = field(default_factory=list)
    base_rules_enabled: bool = True
    rule_version: int = 0


@dataclass
class _CacheEntry:
    profile: StreamProfile
    expires_at: float


_cache: dict[str, _CacheEntry] = {}


# ─────────────────────────────────────────────────────────────────────────────
# DynamoDB helpers
# ─────────────────────────────────────────────────────────────────────────────

def _deserialize_rules(raw_rules: list[dict[str, Any]]) -> list[SanitizationRule]:
    rules: list[SanitizationRule] = []
    for r in raw_rules:
        try:
            rules.append(
                SanitizationRule(
                    name=r["name"],
                    pattern=re.compile(r["pattern"], int(r.get("flags", 0))),
                    replacement=r["replacement"],
                )
            )
        except (re.error, KeyError) as exc:
            logger.warning("Skipping invalid rule in stream profile: %s — %s", r, exc)
    return rules


def _load_from_dynamodb(source_id: str) -> StreamProfile | None:
    if not STREAM_PROFILES_TABLE:
        return None
    table = _dynamodb.Table(STREAM_PROFILES_TABLE)
    response = table.get_item(Key={"StreamId": source_id})
    item = response.get("Item")
    if not item:
        return None
    return StreamProfile(
        source_id=source_id,
        custom_rules=_deserialize_rules(item.get("CustomRules", [])),
        base_rules_enabled=item.get("BaseRulesEnabled", True),
        rule_version=int(item.get("RuleVersion", 0)),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def get_profile(source_id: str) -> StreamProfile:
    """
    Return the StreamProfile for *source_id*, using a 5-minute in-memory cache.
    Falls back to an empty profile (base rules only) if none exists in DynamoDB.
    """
    now = time.monotonic()
    entry = _cache.get(source_id)
    if entry and entry.expires_at > now:
        return entry.profile

    profile = _load_from_dynamodb(source_id) or StreamProfile(source_id=source_id)
    _cache[source_id] = _CacheEntry(profile=profile, expires_at=now + _CACHE_TTL_SECONDS)
    return profile


def invalidate_cache(source_id: str | None = None) -> None:
    """
    Evict one entry (or the whole cache if *source_id* is None).
    Called by the enhancement agent after new rules are stored.
    """
    if source_id is None:
        _cache.clear()
    else:
        _cache.pop(source_id, None)


def sanitize_for_stream(message: str, source_id: str) -> FingerprintResult:
    """
    Sanitize *message* using the per-stream rule set for *source_id*.

    Rule evaluation order:
      1. Custom rules for this stream (stream-specific, higher specificity).
      2. Base RULES from sanitizer.py (if BaseRulesEnabled is True).
    """
    profile = get_profile(source_id)
    rules = profile.custom_rules + (RULES if profile.base_rules_enabled else [])
    return apply_rules(message, rules)
