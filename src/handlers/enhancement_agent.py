"""
src/handlers/enhancement_agent.py
-----------------------------------
Lambda handler for the self-enhancing rule generation pipeline.

Invoked by a Step Functions state machine (daily, via EventBridge).
Each Step Functions state calls this Lambda with a different ``action`` value.
Only lightweight metadata is exchanged via Step Functions state — no large
payloads. All heavy data (embeddings, cluster results) stays in DynamoDB.

Actions
───────
  list_streams         Scan UnknownPatterns for distinct StreamIds that have
                       UNPROCESSED records. Returns {"stream_ids": [...], "total": N}.

  embed_batch          For a given stream_id, fetch UNPROCESSED records, call
                       Bedrock Titan to embed each message, update Status=EMBEDDED.
                       Returns {"stream_id": "...", "embedded_count": N}.

  cluster_and_generate For a given stream_id, fetch EMBEDDED records, run NumPy
                       DBSCAN clustering, call Claude to generate a regex rule per
                       cluster, validate rules, append to StreamProfile (optimistic
                       concurrency), mark records PROCESSED.
                       Returns {"stream_id": "...", "rules_generated": N,
                                "processed_count": N}.

Step Functions state machine passes:
  list_streams  → {"action": "list_streams"}
  embed_batch   → {"action": "embed_batch", "stream_id": "<id>"}
  cluster_and_generate → {"action": "cluster_and_generate", "stream_id": "<id>"}

Env vars (in addition to shared Globals in template.yaml):
  UNKNOWN_PATTERNS_TABLE  DynamoDB table name for unknown log patterns
  STREAM_PROFILES_TABLE   DynamoDB table name for per-stream rule profiles
  VECTOR_BACKEND          dynamodb | opensearch
  BEDROCK_EMBEDDING_MODEL Titan model ID
  BEDROCK_LLM_MODEL       Claude model ID
  CLUSTER_EPS             DBSCAN epsilon (cosine distance, default 0.15)
  CLUSTER_MIN_SAMPLES     DBSCAN min_samples (default 2)
  CLUSTER_BATCH_CAP       Max vectors to cluster per stream per run (default 500)
"""
import logging
import os
import uuid
from collections import defaultdict
from typing import Any

import boto3
from botocore.exceptions import ClientError

from ai.embedder import embed
from ai.rule_generator import generate_rule
from analyzer.stream_profile import invalidate_cache
from clustering.numpy_cluster import cluster_vectors, decode_vector
from vector_store.factory import get_vector_store

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

STREAM_PROFILES_TABLE: str = os.environ["STREAM_PROFILES_TABLE"]

_dynamodb = boto3.resource("dynamodb")


# ─────────────────────────────────────────────────────────────────────────────
# Action: list_streams
# ─────────────────────────────────────────────────────────────────────────────

def _list_streams(event: dict[str, Any]) -> dict[str, Any]:
    store = get_vector_store()
    stream_ids = store.list_streams_with_unprocessed()
    logger.info("Found %d streams with unprocessed patterns", len(stream_ids))
    return {"stream_ids": stream_ids, "total": len(stream_ids)}


# ─────────────────────────────────────────────────────────────────────────────
# Action: embed_batch
# ─────────────────────────────────────────────────────────────────────────────

def _embed_batch(event: dict[str, Any]) -> dict[str, Any]:
    stream_id: str = event["stream_id"]
    store = get_vector_store()
    records = store.fetch_unprocessed(stream_id, status="UNPROCESSED")

    if not records:
        logger.info("No UNPROCESSED records for stream %s", stream_id)
        return {"stream_id": stream_id, "embedded_count": 0}

    embedded = 0
    failed = 0
    for record in records:
        pattern_id: str = record["PatternId"]
        message: str = record.get("Message", "")
        try:
            vector = embed(message)
            import numpy as np
            embedding_bytes = np.array(vector, dtype="<f4").tobytes()
            store.update_status(
                stream_id=stream_id,
                pattern_id=pattern_id,
                status="EMBEDDED",
                extra={"Embedding": embedding_bytes},
            )
            embedded += 1
        except Exception:
            logger.exception(
                "Embedding failed for stream=%s pattern=%s — skipping",
                stream_id,
                pattern_id,
            )
            failed += 1

    logger.info(
        "embed_batch stream=%s embedded=%d failed=%d", stream_id, embedded, failed
    )
    return {"stream_id": stream_id, "embedded_count": embedded, "failed_count": failed}


# ─────────────────────────────────────────────────────────────────────────────
# Action: cluster_and_generate
# ─────────────────────────────────────────────────────────────────────────────

def _cluster_and_generate(event: dict[str, Any]) -> dict[str, Any]:
    stream_id: str = event["stream_id"]
    store = get_vector_store()
    records = store.fetch_unprocessed(stream_id, status="EMBEDDED")

    if not records:
        logger.info("No EMBEDDED records for stream %s", stream_id)
        return {"stream_id": stream_id, "rules_generated": 0, "processed_count": 0}

    # ── 1. Decode embeddings ─────────────────────────────────────────────────
    ids: list[str] = []
    vectors: list[Any] = []
    messages: list[str] = []

    for record in records:
        raw = record.get("Embedding")
        if raw is None:
            continue
        try:
            vec = decode_vector(bytes(raw))
        except Exception:
            logger.warning("Could not decode embedding for pattern %s", record.get("PatternId"))
            continue
        item_id = record["PatternId"]
        ids.append(item_id)
        vectors.append(vec)
        messages.append(record.get("SanitizedMessage") or record.get("Message", ""))

    if not ids:
        return {"stream_id": stream_id, "rules_generated": 0, "processed_count": 0}

    # ── 2. Cluster ────────────────────────────────────────────────────────────
    cluster_result = cluster_vectors(ids, vectors)
    logger.info(
        "Clustered %d vectors for stream=%s", len(cluster_result), stream_id
    )

    # ── 3. Group by cluster label (skip noise label -1) ───────────────────────
    clusters: dict[int, list[str]] = defaultdict(list)
    for item_id, label in cluster_result:
        if label != -1:
            clusters[label].append(item_id)

    # ── 4. Generate rules per cluster ─────────────────────────────────────────
    id_to_message: dict[str, str] = dict(zip(ids, messages))
    new_rules: list[dict[str, Any]] = []
    cluster_id_map: dict[str, str] = {}  # item_id → cluster_uuid

    for label, member_ids in clusters.items():
        cluster_uuid = str(uuid.uuid4())
        samples = [id_to_message[mid] for mid in member_ids if mid in id_to_message]
        rule = generate_rule(samples)
        if rule:
            rule["cluster_id"] = cluster_uuid
            new_rules.append(rule)
        for mid in member_ids:
            cluster_id_map[mid] = cluster_uuid

    logger.info(
        "Generated %d rules from %d clusters for stream=%s",
        len(new_rules),
        len(clusters),
        stream_id,
    )

    # ── 5. Store rules to StreamProfile with optimistic concurrency ────────────
    if new_rules:
        _store_rules(stream_id, new_rules)

    # ── 6. Mark all records PROCESSED ────────────────────────────────────────
    processed = 0
    for item_id, label in cluster_result:
        try:
            extra = {}
            if item_id in cluster_id_map:
                extra["ClusterId"] = cluster_id_map[item_id]
            store.update_status(
                stream_id=stream_id,
                pattern_id=item_id,
                status="PROCESSED",
                extra=extra or None,
            )
            processed += 1
        except Exception:
            logger.exception(
                "Failed to mark pattern %s as PROCESSED", item_id
            )

    return {
        "stream_id": stream_id,
        "rules_generated": len(new_rules),
        "processed_count": processed,
    }


def _store_rules(stream_id: str, new_rules: list[dict[str, Any]]) -> None:
    """
    Append *new_rules* to the StreamProfile for *stream_id* using optimistic
    concurrency on RuleVersion.  Retries up to 3 times on version conflict.
    """
    table = _dynamodb.Table(STREAM_PROFILES_TABLE)
    MAX_RETRIES = 3

    for attempt in range(MAX_RETRIES):
        # Read current profile (may not exist)
        response = table.get_item(Key={"StreamId": stream_id})
        item = response.get("Item") or {}
        current_version = int(item.get("RuleVersion", 0))
        existing_rules: list[dict] = item.get("CustomRules", [])

        # Avoid duplicate rule names
        existing_names = {r["rule_name"] for r in existing_rules}
        rules_to_add = [r for r in new_rules if r["rule_name"] not in existing_names]
        if not rules_to_add:
            logger.info("No new rule names to add for stream %s", stream_id)
            return

        merged_rules = existing_rules + rules_to_add
        new_version = current_version + 1

        try:
            if item:
                # Update existing profile with version check
                table.update_item(
                    Key={"StreamId": stream_id},
                    UpdateExpression=(
                        "SET CustomRules = :rules, RuleVersion = :new_ver, "
                        "BaseRulesEnabled = if_not_exists(BaseRulesEnabled, :true)"
                    ),
                    ConditionExpression="RuleVersion = :cur_ver",
                    ExpressionAttributeValues={
                        ":rules": merged_rules,
                        ":new_ver": new_version,
                        ":cur_ver": current_version,
                        ":true": True,
                    },
                )
            else:
                # Create new profile
                table.put_item(
                    Item={
                        "StreamId": stream_id,
                        "CustomRules": rules_to_add,
                        "BaseRulesEnabled": True,
                        "RuleVersion": new_version,
                    },
                    ConditionExpression="attribute_not_exists(StreamId)",
                )

            logger.info(
                "Stored %d new rules for stream=%s version=%d→%d",
                len(rules_to_add),
                stream_id,
                current_version,
                new_version,
            )
            # Evict cache so Fingerprinter picks up new rules on next cold start
            invalidate_cache(stream_id)
            return

        except ClientError as exc:
            if exc.response["Error"]["Code"] in (
                "ConditionalCheckFailedException",
            ):
                logger.warning(
                    "Version conflict storing rules for stream=%s (attempt %d/%d), retrying",
                    stream_id,
                    attempt + 1,
                    MAX_RETRIES,
                )
                continue
            raise

    logger.error(
        "Failed to store rules for stream=%s after %d attempts", stream_id, MAX_RETRIES
    )


# ─────────────────────────────────────────────────────────────────────────────
# Handler
# ─────────────────────────────────────────────────────────────────────────────

_ACTIONS = {
    "list_streams": _list_streams,
    "embed_batch": _embed_batch,
    "cluster_and_generate": _cluster_and_generate,
}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Step Functions entry point.

    Expected event shapes:
      {"action": "list_streams"}
      {"action": "embed_batch",          "stream_id": "<log_group>"}
      {"action": "cluster_and_generate", "stream_id": "<log_group>"}
    """
    action: str = event.get("action", "")
    fn = _ACTIONS.get(action)
    if fn is None:
        raise ValueError(f"Unknown action: {action!r}. Valid: {list(_ACTIONS)}")
    return fn(event)
