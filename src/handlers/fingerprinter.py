"""
src/handlers/fingerprinter.py
------------------------------
Lambda handler that generates error fingerprints, maintains state in DynamoDB,
and raises regression alerts via SNS.

DynamoDB schema  (PK = ErrorSignature)
───────────────────────────────────────
  ErrorSignature   (S)  SHA-256 hex of the sanitized log message — partition key.
  FirstSeen        (S)  ISO8601 timestamp of the first occurrence.
  LastSeen         (S)  ISO8601 timestamp of the most recent occurrence.
  OccurrenceCount  (N)  Running count of how many times the pattern was seen.
  SampleMessage    (S)  First raw message that produced this fingerprint.
  ReleaseID        (S)  ReleaseID that *first* introduced this fingerprint.
  SanitizedMessage (S)  Human-readable sanitized form of the pattern.

Regression logic
────────────────
  If a fingerprint is encountered that does NOT yet exist in DynamoDB
  (i.e. it is *new* for the current deployment), an SNS alert is published
  immediately with the sanitized pattern and the originating ReleaseID.
  The raw message is also stored in the UnknownPatterns table so the daily
  enhancement agent can generate stream-specific sanitization rules.

Stream profile adapter
──────────────────────
  Each log group can have custom SanitizationRules stored in DynamoDB
  (StreamProfilesTable). sanitize_for_stream() applies those first, then
  falls back to the base 23-rule set. Profiles are cached in-process for
  5 minutes.
"""
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Shared sanitizer layer — available in Lambda layer or local PYTHONPATH.
from analyzer.sanitizer import FingerprintResult
from analyzer.stream_profile import sanitize_for_stream

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_dynamodb = boto3.resource("dynamodb")
_sns_client = boto3.client("sns")

TABLE_NAME: str = os.environ["TABLE_NAME"]
SNS_TOPIC_ARN: str = os.environ["SNS_TOPIC_ARN"]
RELEASE_ID: str = os.environ.get("RELEASE_ID", "unknown")
AI_PROVIDER: str = os.environ.get("AI_PROVIDER", "none")
UNKNOWN_PATTERNS_TABLE: str = os.environ.get("UNKNOWN_PATTERNS_TABLE", "")

_table = _dynamodb.Table(TABLE_NAME)


# ─────────────────────────────────────────────────────────────────────────────
# AI Hook placeholder
# ─────────────────────────────────────────────────────────────────────────────

def ai_hook(sanitized_message: str, fingerprint: str) -> dict[str, Any]:
    """
    AI enrichment hook — replace this stub with a real Bedrock / Gemini call.

    Expected to return a dict with keys:
      - "summary"  (str)  : one-sentence description of the error pattern
      - "severity" (str)  : CRITICAL | HIGH | MEDIUM | LOW
      - "category" (str)  : e.g. AUTH, NETWORK, DATABASE, PARSING

    The hook is disabled when AI_PROVIDER == "none" (default).

    Example Bedrock implementation (uncomment and adapt):

        import boto3, json
        bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 200,
            "messages": [{
                "role": "user",
                "content": (
                    f"Classify this sanitized log pattern:\\n\\n{sanitized_message}\\n\\n"
                    "Respond with JSON: {summary, severity, category}"
                )
            }]
        })
        response = bedrock.invoke_model(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            body=body,
            contentType="application/json",
            accept="application/json",
        )
        return json.loads(response["body"].read())["content"][0]["text"]

    Example Gemini implementation (uncomment and adapt):

        import google.generativeai as genai, os, json
        genai.configure(api_key=os.environ["GEMINI_API_KEY"])
        model = genai.GenerativeModel("gemini-1.5-pro")
        resp = model.generate_content(
            f"Classify this sanitized log pattern: {sanitized_message}. "
            "Respond with JSON: {{summary, severity, category}}"
        )
        return json.loads(resp.text)
    """
    if AI_PROVIDER == "none":
        return {}

    # TODO: implement Bedrock or Gemini call based on AI_PROVIDER env var.
    logger.warning("AI_PROVIDER=%s configured but ai_hook() is not yet implemented.", AI_PROVIDER)
    return {}


# ─────────────────────────────────────────────────────────────────────────────
# DynamoDB helpers
# ─────────────────────────────────────────────────────────────────────────────

def _upsert_fingerprint(result: FingerprintResult, now_iso: str) -> bool:
    """
    Insert or update a fingerprint record.

    Uses a conditional PutItem (attribute_not_exists) to avoid a separate
    GetItem round-trip and to be safe under concurrent first-seen events.

    Returns ``True`` if this is a **new** fingerprint (first time seen),
    ``False`` if it already existed.
    """
    try:
        _table.put_item(
            Item={
                "ErrorSignature": result.fingerprint,
                "FirstSeen": now_iso,
                "LastSeen": now_iso,
                "OccurrenceCount": 1,
                "SampleMessage": result.original[:1024],    # DDB item size guard
                "SanitizedMessage": result.sanitized[:1024],
                "ReleaseID": RELEASE_ID,
            },
            ConditionExpression="attribute_not_exists(ErrorSignature)",
        )
        return True  # new fingerprint
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Already exists — increment counter only
            _table.update_item(
                Key={"ErrorSignature": result.fingerprint},
                UpdateExpression=(
                    "SET LastSeen = :ls, "
                    "OccurrenceCount = OccurrenceCount + :inc"
                ),
                ExpressionAttributeValues={":ls": now_iso, ":inc": 1},
            )
            return False
        raise


def _capture_unknown_pattern(
    result: FingerprintResult,
    log_group: str,
    now_iso: str,
) -> None:
    """
    Store the new fingerprint in the UnknownPatterns table so the daily
    enhancement agent can embed, cluster, and generate rules for it.

    Silently skipped if UNKNOWN_PATTERNS_TABLE is not configured.
    """
    if not UNKNOWN_PATTERNS_TABLE:
        return
    try:
        _dynamodb.Table(UNKNOWN_PATTERNS_TABLE).put_item(
            Item={
                "StreamId": log_group,
                "PatternId": str(uuid.uuid4()),
                "Message": result.original[:1024],
                "SanitizedMessage": result.sanitized[:1024],
                "Timestamp": now_iso,
                "Status": "UNPROCESSED",
            }
        )
    except Exception:
        logger.exception(
            "Failed to capture unknown pattern for stream=%s — continuing", log_group
        )


def _publish_regression_alert(result: FingerprintResult, ai_metadata: dict[str, Any]) -> None:
    """Publish an SNS alert for a newly-discovered error pattern."""
    message_body = {
        "alert_type": "NEW_ERROR_FINGERPRINT",
        "release_id": RELEASE_ID,
        "fingerprint": result.fingerprint,
        "sanitized_pattern": result.sanitized[:512],
        "sample_message": result.original[:512],
        "rules_applied": result.rules_applied,
        "ai_enrichment": ai_metadata,
    }
    _sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[{RELEASE_ID}] New Error Pattern Detected",
        Message=json.dumps(message_body, indent=2),
        MessageAttributes={
            "alert_type": {
                "DataType": "String",
                "StringValue": "NEW_ERROR_FINGERPRINT",
            },
            "release_id": {
                "DataType": "String",
                "StringValue": RELEASE_ID,
            },
        },
    )
    logger.warning(
        "REGRESSION ALERT: new fingerprint %s detected on ReleaseID %s | pattern: %.120s",
        result.fingerprint[:16],
        RELEASE_ID,
        result.sanitized,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Handler
# ─────────────────────────────────────────────────────────────────────────────

def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Entry point — invoked asynchronously by the Ingestor Lambda.

    Expected event shape::

        {
          "message":   "<raw log line>",
          "timestamp": 1234567890123,    # ms epoch (optional)
          "logGroup":  "/aws/lambda/...",
          "logStream": "2026/04/18/..."
        }
    """
    message: str = event.get("message", "")
    if not message:
        logger.warning("Received empty message — skipping.")
        return {"status": "skipped", "reason": "empty_message"}

    log_group: str = event.get("logGroup", "")
    now_iso: str = datetime.now(tz=timezone.utc).isoformat()

    # ── 1. Sanitize & fingerprint (stream-aware) ───────────────────────────
    result: FingerprintResult = sanitize_for_stream(message, log_group)

    logger.info(
        "Fingerprint generated | fp=%s rules=%s stream=%s",
        result.fingerprint[:16],
        result.rules_applied,
        log_group,
    )

    # ── 2. AI enrichment (no-op when AI_PROVIDER=none) ────────────────────
    ai_metadata: dict[str, Any] = {}
    try:
        ai_metadata = ai_hook(result.sanitized, result.fingerprint)
    except Exception:
        logger.exception("AI hook failed — continuing without enrichment.")

    # ── 3. DynamoDB upsert (conditional write — race-safe) ────────────────
    is_new = _upsert_fingerprint(result, now_iso)

    # ── 4. New pattern handling ────────────────────────────────────────────
    if is_new:
        # 4a. Publish regression alert
        try:
            _publish_regression_alert(result, ai_metadata)
        except Exception:
            logger.exception("Failed to publish regression alert — DDB already updated.")

        # 4b. Capture for daily enhancement agent (fire-and-forget; never raises)
        _capture_unknown_pattern(result, log_group, now_iso)

    return {
        "status": "ok",
        "fingerprint": result.fingerprint,
        "is_new": is_new,
        "rules_applied": result.rules_applied,
    }
