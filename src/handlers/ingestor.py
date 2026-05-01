"""
src/handlers/ingestor.py
------------------------
Lambda handler for CloudWatch Logs subscription events.

Responsibilities:
  1. Decode and decompress the Base64+gzip CloudWatch Logs payload.
  2. Apply the runtime exclusion filter (EXCLUDE_PATTERNS env var) — this
     mirrors the "!=" clauses from the CloudWatch filter pattern and ensures
     the exclusion list stays in template.yaml, not in code.
  3. Forward each qualifying log event to the Fingerprinter Lambda
     asynchronously (Event invocation type).
"""
import base64
import gzip
import json
import logging
import os
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_lambda_client = boto3.client("lambda")

# Runtime exclusion patterns — sourced from the ExcludePatterns SAM parameter
# which is injected as a comma-separated string env var by template.yaml.
_raw_patterns = os.environ.get("EXCLUDE_PATTERNS", "")
EXCLUDE_PATTERNS: list[str] = [p.strip() for p in _raw_patterns.split(",") if p.strip()]

FINGERPRINTER_FUNCTION_NAME: str = os.environ["FINGERPRINTER_FUNCTION_NAME"]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _decode_cw_payload(encoded: str) -> dict[str, Any]:
    """Decode a Base64+gzip CloudWatch Logs subscription payload."""
    compressed = base64.b64decode(encoded)
    raw_json = gzip.decompress(compressed)
    return json.loads(raw_json)


def _is_excluded(message: str) -> bool:
    """Return True if *message* matches any exclusion pattern."""
    lower = message.lower()
    return any(pattern.lower() in lower for pattern in EXCLUDE_PATTERNS)


def _forward_event(log_event: dict[str, Any], log_group: str, log_stream: str) -> None:
    """Asynchronously invoke the Fingerprinter Lambda with a single log event."""
    payload = {
        "message": log_event.get("message", ""),
        "timestamp": log_event.get("timestamp"),
        "logGroup": log_group,
        "logStream": log_stream,
    }
    _lambda_client.invoke(
        FunctionName=FINGERPRINTER_FUNCTION_NAME,
        InvocationType="Event",  # async — fire-and-forget
        Payload=json.dumps(payload).encode(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Handler
# ─────────────────────────────────────────────────────────────────────────────

def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Entry point for CloudWatch Logs subscription trigger.

    Expected event shape::

        {
          "awslogs": {
            "data": "<Base64+gzip encoded CloudWatch Logs payload>"
          }
        }
    """
    encoded_data: str = event["awslogs"]["data"]
    cw_payload = _decode_cw_payload(encoded_data)

    log_group: str = cw_payload.get("logGroup", "")
    log_stream: str = cw_payload.get("logStream", "")
    log_events: list[dict[str, Any]] = cw_payload.get("logEvents", [])

    total = len(log_events)
    forwarded = 0
    excluded = 0

    for log_event in log_events:
        message: str = log_event.get("message", "")

        if _is_excluded(message):
            excluded += 1
            logger.debug("Excluded log event: %.120s", message)
            continue

        _forward_event(log_event, log_group, log_stream)
        forwarded += 1

    logger.info(
        "Processed %d events | forwarded=%d excluded=%d | group=%s",
        total,
        forwarded,
        excluded,
        log_group,
    )
    return {"total": total, "forwarded": forwarded, "excluded": excluded}
