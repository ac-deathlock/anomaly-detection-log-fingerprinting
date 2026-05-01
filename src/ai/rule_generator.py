"""
src/ai/rule_generator.py
-------------------------
Uses Bedrock Claude to generate a SanitizationRule from a cluster of similar
log messages. The generated regex is validated before being returned.

Env vars:
  BEDROCK_LLM_MODEL   Claude model ID (default: anthropic.claude-3-5-sonnet-20241022-v2:0)
  BEDROCK_REGION      AWS region (default: us-east-1)
"""
import json
import logging
import os
import re
from typing import Any

import boto3

logger = logging.getLogger(__name__)

LLM_MODEL: str = os.environ.get(
    "BEDROCK_LLM_MODEL", "anthropic.claude-3-5-sonnet-20241022-v2:0"
)

_bedrock = boto3.client(
    "bedrock-runtime",
    region_name=os.environ.get("BEDROCK_REGION", "us-east-1"),
)

_PROMPT_TEMPLATE = """\
You are a log sanitization expert. The log messages below are from the same \
error-pattern cluster (semantically similar, dynamically varying values).

Generate ONE Python regex rule that normalizes the dynamic parts so all samples \
produce the same sanitized string.

Samples (up to 10):
{samples}

Requirements:
1. Use capture groups only where needed for the replacement string.
2. Replace dynamic parts with descriptive placeholders: <HOSTNAME>, <ID>, <NUM>, \
<PATH>, <TOKEN>, <TIMESTAMP>, etc.
3. rule_name must be SCREAMING_SNAKE_CASE and describe what is being matched.
4. Focus on the most variable part across the samples; leave static text as-is.
5. The regex must NOT match an empty string.
6. Respond ONLY with a single JSON object — no explanation, no markdown fences.

JSON format:
{{"rule_name": "...", "pattern": "...", "replacement": "...", "flags": 0}}
"""


def _call_claude(prompt: str) -> str:
    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 600,
            "messages": [{"role": "user", "content": prompt}],
        }
    )
    response = _bedrock.invoke_model(
        modelId=LLM_MODEL,
        body=body,
        contentType="application/json",
        accept="application/json",
    )
    result: dict[str, Any] = json.loads(response["body"].read())
    return result["content"][0]["text"].strip()


def _validate_rule(rule: dict[str, Any], samples: list[str]) -> bool:
    """
    Return True if the rule:
      1. Has all required keys.
      2. Regex compiles without error.
      3. Regex does not match an empty string (guards against over-broad patterns).
      4. Regex actually matches at least one of the provided samples.
    """
    for key in ("rule_name", "pattern", "replacement", "flags"):
        if key not in rule:
            logger.warning("Rule missing key: %s", key)
            return False

    try:
        compiled = re.compile(rule["pattern"], int(rule.get("flags", 0)))
    except re.error as exc:
        logger.warning("Rule regex compile error: %s", exc)
        return False

    if compiled.match(""):
        logger.warning("Rule regex matches empty string — too broad, rejected")
        return False

    if not any(compiled.search(s) for s in samples):
        logger.warning("Rule regex does not match any sample — rejected")
        return False

    return True


def generate_rule(samples: list[str]) -> dict[str, Any] | None:
    """
    Given a list of log messages from the same cluster, return a rule dict
    compatible with SanitizationRule or None if generation/validation fails.

    Attempts up to 2 times before giving up.
    """
    if not samples:
        return None

    sample_text = "\n".join(f"- {s[:200]}" for s in samples[:10])
    prompt = _PROMPT_TEMPLATE.format(samples=sample_text)

    for attempt in range(2):
        try:
            raw = _call_claude(prompt)
            # Strip markdown fences if Claude wraps the JSON anyway
            raw = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            rule = json.loads(raw)
            if _validate_rule(rule, samples):
                return rule
            logger.warning("Rule failed validation on attempt %d", attempt + 1)
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("Rule generation parse error (attempt %d): %s", attempt + 1, exc)

    return None
