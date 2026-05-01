"""
scripts/generate_regression_samples.py
---------------------------------------
Pick 50 diverse log samples from logs.json — 5-7 per category —
and emit a JSON file used by the pytest regression suite.

Run once whenever you want to refresh the golden-file fixtures.
Output: tests/fixtures/regression_samples.json
"""
import json
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.analyzer.sanitizer import sanitize  # noqa: E402

random.seed(42)

TARGETS: dict[str, int] = {
    "vpc_flow": 6,
    "unauthorized": 5,
    "mimecast": 7,
    "api_error": 4,
    "o365": 5,
    "timestamp_parse": 5,
    "dns": 5,
    "mssql": 2,
    "ms_auth": 7,
    "generic": 4,
}


def categorize(msg: str) -> str:
    ml = msg.lower()
    if "aws_cloudwatch_vpcflow" in ml:
        return "vpc_flow"
    if "unauthorized" in ml and "exception" in ml:
        return "unauthorized"
    if "mimecast" in ml:
        return "mimecast"
    if "unable to get timestamp" in ml:
        return "timestamp_parse"
    if "questionname" in ml or "ms_dns" in ml:
        return "dns"
    if "mssql" in ml:
        return "mssql"
    if "ms_azure_ad" in ml or "microsoft-windows-security" in ml or "aadsts" in ml:
        return "ms_auth"
    if "cloudint.api" in ml and "generic error" in ml:
        return "api_error"
    if any(x in ml for x in ["cloudint.o365", "cloudint.ms_graph", "cloudint.duo"]):
        return "o365"
    if "helix" in ml:
        return "generic"
    return "other"


def main() -> None:
    log_path = ROOT / "logs.json"
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)

    buckets: dict[str, list[str]] = {k: [] for k in list(TARGETS) + ["other"]}

    for entry in data:
        raw = entry.get("@message", "")
        msg = str(raw).strip() if raw else ""
        if msg:
            buckets[categorize(msg)].append(msg)

    samples: list[dict] = []
    for cat, count in TARGETS.items():
        pool = buckets[cat]
        chosen = random.sample(pool, min(count, len(pool)))
        for msg in chosen:
            result = sanitize(msg)
            samples.append({
                "category": cat,
                "message": msg,
                "expected_fingerprint": result.fingerprint,
                "sanitized": result.sanitized[:300],
                "rules_applied": result.rules_applied,
            })

    # Pad to 50 with 'other' samples
    remaining = 50 - len(samples)
    other_pool = list(buckets["other"])
    random.shuffle(other_pool)
    for msg in other_pool[:remaining]:
        result = sanitize(msg)
        samples.append({
            "category": "other",
            "message": msg,
            "expected_fingerprint": result.fingerprint,
            "sanitized": result.sanitized[:300],
            "rules_applied": result.rules_applied,
        })

    out_dir = ROOT / "tests" / "fixtures"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "regression_samples.json"

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(samples[:50], fh, indent=2, ensure_ascii=False)

    print(f"Written {len(samples[:50])} samples to {out_path}")
    for cat in TARGETS:
        cat_count = sum(1 for s in samples if s["category"] == cat)
        print(f"  {cat:<20}: {cat_count}")


if __name__ == "__main__":
    main()
