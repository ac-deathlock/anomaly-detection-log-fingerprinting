#!/usr/bin/env python3
"""
scripts/analyze_compression.py
-------------------------------
Runs every log in logs.json through the sanitizer and reports:

  - Total logs processed
  - Total unique fingerprints generated
  - Compression ratio
  - Top-5 most frequent fingerprints with representative original messages

Usage:
    python scripts/analyze_compression.py [--logs PATH] [--top N]
"""
import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

# Ensure the project root is on sys.path regardless of where the script is run.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.analyzer.sanitizer import sanitize, FingerprintResult  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_logs(path: Path) -> list[str]:
    """Return a flat list of @message strings from the JSON log file."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)

    messages: list[str] = []
    for entry in data:
        # Support both "@message" (CloudWatch Insights export) and "message"
        msg = entry.get("@message") or entry.get("message") or ""
        if msg:
            messages.append(str(msg).strip())
    return messages


def _truncate(text: str, width: int = 120) -> str:
    return text if len(text) <= width else text[:width] + " …"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Log fingerprint compression analyser")
    parser.add_argument(
        "--logs",
        default=str(ROOT / "logs.json"),
        help="Path to the JSON log file (default: logs.json in project root)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top fingerprints to display (default: 5)",
    )
    args = parser.parse_args()

    log_path = Path(args.logs)
    if not log_path.exists():
        print(f"ERROR: Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    print(f"\nLoading logs from: {log_path}")
    messages = load_logs(log_path)
    total = len(messages)
    print(f"Loaded {total:,} log entries.\n")
    print("Running sanitizer …", flush=True)

    t0 = time.perf_counter()

    # fingerprint → list of (sanitized_text, original_message)
    fingerprint_map: dict[str, list[tuple[str, str]]] = defaultdict(list)
    freq: Counter = Counter()

    for msg in messages:
        result: FingerprintResult = sanitize(msg)
        fp = result.fingerprint
        freq[fp] += 1
        # Store up to 3 originals per fingerprint for the report sample
        if len(fingerprint_map[fp]) < 3:
            fingerprint_map[fp].append((result.sanitized, result.original))

    elapsed = time.perf_counter() - t0
    unique = len(freq)

    # ---------------------------------------------------------------------------
    # Report
    # ---------------------------------------------------------------------------
    separator = "=" * 80

    print(separator)
    print("  LOG FINGERPRINT COMPRESSION REPORT")
    print(separator)
    print(f"  Total logs processed  : {total:>10,}")
    print(f"  Unique fingerprints   : {unique:>10,}")
    print(f"  Compression ratio     : {total / unique:>10.1f}x  "
          f"({total:,} logs → {unique:,} unique patterns)")
    print(f"  Processing time       : {elapsed:>10.3f}s  "
          f"({total / elapsed:,.0f} logs/sec)")
    print(separator)

    # ---------------------------------------------------------------------------
    # Top-N fingerprints
    # ---------------------------------------------------------------------------
    print(f"\n  TOP {args.top} MOST FREQUENT FINGERPRINTS")
    print(separator)

    for rank, (fp, count) in enumerate(freq.most_common(args.top), start=1):
        pct = count / total * 100
        sanitized_sample, original_sample = fingerprint_map[fp][0]

        print(f"\n  #{rank}  Occurrences: {count:,}  ({pct:.1f}% of all logs)")
        print(f"  Fingerprint : {fp[:16]}…")
        print(f"  SANITIZED   : {_truncate(sanitized_sample)}")

        # Show up to 3 original variants to prove the fingerprint collapses them
        variants = fingerprint_map[fp]
        print(f"  ORIGINALS ({len(variants)} shown):")
        for idx, (_, orig) in enumerate(variants, start=1):
            print(f"    [{idx}] {_truncate(orig)}")

    print(f"\n{separator}")

    # ---------------------------------------------------------------------------
    # Rule hit distribution
    # ---------------------------------------------------------------------------
    rule_hits: Counter = Counter()
    for msg in messages:
        result = sanitize(msg)
        for rule in result.rules_applied:
            rule_hits[rule] += 1

    print("\n  SANITIZATION RULE HIT FREQUENCY")
    print(separator)
    print(f"  {'Rule':<25} {'Logs Affected':>15}  {'%':>6}")
    print(f"  {'-'*25} {'-'*15}  {'-'*6}")
    for rule_name, hits in rule_hits.most_common():
        print(f"  {rule_name:<25} {hits:>15,}  {hits/total*100:>5.1f}%")

    print(f"\n{separator}\n")


if __name__ == "__main__":
    main()
