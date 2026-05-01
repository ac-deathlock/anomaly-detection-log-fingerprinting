"""
Log sanitizer: strips environment-specific tokens from raw log messages
to produce stable, comparable fingerprints.

Substitution rules are applied in priority order — patterns that are more
specific (e.g. ISO8601 timestamps) must come before patterns that are more
general (e.g. bare numbers) to avoid partial replacements.
"""
import hashlib
import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Substitution rule registry
# Each tuple: (compiled_regex, replacement_string, rule_name)
# ORDER MATTERS — do not reorder without reviewing interactions.
# ---------------------------------------------------------------------------

@dataclass
class SanitizationRule:
    name: str
    pattern: re.Pattern
    replacement: str


def _rule(name: str, pattern: str, replacement: str, flags: int = 0) -> SanitizationRule:
    return SanitizationRule(name=name, pattern=re.compile(pattern, flags), replacement=replacement)


RULES: list[SanitizationRule] = [
    # 0. VPC Flow rawmsg — replace the entire space-delimited flow record FIRST,
    #    before any other rules run on it.  All meaningful fields are duplicated
    #    in the structured JSON that follows (srcipv4, dstipv4, action, etc.).
    _rule(
        "VPC_FLOW_RAWMSG",
        r'"rawmsg"\s*:\s*"[^"]+"',
        '"rawmsg":"<VPC-FLOW-RECORD>"',
    ),
    # 1. ISO8601 / log-prefixed timestamps  e.g. 2026-04-18T14:16:50.848Z or 2026-04-18 14:16:50,848
    _rule(
        "ISO8601_TIMESTAMP",
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.,]\d{3,6}(?:[-+]\d{2}:\d{2}|Z)?",
        "<TIMESTAMP>",
    ),
    # 2. Full UUIDs (version-agnostic)
    _rule(
        "UUID",
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "<UUID>",
    ),
    # 3. IPv4 addresses (must precede bare 12-digit account IDs)
    _rule(
        "IPv4",
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "<IPv4>",
    ),
    # 4. AWS ENI IDs  e.g. eni-08958236e071f7da3
    _rule(
        "ENI_ID",
        r"\beni-[0-9a-f]{8,17}\b",
        "<ENI-ID>",
    ),
    # 5. Epoch timestamps anchored to current era (starts 1600000000)
    #    Supports both second-precision (10 digits) and millisecond-precision (13 digits).
    _rule(
        "EPOCH_TIMESTAMP",
        r"\b1[6-9]\d{8,11}\b",
        "<EPOCH>",
    ),
    # 6. AWS Account IDs — exactly 12 digits standing alone
    _rule(
        "AWS_ACCOUNT_ID",
        r"\b[0-9]{12}\b",
        "<AWS-ACCOUNT>",
    ),
    # 7. Windows Security Identifier (SID)
    _rule(
        "SID",
        r"S-1-[0-9\-]{15,}",
        "<SID>",
    ),
    # 8. Hex literals  0x followed by 4+ hex digits
    _rule(
        "HEX_CODE",
        r"\b0x[0-9a-fA-F]{4,}\b",
        "<HEX>",
    ),
    # 9. Port numbers attached to port/srcport/dstport keys
    _rule(
        "PORT_NUMBER",
        r"((?:src|dst)?port)(['\"\s:=]*)(\d{4,5})\b",
        r"\1\2<PORT>",
    ),
    # 10. Thread IDs  ThreadId / threadid  followed by 4 uppercase hex chars
    _rule(
        "THREAD_ID",
        r"(ThreadId|threadid)(['\"\s:=]+)([0-9A-F]{4})\b",
        r"\1\2<THREAD>",
    ),
    # 11. Trace / correlation IDs  (named key + hex-uuid-like value)
    _rule(
        "TRACE_ID",
        r"(trace_id|correlation_id)(['\"\s:=]+)([0-9a-f\-]{30,50})",
        r"\1\2<TRACE-ID>",
    ),
    # 12. Windows file paths  e.g. C:\Windows\System32\dns\dns.log
    _rule(
        "WIN_PATH",
        r"[A-Z]:\\[^\s\r\n\"]+",
        "<WIN-PATH>",
    ),
    # 13. Linux service/runtime paths  /var /opt /usr /tmp
    _rule(
        "LINUX_PATH",
        r"/(?:var|opt|usr|tmp)/[^\s\r\n\"]+",
        "<LINUX-PATH>",
    ),
    # 14. Bare numeric record / packet / byte counts  large stand-alone integers
    #     (applied last so earlier rules that need digits are already done)
    _rule(
        "LARGE_NUMBER",
        r"\b[0-9]{5,10}\b",
        "<NUM>",
    ),
    # 15. JSON quoted numeric values  e.g. "dstport":"5432", "bytes":"2393"
    #     Applied after LARGE_NUMBER so 5+ digit values are already replaced;
    #     this catches the remaining 1-4 digit quoted values.
    _rule(
        "JSON_QUOTED_NUMBER",
        r'(":\s*")(\d{1,4})(")',
        r"\1<NUM>\3",
    ),
    # 16. JSON unquoted numeric values  e.g. "EventID":4673, "packets":17
    #     Matches  "key": digits  at a JSON value boundary.
    _rule(
        "JSON_UNQUOTED_NUMBER",
        r'(":\s*)(\d+)(?=[,}\s\]])',
        r"\1<NUM>",
    ),
    # 17. AADSTS / Microsoft AAD error codes  e.g. AADSTS700016, AADSTS70011
    _rule(
        "AADSTS_CODE",
        r"\bAADSTS\d{4,}\b",
        "AADSTS<CODE>",
    ),
    # 18. DNS question / query names  e.g. "QuestionName":"e3913.cd.akamaiedge.net"
    _rule(
        "DNS_QUESTION_NAME",
        r'("QuestionName"\s*:\s*")[^"]+(")',
        r"\1<HOSTNAME>\2",
        re.IGNORECASE,
    ),
    # 19. Hex packet / internal identifiers without 0x prefix (DNS, Windows events)
    #     e.g. InternalPacketIdentifier":"00000175A743E9D0", Xid":"a103"
    _rule(
        "HEX_PACKET_ID",
        r'("(?:InternalPacketIdentifier|Xid|FlagsHex|ProviderGuid|Keywords)"\s*:\s*["{]?)([0-9a-fA-F\-]{4,})(["}\s,])',
        r"\1<HEX-ID>\3",
        re.IGNORECASE,
    ),
    # 20. DNS / NXLog infomsg field — the entire raw info line is per-packet unique
    _rule(
        "DNS_INFOMSG",
        r'"infomsg"\s*:\s*"[^"]+"',
        '"infomsg":"<DNS-MSG>"',
        re.IGNORECASE,
    ),
    # 21. Floating-point values  e.g. reportduration: 8703.2986, duration: 0.0485
    _rule(
        "FLOAT_VALUE",
        r"\b\d+\.\d{3,}\b",
        "<FLOAT>",
    ),
    # 22. Dotted hostname / FQDN values  e.g. gwadsdsp12.gwl.bz, cladsdsp08.canadalife.bz
    #     Restricted to known TLDs to avoid matching Python logger names (e.g. helix.cloudint.mimecast).
    _rule(
        "FQDN",
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|org|net|io|bz|ca|local|gov|edu|uk|gz|co)\b",
        "<FQDN>",
        re.IGNORECASE,
    ),
    # 23. NXLog / agent version strings  e.g. "NXLogVersion":"6.3.9425"
    _rule(
        "AGENT_VERSION",
        r'"(?:NXLogVersion|agentversion|NXLogConfVer)"\s*:\s*"[^"]+"',
        r'"<agent-key>":"<VERSION>"',
        re.IGNORECASE,
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class FingerprintResult:
    original: str
    sanitized: str
    fingerprint: str          # SHA-256 hex digest of sanitized string
    rules_applied: list[str] = field(default_factory=list)


def apply_rules(message: str, rules: list[SanitizationRule]) -> FingerprintResult:
    """
    Apply *rules* (in order) to *message* and return a :class:`FingerprintResult`.

    This is the core engine used by both :func:`sanitize` (base rules) and
    :func:`~analyzer.stream_profile.sanitize_for_stream` (per-stream rules).
    """
    sanitized = message
    applied: list[str] = []

    for rule in rules:
        new_text, count = rule.pattern.subn(rule.replacement, sanitized)
        if count:
            sanitized = new_text
            applied.append(rule.name)

    # Collapse runs of whitespace so minor formatting differences don't produce
    # different fingerprints.
    sanitized = re.sub(r"\s+", " ", sanitized).strip()

    digest = hashlib.sha256(sanitized.encode("utf-8", errors="replace")).hexdigest()

    return FingerprintResult(
        original=message,
        sanitized=sanitized,
        fingerprint=digest,
        rules_applied=applied,
    )


def sanitize(message: str) -> FingerprintResult:
    """
    Apply the default RULES to *message* and return a :class:`FingerprintResult`.

    The returned ``fingerprint`` is a SHA-256 hex digest of the sanitized text,
    suitable for use as a DynamoDB partition key.
    """
    return apply_rules(message, RULES)


def fingerprint(message: str) -> str:
    """Convenience wrapper — returns only the hex fingerprint string."""
    return sanitize(message).fingerprint


def get_rules() -> list[SanitizationRule]:
    """Return the current ordered list of sanitization rules (read-only copy)."""
    return list(RULES)
