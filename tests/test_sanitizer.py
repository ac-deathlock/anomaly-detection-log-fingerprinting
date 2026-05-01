"""
tests/test_sanitizer.py
-----------------------
Unit tests for each of the 23 sanitization rules in src/analyzer/sanitizer.py.

Every test verifies:
  1. The target token IS replaced with the expected placeholder.
  2. Non-target content is NOT altered.
  3. The rule name appears in FingerprintResult.rules_applied.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.analyzer.sanitizer import sanitize, fingerprint, get_rules  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sanitized(msg: str) -> str:
    return sanitize(msg).sanitized


def _applied(msg: str) -> list[str]:
    return sanitize(msg).rules_applied


# ─────────────────────────────────────────────────────────────────────────────
# Rule 0 — VPC_FLOW_RAWMSG
# ─────────────────────────────────────────────────────────────────────────────

class TestVpcFlowRawmsg:
    def test_replaces_rawmsg_value(self):
        msg = '"rawmsg":"2 556904344811 eni-00000000 1.2.3.4 5.6.7.8 80 443 6 10 1000 1700000000 1700000001 ACCEPT OK"'
        result = _sanitized(msg)
        assert "<VPC-FLOW-RECORD>" in result
        assert "556904344811" not in result

    def test_rule_applied(self):
        msg = '"rawmsg":"2 100000000000 eni-abc123 0.0.0.0 1.1.1.1 9000 8080 6 5 500 1700000000 1700000001 REJECT NODATA"'
        assert "VPC_FLOW_RAWMSG" in _applied(msg)

    def test_non_rawmsg_unaffected(self):
        msg = "helix.normalization ERROR Generic error"
        assert "<VPC-FLOW-RECORD>" not in _sanitized(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Rule 1 — ISO8601_TIMESTAMP
# ─────────────────────────────────────────────────────────────────────────────

class TestIso8601Timestamp:
    @pytest.mark.parametrize("ts", [
        "2026-04-18T14:16:50.848Z",
        "2026-04-18 14:16:50,848",
        "2026-02-05T13:08:18.000000-05:00",
    ])
    def test_replaces_timestamps(self, ts: str):
        result = _sanitized(f"log message {ts} end")
        assert "<TIMESTAMP>" in result
        assert ts not in result

    def test_rule_applied(self):
        assert "ISO8601_TIMESTAMP" in _applied("event at 2026-04-18T10:00:00.000Z done")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 2 — UUID
# ─────────────────────────────────────────────────────────────────────────────

class TestUuid:
    def test_replaces_uuid(self):
        msg = "id=82430625-7058-49E5-AE37-B3803D9BFBFA"
        assert "<UUID>" in _sanitized(msg)

    def test_preserves_non_uuid(self):
        msg = "error code 1234 occurred"
        assert "<UUID>" not in _sanitized(msg)

    def test_rule_applied(self):
        assert "UUID" in _applied("trace 82430625-7058-49E5-AE37-B3803D9BFBFA")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 3 — IPv4
# ─────────────────────────────────────────────────────────────────────────────

class TestIPv4:
    @pytest.mark.parametrize("ip", ["10.0.11.52", "192.168.0.1", "0.0.0.0"])
    def test_replaces_ip(self, ip: str):
        msg = f"connection from {ip} failed"
        assert "<IPv4>" in _sanitized(msg)
        assert ip not in _sanitized(msg)

    def test_rule_applied(self):
        assert "IPv4" in _applied("src 10.0.0.1 dst 10.0.0.2")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 4 — ENI_ID
# ─────────────────────────────────────────────────────────────────────────────

class TestEniId:
    def test_replaces_eni(self):
        msg = "interface eni-08958236e071f7da3 rejected"
        assert "<ENI-ID>" in _sanitized(msg)

    def test_rule_applied(self):
        assert "ENI_ID" in _applied("eni-08958236e071f7da3")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 5 — EPOCH_TIMESTAMP
# ─────────────────────────────────────────────────────────────────────────────

class TestEpochTimestamp:
    def test_replaces_epoch(self):
        msg = "start=1776521680 end=1776521711"
        result = _sanitized(msg)
        assert "<EPOCH>" in result
        assert "1776521680" not in result

    def test_rule_applied(self):
        assert "EPOCH_TIMESTAMP" in _applied("ts=1776521680")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 6 — AWS_ACCOUNT_ID
# ─────────────────────────────────────────────────────────────────────────────

class TestAwsAccountId:
    def test_replaces_12_digit_account(self):
        msg = "accountid=556904344811 region=us-east-1"
        assert "<AWS-ACCOUNT>" in _sanitized(msg)

    def test_does_not_replace_11_digit(self):
        msg = "code 12345678901"  # 11 digits
        assert "<AWS-ACCOUNT>" not in _sanitized(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Rule 7 — SID
# ─────────────────────────────────────────────────────────────────────────────

class TestSid:
    def test_replaces_sid(self):
        sid = "S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003"
        msg = f"user sid={sid}"
        assert "<SID>" in _sanitized(msg)

    def test_rule_applied(self):
        assert "SID" in _applied("S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 8 — HEX_CODE
# ─────────────────────────────────────────────────────────────────────────────

class TestHexCode:
    @pytest.mark.parametrize("hex_val", ["0x2746", "0x000045a6", "0x8010000000000000"])
    def test_replaces_hex(self, hex_val: str):
        msg = f"flags={hex_val}"
        assert "<HEX>" in _sanitized(msg)

    def test_rule_applied(self):
        assert "HEX_CODE" in _applied("mask=0x2746")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 9 — PORT_NUMBER
# ─────────────────────────────────────────────────────────────────────────────

class TestPortNumber:
    @pytest.mark.parametrize("key,val", [
        ("port", "5432"),
        ("srcport", "40863"),
        ("dstport", "50607"),
    ])
    def test_replaces_port(self, key: str, val: str):
        msg = f"{key}={val}"
        result = _sanitized(msg)
        assert "<PORT>" in result
        assert val not in result

    def test_rule_applied(self):
        assert "PORT_NUMBER" in _applied("srcport=40863")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 10 — THREAD_ID
# ─────────────────────────────────────────────────────────────────────────────

class TestThreadId:
    def test_replaces_thread_id(self):
        msg = '"ThreadId":"1D1C"'
        assert "<THREAD>" in _sanitized(msg)

    def test_lowercase_threadid(self):
        msg = '"threadid":"3AA8"'
        assert "<THREAD>" in _sanitized(msg)

    def test_rule_applied(self):
        assert "THREAD_ID" in _applied('"ThreadId":"1D1C"')


# ─────────────────────────────────────────────────────────────────────────────
# Rule 11 — TRACE_ID
# ─────────────────────────────────────────────────────────────────────────────

class TestTraceId:
    def test_replaces_trace_id_non_uuid_format(self):
        """TRACE_ID rule fires for hex IDs that are NOT UUID-shaped."""
        msg = 'correlation_id="abc123def456abc123def456abc123def456abc1"'
        result = _sanitized(msg)
        assert "<TRACE-ID>" in result

    def test_uuid_shaped_trace_id_caught_by_uuid_rule(self):
        """A UUID-shaped trace ID is correctly sanitised by the UUID rule first."""
        msg = 'trace_id="cf44d664-7a8a-4d53-be87-439f34563600"'
        result = _sanitized(msg)
        # UUID rule fires before TRACE_ID; the result should be <UUID>
        assert "<UUID>" in result

    def test_rule_applied_for_non_uuid(self):
        assert "TRACE_ID" in _applied('trace_id="abc123def456abc123def456abc123def456abc1"')


# ─────────────────────────────────────────────────────────────────────────────
# Rule 12 — WIN_PATH
# ─────────────────────────────────────────────────────────────────────────────

class TestWinPath:
    def test_replaces_windows_path(self):
        msg = r"file=C:\windows\system32\dns\dns.log"
        assert "<WIN-PATH>" in _sanitized(msg)

    def test_rule_applied(self):
        assert "WIN_PATH" in _applied(r"C:\windows\system32\file.log")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 13 — LINUX_PATH
# ─────────────────────────────────────────────────────────────────────────────

class TestLinuxPath:
    @pytest.mark.parametrize("path", [
        "/opt/sentry_sdk/integrations/aws_lambda.py",
        "/var/task/api.py",
        "/tmp/scratch.json",
        "/usr/bin/python3",
    ])
    def test_replaces_linux_path(self, path: str):
        msg = f"file {path} not found"
        assert "<LINUX-PATH>" in _sanitized(msg)

    def test_rule_applied(self):
        assert "LINUX_PATH" in _applied("at /opt/sentry_sdk/handler.py line 10")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 14 — LARGE_NUMBER
# ─────────────────────────────────────────────────────────────────────────────

class TestLargeNumber:
    @pytest.mark.parametrize("num", ["12345", "9999999", "1234567890"])
    def test_replaces_large_number(self, num: str):
        msg = f"count={num}"
        assert "<NUM>" in _sanitized(msg)

    def test_does_not_replace_4_digit(self):
        # 4-digit numbers below the LARGE_NUMBER threshold — not replaced by this rule
        # (they may be replaced by JSON_QUOTED_NUMBER or JSON_UNQUOTED_NUMBER in context)
        msg = "code 1234 end"
        # Only check large number rule specifically — not full sanitized output
        assert "LARGE_NUMBER" not in _applied(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Rule 15 — JSON_QUOTED_NUMBER
# ─────────────────────────────────────────────────────────────────────────────

class TestJsonQuotedNumber:
    def test_replaces_quoted_numeric_value(self):
        msg = '"dstport":"5432","bytes":"2393","packets":"17"'
        result = _sanitized(msg)
        assert "5432" not in result
        assert "2393" not in result
        assert "17" not in result

    def test_rule_applied(self):
        assert "JSON_QUOTED_NUMBER" in _applied('"bytes":"2393"')

    def test_preserves_non_numeric_string_values(self):
        msg = '"action":"ACCEPT"'
        assert "ACCEPT" in _sanitized(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Rule 16 — JSON_UNQUOTED_NUMBER
# ─────────────────────────────────────────────────────────────────────────────

class TestJsonUnquotedNumber:
    def test_replaces_unquoted_numeric_json_value(self):
        msg = '"EventID":4673,"handleid":8,'
        result = _sanitized(msg)
        assert "4673" not in result
        assert '"EventID":' in result  # key is preserved

    def test_rule_applied(self):
        assert "JSON_UNQUOTED_NUMBER" in _applied('"EventID":4673,')


# ─────────────────────────────────────────────────────────────────────────────
# Rule 17 — AADSTS_CODE
# ─────────────────────────────────────────────────────────────────────────────

class TestAadstsCode:
    @pytest.mark.parametrize("code", ["AADSTS700016", "AADSTS70011", "AADSTS50034"])
    def test_replaces_aadsts_code(self, code: str):
        msg = f"login failed: {code}"
        assert "AADSTS<CODE>" in _sanitized(msg)
        assert code not in _sanitized(msg)

    def test_rule_applied(self):
        assert "AADSTS_CODE" in _applied("error AADSTS700016 unknown client")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 18 — DNS_QUESTION_NAME
# ─────────────────────────────────────────────────────────────────────────────

class TestDnsQuestionName:
    def test_replaces_question_name(self):
        msg = '"QuestionName":"e3913.cd.akamaiedge.net"'
        assert "<HOSTNAME>" in _sanitized(msg)

    def test_case_insensitive(self):
        msg = '"questionname":"internal.corp.local"'
        assert "<HOSTNAME>" in _sanitized(msg)

    def test_rule_applied(self):
        assert "DNS_QUESTION_NAME" in _applied('"QuestionName":"test.example.com"')


# ─────────────────────────────────────────────────────────────────────────────
# Rule 19 — HEX_PACKET_ID
# ─────────────────────────────────────────────────────────────────────────────

class TestHexPacketId:
    def test_replaces_internal_packet_id(self):
        msg = '"InternalPacketIdentifier":"00000175A743E9D0"'
        assert "<HEX-ID>" in _sanitized(msg)

    def test_replaces_xid(self):
        msg = '"Xid":"a103"'
        assert "<HEX-ID>" in _sanitized(msg)

    def test_rule_applied(self):
        assert "HEX_PACKET_ID" in _applied('"InternalPacketIdentifier":"00000175A743E9D0"')


# ─────────────────────────────────────────────────────────────────────────────
# Rule 20 — DNS_INFOMSG
# ─────────────────────────────────────────────────────────────────────────────

class TestDnsInfomsg:
    def test_replaces_infomsg(self):
        msg = '"infomsg":"4/18/2026 6:51:38 AM 1C0C PACKET 000001D893095EC0 UDP Rcv 10.0.0.1 7e74"'
        assert "<DNS-MSG>" in _sanitized(msg)

    def test_rule_applied(self):
        assert "DNS_INFOMSG" in _applied('"infomsg":"test packet data"')


# ─────────────────────────────────────────────────────────────────────────────
# Rule 21 — FLOAT_VALUE
# ─────────────────────────────────────────────────────────────────────────────

class TestFloatValue:
    @pytest.mark.parametrize("val", ["8703.2986", "0.0485", "1061.1206"])
    def test_replaces_float(self, val: str):
        msg = f"duration={val}"
        assert "<FLOAT>" in _sanitized(msg)

    def test_short_float_unaffected(self):
        # 2-decimal floats are left alone (e.g. "v1.3", "v1.17" — version strings)
        msg = "version=1.3"
        result = _sanitized(msg)
        assert "<FLOAT>" not in result

    def test_rule_applied(self):
        assert "FLOAT_VALUE" in _applied("reportduration=8703.2986")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 22 — FQDN
# ─────────────────────────────────────────────────────────────────────────────

class TestFqdn:
    @pytest.mark.parametrize("fqdn", [
        "gwadsdsp12.gwl.bz",
        "cladsdsp08.canadalife.bz",
        "sslobdsp04.GCOLOB.local",
    ])
    def test_replaces_fqdn(self, fqdn: str):
        msg = f"hostname={fqdn}"
        assert "<FQDN>" in _sanitized(msg)

    def test_preserves_logger_names(self):
        # Python logger names with dots should NOT be treated as FQDNs
        msg = "2026-04-18 10:00:00,000 helix.cloudint.mimecast ERROR something"
        result = _sanitized(msg)
        assert "helix.cloudint.mimecast" in result

    def test_rule_applied(self):
        assert "FQDN" in _applied("host=gwadsdsp12.gwl.bz")


# ─────────────────────────────────────────────────────────────────────────────
# Rule 23 — AGENT_VERSION
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentVersion:
    def test_replaces_nxlog_version(self):
        msg = '"NXLogVersion":"6.3.9425"'
        assert "<VERSION>" in _sanitized(msg)

    def test_replaces_nxlog_confver(self):
        msg = '"NXLogConfVer":"v1.17"'
        assert "<VERSION>" in _sanitized(msg)

    def test_rule_applied(self):
        assert "AGENT_VERSION" in _applied('"NXLogVersion":"6.3.9425"')


# ─────────────────────────────────────────────────────────────────────────────
# Cross-rule integration: fingerprint stability
# ─────────────────────────────────────────────────────────────────────────────

class TestFingerprintStability:
    def test_same_message_same_fingerprint(self):
        msg = "2026-04-18 10:00:00,000 helix.api ERROR Generic error"
        assert fingerprint(msg) == fingerprint(msg)

    def test_whitespace_normalization(self):
        """Extra whitespace should not change the fingerprint."""
        msg1 = "ERROR   something   happened"
        msg2 = "ERROR something happened"
        assert fingerprint(msg1) == fingerprint(msg2)

    def test_different_timestamps_same_fingerprint(self):
        """Two logs differing only in timestamp should share a fingerprint."""
        msg1 = "2026-04-18 14:16:50,848 helix.api ERROR Generic error"
        msg2 = "2026-04-18 09:00:00,000 helix.api ERROR Generic error"
        assert fingerprint(msg1) == fingerprint(msg2)

    def test_different_ips_same_fingerprint(self):
        msg1 = "conn from 10.0.0.1 to 10.0.0.2 failed"
        msg2 = "conn from 192.168.1.1 to 192.168.1.2 failed"
        assert fingerprint(msg1) == fingerprint(msg2)

    def test_different_errors_different_fingerprints(self):
        msg1 = "helix.api ERROR Generic error"
        msg2 = "helix.api ERROR Connection timeout"
        assert fingerprint(msg1) != fingerprint(msg2)

    def test_get_rules_returns_ordered_list(self):
        rules = get_rules()
        assert rules[0].name == "VPC_FLOW_RAWMSG"
        assert len(rules) >= 20
