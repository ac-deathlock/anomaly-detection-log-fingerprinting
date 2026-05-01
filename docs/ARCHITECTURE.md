# Log Fingerprinting & Pattern Discovery Pipeline — Architecture

## 1. System Overview

The Log Fingerprinting Pipeline is a serverless, event-driven system that ingests
high-volume CloudWatch log streams, strips environment-specific noise from error
messages via a deterministic regex-based sanitizer, and stores stable SHA-256
fingerprints in DynamoDB. When a new release introduces an error pattern that
has never appeared before, an SNS alert fires immediately — enabling pre-production
regression detection without any manual log review.

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  LOG PRODUCERS                                                              │
│  (Lambda, ECS, EC2, NXLog agents, Mimecast, O365, VPC Flow, DNS…)          │
└────────────────────────────┬────────────────────────────────────────────────┘
                             │  CloudWatch Logs
                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  CLOUDWATCH LOG GROUP  (/aws/lambda/my-app, /helix/normalization, …)        │
│                                                                             │
│  Subscription Filter                                                        │
│  { ($.message = "*ERROR*")                                                  │
│    && ($.message != "*Unable to upload to API*")                            │
│    && ($.message != "*friendly_reason:*") }                                 │
└────────────────────────────┬────────────────────────────────────────────────┘
                             │  gzip+base64 payload
                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  INGESTOR LAMBDA  (log-fp-ingestor-{env}:LIVE)                              │
│  • Decodes CloudWatch payload (base64 → gzip → JSON)                        │
│  • Applies runtime ExcludePatterns (comma-list from env var / SSM)          │
│  • Async-invokes Fingerprinter for each qualifying event                    │
│  • Dead Letter Queue on failure (SQS)                                       │
└────────────────────────────┬────────────────────────────────────────────────┘
                             │  async Lambda:InvokeFunction (Event type)
                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  FINGERPRINTER LAMBDA  (log-fp-fingerprinter-{env}:LIVE)                    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────┐               │
│  │  SANITIZER  (src/analyzer/sanitizer.py)                 │               │
│  │  23 ordered regex rules:                                │               │
│  │  VPC_FLOW_RAWMSG → ISO8601_TIMESTAMP → UUID → IPv4      │               │
│  │  → ENI_ID → EPOCH → AWS_ACCOUNT → SID → HEX_CODE       │               │
│  │  → PORT → THREAD_ID → TRACE_ID → WIN_PATH               │               │
│  │  → LINUX_PATH → LARGE_NUMBER → JSON_QUOTED_NUM          │               │
│  │  → JSON_UNQUOTED_NUM → AADSTS_CODE                      │               │
│  │  → DNS_QUESTION_NAME → HEX_PACKET_ID → DNS_INFOMSG      │               │
│  │  → FLOAT_VALUE → FQDN → AGENT_VERSION                   │               │
│  │                                                         │               │
│  │  Output: SHA-256( sanitized_message )  = fingerprint    │               │
│  └───────────────────────┬─────────────────────────────────┘               │
│                          │                                                  │
│  ┌───────────────────────▼──────────────┐                                  │
│  │  DynamoDB  GetItem(ErrorSignature)   │                                  │
│  │                                      │                                  │
│  │  EXISTS?                             │                                  │
│  │  YES → UpdateItem (LastSeen, Count)  │                                  │
│  │  NO  → PutItem (FirstSeen, ReleaseID,│                                  │
│  │         SampleMessage, Sanitized)    │                                  │
│  └───────────────────────┬──────────────┘                                  │
│                          │  NO (new fingerprint)                           │
│  ┌───────────────────────▼──────────────┐                                  │
│  │  SNS: Publish RegressionAlert        │                                  │
│  │  Subject: "[v2.1.0] New Error Pattern│                                  │
│  │  Detected"                           │                                  │
│  └──────────────────────────────────────┘                                  │
│                                                                             │
│  ┌──────────────────────────────────────┐                                  │
│  │  AI Hook  (optional)                 │                                  │
│  │  AI_PROVIDER=bedrock → Bedrock       │                                  │
│  │  AI_PROVIDER=gemini  → Gemini        │                                  │
│  │  Enriches: summary, severity,        │                                  │
│  │  category, suggested fix             │                                  │
│  └──────────────────────────────────────┘                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                             │  regression alert
                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  SNS TOPIC  (log-fingerprint-regressions-{env})                             │
│  → E-mail subscription (ops@company.com)                                   │
│  → PagerDuty / Slack (add your own subscription)                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. DynamoDB Data Model

**Table:** `log-fingerprints-{env}`
**Billing:** On-demand (PAY_PER_REQUEST)
**Encryption:** AWS KMS CMK (customer-managed)
**PITR:** Enabled

| Attribute | Type | Description |
|---|---|---|
| `ErrorSignature` **(PK)** | String | SHA-256 hex of the sanitized log message |
| `FirstSeen` | String | ISO8601 timestamp of first occurrence |
| `LastSeen` | String | ISO8601 timestamp of most recent occurrence |
| `OccurrenceCount` | Number | Running total of how many times this pattern fired |
| `SampleMessage` | String | First raw log message (truncated to 1024 chars) |
| `SanitizedMessage` | String | Human-readable sanitized form of the pattern |
| `ReleaseID` | String | Release version that **first** introduced this fingerprint |
| `TTL` | Number | (Optional) Unix epoch for automatic expiry |

**Access patterns:**
- `GetItem(ErrorSignature)` — check existence (Fingerprinter, O(1))
- `PutItem` — first-time registration (Fingerprinter, O(1))
- `UpdateItem` — increment counter (Fingerprinter, O(1))

---

## 4. Sanitizer Rule Set (23 Ordered Rules)

Rules are applied in **strict priority order**. Higher specificity rules precede general
number-catching rules to avoid partial replacements.

| # | Rule Name | Pattern Target | Placeholder |
|---|---|---|---|
| 0 | `VPC_FLOW_RAWMSG` | Entire `"rawmsg":"…"` VPC flow record | `<VPC-FLOW-RECORD>` |
| 1 | `ISO8601_TIMESTAMP` | `2026-04-18T14:16:50.848Z`, `2026-04-18 14:16:50,848` | `<TIMESTAMP>` |
| 2 | `UUID` | `82430625-7058-49E5-AE37-B3803D9BFBFA` | `<UUID>` |
| 3 | `IPv4` | `10.0.11.52`, `192.168.0.1` | `<IPv4>` |
| 4 | `ENI_ID` | `eni-08958236e071f7da3` | `<ENI-ID>` |
| 5 | `EPOCH_TIMESTAMP` | `1776521680` (10–13 digit era timestamps) | `<EPOCH>` |
| 6 | `AWS_ACCOUNT_ID` | `556904344811` (exactly 12 digits) | `<AWS-ACCOUNT>` |
| 7 | `SID` | `S-1-5-80-3880718306-…` | `<SID>` |
| 8 | `HEX_CODE` | `0x2746`, `0x8010000000000000` | `<HEX>` |
| 9 | `PORT_NUMBER` | `srcport=40863`, `dstport=5432` | `<PORT>` |
| 10 | `THREAD_ID` | `"ThreadId":"1D1C"` | `<THREAD>` |
| 11 | `TRACE_ID` | `trace_id="abc…"` (non-UUID format) | `<TRACE-ID>` |
| 12 | `WIN_PATH` | `C:\windows\system32\dns\dns.log` | `<WIN-PATH>` |
| 13 | `LINUX_PATH` | `/opt/sentry_sdk/handler.py` | `<LINUX-PATH>` |
| 14 | `LARGE_NUMBER` | 5–10 digit standalone integers | `<NUM>` |
| 15 | `JSON_QUOTED_NUMBER` | `"bytes":"2393"` | `<NUM>` |
| 16 | `JSON_UNQUOTED_NUMBER` | `"EventID":4673` | `<NUM>` |
| 17 | `AADSTS_CODE` | `AADSTS700016`, `AADSTS70011` | `AADSTS<CODE>` |
| 18 | `DNS_QUESTION_NAME` | `"QuestionName":"host.example.com"` | `<HOSTNAME>` |
| 19 | `HEX_PACKET_ID` | `"InternalPacketIdentifier":"000001…"` | `<HEX-ID>` |
| 20 | `DNS_INFOMSG` | `"infomsg":"4/18/2026 6:51:38 AM…"` | `<DNS-MSG>` |
| 21 | `FLOAT_VALUE` | `reportduration:8703.2986` (3+ decimal places) | `<FLOAT>` |
| 22 | `FQDN` | `gwadsdsp12.gwl.bz`, `host.canadalife.bz` | `<FQDN>` |
| 23 | `AGENT_VERSION` | `"NXLogVersion":"6.3.9425"` | `<VERSION>` |

**Compression achieved on 10,000 real logs:**

```
Total logs processed  :  10,000
Unique fingerprints   :   4,265
Compression ratio     :     2.3x   (2,860 logs/sec)
```

Top rules by hit rate: ISO8601 (89.9%) → IPv4 (24.1%) → JSON_QUOTED_NUM (15.4%)
→ VPC_FLOW_RAWMSG (10.8%) → DNS_INFOMSG (7.8%) → UUID (8.9%)

---

## 5. Regression Detection Logic

```
                ┌─────────────────────────┐
                │  New log event arrives  │
                └────────────┬────────────┘
                             │
                      sanitize(msg)
                             │
                    fingerprint = SHA-256
                             │
              ┌──────────────▼─────────────┐
              │  DynamoDB.GetItem(fp)      │
              └──────────────┬─────────────┘
                             │
               ┌─────────────┴──────────────┐
               │ EXISTS?                    │
          YES  │                  NO        │
               ▼                            ▼
    UpdateItem (LastSeen++)      PutItem (FirstSeen=now,
    No alert.                    ReleaseID=current)
                                            │
                                    SNS.Publish()
                                    Subject: "[v2.1.0] New Error"
                                    Body: sanitized pattern,
                                          sample message, ReleaseID
```

**Key insight:** The `ReleaseID` is set **once** at `FirstSeen`. On subsequent
releases, if an existing fingerprint reappears it is *not* re-alerted — only
genuinely *new* patterns that DynamoDB has never seen before trigger an alert.

---

## 6. Security Model

| Control | Implementation |
|---|---|
| **Encryption at rest** | DynamoDB: KMS CMK. SNS: KMS CMK. SQS: KMS CMK. S3: AES-256 |
| **Encryption in transit** | All AWS API calls use TLS 1.2+ by default |
| **IAM least privilege** | Ingestor: `lambda:InvokeFunction` (fingerprinter alias only). Fingerprinter: `dynamodb:{GetItem,PutItem,UpdateItem}` on the specific table ARN, `sns:Publish` on the specific topic ARN |
| **Lambda aliases** | The subscription filter and Ingestor both target `:LIVE` alias — only deployed code serves traffic |
| **CodeDeploy canary** | Prod uses `LambdaCanary10Percent5Minutes` — 10% traffic on new version for 5 min, auto-rollback if alarms fire |
| **Dead Letter Queue** | Failed Lambda invocations go to SQS DLQ — no silent data loss |
| **CloudWatch Alarms** | Error rate, p99 latency, DLQ depth — all wire to SNS → auto-rollback CodeDeploy |
| **No secrets in code** | ReleaseID, ExcludePatterns stored in SSM Parameter Store and Lambda env vars |
| **S3 bucket hardening** | Block all public access, versioning enabled, SSE-AES256 |

---

## 7. Component Inventory

| Component | Type | Purpose |
|---|---|---|
| `log-fp-ingestor-{env}` | Lambda | CW Logs decoder, exclusion filter, async dispatcher |
| `log-fp-fingerprinter-{env}` | Lambda | Sanitizer, DynamoDB upsert, SNS alert, AI hook |
| `log-fingerprints-{env}` | DynamoDB | Persistent fingerprint state store |
| `log-fingerprint-regressions-{env}` | SNS | Regression alerts |
| `log-fingerprint-alarms-{env}` | SNS | CloudWatch alarm notifications |
| `log-fingerprinter-dlq-{env}` | SQS | Dead-letter queue for failed invocations |
| `alias/log-fingerprinting-{env}` | KMS CMK | Encryption for DynamoDB, SNS, SQS |
| `/log-fingerprinting/{env}/…` | SSM | Runtime config (ExcludePatterns, ReleaseID) |
| CloudWatch Alarms (×4) | CW Alarm | Error rate, p99 latency, DLQ depth |
| `log-fingerprinting-{env}` | CodeDeploy | Lambda traffic-shifting |
| `log-fingerprinting-pipeline` | CodePipeline | CI/CD: Source→Test→Package→Dev→Approve→Prod |

---

## 8. Scaling Characteristics

| Dimension | Behaviour |
|---|---|
| **Throughput** | Lambda scales to 1,000 concurrent executions by default. DynamoDB PAY_PER_REQUEST scales automatically. |
| **DynamoDB hot keys** | Fingerprints are SHA-256 hashes — uniformly distributed, no hot-partition risk. |
| **Fingerprinter concurrency cap** | `ReservedConcurrentExecutions: 50` — prevents DynamoDB burst billing; tune upward if needed. |
| **CW Subscription Filter** | Up to 2 subscription filters per log group. One per ingestor. |
| **Lambda cold starts** | arm64 + Python 3.12 + no heavy dependencies → p50 cold start ~200ms. |
| **Cost at scale** | At 10,000 logs/day: ~$0.002 Lambda + ~$0.01 DynamoDB + ~$0 SNS. Negligible. |

---

## 9. Failure Modes & Recovery

| Failure | Detection | Recovery |
|---|---|---|
| Fingerprinter Lambda throws | `FingerprinterErrorAlarm` (>5 errors/5min) | CodeDeploy auto-rollback if in canary window; DLQ captures message |
| DynamoDB latency spike | `FingerprinterDurationAlarm` (p99 > 10s) | Alert + CodeDeploy rollback |
| DLQ accumulating | `DLQDepthAlarm` (≥1 message) | Alert; replay via SQS→Lambda manually |
| Ingestor crash | `IngestorErrorAlarm` | CodeDeploy rollback |
| Bad regex introduced | Regression test fails in CI | Pipeline halted before deployment |
| Wrong fingerprints after rule change | `test_regression.py` fails | Pipeline halted; regenerate fixture intentionally |
| SNS delivery failure | SNS retry policy (3 attempts + DLQ) | Check SNS console delivery status |

---

## 10. Extension Points

| Hook | How to Use |
|---|---|
| **AI Enrichment** | Set `AI_PROVIDER=bedrock` or `gemini`; implement `ai_hook()` in `fingerprinter.py` |
| **Slack/PagerDuty alerts** | Add SNS subscription to `RegressionAlertTopic` with HTTPS endpoint |
| **Additional log groups** | Create another `AWS::Logs::SubscriptionFilter` pointing at same Ingestor |
| **New sanitization rule** | Add to `RULES` list in `sanitizer.py`; regenerate fixture; tests enforce stability |
| **Fingerprint expiry** | Enable `TTL` attribute on DynamoDB table; set `TTL` in `PutItem` |
| **Grafana dashboard** | CloudWatch metrics namespace `AWS/Lambda` + `AWS/DynamoDB` — all metrics available |
