# Copilot Instructions — Log Fingerprinting Pipeline

## Tech Stack
- **Runtime:** Python 3.12, AWS SAM (Serverless Application Model)
- **Infrastructure:** Lambda (arm64), DynamoDB (PAY_PER_REQUEST), SNS, CloudWatch Logs, Step Functions, EventBridge Scheduler
- **Testing:** `pytest` + `moto` for AWS mocking; `numpy`/`scikit-learn` for clustering tests
- **Code style:** PEP8, type hints required on all functions

---

## Commands

```powershell
# Run full test suite
pytest tests/ -v

# Run a single test class or test
pytest tests/test_sanitizer.py::TestVpcFlowRawmsg -v
pytest tests/test_clustering.py::TestClusterVectors::test_two_clusters_detected -v

# Run with coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Analyze sanitizer compression on logs.json (no AWS needed)
python scripts/analyze_compression.py --top 10

# Regenerate regression golden file after intentional rule changes
python scripts/generate_regression_samples.py

# Deploy to dev
.\scripts\deploy.ps1 -Environment dev -ArtifactBucket "<bucket>" -SourceLogGroup "<log-group>"
```

---

## Architecture

**Event flow (hot path — per log event):**

```
CloudWatch Log Group
  → Subscription Filter (ERROR-level, first-pass exclusions)
  → Ingestor Lambda      (decodes base64+gzip, applies runtime ExcludePatterns, async-invokes Fingerprinter)
  → Fingerprinter Lambda (sanitize_for_stream → SHA-256 → conditional DynamoDB write → SNS alert if new
                          → store raw message in UnknownPatterns table if new fingerprint)
```

**Daily enhancement pipeline (cold path — AI agent):**

```
EventBridge Scheduler (02:00 UTC)
  → Step Functions EnhancementPipeline
      ListStreams action     → finds distinct StreamIds with UNPROCESSED records
      Map (per stream, MaxConcurrency=5):
        EmbedBatch action        → calls Bedrock Titan, sets Status=EMBEDDED
        ClusterAndGenerate action → NumPy DBSCAN clustering → Claude rule generation
                                    → stores rules in StreamProfilesTable (optimistic concurrency)
                                    → marks records PROCESSED
```

**Source layout:**
- `src/handlers/ingestor.py` — CW Logs decoder + exclusion filter + async dispatcher
- `src/handlers/fingerprinter.py` — stream-aware sanitize → conditional DDB write → SNS alert → unknown capture
- `src/handlers/enhancement_agent.py` — action-dispatch handler for Step Functions (list_streams | embed_batch | cluster_and_generate)
- `src/analyzer/sanitizer.py` — 23 ordered base rules; `apply_rules(msg, rules)` is the core engine; `sanitize(msg)` uses base rules
- `src/analyzer/stream_profile.py` — per-stream rule adapter with 5-min in-memory TTL cache
- `src/vector_store/` — `base.py` (ABC), `factory.py` (env-driven), `dynamo_store.py`, `opensearch_store.py`
- `src/ai/embedder.py` — Bedrock Titan Embeddings wrapper
- `src/ai/rule_generator.py` — Bedrock Claude rule generation with regex validation
- `src/clustering/numpy_cluster.py` — DBSCAN on cosine distance with NumPy + scikit-learn
- `layer/requirements.txt` — deps for `AgentDepsLayer` (numpy, scikit-learn, opensearch-py)

**DynamoDB tables:**
| Table | Key | Purpose |
|---|---|---|
| `log-fingerprints-{env}` | PK=ErrorSignature | SHA-256 fingerprint state |
| `log-stream-profiles-{env}` | PK=StreamId | Per-stream custom rule sets |
| `log-unknown-patterns-{env}` | PK=StreamId, SK=PatternId | New patterns pending AI enhancement |

**UnknownPatterns Status lifecycle:** `UNPROCESSED` → `EMBEDDED` → `PROCESSED`

---

## Key Conventions

### Sanitizer rule ordering is critical
`RULES` in `sanitizer.py` is an ordered list. `apply_rules(msg, rules)` is the shared engine — both `sanitize()` and `sanitize_for_stream()` call it. Stream-specific rules are prepended (run before base rules). **Never reorder base RULES without reviewing interactions.**

### Changing sanitizer rules requires fixture regeneration
`test_regression.py` compares against a golden file (`tests/fixtures/regression_samples.json`). Any intentional rule change requires:
```powershell
python scripts/generate_regression_samples.py
pytest tests/test_regression.py -v
git add tests/fixtures/regression_samples.json
```

### Vector backend is configurable — `VECTOR_BACKEND=dynamodb|opensearch`
- `dynamodb`: stores embeddings as little-endian float32 bytes (Binary), clusters in-process with NumPy. Capped at 500 vectors/stream/run (`CLUSTER_BATCH_CAP`).
- `opensearch`: uses k-NN HNSW index with `cosinesimil` space. Requires `OPENSEARCH_ENDPOINT`.
- Dimension is model-driven: Titan V2 = 1024, Titan V1 = 1536. The OpenSearch index is created at Lambda init if absent.

### Fingerprint upsert uses conditional write (race-safe)
`put_item` with `ConditionExpression="attribute_not_exists(ErrorSignature)"`. On `ConditionalCheckFailedException` → `update_item` to increment counter. No separate `get_item` round-trip.

### StreamProfile cache invalidation
`invalidate_cache(source_id)` is called by the enhancement agent after storing new rules. The Fingerprinter picks them up on the next cold start or after the 5-min TTL. Cache is module-level `dict` — isolated per Lambda instance.

### Rule storage uses optimistic concurrency on `RuleVersion`
`_store_rules()` in `enhancement_agent.py` reads current version, writes with `ConditionExpression="RuleVersion = :cur_ver"`, retries up to 3 times on conflict. Duplicate rule names (same `rule_name`) are silently skipped.

### Step Functions passes only metadata — no large payloads
Embedding arrays and cluster results are stored in DynamoDB directly by the Lambda; Step Functions state only carries `stream_id`, counts, and action names to stay well under the 256 KB state limit.

### ExcludePatterns live in the template, not in code
The `ExcludePatterns` SAM parameter (comma-delimited) is injected as `EXCLUDE_PATTERNS` env var. Update `template.yaml` or SSM; do not hard-code exclusion strings in Lambda source.

### AI hook is a stub — do not treat it as implemented
`ai_hook()` in `fingerprinter.py` returns `{}` when `AI_PROVIDER=none` (default). The enhancement agent's Bedrock calls (`embedder.py`, `rule_generator.py`) are the active AI path.

### Test imports use explicit `sys.path` injection
All test files insert both the repo root and `src/` into `sys.path`. Do not remove these lines.

### Lambda functions target arm64
All functions use `Architectures: [arm64]`. The `AgentDepsLayer` must be built for arm64 (`sam build` handles this via `BuildMethod: python3.12`).


## Tech Stack
- **Runtime:** Python 3.12, AWS SAM (Serverless Application Model)
- **Infrastructure:** Lambda (arm64), DynamoDB (PAY_PER_REQUEST), SNS, CloudWatch Logs
- **Testing:** `pytest` + `moto` for AWS mocking
- **Code style:** PEP8, type hints required on all functions

---

## Commands

```powershell
# Run full test suite
pytest tests/ -v

# Run a single test class or test
pytest tests/test_sanitizer.py::TestVpcFlowRawmsg -v
pytest tests/test_regression.py::TestUnauthorizedDeduplication -v

# Run with coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Analyze sanitizer compression on logs.json (no AWS needed)
python scripts/analyze_compression.py --top 10

# Regenerate regression golden file after intentional rule changes
python scripts/generate_regression_samples.py

# Deploy to dev
.\scripts\deploy.ps1 -Environment dev -ArtifactBucket "<bucket>" -SourceLogGroup "<log-group>"
```

---

## Architecture

**Event flow:**

```
CloudWatch Log Group
  → Subscription Filter (ERROR-level, first-pass exclusions)
  → Ingestor Lambda      (decodes base64+gzip payload, applies runtime ExcludePatterns, async-invokes Fingerprinter per event)
  → Fingerprinter Lambda (sanitizes message → SHA-256 fingerprint → DynamoDB upsert → SNS alert if new)
```

**Source layout:**
- `src/handlers/ingestor.py` — CW Logs decoder + exclusion filter + async dispatcher
- `src/handlers/fingerprinter.py` — sanitize → DynamoDB upsert → SNS regression alert → optional AI hook
- `src/analyzer/sanitizer.py` — 23 ordered regex rules; deployed as a shared Lambda Layer (`SanitizerLayer`)
- `tests/test_sanitizer.py` — per-rule unit tests (23 rule classes)
- `tests/test_regression.py` — golden-file regression suite (50 samples in `tests/fixtures/regression_samples.json`)
- `template.yaml` — single SAM template defining all resources; `cloudformation/` holds supplementary stacks

**DynamoDB schema** (`log-fingerprints-{env}`, PK = `ErrorSignature`):
- `ErrorSignature` (PK) — SHA-256 hex of the sanitized message
- `FirstSeen`, `LastSeen` — ISO8601 timestamps
- `OccurrenceCount` — running counter (UpdateItem increment)
- `SampleMessage`, `SanitizedMessage` — truncated to 1024 chars on write
- `ReleaseID` — set once at `FirstSeen`; never overwritten

**Regression detection:** A fingerprint is "new" if `GetItem` returns nothing. On new → `PutItem` + `SNS.Publish`. On existing → `UpdateItem` (LastSeen + count), no alert.

---

## Key Conventions

### Sanitizer rule ordering is critical
`RULES` in `sanitizer.py` is an ordered list. More-specific patterns (e.g., `VPC_FLOW_RAWMSG`, `ISO8601_TIMESTAMP`, `UUID`, `IPv4`) must precede general number-catching rules (`LARGE_NUMBER`, `JSON_QUOTED_NUMBER`, `JSON_UNQUOTED_NUMBER`). **Never reorder without reviewing interactions.**

### Changing sanitizer rules requires fixture regeneration
`test_regression.py` compares against a golden file. Any intentional rule change that alters fingerprints requires:
```powershell
python scripts/generate_regression_samples.py
pytest tests/test_regression.py -v  # verify, then commit the updated fixture
```
A failing regression test in CI is the gate against accidental fingerprint drift.

### ExcludePatterns live in the template, not in code
The `ExcludePatterns` SAM parameter (comma-delimited list) is injected as the `EXCLUDE_PATTERNS` env var. The Ingestor reads it at cold-start. To add an exclusion pattern, update `template.yaml` (or SSM); do not hard-code strings in Lambda source.

### Config via environment variables only
All runtime configuration (`TABLE_NAME`, `SNS_TOPIC_ARN`, `RELEASE_ID`, `AI_PROVIDER`, `FINGERPRINTER_FUNCTION_NAME`) comes from env vars set in `template.yaml` Globals or per-function `Environment` blocks.

### AI hook is a stub — do not treat it as implemented
`ai_hook()` in `fingerprinter.py` returns `{}` when `AI_PROVIDER=none` (default). Bedrock/Gemini examples are in docstring comments. Set `AI_PROVIDER` to `bedrock` or `gemini` and implement the function body to enable enrichment.

### Test imports use explicit `sys.path` injection
Both test files insert the repo root into `sys.path` before importing `src.*`. This allows running tests without `pip install -e .`. Do not remove these lines.

### SampleMessage / SanitizedMessage are truncated to 1024 chars on `PutItem`
This is a DynamoDB item size guard. If you add new string attributes to the `PutItem` call, apply the same guard.

### Lambda functions target arm64
All functions use `Architectures: [arm64]` (set in SAM Globals). Layer builds and any native dependencies must also target arm64.
