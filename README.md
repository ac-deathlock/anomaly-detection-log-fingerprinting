# Log Fingerprinting Pipeline

Serverless pipeline for detecting new error patterns in CloudWatch Logs.

The system sanitizes noisy log messages into stable fingerprints, stores them in DynamoDB, alerts when a release introduces a previously unseen pattern, and runs a daily enhancement pipeline to generate stream-specific sanitization rules for unknown patterns.

## What It Does

- Ingests CloudWatch Logs through a subscription filter.
- Applies deterministic sanitization rules to remove environment-specific values.
- Hashes the sanitized message with SHA-256 to create a stable fingerprint.
- Stores fingerprint state in DynamoDB using a race-safe conditional write.
- Publishes an SNS alert when a fingerprint is seen for the first time.
- Captures unknown patterns for a daily AI-assisted clustering and rule-generation pipeline.

## Architecture

### Hot Path

1. CloudWatch Logs sends matching events to the Ingestor Lambda.
2. The Ingestor decodes the payload, applies `EXCLUDE_PATTERNS`, and asynchronously invokes the Fingerprinter.
3. The Fingerprinter applies stream-specific rules first, then base sanitizer rules.
4. The sanitized message is hashed and upserted into the fingerprint table.
5. New fingerprints trigger an SNS alert and are stored in the unknown-patterns table.

### Daily Enhancement Path

1. EventBridge Scheduler starts the Step Functions enhancement workflow.
2. The workflow finds streams with `UNPROCESSED` unknown patterns.
3. The enhancement agent embeds, clusters, and generates candidate rules per stream.
4. New rules are stored in the stream profiles table with optimistic concurrency.

For deeper architecture detail, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Repository Layout

```text
src/
  analyzer/              Core sanitization and stream profile logic
  handlers/              Lambda handlers for ingest, fingerprint, and enhancement
  ai/                    Bedrock embedding and rule-generation clients
  clustering/            NumPy/scikit-learn clustering logic
  vector_store/          DynamoDB and OpenSearch vector backends
tests/                   Pytest suite with regression and integration-style tests
scripts/                 Deployment and fixture-generation utilities
docs/                    Architecture and deployment documentation
template.yaml            Main AWS SAM stack
```

## Requirements

- Python 3.12
- AWS CLI v2
- AWS SAM CLI
- PowerShell 7 on Windows for the provided deployment script

Install dependencies:

```powershell
pip install -r requirements-dev.txt
```

## Local Development

Run the full test suite:

```powershell
pytest tests/ -v
```

Run a targeted test:

```powershell
pytest tests/test_sanitizer.py::TestVpcFlowRawmsg -v
pytest tests/test_clustering.py::TestClusterVectors::test_two_clusters_detected -v
```

Run with coverage:

```powershell
pytest tests/ -v --cov=src --cov-report=term-missing
```

Analyze sanitizer compression against sample logs:

```powershell
python scripts/analyze_compression.py --top 10
```

If sanitizer rule changes are intentional, regenerate the golden regression fixture:

```powershell
python scripts/generate_regression_samples.py
pytest tests/test_regression.py -v
```

## Deployment

Deploy to `dev` with the provided script:

```powershell
.\scripts\deploy.ps1 -Environment dev -ArtifactBucket "<bucket>" -SourceLogGroup "<log-group>"
```

The SAM template provisions:

- `log-fingerprints-{env}` for fingerprint state
- `log-stream-profiles-{env}` for per-stream rules
- `log-unknown-patterns-{env}` for enhancement candidates
- Ingestor and Fingerprinter Lambdas
- SNS alerting resources
- Supporting workflow resources for the enhancement pipeline

Deployment details, rollout strategy, and rollback procedures are documented in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Configuration

Primary runtime configuration is passed through environment variables defined in [template.yaml](template.yaml), including:

- `RELEASE_ID`
- `EXCLUDE_PATTERNS`
- `AI_PROVIDER`
- `VECTOR_BACKEND`
- `BEDROCK_EMBEDDING_MODEL`
- `BEDROCK_LLM_MODEL`
- `CLUSTER_EPS`

## Key Conventions

- Sanitizer rule ordering is critical. Stream-specific rules run before base rules.
- Fingerprint writes use a conditional insert followed by update-on-conflict to avoid races.
- Unknown pattern lifecycle is `UNPROCESSED -> EMBEDDED -> PROCESSED`.
- Changing sanitizer behavior may require updating `tests/fixtures/regression_samples.json`.
- The vector backend is selectable with `VECTOR_BACKEND=dynamodb|opensearch`.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
