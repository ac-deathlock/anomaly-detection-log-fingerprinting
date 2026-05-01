# Log Fingerprinting Pipeline — Deployment Strategy

## Pre-requisites

| Tool | Version | Install |
|---|---|---|
| AWS CLI | ≥ 2.x | https://aws.amazon.com/cli/ |
| AWS SAM CLI | ≥ 1.110 | https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html |
| Python | 3.12.x | https://www.python.org/downloads/ |
| Git | any | https://git-scm.com |
| PowerShell | 7.x (Windows) | https://github.com/PowerShell/PowerShell |

**AWS Permissions required for the deploying identity:**
- `cloudformation:*`
- `s3:{CreateBucket,PutObject,GetObject,PutBucketVersioning,PutBucketEncryption,PutPublicAccessBlock}`
- `lambda:{CreateFunction,UpdateFunctionCode,UpdateAlias,CreateAlias,GetFunction,AddPermission}`
- `iam:{CreateRole,AttachRolePolicy,PassRole}`
- `dynamodb:{CreateTable,DescribeTable}`
- `sns:{CreateTopic,Subscribe,SetTopicAttributes}`
- `sqs:{CreateQueue,GetQueueAttributes}`
- `kms:{CreateKey,CreateAlias,EnableKeyRotation}`
- `ssm:{PutParameter,GetParameter}`

---

## Environments

| Environment | Stack Name | CodeDeploy Strategy | Approval Gate |
|---|---|---|---|
| `dev` | `log-fingerprinting-dev` | `LambdaAllAtOnce` | ❌ None |
| `staging` | `log-fingerprinting-staging` | `LambdaAllAtOnce` | ❌ None |
| `prod` | `log-fingerprinting-prod` | `LambdaCanary10Percent5Minutes` | ✅ Manual |

---

## Quick-Start: First-Time Bootstrap (dev)

```powershell
# 1. Clone the repo
git clone https://github.com/YOUR_ORG/log-fingerprinting.git
cd log-fingerprinting

# 2. Install Python dev dependencies
pip install -r requirements-dev.txt

# 3. Confirm all tests pass locally
pytest tests/ -v

# 4. Set your AWS profile (optional if using default)
$env:AWS_PROFILE = "your-profile"
$env:AWS_DEFAULT_REGION = "us-east-1"

# 5. Deploy to dev
.\scripts\deploy.ps1 `
    -Environment dev `
    -ArtifactBucket "my-org-log-fp-artifacts" `
    -SourceLogGroup "/aws/lambda/my-application" `
    -AlertEmail "you@company.com"
```

The script will:
1. Run the full pytest suite
2. Validate both CloudFormation templates
3. Create the S3 artifact bucket (if it doesn't exist) with versioning + encryption
4. Zip and upload Lambda packages tagged with the git SHA
5. Create (or update) the `log-fingerprinting-dev` CloudFormation stack
6. Run a smoke test invoking the Fingerprinter Lambda directly

---

## Day-to-Day Release Workflow

### Option A — Manual deploy (dev/staging)

```powershell
# After code changes
git add .
git commit -m "feat: add AADSTS rule for new Azure error codes"
git push origin main

# Deploy to staging
.\scripts\deploy.ps1 -Environment staging -ArtifactBucket "my-org-log-fp-artifacts" `
    -SourceLogGroup "/aws/lambda/my-application" -AlertEmail "ops@company.com"
```

### Option B — Automated CI/CD pipeline (recommended for prod)

Once the pipeline stack is deployed, every `git push origin main` triggers:

```
GitHub Push
    → CodePipeline Source stage (CodeStar Connection)
    → CodeBuild: Test   → pytest tests/ (143 tests)
    → CodeBuild: Package → zip + upload to S3/releases/{sha}/
    → CloudFormation:   Deploy to log-fingerprinting-dev (LambdaAllAtOnce)
    → Manual Approval   (e-mail to approver)
    → CloudFormation:   Deploy to log-fingerprinting-prod (Canary 10%)
```

**To deploy the pipeline itself (one-time):**

```powershell
# First, create a CodeStar Connection to GitHub in the AWS Console
# (Settings → Connections → Create connection → GitHub)
# Copy the Connection ARN

.\scripts\deploy.ps1 `
    -Environment prod `
    -ArtifactBucket "my-org-log-fp-artifacts" `
    -SourceLogGroup "/aws/lambda/my-application" `
    -AlertEmail "ops@company.com" `
    -DeployPipeline `
    -GitHubOwner "your-github-org" `
    -GitHubRepo "log-fingerprinting" `
    -GitHubConnectionArn "arn:aws:codestar-connections:us-east-1:123456789012:connection/abc123" `
    -ApprovalEmail "release-approver@company.com"
```

---

## ReleaseID Update Procedure

The `ReleaseID` is how regression detection knows to alert on patterns that have
never appeared before. **Update it with every production release.**

### Automatic (via git tags — recommended)

```bash
# Tag a new release
git tag v2.1.0
git push origin v2.1.0
```

The CodeBuild package stage reads `git describe --tags` and passes it as
`ReleaseID` to CloudFormation automatically.

### Manual

```powershell
# Update via SSM directly (Lambda picks it up on next cold start)
aws ssm put-parameter `
    --name "/log-fingerprinting/prod/release-id" `
    --value "v2.1.0" `
    --overwrite
```

**What happens after a ReleaseID update:**
1. The Lambda environment variable `RELEASE_ID` is refreshed on next deploy/cold-start
2. All new log events after the update use the new ReleaseID
3. If a log event's fingerprint has never been seen before, DynamoDB `PutItem` fires
   and an SNS alert is published with subject: `[v2.1.0] New Error Pattern Detected`
4. Existing fingerprints from previous releases are **not** re-alerted

---

## ExcludePatterns Update Procedure

To add or remove CloudWatch filter exclusions **without touching code**:

### Via CloudFormation re-deploy

```powershell
# Edit template.yaml  Default value, or pass at deploy time:
.\scripts\deploy.ps1 -Environment prod -ExcludePatterns "Unable to upload to API,friendly_reason:,health check"
```

### Via SSM (takes effect on next Lambda invocation)

```powershell
aws ssm put-parameter `
    --name "/log-fingerprinting/prod/exclude-patterns" `
    --value "Unable to upload to API,friendly_reason:,health check" `
    --overwrite
```

The Ingestor Lambda reads `EXCLUDE_PATTERNS` from its environment on cold start.
To force an immediate refresh, perform a zero-downtime redeploy:

```powershell
aws lambda update-function-configuration `
    --function-name log-fp-ingestor-prod `
    --environment "Variables={RELEASE_ID=v2.1.0,EXCLUDE_PATTERNS=Unable to upload to API\,friendly_reason:}"
```

---

## Blue/Green Lambda Canary Explained (Production)

```
                   ┌──────────┐
         10%       │  v2      │  ← new version (just deployed)
    ──────────────►│ (canary) │
                   └──────────┘
   ALL TRAFFIC
   via :LIVE alias
                   ┌──────────┐
         90%       │  v1      │  ← stable previous version
    ──────────────►│(baseline)│
                   └──────────┘

  After 5 minutes with 0 alarms → 100% shifted to v2
  If FingerprinterErrorAlarm fires → automatic rollback to v1
```

**Monitored alarms (any one triggers auto-rollback):**
- `FingerprinterErrorAlarm` — error rate > 5% for 5 minutes
- `FingerprinterDurationAlarm` — p99 > 10,000ms for 5 minutes

**Manual rollback (emergency):**

```powershell
# Find the previous Lambda version
aws lambda list-aliases --function-name log-fp-fingerprinter-prod

# Point LIVE alias back to v1
aws lambda update-alias `
    --function-name log-fp-fingerprinter-prod `
    --name LIVE `
    --function-version 1 `
    --routing-config AdditionalVersionWeights={}
```

---

## Rollback Runbook

### Scenario 1: Bad regex rule causes fingerprint explosion

**Symptoms:** `analyze_compression.py` reports ratio drops below 1.5x; DynamoDB write
throttling alarm fires; regression SNS floods inbox.

```powershell
# 1. Immediately roll back Lambda alias manually (see above)

# 2. Revert the sanitizer change
git revert HEAD --no-edit
git push origin main   # triggers pipeline re-deploy

# 3. Regenerate regression fixtures if intentional rule change
python scripts/generate_regression_samples.py
pytest tests/test_regression.py -v   # verify
git add tests/fixtures/regression_samples.json
git commit -m "fix: regenerate regression fixtures for rule change"
```

### Scenario 2: CodeDeploy canary auto-rollback fired

```powershell
# Check CodeDeploy deployment status
aws deploy list-deployments --deployment-group-name log-fingerprinting-prod --region us-east-1

# Get failure details
aws deploy get-deployment --deployment-id d-XXXXXXXXX

# Check Lambda error logs
aws logs filter-log-events `
    --log-group-name "/aws/lambda/log-fp-fingerprinter-prod" `
    --filter-pattern "ERROR" `
    --start-time (([DateTimeOffset]::UtcNow.AddMinutes(-30)).ToUnixTimeMilliseconds())
```

### Scenario 3: DLQ accumulating (messages stuck)

```powershell
# Get DLQ URL
$dlqUrl = aws sqs get-queue-url `
    --queue-name "log-fingerprinter-dlq-prod" `
    --query QueueUrl --output text

# Inspect a sample message
aws sqs receive-message --queue-url $dlqUrl --max-number-of-messages 1

# Replay: re-invoke Fingerprinter Lambda with DLQ messages
# (manual step — no automated replay configured by default)
```

---

## Updating Sanitizer Rules

1. Edit `src/analyzer/sanitizer.py` — add/modify in `RULES` list
2. Run compression analysis to see the impact:
   ```powershell
   python scripts/analyze_compression.py --top 10
   ```
3. If adding a genuinely new rule (intentional break of old fingerprints):
   ```powershell
   python scripts/generate_regression_samples.py   # regenerate golden file
   ```
4. Run full test suite:
   ```powershell
   pytest tests/ -v
   ```
5. Commit and push — pipeline handles the rest

---

## Secrets Management

| Secret | Storage | How it's used |
|---|---|---|
| AWS credentials | `~/.aws/credentials` or IAM role | Never in code |
| ReleaseID | SSM Parameter Store | Lambda env var + CloudFormation param |
| ExcludePatterns | SSM Parameter Store | Lambda env var |
| Alert email | CloudFormation parameter | SSM + SNS subscription |
| AI API keys (Gemini) | SSM SecureString / Secrets Manager | Fetched in `ai_hook()` at runtime |

**Never put credentials or API keys in:**
- `template.yaml` default values
- Python source files
- Git commits

---

## Local Testing Without AWS

```powershell
# Run all unit tests (no AWS needed)
pytest tests/ -v --cov=src --cov-report=term-missing

# Analyze compression on logs.json (no AWS needed)
python scripts/analyze_compression.py --top 10

# Test the sanitizer interactively (Python REPL)
python -c "
from src.analyzer.sanitizer import sanitize, fingerprint
msg = '2026-04-18 10:00:00 ERROR Cannot connect to 10.0.1.5:5432 (uuid=82430625-7058-49E5-AE37-B3803D9BFBFA)'
result = sanitize(msg)
print('Sanitized:', result.sanitized)
print('Fingerprint:', result.fingerprint[:16], '...')
"
```

---

## Environment Promotion Matrix

```
dev  ──(auto)──►  staging  ──(manual approval)──►  prod
 │                   │                               │
 │  LambdaAllAtOnce  │  LambdaAllAtOnce              │  LambdaCanary10Percent5Minutes
 │  No approval      │  No approval                  │  Manual approval required
 │  Alert: dev team  │  Alert: dev+qa team            │  Alert: ops + pagerduty
 │                   │                               │
 └─ Auto-rollback:   └─ Auto-rollback:               └─ Auto-rollback:
    on error alarm      on error alarm                  on error alarm (canary)
```

---

## Operational Runbook: Day-to-Day

| Task | Command |
|---|---|
| Check fingerprint count for today | `aws dynamodb scan --table-name log-fingerprints-prod --select COUNT` |
| Find most common new patterns | Query DDB for `FirstSeen >= today` |
| Silence a known error pattern | Add to ExcludePatterns via SSM |
| Check Lambda error rate | CloudWatch → `log-fp-fingerprinter-prod` → Monitoring tab |
| View recent regression alerts | SNS console → `log-fingerprint-regressions-prod` → Subscriptions |
| Manually invoke a smoke test | `aws lambda invoke --function-name log-fp-fingerprinter-prod:LIVE --payload …` |
| DLQ message count | `aws sqs get-queue-attributes --attribute-names ApproximateNumberOfMessages` |
