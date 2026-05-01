#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Deploy the Log Fingerprinting Pipeline to AWS.

.DESCRIPTION
    Full deployment script:
      1. Validates CloudFormation templates
      2. Packages and uploads Lambda ZIPs to S3
      3. Deploys the infrastructure stack (infra.yaml)
      4. Optionally deploys the CI/CD pipeline stack (pipeline.yaml)
      5. Runs a post-deploy smoke test

.PARAMETER Environment
    Target environment: dev | staging | prod (default: dev)

.PARAMETER ReleaseID
    Semantic version for this release (default: git short SHA)

.PARAMETER Region
    AWS region (default: us-east-1)

.PARAMETER ArtifactBucket
    S3 bucket for Lambda ZIP packages (created if it doesn't exist)

.PARAMETER SourceLogGroup
    CloudWatch Log Group to subscribe to

.PARAMETER AlertEmail
    E-mail for regression SNS alerts

.PARAMETER DeployPipeline
    Also deploy the CI/CD pipeline stack

.EXAMPLE
    # First-time dev deployment
    .\scripts\deploy.ps1 -Environment dev -SourceLogGroup "/aws/lambda/my-app" -AlertEmail "ops@co.com" -ArtifactBucket "my-org-log-fp-artifacts"

.EXAMPLE
    # Production deployment with pipeline
    .\scripts\deploy.ps1 -Environment prod -ReleaseID "2.1.0" -DeployPipeline -AlertEmail "ops@co.com" -ArtifactBucket "my-org-log-fp-artifacts"
#>

[CmdletBinding()]
param(
    [ValidateSet("dev","staging","prod")]
    [string]$Environment = "dev",

    [string]$ReleaseID = "",

    [string]$Region = "us-east-1",

    [Parameter(Mandatory)]
    [string]$ArtifactBucket,

    [Parameter(Mandatory)]
    [string]$SourceLogGroup,

    [string]$AlertEmail = "",

    [string]$AlarmEmail = "",

    [switch]$DeployPipeline,

    [string]$GitHubOwner = "",
    [string]$GitHubRepo = "log-fingerprinting",
    [string]$GitHubConnectionArn = "",
    [string]$ApprovalEmail = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
$SCRIPT_DIR   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ROOT         = Split-Path -Parent $SCRIPT_DIR
$CFN_DIR      = Join-Path $ROOT "cloudformation"
$INFRA_TMPL   = Join-Path $CFN_DIR "infra.yaml"
$PIPELINE_TMPL= Join-Path $CFN_DIR "pipeline.yaml"
$STACK_NAME   = "log-fingerprinting-$Environment"
$PIPELINE_STACK = "log-fingerprinting-pipeline"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
function Write-Step([string]$msg) {
    Write-Host "`n$(('─' * 60))" -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host "$(('─' * 60))" -ForegroundColor Cyan
}

function Write-Success([string]$msg) { Write-Host "  ✅  $msg" -ForegroundColor Green }
function Write-Warn([string]$msg)    { Write-Host "  ⚠️   $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg)    { Write-Host "  ❌  $msg" -ForegroundColor Red }

function Assert-Aws {
    if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
        Write-Fail "AWS CLI not found. Install: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html"
        exit 1
    }
    $identity = aws sts get-caller-identity --output json | ConvertFrom-Json
    Write-Success "AWS identity: $($identity.Arn)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 0: Pre-flight
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Pre-flight checks"
Assert-Aws

if ($ReleaseID -eq "") {
    try {
        $ReleaseID = git -C $ROOT rev-parse --short HEAD 2>$null
        if (-not $ReleaseID) { $ReleaseID = "local-$(Get-Date -Format 'yyyyMMddHHmm')" }
    } catch {
        $ReleaseID = "local-$(Get-Date -Format 'yyyyMMddHHmm')"
    }
}
Write-Success "Environment : $Environment"
Write-Success "ReleaseID   : $ReleaseID"
Write-Success "Region      : $Region"
Write-Success "Stack       : $STACK_NAME"

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Run tests (skip with -SkipTests if desired)
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Running test suite"
Push-Location $ROOT
try {
    python -m pytest tests/ -q --tb=short
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Tests failed — aborting deployment."
        exit 1
    }
    Write-Success "All tests passed."
} finally {
    Pop-Location
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Validate CFN templates
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Validating CloudFormation templates"
aws cloudformation validate-template `
    --template-body file://$INFRA_TMPL `
    --region $Region | Out-Null
Write-Success "infra.yaml is valid."

if ($DeployPipeline) {
    aws cloudformation validate-template `
        --template-body file://$PIPELINE_TMPL `
        --region $Region | Out-Null
    Write-Success "pipeline.yaml is valid."
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Ensure S3 artifact bucket exists
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Ensuring S3 artifact bucket: $ArtifactBucket"
$bucketExists = aws s3api head-bucket --bucket $ArtifactBucket 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warn "Bucket not found — creating..."
    if ($Region -eq "us-east-1") {
        aws s3api create-bucket --bucket $ArtifactBucket --region $Region | Out-Null
    } else {
        aws s3api create-bucket --bucket $ArtifactBucket --region $Region `
            --create-bucket-configuration LocationConstraint=$Region | Out-Null
    }
    aws s3api put-bucket-versioning --bucket $ArtifactBucket `
        --versioning-configuration Status=Enabled | Out-Null
    aws s3api put-bucket-encryption --bucket $ArtifactBucket `
        --server-side-encryption-configuration '{
            "Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]
        }' | Out-Null
    aws s3api put-public-access-block --bucket $ArtifactBucket `
        --public-access-block-configuration `
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" | Out-Null
    Write-Success "Bucket created and hardened."
} else {
    Write-Success "Bucket already exists."
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Package Lambda functions
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Packaging Lambda functions"
$distDir = Join-Path $ROOT "dist"
if (Test-Path $distDir) { Remove-Item $distDir -Recurse -Force }
New-Item -ItemType Directory $distDir | Out-Null

# Ingestor package
$ingestorDir = Join-Path $distDir "ingestor"
New-Item -ItemType Directory $ingestorDir | Out-Null
Copy-Item (Join-Path $ROOT "src\handlers\ingestor.py") $ingestorDir
Copy-Item (Join-Path $ROOT "src\analyzer") $ingestorDir -Recurse
$ingestorZip = Join-Path $distDir "ingestor.zip"
Compress-Archive -Path "$ingestorDir\*" -DestinationPath $ingestorZip -Force
Write-Success "Ingestor ZIP: $(((Get-Item $ingestorZip).Length / 1KB).ToString('F1')) KB"

# Fingerprinter package
$fpDir = Join-Path $distDir "fingerprinter"
New-Item -ItemType Directory $fpDir | Out-Null
Copy-Item (Join-Path $ROOT "src\handlers\fingerprinter.py") $fpDir
Copy-Item (Join-Path $ROOT "src\analyzer") $fpDir -Recurse
$fpZip = Join-Path $distDir "fingerprinter.zip"
Compress-Archive -Path "$fpDir\*" -DestinationPath $fpZip -Force
Write-Success "Fingerprinter ZIP: $(((Get-Item $fpZip).Length / 1KB).ToString('F1')) KB"

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Upload to S3
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Uploading packages to S3 (releases/$ReleaseID/)"
$ingestorKey    = "releases/$ReleaseID/ingestor.zip"
$fpKey          = "releases/$ReleaseID/fingerprinter.zip"

aws s3 cp $ingestorZip "s3://$ArtifactBucket/$ingestorKey" --region $Region | Out-Null
Write-Success "Uploaded: s3://$ArtifactBucket/$ingestorKey"

aws s3 cp $fpZip "s3://$ArtifactBucket/$fpKey" --region $Region | Out-Null
Write-Success "Uploaded: s3://$ArtifactBucket/$fpKey"

# ─────────────────────────────────────────────────────────────────────────────
# Step 6: Deploy infrastructure stack
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Deploying infrastructure stack: $STACK_NAME"

$cfnParams = @(
    "ParameterKey=Environment,ParameterValue=$Environment",
    "ParameterKey=ReleaseID,ParameterValue=$ReleaseID",
    "ParameterKey=SourceLogGroupName,ParameterValue=$SourceLogGroup",
    "ParameterKey=CodeBucketName,ParameterValue=$ArtifactBucket",
    "ParameterKey=IngestorS3Key,ParameterValue=$ingestorKey",
    "ParameterKey=FingerprinterS3Key,ParameterValue=$fpKey"
)
if ($AlertEmail) { $cfnParams += "ParameterKey=AlertEmail,ParameterValue=$AlertEmail" }
if ($AlarmEmail) { $cfnParams += "ParameterKey=AlarmEmail,ParameterValue=$AlarmEmail" }

$stackStatus = aws cloudformation describe-stacks --stack-name $STACK_NAME `
    --region $Region --query "Stacks[0].StackStatus" --output text 2>$null

if ($stackStatus -match "COMPLETE" -or $stackStatus -match "ROLLBACK") {
    Write-Warn "Updating existing stack..."
    aws cloudformation update-stack `
        --stack-name $STACK_NAME `
        --template-body file://$INFRA_TMPL `
        --parameters $cfnParams `
        --capabilities CAPABILITY_NAMED_IAM `
        --region $Region | Out-Null
    Write-Warn "Waiting for update to complete (this may take 2-5 minutes)..."
    aws cloudformation wait stack-update-complete --stack-name $STACK_NAME --region $Region
} else {
    Write-Warn "Creating new stack..."
    aws cloudformation create-stack `
        --stack-name $STACK_NAME `
        --template-body file://$INFRA_TMPL `
        --parameters $cfnParams `
        --capabilities CAPABILITY_NAMED_IAM `
        --on-failure ROLLBACK `
        --region $Region | Out-Null
    Write-Warn "Waiting for creation to complete (this may take 3-7 minutes)..."
    aws cloudformation wait stack-create-complete --stack-name $STACK_NAME --region $Region
}

Write-Success "Stack deployed successfully."

# ─────────────────────────────────────────────────────────────────────────────
# Step 7: Smoke test — invoke fingerprinter directly
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Smoke test — invoking Fingerprinter Lambda"
$testPayload = '{"message":"2026-04-18 10:00:00,000 helix.api ERROR Generic error","logGroup":"/test","logStream":"test"}'
$testPayloadFile = Join-Path $distDir "smoke_test_payload.json"
$testPayload | Out-File -Encoding utf8 -FilePath $testPayloadFile
$responseFile = Join-Path $distDir "smoke_test_response.json"

aws lambda invoke `
    --function-name "log-fp-fingerprinter-$Environment`:LIVE" `
    --payload file://$testPayloadFile `
    --region $Region `
    $responseFile | Out-Null

$response = Get-Content $responseFile | ConvertFrom-Json
if ($response.status -eq "ok") {
    Write-Success "Smoke test PASSED — fingerprint: $($response.fingerprint.Substring(0,16))..."
    Write-Success "Is new fingerprint: $($response.is_new)"
} else {
    Write-Fail "Smoke test FAILED — response: $($response | ConvertTo-Json)"
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 8 (optional): Deploy CI/CD pipeline stack
# ─────────────────────────────────────────────────────────────────────────────
if ($DeployPipeline) {
    Write-Step "Deploying CI/CD pipeline stack: $PIPELINE_STACK"

    if (-not $GitHubOwner -or -not $GitHubConnectionArn -or -not $ApprovalEmail) {
        Write-Fail "To deploy the pipeline, provide: -GitHubOwner, -GitHubConnectionArn, -ApprovalEmail"
        exit 1
    }

    $pipelineParams = @(
        "ParameterKey=GitHubOwner,ParameterValue=$GitHubOwner",
        "ParameterKey=GitHubRepo,ParameterValue=$GitHubRepo",
        "ParameterKey=GitHubConnectionArn,ParameterValue=$GitHubConnectionArn",
        "ParameterKey=ArtifactBucketName,ParameterValue=$ArtifactBucket",
        "ParameterKey=ApprovalEmail,ParameterValue=$ApprovalEmail"
    )

    $pipelineStatus = aws cloudformation describe-stacks --stack-name $PIPELINE_STACK `
        --region $Region --query "Stacks[0].StackStatus" --output text 2>$null

    if ($pipelineStatus -match "COMPLETE") {
        aws cloudformation update-stack `
            --stack-name $PIPELINE_STACK `
            --template-body file://$PIPELINE_TMPL `
            --parameters $pipelineParams `
            --capabilities CAPABILITY_NAMED_IAM `
            --region $Region | Out-Null
        aws cloudformation wait stack-update-complete --stack-name $PIPELINE_STACK --region $Region
    } else {
        aws cloudformation create-stack `
            --stack-name $PIPELINE_STACK `
            --template-body file://$PIPELINE_TMPL `
            --parameters $pipelineParams `
            --capabilities CAPABILITY_NAMED_IAM `
            --region $Region | Out-Null
        aws cloudformation wait stack-create-complete --stack-name $PIPELINE_STACK --region $Region
    }
    Write-Success "CI/CD pipeline stack deployed."
}

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup & summary
# ─────────────────────────────────────────────────────────────────────────────
Remove-Item $distDir -Recurse -Force

Write-Host ""
Write-Host "$(('═' * 60))" -ForegroundColor Green
Write-Host "  DEPLOYMENT COMPLETE" -ForegroundColor Green
Write-Host "$(('═' * 60))" -ForegroundColor Green
Write-Host "  Environment : $Environment"
Write-Host "  ReleaseID   : $ReleaseID"
Write-Host "  Stack       : $STACK_NAME"
Write-Host "  Region      : $Region"
Write-Host ""
Write-Host "  Console links:"
Write-Host "  DynamoDB : https://$Region.console.aws.amazon.com/dynamodbv2/home?region=$Region#table?name=log-fingerprints-$Environment"
Write-Host "  Lambda   : https://$Region.console.aws.amazon.com/lambda/home?region=$Region#/functions/log-fp-fingerprinter-$Environment"
Write-Host "  Alarms   : https://$Region.console.aws.amazon.com/cloudwatch/home?region=$Region#alarmsV2:"
Write-Host ""
