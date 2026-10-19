<#
.SYNOPSIS
  Deploy the GuardianAI public relay (POST /api/v1/attest) to Google Cloud Run.

.DESCRIPTION
  First time:  .\deploy\relay\deploy.ps1 -Setup
               Enables the Cloud APIs, copies GUARDIAN_ATTESTATION_SIGNER_KEY from .env into Secret Manager
               (never printed), and lets Cloud Run read it.
  Every deploy: .\deploy\relay\deploy.ps1
               Builds a relay-only image with Cloud Build and deploys it with exactly one always-on instance.
  Then:        firebase deploy --only hosting
               (firebase.json forwards aiguardian.dev/api/** to this service.)

  Optional: -CorsOrigins "http://localhost:5173" lets a local explorer call the Cloud Run URL directly.
#>
param(
    [string]$Project = "kadan-kanakku",
    [string]$Region = "us-central1",
    [string]$Service = "guardian-relay",
    [string]$Secret = "guardian-attestation-signer",
    [string]$CorsOrigins = "",
    [switch]$Setup
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

function Invoke-GCloud {
    param([Parameter(Mandatory)][string[]]$GArgs)
    & gcloud @GArgs
    if ($LASTEXITCODE -ne 0) { throw "gcloud $($GArgs[0..1] -join ' ') failed (exit $LASTEXITCODE)" }
}

function Test-GCloud {
    param([Parameter(Mandatory)][string[]]$GArgs)
    # Windows PowerShell turns native stderr into terminating errors under "Stop"; probe with Continue.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & gcloud @GArgs 2>&1 | Out-Null; return ($LASTEXITCODE -eq 0) } finally { $ErrorActionPreference = $prev }
}

if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
    throw "gcloud is not installed. Install the Google Cloud CLI, run 'gcloud auth login', then retry."
}

# ---------------------------------------------------------------- one-time setup
if ($Setup) {
    Write-Host "Enabling Cloud Run, Cloud Build, Artifact Registry and Secret Manager on $Project..."
    Invoke-GCloud @("services", "enable", "run.googleapis.com", "cloudbuild.googleapis.com",
        "artifactregistry.googleapis.com", "secretmanager.googleapis.com", "--project", $Project)

    $envFile = Join-Path $Root ".env"
    if (-not (Test-Path $envFile)) { throw ".env not found at $envFile" }
    $line = Get-Content $envFile | Where-Object { $_ -match '^\s*GUARDIAN_ATTESTATION_SIGNER_KEY\s*=' } | Select-Object -First 1
    if (-not $line) { throw "GUARDIAN_ATTESTATION_SIGNER_KEY is not set in .env" }
    $key = ($line -split '=', 2)[1].Trim().Trim('"').Trim("'")
    if ($key -notmatch '^(0x)?[0-9a-fA-F]{64}$') { throw "GUARDIAN_ATTESTATION_SIGNER_KEY in .env is not a 32-byte hex key" }

    $tmp = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllText($tmp, $key)  # no trailing newline
        if (Test-GCloud @("secrets", "describe", $Secret, "--project", $Project)) {
            Write-Host "Adding a new version of secret $Secret..."
            Invoke-GCloud @("secrets", "versions", "add", $Secret, "--data-file", $tmp, "--project", $Project)
        } else {
            Write-Host "Creating secret $Secret..."
            Invoke-GCloud @("secrets", "create", $Secret, "--data-file", $tmp, "--replication-policy", "automatic", "--project", $Project)
        }
    } finally {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        $key = $null
    }

    $number = (& gcloud projects describe $Project --format "value(projectNumber)").Trim()
    if (-not $number) { throw "Could not read the project number for $Project" }
    Invoke-GCloud @("secrets", "add-iam-policy-binding", $Secret,
        "--member", "serviceAccount:$number-compute@developer.gserviceaccount.com",
        "--role", "roles/secretmanager.secretAccessor", "--project", $Project)

    Write-Host "`nSetup done. Next: .\deploy\relay\deploy.ps1"
    return
}

# ---------------------------------------------------------------- build context (relay only)
$ctx = Join-Path ([IO.Path]::GetTempPath()) "guardian-relay-src"
if (Test-Path $ctx) { Remove-Item $ctx -Recurse -Force }
New-Item -ItemType Directory -Path $ctx | Out-Null
New-Item -ItemType Directory -Path (Join-Path $ctx "config") | Out-Null
Copy-Item (Join-Path $PSScriptRoot "Dockerfile"), (Join-Path $PSScriptRoot "requirements.txt") $ctx

robocopy (Join-Path $Root "guardian") (Join-Path $ctx "guardian") /E /XD __pycache__ artifacts "study cases" /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "Copying guardian/ failed (robocopy exit $LASTEXITCODE)" }
$global:LASTEXITCODE = 0

foreach ($f in @("agent_passkey_identities.json", "threat_oracle_feed.json")) {
    $src = Join-Path $Root "config\$f"
    if (Test-Path $src) { Copy-Item $src (Join-Path $ctx "config") }
}

# ---------------------------------------------------------------- deploy
$envVars = @(
    "GUARDIAN_ENV=production",
    "MONAD_TESTNET_RPC=https://testnet-rpc.monad.xyz",
    "GUARDIAN_POLICY_GUARD_CONTRACT_MONAD=0xa0ae75AaaB1c05D49fd5D15a0a95e0171aEDbB7d"
)
if ($CorsOrigins) { $envVars += "GUARDIAN_CORS_ORIGINS=$CorsOrigins" }
# "^;^" switches gcloud's list separator to ';' so a comma-separated CORS list survives.
$envArg = "^;^" + ($envVars -join ";")

Write-Host "Building and deploying $Service to $Region (this takes a few minutes)..."
Invoke-GCloud @(
    "run", "deploy", $Service,
    "--source", $ctx,
    "--project", $Project,
    "--region", $Region,
    "--allow-unauthenticated",
    # One always-on instance: no cold starts for judges, and the relay's in-memory nonce,
    # daily-cap and rate-limit state stays consistent.
    "--min-instances", "1",
    "--max-instances", "1",
    "--concurrency", "16",
    "--cpu", "1",
    "--memory", "512Mi",
    "--timeout", "30",
    "--set-secrets", "GUARDIAN_ATTESTATION_SIGNER_KEY=${Secret}:latest",
    "--set-env-vars", $envArg
)

Remove-Item $ctx -Recurse -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- smoke test
$url = (& gcloud run services describe $Service --project $Project --region $Region --format "value(status.url)").Trim()
Write-Host "`nService URL: $url"
$health = Invoke-RestMethod "$url/health"
Write-Host "GET /health -> $($health.status)"
try {
    Invoke-WebRequest "$url/rules" -UseBasicParsing | Out-Null
    Write-Warning "GET /rules answered: admin routes should be hidden"
} catch {
    Write-Host "GET /rules -> $($_.Exception.Response.StatusCode.value__) (hidden, as expected)"
}
Write-Host "`nNext: firebase deploy --only hosting   (aiguardian.dev/api/v1/attest -> $Service)"
