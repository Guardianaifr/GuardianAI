<#
.SYNOPSIS
  Deploy the GuardianAI public relay to Railway from the relay files only (not the repo's one-click stack).

.DESCRIPTION
  Before the first run:
    1. npm i -g @railway/cli        then   railway login
    2. railway.com dashboard: New project -> Empty project. Inside it: Create -> Empty service, name it "guardian-relay".

  Then from the repo root:
    .\deploy\relay\deploy-railway.ps1            # first run asks you to pick the project / environment / service
    .\deploy\relay\deploy-railway.ps1 -SkipVars  # later deploys: code only

  Why not "Deploy from GitHub": the repo's root railway.json starts the full one-click stack, and
  config/agent_passkey_identities.json is not committed. This script uploads only what the relay needs.
#>
param(
    [string]$CorsOrigins = "https://aiguardian.dev,http://localhost:5173",
    [string]$RpcUrl = "https://testnet-rpc.monad.xyz",
    [switch]$SkipVars
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

function Test-Railway {
    param([Parameter(Mandatory)][string[]]$RArgs)
    # Windows PowerShell turns native stderr into terminating errors under "Stop"; probe with Continue.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & railway @RArgs 2>&1 | Out-Null; return ($LASTEXITCODE -eq 0) } finally { $ErrorActionPreference = $prev }
}

function Invoke-Railway {
    param([Parameter(Mandatory)][string[]]$RArgs)
    & railway @RArgs
    if ($LASTEXITCODE -ne 0) { throw "railway $($RArgs[0]) failed (exit $LASTEXITCODE)" }
}

if (-not (Get-Command railway -ErrorAction SilentlyContinue)) {
    throw "Railway CLI not found. Run: npm i -g @railway/cli   then: railway login"
}

# ---------------------------------------------------------------- build context (relay only)
# Stable folder so the Railway link made on the first run is reused by later runs.
$ctx = Join-Path $Root ".railway-relay"
if (Test-Path $ctx) {
    Get-ChildItem $ctx -Force | Remove-Item -Recurse -Force
} else {
    New-Item -ItemType Directory -Path $ctx | Out-Null
}
New-Item -ItemType Directory -Path (Join-Path $ctx "config") -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot "Dockerfile"), (Join-Path $PSScriptRoot "requirements.txt") $ctx

robocopy (Join-Path $Root "guardian") (Join-Path $ctx "guardian") /E /XD __pycache__ artifacts "study cases" /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "Copying guardian/ failed (robocopy exit $LASTEXITCODE)" }
$global:LASTEXITCODE = 0

foreach ($f in @("agent_passkey_identities.json", "threat_oracle_feed.json")) {
    $src = Join-Path $Root "config\$f"
    if (Test-Path $src) { Copy-Item $src (Join-Path $ctx "config") }
}
if (-not (Test-Path (Join-Path $ctx "config\agent_passkey_identities.json"))) {
    Write-Warning "config\agent_passkey_identities.json missing: passkey-bound agents would not need a signed card"
}

# Railway config for this service only (the repo-root railway.json is not uploaded).
@'
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": { "builder": "DOCKERFILE", "dockerfilePath": "Dockerfile" },
  "deploy": {
    "healthcheckPath": "/health",
    "healthcheckTimeout": 60,
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}
'@ | Set-Content -Path (Join-Path $ctx "railway.json") -Encoding ascii

Push-Location $ctx
try {
    # The CLI remembers the link per folder; "railway status" fails when this folder is not linked yet.
    if (-not (Test-Railway @("status"))) {
        Write-Host "Pick your project, the environment (production) and the service guardian-relay:"
        Invoke-Railway @("link")
    }

    # ------------------------------------------------------------ variables
    if (-not $SkipVars) {
        $envFile = Join-Path $Root ".env"
        $line = Get-Content $envFile | Where-Object { $_ -match '^\s*GUARDIAN_ATTESTATION_SIGNER_KEY\s*=' } | Select-Object -First 1
        if (-not $line) { throw "GUARDIAN_ATTESTATION_SIGNER_KEY is not set in .env" }
        $key = ($line -split '=', 2)[1].Trim().Trim('"').Trim("'")
        if ($key -notmatch '^(0x)?[0-9a-fA-F]{64}$') { throw "GUARDIAN_ATTESTATION_SIGNER_KEY in .env is not a 32-byte hex key" }

        $vars = [ordered]@{
            "GUARDIAN_ENV"                         = "production"
            "MONAD_TESTNET_RPC"                    = $RpcUrl
            "GUARDIAN_POLICY_GUARD_CONTRACT_MONAD" = "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60"
            "GUARDIAN_CORS_ORIGINS"                = $CorsOrigins
            "GUARDIAN_ATTESTATION_SIGNER_KEY"      = $key
        }
        foreach ($k in $vars.Keys) {
            Write-Host "Setting $k"
            if (-not (Test-Railway @("variable", "set", "$k=$($vars[$k])"))) {
                # Other CLI versions spell it "variables --set"
                if (-not (Test-Railway @("variables", "--set", "$k=$($vars[$k])"))) {
                    throw "Could not set $k. Set it in the dashboard: service -> Variables."
                }
            }
        }
        $key = $null
        $vars = $null
    }

    # ------------------------------------------------------------ deploy
    Write-Host "Uploading and building (a few minutes)..."
    Invoke-Railway @("up", "--detach")

    Write-Host "`nPublic URL (creates one the first time):"
    & railway domain
} finally {
    Pop-Location
}

Write-Host @"

When the build is live, check it (put your URL in `$u):
  `$u = "https://<your-app>.up.railway.app"
  Invoke-RestMethod "`$u/health"
  Invoke-RestMethod "`$u/api/v1/attest" -Method Post -ContentType "application/json" -Body '{"agent_id":"smoke","target":"0x00000000000000000000000000000000000000c1","value":1}'
Expect status "approved". If it says the threat feed is unreachable, the trial is the Limited one
(outbound network restricted): verify your account at railway.com/verify.
"@
