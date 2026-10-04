# Run the GuardianAI Chainlink CRE workflow simulation on Windows and broadcast the report to Monad testnet.
# Use this when you can't create a CRE API key: `cre login` opens your browser and works locally.
#
#   cd F:\Saas\guardianai-basic-launch
#   powershell -ExecutionPolicy Bypass -File metropolis\chainlink\run-cre-simulate.ps1
#
# Output is saved to metropolis\chainlink\cre_simulate_output.txt so Claude can read and verify it.
$ErrorActionPreference = "Continue"
$Root  = (Resolve-Path "$PSScriptRoot\..\..").Path
$Cre   = "$Root\metropolis\chainlink"
$Out   = "$Cre\cre_simulate_output.txt"

# Ensure newly installed CLI paths are loaded in this session
$env:Path = "$env:LOCALAPPDATA\Programs\cre;$env:USERPROFILE\.bun\bin;" + $env:Path

function Need($cmd, $hint) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { Write-Host "Missing '$cmd'. $hint" -ForegroundColor Red; exit 1 }
}
Need "cre" "Install the CRE CLI for Windows: https://docs.chain.link/cre/getting-started/cli-installation (then open a new terminal)."
Need "bun" "Install Bun: powershell -c `"irm bun.sh/install.ps1 | iex`" (then open a new terminal)."

# 1. Log in (browser). Skipped if already logged in.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[1/5] Checking CRE login..." -ForegroundColor Cyan
$loginOutput = & cre whoami --non-interactive 2>&1 | Out-String
$isLoggedOut = ($LASTEXITCODE -ne 0) -or ($loginOutput -match "not logged in|Authentication required")
$ErrorActionPreference = $prevEAP

if ($isLoggedOut) {
  Write-Host "Not logged in. Opening browser for cre login (finish sign-in in the browser)..." -ForegroundColor Yellow
  cre login
  if ($LASTEXITCODE -ne 0) { Write-Host "cre login failed. Run 'cre login' by itself, then re-run this script." -ForegroundColor Red; exit 1 }
} else { Write-Host ($loginOutput.Trim()) }

Write-Host "[2/5] Writing CRE .env (broadcast key)..." -ForegroundColor Cyan
# 2. CLI secrets: broadcast with the deployer key from the repo .env (never committed; .gitignore covers .env)
$envLine = Get-Content "$Root\.env" | Where-Object { $_ -match '^GUARDIAN_DEPLOYER_PRIVATE_KEY=' } | Select-Object -First 1
if (-not $envLine) { Write-Host "GUARDIAN_DEPLOYER_PRIVATE_KEY not found in .env" -ForegroundColor Red; exit 1 }
$key = ($envLine -split '=', 2)[1].Trim().Trim('"').Trim("'") -replace '^0x', ''
Set-Content -Path "$Cre\.env" -Value "CRE_ETH_PRIVATE_KEY=$key" -Encoding ascii

Write-Host "[3/5] bun install (workflow deps)..." -ForegroundColor Cyan
# 3. Workflow dependencies (+ Javy compiler)
Push-Location "$Cre\guardian-threat-sync"; bun install; Pop-Location

Write-Host "[4/5] Starting GuardianAI relay on :8546..." -ForegroundColor Cyan
# 4. GuardianAI relay serving the threat feed on :8546
$py = if (Test-Path "$Root\.venv312\Scripts\python.exe") { "$Root\.venv312\Scripts\python.exe" } else { "python" }
$relay = Start-Process -FilePath $py -ArgumentList "tools\run_relay.py", "8546" -WorkingDirectory $Root -PassThru -WindowStyle Hidden
try {
  $ok = $false
  for ($i = 0; $i -lt 60 -and -not $ok; $i++) {
    try { Invoke-RestMethod "http://127.0.0.1:8546/api/v1/threat-oracle/feed" -TimeoutSec 2 | Out-Null; $ok = $true } catch { Start-Sleep 1 }
  }
  if (-not $ok) { Write-Host "Relay did not start on :8546" -ForegroundColor Red; exit 1 }

  Write-Host "[5/5] cre workflow simulate --broadcast ..." -ForegroundColor Cyan
  # 5. Simulate and broadcast the DON report to GuardianThreatOracle on Monad testnet
  Push-Location $Cre
  cre workflow simulate guardian-threat-sync --target staging-settings -e .env --broadcast --non-interactive --trigger-index 0 2>&1 | Tee-Object -FilePath $Out
  Pop-Location
} finally {
  Stop-Process -Id $relay.Id -ErrorAction SilentlyContinue
}
Write-Host "`nSaved output to $Out. Tell Claude it's done." -ForegroundColor Green
