param(
    [string]$TargetUrl = "http://127.0.0.1:8080",
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$envFile = Join-Path $PSScriptRoot ".env.production"
$exampleFile = Join-Path $PSScriptRoot ".env.production.example"
$pythonExe = Join-Path $root ".venv312\Scripts\python.exe"

function New-SecretValue {
    param([int]$Length = 40)
    $raw = [Convert]::ToBase64String((1..48 | ForEach-Object { Get-Random -Maximum 256 }))
    $safe = ($raw -replace "[^A-Za-z0-9_-]", "")
    if ($safe.Length -lt $Length) {
        return ($safe + "A" * $Length).Substring(0, $Length)
    }
    return $safe.Substring(0, $Length)
}

if (-not (Test-Path $envFile)) {
    Copy-Item $exampleFile $envFile -Force
}

$lines = Get-Content $envFile
$updated = @()
foreach ($line in $lines) {
    if ($line -match "^\s*#|^\s*$") {
        $updated += $line
        continue
    }
    $parts = $line -split "=", 2
    if ($parts.Count -ne 2) {
        $updated += $line
        continue
    }
    $key = $parts[0].Trim()
    $value = $parts[1].Trim()
    if ($value -like "REPLACE_WITH_STRONG*") {
        $value = New-SecretValue
    }
    $updated += "$key=$value"
}
Set-Content -Path $envFile -Value $updated -Encoding UTF8

foreach ($line in (Get-Content $envFile)) {
    if ($line -match "^\s*#|^\s*$") { continue }
    $parts = $line -split "=", 2
    if ($parts.Count -ne 2) { continue }
    [System.Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), "Process")
}

if (-not (Test-Path $pythonExe)) {
    throw "Python venv not found at $pythonExe"
}

Push-Location $root
try {
    & $pythonExe -m pip install -r requirements.txt
    if ($NoStart) {
        & $pythonExe guardianctl.py one-click --target-url $TargetUrl --no-start
    } else {
        & $pythonExe guardianctl.py one-click --target-url $TargetUrl
    }
}
finally {
    Pop-Location
}
