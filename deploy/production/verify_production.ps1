param(
    [string]$User = "admin",
    [string]$Pass = ""
)

$ErrorActionPreference = "Stop"

if (-not $Pass) {
    throw "Pass is required. Example: .\verify_production.ps1 -Pass GuardianAdmin12345"
}

$bytes = [System.Text.Encoding]::ASCII.GetBytes("$User`:$Pass")
$basic = [Convert]::ToBase64String($bytes)
$headers = @{ Authorization = "Basic $basic" }

Invoke-WebRequest -Uri "http://127.0.0.1:8081/health" -UseBasicParsing | Out-Null
Invoke-WebRequest -Uri "http://127.0.0.1:8001/health" -UseBasicParsing | Out-Null
$resp = Invoke-WebRequest -Uri "http://127.0.0.1:8001/api/v1/events" -Headers $headers -UseBasicParsing

Write-Host "Proxy health OK (8081)"
Write-Host "Backend health OK (8001)"
Write-Host "Authenticated events API OK (200)"
Write-Host "Events payload size:" $resp.Content.Length
