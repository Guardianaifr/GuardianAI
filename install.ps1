param(
    [switch]$SkipNode,
    [switch]$SkipPythonInstall,
    [switch]$RunSetup,
    [switch]$RunStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Get-Python312Path {
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        try {
            $resolved = & py -3.12 -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $resolved) {
                return $resolved.Trim()
            }
        }
        catch {
            # ignored
        }
    }

    $candidates = @(
        "$env:LocalAppData\Programs\Python\Python312\python.exe",
        "C:\Python312\python.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    return $null
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Step "GuardianAI installer starting in $root"

$python312 = Get-Python312Path
if (-not $python312) {
    if (-not $SkipPythonInstall) {
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if ($winget) {
            Write-Step "Python 3.12 not found. Installing with winget"
            & winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements
            $python312 = Get-Python312Path
        }
    }
}

if (-not $python312) {
    throw "Python 3.12 was not found. Install Python 3.12, then rerun install.ps1."
}

Write-Host "Using Python: $python312"

$venvDir = Join-Path $root ".venv312"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$pythonHashFile = Join-Path $venvDir ".guardian_requirements.sha256"
$requirementsHash = (Get-FileHash (Join-Path $root "requirements.txt") -Algorithm SHA256).Hash

if (-not (Test-Path $venvPython)) {
    Write-Step "Creating virtual environment"
    & $python312 -m venv $venvDir
}
else {
    Write-Step "Using existing virtual environment: $venvDir"
}

if (-not (Test-Path $venvPython)) {
    throw "Virtual environment was not created correctly: $venvPython"
}

$needsPythonDeps = $true
if (Test-Path $pythonHashFile) {
    $savedHash = (Get-Content $pythonHashFile -Raw).Trim()
    if ($savedHash -eq $requirementsHash) {
        $needsPythonDeps = $false
    }
}

if ($needsPythonDeps) {
    Write-Step "Upgrading pip toolchain"
    & $venvPython -m pip install -q --disable-pip-version-check --no-input --progress-bar off --upgrade pip setuptools wheel

    Write-Step "Installing Python dependencies"
    & $venvPython -m pip install -q --disable-pip-version-check --no-input --progress-bar off -r requirements.txt

    Set-Content -Path $pythonHashFile -Value $requirementsHash -NoNewline
}
else {
    Write-Step "Python dependencies already up to date"
}

if (-not $SkipNode) {
    $nodeLockPath = Join-Path $root "dashboard\package-lock.json"
    $nodeHashFile = Join-Path $root "dashboard\.guardian_node.sha256"
    $npmCmd = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if (-not $npmCmd) {
        $npmCmd = Get-Command npm -ErrorAction SilentlyContinue
    }

    if ($npmCmd) {
        Push-Location (Join-Path $root "dashboard")
        try {
            $needsNodeDeps = -not (Test-Path $nodeHashFile)
            if ((Test-Path $nodeLockPath) -and (Test-Path $nodeHashFile)) {
                $lockHash = (Get-FileHash $nodeLockPath -Algorithm SHA256).Hash
                $savedNodeHash = (Get-Content $nodeHashFile -Raw).Trim()
                if ($savedNodeHash -eq $lockHash) {
                    $needsNodeDeps = $false
                }
            }

            if ($needsNodeDeps) {
                Write-Step "Installing dashboard dependencies"
                if (Test-Path "package-lock.json") {
                    & $npmCmd.Source ci
                    $lockHash = (Get-FileHash "package-lock.json" -Algorithm SHA256).Hash
                    Set-Content -Path $nodeHashFile -Value $lockHash -NoNewline
                }
                else {
                    & $npmCmd.Source install
                }
            }
            else {
                Write-Step "Dashboard dependencies already up to date"
            }
        }
        finally {
            Pop-Location
        }
    }
    else {
        Write-Warning "npm was not found. Skipping dashboard dependency install."
    }
}

Write-Step "Install complete"
Write-Host "Run setup wizard:"
Write-Host "  .\.venv312\Scripts\python.exe guardianctl.py setup"
Write-Host ""
Write-Host "Start GuardianAI:"
Write-Host "  .\.venv312\Scripts\python.exe guardianctl.py start"

if ($RunSetup) {
    Write-Step "Starting setup wizard"
    & $venvPython guardianctl.py setup
}

if ($RunStart) {
    Write-Step "Starting GuardianAI stack"
    & $venvPython guardianctl.py start
}
