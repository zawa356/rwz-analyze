$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Venv = Join-Path $Root ".venv"
$Req  = Join-Path $Root "requirements.txt"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  Write-Error "python not found"
  exit 1
}

if (-not (Test-Path $Venv)) {
  python -m venv $Venv
}

$Python = Join-Path $Venv "Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -r $Req

Write-Host "Venv ready: $Venv"
