$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Venv = Join-Path $Root ".venv"
$Req  = Join-Path $Root "requirements.txt"

$PythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
  $PythonCmd = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
  $PythonCmd = "python3"
} else {
  Write-Error "python/python3 not found"
  exit 1
}

function Get-VenvPythonPath([string]$Base) {
  $candidates = @(
    (Join-Path $Base "Scripts\python.exe"),
    (Join-Path $Base "bin/python")
  )
  foreach ($p in $candidates) {
    if (Test-Path $p) { return $p }
  }
  return $null
}

$Python = Get-VenvPythonPath $Venv
if (-not $Python) {
  if (Test-Path $Venv) {
    Write-Warning "Existing .venv is incomplete. Recreating: $Venv"
    Remove-Item -Recurse -Force $Venv
  }

  & $PythonCmd -m venv $Venv
  $Python = Get-VenvPythonPath $Venv
}

if (-not $Python) {
  Write-Error "venv python not found after creation: $Venv"
  exit 1
}

& $Python -m pip install --upgrade pip
& $Python -m pip install -r $Req

Write-Host "Venv ready: $Venv"
