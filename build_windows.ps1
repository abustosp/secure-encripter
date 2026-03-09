$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$distPath = Join-Path $projectRoot "Ejecutable"
$workPath = Join-Path $projectRoot "temp_build"

$pyinstaller = "pyinstaller"
if (Test-Path "$projectRoot\venv\Scripts\pyinstaller.exe") {
    $pyinstaller = "$projectRoot\venv\Scripts\pyinstaller.exe"
}

$pythonCmd = "python"
if (Test-Path "$projectRoot\venv\Scripts\python.exe") {
    $pythonCmd = "$projectRoot\venv\Scripts\python.exe"
}

if ($pyinstaller -eq "pyinstaller" -and -not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    throw "Error: pyinstaller no encontrado. Activa el venv o instala pyinstaller."
}

if ($pythonCmd -eq "python" -and -not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Error: python no encontrado. Activa el venv o instala Python."
}

Write-Host "=== Compilando Secure Encrypter ===" -ForegroundColor Cyan

$iconPath = Join-Path $projectRoot "bin\ABP-blanco-en-fondo-negro.ico"

& $pyinstaller `
  --noconfirm `
  --clean `
  --onefile `
  --windowed `
  --distpath "$distPath" `
  --workpath "$workPath" `
  --specpath "$workPath" `
  --name "secure-encrypter" `
  --icon "$iconPath" `
  ".\app.py"

if (-not $?) {
    throw "Error durante la compilación con PyInstaller"
}

Write-Host "=== Copiando archivos adicionales ===" -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path (Join-Path $distPath "bin") | Out-Null
Copy-Item ".\bin\*" (Join-Path $distPath "bin") -Force -Recurse

if (Test-Path ".\README.md") {
    Copy-Item ".\README.md" (Join-Path $distPath "README.md") -Force
}

Write-Host "Ejecutable creado en: $distPath" -ForegroundColor Green
