$ErrorActionPreference = "Stop"

$ProjectFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $ProjectFolder ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw "Python environment not found at $Python"
}

& $Python -m pip install -r (Join-Path $ProjectFolder "requirements.txt")
if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed with exit code $LASTEXITCODE."
}

& $Python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --name HikvisionEventRetriever `
    (Join-Path $ProjectFolder "retrieve_events.py")
if ($LASTEXITCODE -ne 0) {
    throw "Interactive executable build failed with exit code $LASTEXITCODE."
}

& $Python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --name HikvisionEventRetrieverAutomated `
    (Join-Path $ProjectFolder "retrieve_events_automated.py")
if ($LASTEXITCODE -ne 0) {
    throw "Automated executable build failed with exit code $LASTEXITCODE."
}

& $Python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --name DSG_automated `
    (Join-Path $ProjectFolder "retrieve_events_dsg_automated.py")
if ($LASTEXITCODE -ne 0) {
    throw "DSG automated executable build failed with exit code $LASTEXITCODE."
}

$ReleaseFolder = Join-Path $ProjectFolder "dist"

Write-Host ""
Write-Host "Build complete:"
Write-Host "  $ReleaseFolder\HikvisionEventRetriever.exe"
Write-Host "  $ReleaseFolder\HikvisionEventRetrieverAutomated.exe"
Write-Host "  $ReleaseFolder\DSG_automated.exe"
Write-Host "Run each automated EXE once with --setup before scheduling it."
