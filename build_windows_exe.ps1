
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Building Smartbox Sentinel EXE..."
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install pyinstaller
pyinstaller --onefile --windowed --name SmartboxSentinel sentinel.py
Write-Host "Done: dist\SmartboxSentinel.exe"
