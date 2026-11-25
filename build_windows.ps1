# Run in PowerShell from the repository folder.
$ErrorActionPreference = "Stop"
py -3 -m pip install --upgrade pip pyinstaller
py -3 -m PyInstaller --noconfirm --clean --onefile --windowed --name BudgieOS-Security-Toolkit app.py
Write-Host "Build complete: dist\BudgieOS-Security-Toolkit.exe"
