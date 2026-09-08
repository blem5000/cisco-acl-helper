# Build Cisco ACL Helper to a single .exe (Windows PowerShell)
# Run from the ACL folder:  powershell -ExecutionPolicy Bypass -File build_exe.ps1

$ErrorActionPreference = "Stop"

python -m pip install --upgrade pip
pip install -r requirements.txt

# --noconsole = GUI app (no black console window). Use --console for debugging.
python -m PyInstaller --noconfirm --clean --onefile --noconsole `
  --name "CiscoACLHelper" `
  --collect-submodules paramiko `
  --collect-submodules cryptography `
  app.py

Write-Host ""
Write-Host "Done. EXE is in dist\CiscoACLHelper.exe"
