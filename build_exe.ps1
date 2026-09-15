# Build Cisco ACL Helper for fast startup (Windows PowerShell)
# Run from the ACL folder:  powershell -ExecutionPolicy Bypass -File build_exe.ps1
#
# Uses --onedir on purpose: a single-file exe must unpack ~100 MB to a temp
# folder on EVERY launch (slow + rescanned by antivirus each time).
# A folder build starts in seconds; it is zipped for the GitHub release.

$ErrorActionPreference = "Stop"

python -m pip install --upgrade pip
pip install -r requirements.txt

# folder build (fast start, no unpacking)
python -m PyInstaller --noconfirm --clean --onedir --noconsole `
  --name "CiscoACLHelper" `
  --collect-submodules paramiko `
  --collect-submodules cryptography `
  app.py

# separate updater program (own window with progress, no cmd/powershell).
# Single-file on purpose: it is copied to %TEMP% and run from there so it
# can replace every file in the app folder, including its own bundled copy.
# Stdlib + tkinter only, so the onefile unpack cost is negligible.
python -m PyInstaller --noconfirm --clean --onefile --noconsole `
  --name "CiscoACLHelperUpdater" `
  updater_app.py

$UpdSrc = "dist\CiscoACLHelperUpdater.exe"
if (Test-Path $UpdSrc) { Move-Item $UpdSrc "dist\CiscoACLHelper\CiscoACLHelperUpdater.exe" -Force }

$Zip = "dist\CiscoACLHelper-windows.zip"
if (Test-Path $Zip) { Remove-Item $Zip -Force }
Compress-Archive -Path "dist\CiscoACLHelper" -DestinationPath $Zip

Write-Host ""
Write-Host "Done. Run:  dist\CiscoACLHelper\CiscoACLHelper.exe"
Write-Host "Release asset: $Zip"
