# GateCrash install script (Windows / PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "[*] Creating virtual environment..."
python -m venv .venv
& .\.venv\Scripts\Activate.ps1

Write-Host "[*] Installing core dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

Write-Host "[*] Running smoke tests..."
python test_smoke.py

Write-Host ""
Write-Host "[+] Install complete. Activate with: .\.venv\Scripts\Activate.ps1"
Write-Host "[+] Next steps:"
Write-Host "    copy config.example.yaml config.yaml"
Write-Host "    # Edit config.yaml with target tenant details"
Write-Host "    python -u cli.py recon --config config.yaml --quick"
Write-Host ""
Write-Host "[*] Optional tools (install separately if needed):"
Write-Host "    pip install roadtx          # device registration + PRT"
