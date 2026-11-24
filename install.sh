#!/bin/bash
# GateCrash install script (Linux / macOS / WSL / Kali)
set -e

echo "[*] Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

echo "[*] Installing core dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Running smoke tests..."
python test_smoke.py

echo ""
echo "[+] Install complete. Activate with: source .venv/bin/activate"
echo "[+] Next steps:"
echo "    cp config.example.yaml config.yaml"
echo "    # Edit config.yaml with target tenant details"
echo "    python -u cli.py recon --config config.yaml --quick"
echo ""
echo "[*] Optional tools (install separately if needed):"
echo "    pip install roadtx          # device registration + PRT"
echo "    # pytune                    # Intune MDM (Linux only, manual install)"
