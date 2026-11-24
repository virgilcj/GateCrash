"""Module 10: Reporting.

Builds a CA policy matrix (platform x resource x error code), a findings summary, and a token
inventory. Emits JSON + Markdown into the engagement reports directory.
"""
import glob
import json
import os

from lib import errors
from lib.logger import get as get_log
from lib.util import decode_jwt, now_iso


def run(cfg, eng, args):
    log = get_log()
    log.info("[report] === Generating Assessment Report ===")
    recon = eng.load_json("evidence", "recon") or {}
    tokens = _token_inventory(eng)
    log.info(f"[report] Token inventory: {len(tokens)} tokens found")
    findings = _findings(recon, tokens, eng)
    log.info(f"[report] Findings: {len(findings)} vulnerabilities cataloged")

    report = {"engagement": cfg.engagement_name, "tenant_id": cfg.tenant_id,
              "username": cfg.username, "generated": now_iso(),
              "summary": recon.get("summary", {}), "findings": findings,
              "tokens": tokens, "matrix": recon.get("matrix", {})}
    jpath = eng.save_json("reports", "report", report)
    mpath = _markdown(eng, report)
    for f in findings:
        status_icon = {"OBSERVED": "[!]", "POSSIBLE": "[?]", "N/A": "[-]"}.get(f.get("status"), "[?]")
        log.info(f"[report]   {status_icon} {f['id']} [{f['severity']}] {f['title']} -- {f.get('status')}")
    log.info(f"[report] JSON     -> {jpath}")
    log.info(f"[report] Markdown -> {mpath}")
    return report


def _token_inventory(eng):
    out = []
    for path in glob.glob(os.path.join(eng.tokens, "*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                tok = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        claims = {}
        if tok.get("access_token"):
            try:
                claims = decode_jwt(tok["access_token"])
            except Exception:
                pass
        out.append({"name": os.path.splitext(os.path.basename(path))[0],
                    "aud": claims.get("aud"), "upn": tok.get("upn") or claims.get("upn"),
                    "amr": claims.get("amr"), "deviceid": claims.get("deviceid"),
                    "source": tok.get("source"), "has_refresh": bool(tok.get("refresh_token"))})
    return out


def _findings(recon, tokens, eng=None):
    """Azure CA vulnerability catalog (VULN-01..06), flagged observed/not-observed from output."""
    s = recon.get("summary", {})
    surface = recon.get("resource_surface", {})
    dev = (eng.load_json("evidence", "device_reg") if eng else None) or {}
    intune = (eng.load_json("evidence", "intune_enroll") if eng else None) or {}
    syncml = (eng.load_json("evidence", "syncml_intel") if eng else None) or {}

    mfa_only = sorted(r for r, v in surface.items() if v.get("mfa_only_on"))
    group_leak = any((t.get("deviceid") is None and t.get("aud", "").startswith("urn:ms-drs"))
                     for t in tokens) or any("drs" in (t.get("name") or "") for t in tokens)

    catalog = [
        ("VULN-01", "CA platform misconfiguration -- macOS/iOS/Android exempt from device compliance",
         "Critical", "9.1", bool(s.get("bypass_platforms")),
         f"Device-compliance CA not enforced for {', '.join(s.get('bypass_platforms') or [])}; "
         f"spoofed mobile/macOS UA yields 50076 (MFA only) not 53003 for {len(mfa_only)} resources "
         f"(e.g. {', '.join(mfa_only[:6])}). One MFA -> full M365 access."),
        ("VULN-02", "DRS CA exemption enables rogue device registration", "High", "7.5",
         bool(dev.get("device_id")) or "drs" in {t.get("name") for t in tokens},
         f"DRS (urn:ms-drs) returns 50076 not 53003; a DRS token registers a device with a 10yr "
         f"cert. {('Registered device ' + dev['device_id']) if dev.get('device_id') else 'DRS token obtained.'}"),
        ("VULN-03", "Intune MDM enrollment from external unmanaged device", "High", "7.3",
         bool(intune.get("mdm_pfx")),
         "Rogue device enrolled in Intune MDM (device cert + device_token + hybrid); "
         "Microsoft-issued MDM cert enables mTLS with no further MFA."),
        ("VULN-04", "Corporate data exposure via SyncML management channel", "High", "7.1",
         bool(syncml),
         f"SyncML checkin leaked: {', '.join(k for k in syncml if k != 'certificates')}"
         + (f"; {len(syncml.get('certificates', []))} CA certs" if syncml.get('certificates') else "")),
        ("VULN-05", "DRS accepts unauthorized compliance write", "Medium", "5.3", None,
         "DRS compliance PATCH returns 200 but does NOT propagate to the AAD device object "
         "(defense-in-depth holds today; future-risk if Microsoft changes propagation)."),
        ("VULN-06", "AAD group/role disclosure via DRS JWT claims", "Medium", "5.0", group_leak,
         "DRS bearer tokens carry groups[] and wids[] claims, leaking group membership + roles "
         "to any DRS-token holder without a device-compliance check."),
    ]

    findings = []
    for vid, title, sev, cvss, observed, detail in catalog:
        status = "OBSERVED" if observed else ("N/A" if observed is False else "POSSIBLE")
        findings.append({"id": vid, "title": title, "severity": sev, "cvss": cvss,
                         "status": status, "detail": detail})
    if s.get("legacy_enabled"):
        findings.append({"id": "VULN-07", "title": "Legacy authentication enabled", "severity": "High",
                         "cvss": "7.4", "status": "OBSERVED",
                         "detail": "SMTP/IMAP accepted credentials -> direct mailbox access bypassing CA."})
    if s.get("client_gaps"):
        findings.append({"id": "VULN-08", "title": "CA policy does not cover all first-party clients",
                         "severity": "Medium", "cvss": "5.5", "status": "OBSERVED",
                         "detail": f"FOCI/first-party clients with CA gaps: {', '.join(s['client_gaps'][:10])}. "
                                   "CA policy scoped to specific apps may miss other Microsoft apps in the same "
                                   "FOCI family that share refresh tokens."})
    if s.get("device_code_allowed"):
        findings.append({"id": "VULN-09", "title": "Device-code flow allowed (bypasses local CA)",
                         "severity": "Medium", "cvss": "5.8", "status": "OBSERVED",
                         "detail": f"Device-code auth allowed for: {', '.join(s['device_code_allowed'])}. "
                                   "User approves on another device; local CA (device compliance, platform) "
                                   "is not evaluated. Can be used for initial access or phishing."})
    return findings


def _markdown(eng, report):
    lines = [f"# CA Assessment: {report['engagement']}", "",
             f"- Tenant: `{report['tenant_id']}`",
             f"- User: `{report['username']}`",
             f"- Generated: {report['generated']}", "", "## Vulnerabilities", "",
             "| ID | Severity | CVSS | Status | Title |", "|---|---|---|---|---|"]
    for f in report["findings"]:
        lines.append(f"| {f.get('id', '-')} | {f['severity']} | {f.get('cvss', '')} | "
                     f"{f.get('status', '')} | {f['title']} |")
    lines.append("")
    for f in report["findings"]:
        lines += [f"### {f.get('id', '')} [{f['severity']}] {f['title']}",
                  f"*Status: {f.get('status', '')}*", "", f["detail"], ""]

    lines += ["## CA Policy Matrix", "", "Error code per platform x client x resource "
              "(200 = token, 50076 = MFA only / bypass, 53003 = CA blocked).", ""]
    matrix = report.get("matrix", {})
    # Flatten to one table per client.
    clients_seen = set()
    for by_client in matrix.values():
        clients_seen.update(by_client.keys())
    for client in sorted(clients_seen):
        resources = []
        for by_client in matrix.values():
            resources += list(by_client.get(client, {}).keys())
        resources = sorted(set(resources))
        if not resources:
            continue
        lines += [f"**client: {client}**", "", "| Platform | " + " | ".join(resources) + " |",
                  "|" + "---|" * (len(resources) + 1)]
        for platform in sorted(matrix.keys()):
            row = matrix[platform].get(client, {})
            cells = [_cell(row.get(r, "-")) for r in resources]
            lines.append(f"| {platform} | " + " | ".join(cells) + " |")
        lines.append("")

    lines += ["## Token Inventory", "", "| Name | Audience | AMR | DeviceID | Source |",
              "|---|---|---|---|---|"]
    for t in report["tokens"]:
        lines.append(f"| {t['name']} | {t.get('aud') or '-'} | {t.get('amr') or '-'} | "
                     f"{t.get('deviceid') or '-'} | {t.get('source') or '-'} |")
    lines.append("")

    path = os.path.join(eng.reports, "report.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def _cell(code):
    code = str(code)
    mark = {"200": "✅200", "50076": "⚠️50076", "53003": "❌53003",
            "530003": "❌53003", "530084": "❌530084"}.get(code)
    return mark or code
