"""Shared OAuth HTTP primitives: ROPC, auth-code exchange, refresh-token pivot, device code.

Thin wrappers over the token endpoints so recon / token_ops / platform_bypass don't each
re-implement them. Every call returns (status_code, parsed_dict).
"""
import requests

from .util import LOGIN


def _json(r):
    try:
        return r.json()
    except ValueError:
        return {"raw": r.text[:500]}


def ropc_v1(session, tenant, client_id, username, password, resource, ua=None):
    """ROPC against the v1.0 endpoint (resource=)."""
    headers = {"User-Agent": ua} if ua else {}
    r = session.post(f"{LOGIN}/{tenant}/oauth2/token", headers=headers, data={
        "grant_type": "password", "client_id": client_id,
        "username": username, "password": password, "resource": resource,
    })
    return r.status_code, _json(r)


def ropc_v2(session, tenant, client_id, username, password, scope, ua=None):
    """ROPC against the v2.0 endpoint (scope=)."""
    headers = {"User-Agent": ua} if ua else {}
    r = session.post(f"{LOGIN}/{tenant}/oauth2/v2.0/token", headers=headers, data={
        "grant_type": "password", "client_id": client_id,
        "username": username, "password": password, "scope": scope,
    })
    return r.status_code, _json(r)


def exchange_code_v2(session, tenant, client_id, code, redirect_uri, code_verifier, ua=None):
    """Exchange an auth code (v2.0 + PKCE)."""
    headers = {"User-Agent": ua} if ua else {}
    r = session.post(f"{LOGIN}/{tenant}/oauth2/v2.0/token", headers=headers, data={
        "grant_type": "authorization_code", "client_id": client_id, "code": code,
        "redirect_uri": redirect_uri, "code_verifier": code_verifier,
    })
    return r.status_code, _json(r)


def refresh_v2(session, tenant, client_id, refresh_token, scope, ua=None):
    """Pivot a refresh token to another resource (v2.0 scope)."""
    headers = {"User-Agent": ua} if ua else {}
    r = session.post(f"{LOGIN}/{tenant}/oauth2/v2.0/token", headers=headers, data={
        "grant_type": "refresh_token", "client_id": client_id,
        "refresh_token": refresh_token, "scope": scope,
    })
    return r.status_code, _json(r)


def refresh_v1(session, tenant, client_id, refresh_token, resource, ua=None):
    """Pivot a refresh token to another resource (v1.0 resource)."""
    headers = {"User-Agent": ua} if ua else {}
    r = session.post(f"{LOGIN}/{tenant}/oauth2/token", headers=headers, data={
        "grant_type": "refresh_token", "client_id": client_id,
        "refresh_token": refresh_token, "resource": resource,
    })
    return r.status_code, _json(r)


def device_code_start(session, client_id, scope, tenant="common"):
    r = session.post(f"{LOGIN}/{tenant}/oauth2/v2.0/devicecode",
                     data={"client_id": client_id, "scope": scope})
    return r.status_code, _json(r)


def device_code_poll(session, client_id, device_code, tenant="common"):
    r = session.post(f"{LOGIN}/{tenant}/oauth2/v2.0/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": client_id, "device_code": device_code,
    })
    return r.status_code, _json(r)
