"""Module 5: MFA push handler (StrongAuth BeginAuth / EndAuth / ProcessAuth).

Gotchas handled:
 #2  ProcessAuth uses data= (form POST), never json= -> else AADSTS90014.
 #4  EndAuth success is "Success" (also accept PhoneAppNotificationApproved / AuthenticationSucceeded).
 #5  BeginAuth Success=False / DuplicateRequest -> push not sent, wait and retry upstream.
 #10 MFA number written to stdout AND file immediately, flushed (SSH buffering).

Used by prt_broker and drs_ops. Also exposes a two-phase send/wait split for SSH sessions.
"""
import json
import os
import time

from lib.logger import get as get_log
from lib.util import LOGIN, write_mfa_number

SAS = f"{LOGIN}/common/SAS"
SUCCESS_VALUES = {"Success", "PhoneAppNotificationApproved", "AuthenticationSucceeded"}
FAIL_VALUES = {"AuthenticationFailed", "Denied", "PhoneAppNotificationFailed", "UserAuthFailed"}


class MfaError(Exception):
    pass


class MfaDuplicate(MfaError):
    """BeginAuth refused because a push was just sent. Caller should refresh authorize + retry."""


def begin_auth(session, ctx, flow_token):
    """Send the push. Returns the BeginAuth JSON. Raises MfaDuplicate on DuplicateRequest."""
    log = get_log()
    log.info("[mfa] Sending MFA push notification (BeginAuth)...")
    r = session.post(f"{SAS}/BeginAuth", json={
        "AuthMethodId": "PhoneAppNotification", "Method": "BeginAuth",
        "ctx": ctx, "flowToken": flow_token}, timeout=20)
    data = r.json()
    if data.get("ResultValue") == "UserAuthFailedDuplicateRequest" or (
            not data.get("Success") and data.get("Entropy") in (0, None)):
        raise MfaDuplicate(data.get("ResultValue", "duplicate"))
    if not data.get("Success"):
        raise MfaError(f"BeginAuth failed: {data.get('ResultValue')}")
    log.info(f"[mfa] Push sent. Number matching entropy: {data.get('Entropy')}")
    return data


def poll_end_auth(session, session_id, flow_token, ctx, timeout=300):
    """Poll EndAuth every 5s up to timeout. Returns (ctx, flow_token) refreshed after approval."""
    log = get_log()
    log.info(f"[mfa] Waiting for MFA approval (polling every 5s, timeout {timeout}s)...")
    polls = max(1, timeout // 5)
    for i in range(polls):
        time.sleep(5)
        r = session.post(f"{SAS}/EndAuth", json={
            "AuthMethodId": "PhoneAppNotification", "Method": "EndAuth",
            "SessionId": session_id, "FlowToken": flow_token, "Ctx": ctx,
            "PollCount": i + 1}, timeout=20)
        data = r.json()
        rv = data.get("ResultValue")
        if data.get("Success") and rv in SUCCESS_VALUES:
            log.info(f"[mfa] MFA APPROVED (poll #{i + 1})")
            return data.get("Ctx", ctx), data.get("FlowToken", flow_token)
        if rv in FAIL_VALUES:
            raise MfaError(f"MFA {rv}")
        if i % 6 == 0:
            log.info(f"[mfa] Still waiting... poll #{i + 1}")
    raise MfaError("MFA not approved within timeout")


def process_auth(session, ctx, flow_token, prt_cookie=None):
    """ProcessAuth after approval. request=ctx (confirmed from reference). Returns response HTML."""
    log = get_log()
    log.info("[mfa] ProcessAuth (exchanging MFA approval for session)...")
    headers = {"X-Ms-Refreshtokencredential": prt_cookie} if prt_cookie else {}
    r = session.post(f"{SAS}/ProcessAuth", data={
        "type": 22, "GeneralVerify": False, "otherIdpType": "other",
        "ctx": ctx, "flowToken": flow_token, "request": ctx,
        "mfaAuthMethod": "PhoneAppNotification"},
        headers=headers, allow_redirects=True, timeout=20)
    return r


def handle_mfa(session, ctx, flow_token, number_file="mfa_number.txt", timeout=300, prt_cookie=None):
    """Full single-process MFA: begin -> write number -> poll -> process. Returns (response, ctx, ft)."""
    begin = begin_auth(session, ctx, flow_token)
    write_mfa_number(begin.get("Entropy"), number_file)
    sid = begin.get("SessionId")
    ft = begin.get("FlowToken", flow_token)
    cx = begin.get("Ctx", ctx)
    cx, ft = poll_end_auth(session, sid, ft, cx, timeout=timeout)
    resp = process_auth(session, cx, ft, prt_cookie=prt_cookie)
    return resp, cx, ft


# --- Two-phase split (SSH scenarios: phase 1 exits so the number prints) -------
def send_phase(session, ctx, flow_token, state_path, number_file="mfa_number.txt"):
    begin = begin_auth(session, ctx, flow_token)
    write_mfa_number(begin.get("Entropy"), number_file)
    state = {"phase": "mfa_sent", "entropy": begin.get("Entropy"),
             "ctx": begin.get("Ctx"), "flowToken": begin.get("FlowToken"),
             "sessionId": begin.get("SessionId")}
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f)
    return begin.get("Entropy")


def wait_phase(session, state_path, timeout=300):
    if not os.path.exists(state_path):
        raise MfaError(f"no state file at {state_path}")
    with open(state_path, encoding="utf-8") as f:
        state = json.load(f)
    return poll_end_auth(session, state["sessionId"], state["flowToken"], state["ctx"], timeout=timeout)
