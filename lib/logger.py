"""Logging: verbose console + detailed file log with full HTTP request/response capture."""
import logging
import os
import time

import requests

_log = logging.getLogger("azca")

# Track request timing
_req_start = {}


def setup(engagement_root, verbose=True):
    """Call once at startup. Console gets INFO, file gets DEBUG (every HTTP req/resp)."""
    _log.setLevel(logging.DEBUG)
    _log.handlers.clear()

    fmt_console = logging.Formatter("[%(name)s] %(message)s")
    fmt_file = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO if verbose else logging.WARNING)
    ch.setFormatter(fmt_console)
    _log.addHandler(ch)

    log_path = os.path.join(engagement_root, "debug.log")
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt_file)
    _log.addHandler(fh)

    _log.info(f"Logging to {log_path}")
    return _log


def get():
    if not _log.handlers:
        # Fallback: console-only if setup() wasn't called (e.g. tests, library use)
        _log.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter("[%(name)s] %(message)s"))
        _log.addHandler(ch)
    return _log


def logged_session(tag="http"):
    """requests.Session with automatic logging of every request and response."""
    s = requests.Session()
    s.hooks["response"].append(lambda r, *a, **kw: _log_response(r, tag))
    return s


def _log_response(resp, tag):
    req = resp.request
    elapsed = resp.elapsed.total_seconds() if hasattr(resp, "elapsed") else 0

    # Console: one-liner per request
    status = resp.status_code
    url_short = req.url[:120] + ("..." if len(req.url) > 120 else "")
    _log.info(f"  {req.method} {url_short} -> {status} ({elapsed:.1f}s)")

    # File: full details
    _log.debug(f"--- HTTP {req.method} {req.url} ---")
    _log.debug(f"Request headers: {dict(req.headers)}")
    if req.body:
        body_str = req.body if isinstance(req.body, str) else str(req.body)[:2000]
        # Mask password in body
        if "passwd=" in body_str or "password=" in body_str.lower():
            import re
            body_str = re.sub(r'(passwd|password)=[^&]*', r'\1=***REDACTED***', body_str, flags=re.I)
        _log.debug(f"Request body: {body_str}")
    _log.debug(f"Response: {status} in {elapsed:.3f}s")
    _log.debug(f"Response headers: {dict(resp.headers)}")
    resp_text = resp.text[:4000] if resp.text else "(empty)"
    _log.debug(f"Response body: {resp_text}")
    if resp.history:
        _log.debug(f"Redirects: {[(r.status_code, r.headers.get('Location', '')[:200]) for r in resp.history]}")
    _log.debug("--- end ---")
