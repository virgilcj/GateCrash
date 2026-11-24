"""Shared non-crypto helpers: base64, HTML/JWT parsing, engagement storage."""
import base64
import json
import os
import re
import time
from datetime import datetime, timezone

LOGIN = "https://login.microsoftonline.com"


def b64url_decode(s):
    if isinstance(s, bytes):
        s = s.decode()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64decode_pad(s):
    if isinstance(s, bytes):
        s = s.decode()
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def extract_from_html(html, key):
    """Pull a JS state variable (sFT, sCtx, stsErrorCode, canary...) from an Azure AD login page."""
    m = re.search(rf'"{re.escape(key)}"\s*:\s*"([^"]*)"', html)
    return m.group(1) if m else None


def extract_code(html):
    """Auth code from a form_post response."""
    m = re.search(r'name="code"\s+value="([^"]+)"', html)
    return m.group(1) if m else None


def decode_jwt(token):
    """Decode a JWT payload without verifying (we never have the signing key)."""
    return json.loads(b64url_decode(token.split(".")[1]))


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def server_nonce(session, tenant):
    """Fresh srv_challenge nonce, required for every PRT cookie."""
    r = session.post(f"{LOGIN}/{tenant}/oauth2/token", data={"grant_type": "srv_challenge"})
    return r.json()["Nonce"]


class Engagement:
    """Output directory layout + JSON helpers. The glue that chains modules together."""

    def __init__(self, output_dir, name):
        self.root = os.path.join(output_dir, name)
        self.tokens = os.path.join(self.root, "tokens")
        self.certs = os.path.join(self.root, "certs")
        self.evidence = os.path.join(self.root, "evidence")
        self.reports = os.path.join(self.root, "reports")
        for d in (self.tokens, self.certs, self.evidence, self.reports):
            os.makedirs(d, exist_ok=True)

    def save_json(self, subdir, name, data):
        if not name.endswith(".json"):
            name += ".json"
        path = os.path.join(getattr(self, subdir), name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path

    def load_json(self, subdir, name):
        if not name.endswith(".json"):
            name += ".json"
        path = os.path.join(getattr(self, subdir), name)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def save_token(self, name, token):
        return self.save_json("tokens", name, token)

    def load_token(self, name):
        # Accept a token id, a filename, or a full path.
        if os.path.sep in name or name.endswith(".json") and os.path.exists(name):
            with open(name, encoding="utf-8") as f:
                return json.load(f)
        return self.load_json("tokens", name)

    def save_evidence(self, name, text):
        path = os.path.join(self.evidence, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text if isinstance(text, str) else json.dumps(text, indent=2))
        return path


def write_mfa_number(number, number_file):
    """Critical: MFA match number to stdout AND file, flushed immediately (SSH buffering)."""
    banner = (
        f"\n{'=' * 60}\n"
        f"{'=' * 60}\n"
        f"       APPROVE MFA ON YOUR PHONE\n"
        f"       ENTER NUMBER:  >>>  {number}  <<<\n"
        f"{'=' * 60}\n"
        f"{'=' * 60}\n"
    )
    print(banner, flush=True)
    try:
        with open(number_file, "w", encoding="utf-8") as f:
            f.write(str(number))
    except OSError:
        pass


def sleep(seconds):
    time.sleep(seconds)
