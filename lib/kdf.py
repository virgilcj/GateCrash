"""PRT cookie creation and the KBKDFHMAC derivation Azure uses for SecureConversation.

Gotcha #1: must be KBKDFHMAC, not manual hmac.new() -- manual HMAC produces subtly
different bytes and causes InvalidTag on JWE decryption.
"""
import base64
import hashlib
import os
import time

import jwt as pyjwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode

from .util import b64url_decode

LABEL = b"AzureAD-SecureConversation"


def derive_key(session_key, context):
    """KBKDFHMAC-SHA256 counter mode, 32-byte output. Used for both PRT signing and JWE decrypt."""
    kdf = KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=32,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=LABEL,
        context=context,
        fixed=None,
        backend=default_backend(),
    )
    return kdf.derive(session_key)


def create_prt_cookie(prt_token, session_key, nonce=None):
    """Build the X-Ms-Refreshtokencredential JWT (KDF v2). session_key is raw bytes."""
    context = os.urandom(24)
    headers = {"ctx": base64.b64encode(context).decode(), "kdf_ver": 2}
    payload = {"refresh_token": prt_token, "is_primary": "true"}
    if nonce:
        payload["request_nonce"] = nonce
    else:
        payload["iat"] = str(int(time.time()))

    # Encode once with a throwaway key just to get the canonical body bytes.
    temp = pyjwt.encode(payload, os.urandom(32), algorithm="HS256", headers=headers)
    body = b64url_decode(temp.split(".")[1])

    d = hashlib.sha256()
    d.update(context)
    d.update(body)
    derived = derive_key(session_key, d.digest())
    return pyjwt.encode(payload, derived, algorithm="HS256", headers=headers)


def sign_prt_request(payload, session_key):
    """Sign an arbitrary payload as a PRT-derived JWT (jwt-bearer exchange). Returns the JWT string."""
    context = os.urandom(24)
    headers = {"ctx": base64.b64encode(context).decode(), "kdf_ver": 2}
    temp = pyjwt.encode(payload, os.urandom(32), algorithm="HS256", headers=headers)
    body = b64url_decode(temp.split(".")[1])
    d = hashlib.sha256()
    d.update(context)
    d.update(body)
    derived = derive_key(session_key, d.digest())
    return pyjwt.encode(payload, derived, algorithm="HS256", headers=headers)


def _demo():
    # KDF is deterministic given key+context; two derivations of the same inputs must match,
    # and a signed PRT cookie must be a 3-part JWT with kdf_ver=2.
    sk = os.urandom(32)
    ctx = os.urandom(24)
    assert derive_key(sk, ctx) == derive_key(sk, ctx)
    assert len(derive_key(sk, ctx)) == 32
    cookie = create_prt_cookie("0.FAKEPRT", sk, nonce="abc")
    assert cookie.count(".") == 2
    hdr = __import__("json").loads(b64url_decode(cookie.split(".")[0]))
    assert hdr["kdf_ver"] == 2 and "ctx" in hdr
    print("kdf ok")


if __name__ == "__main__":
    _demo()
