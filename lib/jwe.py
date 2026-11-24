"""JWE decryption for broker token responses (windows_api_version=2.2).

5 dot-separated parts: header.encrypted_key.iv.ciphertext.tag
AAD is the base64url header bytes. IV length picks the cipher (12=GCM, 16=CBC/PKCS7).
"""
import json

from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .kdf import derive_key
from .util import b64decode_pad, b64url_decode


def is_jwe(text):
    return text.count(".") == 4 and not text.lstrip().startswith("{")


def decrypt_jwe(jwe_str, session_key):
    """Decrypt a JWE string to a dict. Returns parsed JSON if it was plaintext instead."""
    parts = jwe_str.split(".")
    if len(parts) != 5:
        try:
            return json.loads(jwe_str)
        except json.JSONDecodeError:
            return {"error": "not_jwe", "raw": jwe_str[:500]}

    header_b64, _enc_key, iv_b64, ct_b64, tag_b64 = parts
    header = json.loads(b64url_decode(header_b64))
    ctx = b64decode_pad(header.get("ctx", ""))
    derived = derive_key(session_key, ctx)

    iv = b64url_decode(iv_b64)
    ciphertext = b64url_decode(ct_b64)
    tag = b64url_decode(tag_b64)

    if len(iv) == 12:
        plaintext = AESGCM(derived).decrypt(iv, ciphertext + tag, header_b64.encode())
    else:
        cipher = Cipher(algorithms.AES(derived), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = sympadding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()

    return json.loads(plaintext)


def _demo():
    # Round-trip a GCM JWE we build with a known derived key path, proving parse + decrypt.
    import base64
    import os
    from .kdf import derive_key as dk

    sk = os.urandom(32)
    ctx = os.urandom(24)
    header = {"ctx": base64.b64encode(ctx).decode(), "enc": "A256GCM"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    key = dk(sk, ctx)
    iv = os.urandom(12)
    msg = json.dumps({"access_token": "eyJ", "refresh_token": "0.A"}).encode()
    ct = AESGCM(key).encrypt(iv, msg, header_b64.encode())
    ciphertext, tag = ct[:-16], ct[-16:]

    def u(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    jwe = ".".join([header_b64, "", u(iv), u(ciphertext), u(tag)])
    out = decrypt_jwe(jwe, sk)
    assert out["access_token"] == "eyJ"
    print("jwe ok")


if __name__ == "__main__":
    _demo()
