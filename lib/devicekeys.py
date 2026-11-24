"""Device-registration crypto primitives.

Native implementation of the pieces roadtx normally hides: RSA device key, a DER PKCS#10 CSR
(subject CN=<device_id>), and the Windows BCRYPT_RSAPUBLIC_BLOB TransportKey Azure AD uses to
encrypt the returned session key.

BCRYPT_RSAPUBLIC_BLOB layout (little-endian):
  Magic 0x31415352 ("RSA1") | BitLength | cbPublicExp | cbModulus | PublicExponent || Modulus
"""
import base64
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateSigningRequestBuilder, Name, NameAttribute
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

BCRYPT_RSAPUBLIC_MAGIC = 0x31415352  # "RSA1"


def gen_rsa(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())


def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


def csr_der_b64(device_key, device_id):
    """DER PKCS#10 CSR with subject CN=device_id, base64 (for CertificateRequest.Data)."""
    csr = (CertificateSigningRequestBuilder()
           .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, device_id)]))
           .sign(device_key, hashes.SHA256(), default_backend()))
    return base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode()


def transport_key_blob_b64(transport_key):
    """BCRYPT_RSAPUBLIC_BLOB of the transport public key, base64 (for TransportKey field)."""
    pn = transport_key.public_key().public_numbers()
    e = pn.e.to_bytes((pn.e.bit_length() + 7) // 8, "big")
    n = pn.n.to_bytes((pn.n.bit_length() + 7) // 8, "big")
    blob = struct.pack("<II", BCRYPT_RSAPUBLIC_MAGIC, pn.n.bit_length())
    blob += struct.pack("<II", len(e), len(n)) + e + n
    return base64.b64encode(blob).decode()


def _demo():
    dk = gen_rsa()
    tk = gen_rsa()
    csr = csr_der_b64(dk, "00000000-0000-0000-0000-000000000000")
    blob_b64 = transport_key_blob_b64(tk)
    raw = base64.b64decode(blob_b64)
    magic, bitlen, cb_e, cb_n = struct.unpack("<IIII", raw[:16])
    assert magic == BCRYPT_RSAPUBLIC_MAGIC and bitlen == 2048
    assert len(raw) == 16 + cb_e + cb_n
    assert len(base64.b64decode(csr)) > 200  # a real DER CSR
    print("devicekeys ok")


if __name__ == "__main__":
    _demo()
