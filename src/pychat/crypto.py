"""Cryptographic primitives for pychat.

Three concerns live here, and nothing else:

* the scrypt key derivation that turns the room password into a 32-byte key,
* the AES-256-GCM envelope that wraps every post-handshake frame,
* self-signed X.509 certificate generation and SHA-256 fingerprinting.

Nothing in this module logs, prints, or persists key material or plaintext.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import ipaddress
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.x509.oid import NameOID

__all__ = [
    "AAD",
    "KEY_BYTES",
    "NONCE_BYTES",
    "SALT_BYTES",
    "SCRYPT_N",
    "SCRYPT_P",
    "SCRYPT_R",
    "InvalidTag",
    "ServerIdentity",
    "b64d",
    "b64e",
    "derive_key",
    "fingerprint",
    "format_fingerprint",
    "generate_nonce",
    "generate_salt",
    "load_or_create_identity",
    "make_proof",
    "seal",
    "unseal",
    "verify_proof",
]

# --- parameters, fixed by the specification -------------------------------------------

SALT_BYTES = 16
KEY_BYTES = 32
NONCE_BYTES = 12
CHALLENGE_BYTES = 32

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1

AAD = b"pychat/1"

CERT_VALIDITY_DAYS = 730  # two years


# --- base64 helpers -------------------------------------------------------------------


def b64e(raw: bytes) -> str:
    """Encode bytes as a standard base64 string."""
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    """Decode a base64 string, raising ValueError on anything malformed."""
    if not isinstance(text, str):
        raise ValueError("expected a base64 string")
    try:
        return base64.b64decode(text, validate=True)
    except (base64.binascii.Error, ValueError) as exc:  # type: ignore[attr-defined]
        raise ValueError("invalid base64") from exc


# --- key derivation and challenge/response --------------------------------------------


def generate_salt() -> bytes:
    """A fresh 16-byte KDF salt."""
    return os.urandom(SALT_BYTES)


def generate_nonce() -> bytes:
    """A fresh 32-byte authentication challenge."""
    return os.urandom(CHALLENGE_BYTES)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive the 32-byte room key from the password.

    scrypt at n=2**15 costs roughly 100 ms. Callers derive once and cache; never call
    this per message, and never call it on a UI thread.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    if len(salt) != SALT_BYTES:
        raise ValueError(f"salt must be {SALT_BYTES} bytes")
    kdf = Scrypt(salt=salt, length=KEY_BYTES, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def make_proof(key: bytes, nonce: bytes, display_name: str) -> bytes:
    """HMAC-SHA256(key, nonce || display_name) — the client's proof of the password."""
    return hmac.new(key, nonce + display_name.encode("utf-8"), hashlib.sha256).digest()


def verify_proof(key: bytes, nonce: bytes, display_name: str, proof: bytes) -> bool:
    """Constant-time check of a client proof."""
    return hmac.compare_digest(make_proof(key, nonce, display_name), proof)


# --- payload encryption ---------------------------------------------------------------


def seal(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns (nonce, ciphertext-with-tag)."""
    if len(key) != KEY_BYTES:
        raise ValueError(f"key must be {KEY_BYTES} bytes")
    nonce = os.urandom(NONCE_BYTES)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, AAD)


def unseal(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt an AES-256-GCM envelope. Raises InvalidTag on any tampering."""
    if len(key) != KEY_BYTES:
        raise ValueError(f"key must be {KEY_BYTES} bytes")
    if len(nonce) != NONCE_BYTES:
        raise InvalidTag()
    return AESGCM(key).decrypt(nonce, ciphertext, AAD)


# --- certificates ---------------------------------------------------------------------


def fingerprint(cert_der: bytes) -> str:
    """Lowercase hex SHA-256 of a DER-encoded certificate."""
    return hashlib.sha256(cert_der).hexdigest()


def format_fingerprint(hex_digest: str) -> str:
    """Render a fingerprint as colon-separated uppercase pairs, for humans to compare."""
    return ":".join(hex_digest[i : i + 2] for i in range(0, len(hex_digest), 2)).upper()


def _san_entries(hosts: list[str]) -> list[x509.GeneralName]:
    entries: list[x509.GeneralName] = []
    for host in hosts:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            entries.append(x509.DNSName(host))
    return entries


def generate_self_signed(hosts: list[str]) -> tuple[bytes, bytes]:
    """Create an ECDSA P-256 self-signed certificate valid for two years.

    Returns (cert_pem, key_pem). The key is unencrypted, so the caller is responsible
    for writing it with mode 600.
    """
    if not hosts:
        raise ValueError("at least one host is required for the certificate SAN")

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, hosts[0]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pychat"),
        ]
    )
    now = _dt.datetime.now(_dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(_san_entries(hosts)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


@dataclass(frozen=True)
class ServerIdentity:
    """The server's persistent identity: TLS material plus the KDF salt."""

    cert_path: Path
    key_path: Path
    salt: bytes

    @property
    def fingerprint(self) -> str:
        der = x509.load_pem_x509_certificate(self.cert_path.read_bytes()).public_bytes(
            serialization.Encoding.DER
        )
        return fingerprint(der)


def _write_private(path: Path, data: bytes) -> None:
    """Write a file that only the owner can read, without a world-readable window."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def load_or_create_identity(data_dir: Path, hosts: list[str]) -> ServerIdentity:
    """Load cert, key and salt from ``data_dir``, creating them on first run.

    The salt is generated once and persisted, because changing it would invalidate every
    client's derived key.
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    cert_path = data_dir / "server.crt"
    key_path = data_dir / "server.key"
    salt_path = data_dir / "salt.bin"

    if not (cert_path.exists() and key_path.exists()):
        cert_pem, key_pem = generate_self_signed(hosts)
        _write_private(cert_path, cert_pem)
        _write_private(key_path, key_pem)

    if salt_path.exists():
        salt = salt_path.read_bytes()
        if len(salt) != SALT_BYTES:
            raise ValueError(f"{salt_path} is corrupt: expected {SALT_BYTES} bytes")
    else:
        salt = generate_salt()
        _write_private(salt_path, salt)

    return ServerIdentity(cert_path=cert_path, key_path=key_path, salt=salt)


def new_user_id() -> str:
    """A random, unguessable connection identifier."""
    return secrets.token_hex(8)
