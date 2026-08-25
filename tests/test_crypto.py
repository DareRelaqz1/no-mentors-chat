"""Tests for pychat.crypto — pure functions, so cover them exhaustively."""

from __future__ import annotations

import ipaddress

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pychat import crypto

SALT = b"0123456789abcdef"
PASSWORD = "correct horse battery staple"


@pytest.fixture(scope="module")
def key() -> bytes:
    # scrypt costs ~100 ms, so derive once for the whole module.
    return crypto.derive_key(PASSWORD, SALT)


# --- base64 helpers -------------------------------------------------------------------


def test_b64_round_trip():
    raw = bytes(range(256))
    assert crypto.b64d(crypto.b64e(raw)) == raw


@pytest.mark.parametrize("bad", ["not base64!!", "====", "a", 42, None])
def test_b64d_rejects_garbage(bad):
    with pytest.raises(ValueError):
        crypto.b64d(bad)


# --- key derivation -------------------------------------------------------------------


def test_derive_key_is_deterministic(key):
    assert crypto.derive_key(PASSWORD, SALT) == key
    assert len(key) == crypto.KEY_BYTES


def test_derive_key_differs_on_password(key):
    assert crypto.derive_key(PASSWORD + "!", SALT) != key


def test_derive_key_differs_on_salt(key):
    assert crypto.derive_key(PASSWORD, b"fedcba9876543210") != key


@pytest.mark.parametrize("bad_salt", [b"", b"short", b"seventeen bytes!!"])
def test_derive_key_rejects_wrong_salt_length(bad_salt):
    with pytest.raises(ValueError):
        crypto.derive_key(PASSWORD, bad_salt)


def test_derive_key_rejects_empty_password():
    with pytest.raises(ValueError):
        crypto.derive_key("", SALT)


def test_generate_salt_and_nonce_are_random():
    assert len(crypto.generate_salt()) == crypto.SALT_BYTES
    assert len({crypto.generate_salt() for _ in range(16)}) == 16
    assert len(crypto.generate_nonce()) == crypto.CHALLENGE_BYTES
    assert len({crypto.generate_nonce() for _ in range(16)}) == 16


# --- challenge / response -------------------------------------------------------------


def test_proof_round_trip(key):
    nonce = crypto.generate_nonce()
    assert crypto.verify_proof(key, nonce, "Alice", crypto.make_proof(key, nonce, "Alice"))


def test_proof_is_bound_to_the_nonce(key):
    proof = crypto.make_proof(key, crypto.generate_nonce(), "Alice")
    assert not crypto.verify_proof(key, crypto.generate_nonce(), "Alice", proof)


def test_proof_is_bound_to_the_name(key):
    nonce = crypto.generate_nonce()
    proof = crypto.make_proof(key, nonce, "Alice")
    assert not crypto.verify_proof(key, nonce, "Mallory", proof)


def test_proof_fails_under_a_different_key(key):
    nonce = crypto.generate_nonce()
    wrong = crypto.derive_key("wrong password", SALT)
    assert not crypto.verify_proof(wrong, nonce, "Alice", crypto.make_proof(key, nonce, "Alice"))


# --- AES-GCM envelope -----------------------------------------------------------------


def test_seal_open_round_trip(key):
    plaintext = "hello, world — with unicode ✓".encode()
    nonce, ct = crypto.seal(key, plaintext)
    assert len(nonce) == crypto.NONCE_BYTES
    assert plaintext not in ct
    assert crypto.unseal(key, nonce, ct) == plaintext


def test_seal_uses_a_fresh_nonce_each_time(key):
    nonces = {crypto.seal(key, b"same plaintext")[0] for _ in range(32)}
    assert len(nonces) == 32


def test_ciphertexts_differ_for_identical_plaintext(key):
    assert crypto.seal(key, b"x")[1] != crypto.seal(key, b"x")[1]


def test_tampered_ciphertext_is_rejected(key):
    nonce, ct = crypto.seal(key, b"authentic message")
    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    with pytest.raises(InvalidTag):
        crypto.unseal(key, nonce, bytes(tampered))


def test_tampered_nonce_is_rejected(key):
    nonce, ct = crypto.seal(key, b"authentic message")
    tampered = bytearray(nonce)
    tampered[0] ^= 0x01
    with pytest.raises(InvalidTag):
        crypto.unseal(key, bytes(tampered), ct)


def test_truncated_ciphertext_is_rejected(key):
    nonce, ct = crypto.seal(key, b"authentic message")
    with pytest.raises(InvalidTag):
        crypto.unseal(key, nonce, ct[:-1])


def test_wrong_key_is_rejected(key):
    nonce, ct = crypto.seal(key, b"secret")
    with pytest.raises(InvalidTag):
        crypto.unseal(crypto.derive_key("other password", SALT), nonce, ct)


def test_wrong_aad_is_rejected(key):
    """A ciphertext sealed under different AAD must not open with ours."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = b"\x00" * crypto.NONCE_BYTES
    ct = AESGCM(key).encrypt(nonce, b"secret", b"other-protocol")
    with pytest.raises(InvalidTag):
        crypto.unseal(key, nonce, ct)


def test_wrong_nonce_length_is_rejected(key):
    _, ct = crypto.seal(key, b"secret")
    with pytest.raises(InvalidTag):
        crypto.unseal(key, b"too short", ct)


@pytest.mark.parametrize("bad_key", [b"", b"\x00" * 31, b"\x00" * 33])
def test_seal_and_unseal_reject_wrong_key_length(bad_key):
    with pytest.raises(ValueError):
        crypto.seal(bad_key, b"x")
    with pytest.raises(ValueError):
        crypto.unseal(bad_key, b"\x00" * 12, b"x")


# --- certificates ---------------------------------------------------------------------


def _load(cert_pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(cert_pem)


def test_generate_self_signed_is_parseable_with_expected_properties():
    cert_pem, key_pem = crypto.generate_self_signed(["localhost", "127.0.0.1"])
    cert = _load(cert_pem)

    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert cert.public_key().curve.name == "secp256r1"
    assert cert.issuer == cert.subject  # self-signed
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert 729 <= lifetime.days <= 731

    private = serialization.load_pem_private_key(key_pem, password=None)
    assert isinstance(private, ec.EllipticCurvePrivateKey)


def test_san_contains_dns_and_ip_entries():
    cert_pem, _ = crypto.generate_self_signed(["localhost", "127.0.0.1"])
    san = _load(cert_pem).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["localhost"]
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("127.0.0.1")]


def test_san_carries_a_public_host():
    cert_pem, _ = crypto.generate_self_signed(["chat.example.com", "18.184.1.2"])
    san = _load(cert_pem).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "chat.example.com" in san.get_values_for_type(x509.DNSName)
    assert ipaddress.ip_address("18.184.1.2") in san.get_values_for_type(x509.IPAddress)


def test_generate_self_signed_requires_a_host():
    with pytest.raises(ValueError):
        crypto.generate_self_signed([])


def test_fingerprint_is_stable_and_distinguishing():
    a_pem, _ = crypto.generate_self_signed(["localhost"])
    b_pem, _ = crypto.generate_self_signed(["localhost"])
    a_der = _load(a_pem).public_bytes(serialization.Encoding.DER)
    b_der = _load(b_pem).public_bytes(serialization.Encoding.DER)

    assert crypto.fingerprint(a_der) == crypto.fingerprint(a_der)
    assert crypto.fingerprint(a_der) != crypto.fingerprint(b_der)
    assert len(crypto.fingerprint(a_der)) == 64


def test_format_fingerprint_is_human_comparable():
    formatted = crypto.format_fingerprint("aabbcc")
    assert formatted == "AA:BB:CC"


# --- persistent identity --------------------------------------------------------------


def test_identity_is_created_then_reused(tmp_path):
    first = crypto.load_or_create_identity(tmp_path, ["localhost", "127.0.0.1"])
    assert first.cert_path.exists() and first.key_path.exists()
    assert len(first.salt) == crypto.SALT_BYTES

    second = crypto.load_or_create_identity(tmp_path, ["localhost", "127.0.0.1"])
    assert second.salt == first.salt
    assert second.fingerprint == first.fingerprint


def test_identity_files_are_owner_only(tmp_path):
    identity = crypto.load_or_create_identity(tmp_path, ["localhost"])
    for path in (identity.cert_path, identity.key_path, tmp_path / "salt.bin"):
        assert path.stat().st_mode & 0o777 == 0o600, path


def test_identity_rejects_a_corrupt_salt(tmp_path):
    crypto.load_or_create_identity(tmp_path, ["localhost"])
    (tmp_path / "salt.bin").write_bytes(b"too short")
    with pytest.raises(ValueError):
        crypto.load_or_create_identity(tmp_path, ["localhost"])


def test_new_user_id_is_unique_hex():
    ids = {crypto.new_user_id() for _ in range(100)}
    assert len(ids) == 100
    assert all(len(i) == 16 and int(i, 16) >= 0 for i in ids)
