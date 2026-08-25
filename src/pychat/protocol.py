"""Wire protocol: constants, frame builders, and strict parsing.

Both the server and the client import this module, so the two sides can never drift.
Parsing is deliberately paranoid — every frame arriving from the network is untrusted
input, and a malformed one must raise :class:`ProtocolError` rather than blow up
somewhere deeper.
"""

from __future__ import annotations

import json
import time
import unicodedata
from typing import Any

from .crypto import b64d, b64e, seal, unseal

__all__ = [
    "MAX_CLIENTS",
    "MAX_FRAME_BYTES",
    "MAX_MESSAGE_CHARS",
    "MAX_NAME_CHARS",
    "PROTOCOL_VERSION",
    "ProtocolError",
    "auth_fail",
    "auth_frame",
    "auth_ok",
    "decode_envelope",
    "encode_envelope",
    "error_frame",
    "fits_in_frame",
    "msg_frame",
    "normalize_name",
    "parse_frame",
    "roster_frame",
    "server_hello",
    "system_frame",
]

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 8192
MAX_MESSAGE_CHARS = 2000
MAX_NAME_CHARS = 24
MAX_CLIENTS = 50

AUTH_TIMEOUT_SECONDS = 5.0

# Reasons carried by auth_fail. Deliberately coarse: a client learns that it failed,
# never why, except for the version mismatch which is not a secret.
REASON_BAD_CREDENTIALS = "bad_credentials"
REASON_VERSION_MISMATCH = "version_mismatch"
REASON_SERVER_FULL = "server_full"
REASON_RATE_LIMITED = "rate_limited"


class ProtocolError(Exception):
    """A frame was malformed, oversized, or structurally invalid."""


# --- JSON encoding / decoding ---------------------------------------------------------


def dumps(frame: dict[str, Any]) -> str:
    """Compact JSON for a frame."""
    return json.dumps(frame, separators=(",", ":"), ensure_ascii=False)


def parse_frame(raw: str | bytes) -> dict[str, Any]:
    """Decode a JSON frame, enforcing the size cap before anything else.

    Raises ProtocolError for oversized input, non-UTF-8 bytes, invalid JSON, a
    non-object top level, or a missing/non-string ``t``.
    """
    if isinstance(raw, bytes):
        if len(raw) > MAX_FRAME_BYTES:
            raise ProtocolError("frame too large")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError("frame is not valid UTF-8") from exc
    elif isinstance(raw, str):
        if len(raw.encode("utf-8")) > MAX_FRAME_BYTES:
            raise ProtocolError("frame too large")
    else:
        raise ProtocolError("frame must be str or bytes")

    try:
        frame = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ProtocolError("invalid JSON") from exc

    if not isinstance(frame, dict):
        raise ProtocolError("frame must be a JSON object")
    if not isinstance(frame.get("t"), str):
        raise ProtocolError("frame is missing a string type tag")
    return frame


# --- encrypted envelope (§3.4) --------------------------------------------------------


def encode_envelope(key: bytes, inner: dict[str, Any]) -> str:
    """Wrap an inner frame in an AES-256-GCM envelope, ready to send."""
    nonce, ciphertext = seal(key, dumps(inner).encode("utf-8"))
    return dumps({"t": "enc", "n": b64e(nonce), "ct": b64e(ciphertext)})


def fits_in_frame(wire: str) -> bool:
    """Whether an encoded frame is within MAX_FRAME_BYTES.

    Worth checking before sending: MAX_MESSAGE_CHARS is a *character* limit while
    MAX_FRAME_BYTES is a *byte* limit, and base64 inflates ciphertext by a third. A
    2000-character ASCII message is ~2.9 kB on the wire, but 2000 emoji are ~10.9 kB
    and would be rejected by the peer. The sender surfaces that as a clear error
    rather than letting the frame be silently dropped.
    """
    return len(wire.encode("utf-8")) <= MAX_FRAME_BYTES


def decode_envelope(key: bytes, frame: dict[str, Any]) -> dict[str, Any]:
    """Unwrap an envelope and parse the inner frame.

    Raises ProtocolError if the envelope is structurally wrong; lets
    ``cryptography.exceptions.InvalidTag`` propagate so the caller can count
    decryption failures separately from parse failures.
    """
    if frame.get("t") != "enc":
        raise ProtocolError("not an encrypted envelope")
    nonce_b64, ct_b64 = frame.get("n"), frame.get("ct")
    if not isinstance(nonce_b64, str) or not isinstance(ct_b64, str):
        raise ProtocolError("envelope fields must be base64 strings")
    try:
        nonce, ciphertext = b64d(nonce_b64), b64d(ct_b64)
    except ValueError as exc:
        raise ProtocolError("envelope contains invalid base64") from exc
    return parse_frame(unseal(key, nonce, ciphertext))


# --- display names (§5.3) -------------------------------------------------------------


def normalize_name(raw: Any) -> str:
    """Normalize and validate a self-asserted display name.

    Strips, collapses internal whitespace, and rejects control and formatting
    characters outright — they are the classic vector for spoofing a roster entry.
    """
    if not isinstance(raw, str):
        raise ProtocolError("name must be a string")

    name = unicodedata.normalize("NFC", raw)
    name = " ".join(name.split())

    if not name:
        raise ProtocolError("name must not be empty")
    if len(name) > MAX_NAME_CHARS:
        raise ProtocolError(f"name must be at most {MAX_NAME_CHARS} characters")
    if any(unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn") for ch in name):
        raise ProtocolError("name contains disallowed control characters")
    return name


# --- frame builders -------------------------------------------------------------------


def server_hello(salt: bytes, nonce: bytes) -> dict[str, Any]:
    return {
        "t": "server_hello",
        "version": PROTOCOL_VERSION,
        "salt": b64e(salt),
        "nonce": b64e(nonce),
    }


def auth_frame(name: str, proof: bytes) -> dict[str, Any]:
    return {"t": "auth", "version": PROTOCOL_VERSION, "name": name, "proof": b64e(proof)}


def auth_fail(reason: str) -> dict[str, Any]:
    return {"t": "auth_fail", "reason": reason}


def auth_ok(user_id: str, name: str, roster: list[dict[str, str]]) -> dict[str, Any]:
    return {"t": "auth_ok", "user_id": user_id, "name": name, "roster": roster}


def roster_frame(users: list[dict[str, str]]) -> dict[str, Any]:
    return {"t": "roster", "users": users}


def msg_frame(user_id: str, name: str, text: str, ts: float | None = None) -> dict[str, Any]:
    return {"t": "msg", "user_id": user_id, "name": name, "text": text, "ts": ts or time.time()}


def system_frame(text: str, ts: float | None = None) -> dict[str, Any]:
    return {"t": "system", "text": text, "ts": ts or time.time()}


def error_frame(text: str) -> dict[str, Any]:
    return {"t": "error", "text": text}


# --- inbound frame validation ---------------------------------------------------------


def parse_server_hello(frame: dict[str, Any]) -> tuple[int, bytes, bytes]:
    """Validate a server_hello, returning (version, salt, nonce)."""
    if frame.get("t") != "server_hello":
        raise ProtocolError("expected server_hello")
    version = frame.get("version")
    if not isinstance(version, int):
        raise ProtocolError("server_hello version must be an integer")
    try:
        salt, nonce = b64d(frame.get("salt", "")), b64d(frame.get("nonce", ""))
    except ValueError as exc:
        raise ProtocolError("server_hello contains invalid base64") from exc
    if len(salt) != 16 or len(nonce) != 32:
        raise ProtocolError("server_hello salt or nonce has the wrong length")
    return version, salt, nonce


def parse_auth(frame: dict[str, Any]) -> tuple[int, str, bytes]:
    """Validate an auth frame, returning (version, normalized_name, proof)."""
    if frame.get("t") != "auth":
        raise ProtocolError("expected auth")
    version = frame.get("version")
    if not isinstance(version, int):
        raise ProtocolError("auth version must be an integer")
    name = normalize_name(frame.get("name"))
    try:
        proof = b64d(frame.get("proof", ""))
    except ValueError as exc:
        raise ProtocolError("auth proof is not valid base64") from exc
    if len(proof) != 32:
        raise ProtocolError("auth proof has the wrong length")
    return version, name, proof


def parse_client_message(frame: dict[str, Any]) -> str:
    """Validate an inbound client ``msg``, returning its text.

    Length is checked by the caller so it can answer with an ``error`` frame rather
    than dropping the connection.
    """
    if frame.get("t") != "msg":
        raise ProtocolError("expected msg")
    text = frame.get("text")
    if not isinstance(text, str):
        raise ProtocolError("msg text must be a string")
    return text
