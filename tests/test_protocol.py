"""Tests for pychat.protocol — framing, validation, and the encrypted envelope."""

from __future__ import annotations

import json

import pytest
from cryptography.exceptions import InvalidTag

from pychat import crypto
from pychat import protocol as p

KEY = b"\x2b" * 32
OTHER_KEY = b"\x7f" * 32


# --- parse_frame ----------------------------------------------------------------------


def test_parse_frame_accepts_str_and_bytes():
    assert p.parse_frame('{"t":"ping"}')["t"] == "ping"
    assert p.parse_frame(b'{"t":"ping"}')["t"] == "ping"


def test_parse_frame_preserves_unicode():
    assert p.parse_frame(p.dumps({"t": "msg", "text": "héllo ✓"}))["text"] == "héllo ✓"


@pytest.mark.parametrize(
    "bad",
    [
        "not json",
        "",
        "[1,2,3]",  # top level must be an object
        '"a string"',
        "42",
        "null",
        '{"no_type":1}',  # missing t
        '{"t":42}',  # t must be a string
        '{"t":null}',
    ],
)
def test_parse_frame_rejects_malformed(bad):
    with pytest.raises(p.ProtocolError):
        p.parse_frame(bad)


def test_parse_frame_rejects_oversized_input():
    payload = p.dumps({"t": "msg", "text": "x" * (p.MAX_FRAME_BYTES + 100)})
    with pytest.raises(p.ProtocolError, match="too large"):
        p.parse_frame(payload)
    with pytest.raises(p.ProtocolError, match="too large"):
        p.parse_frame(payload.encode())


def test_parse_frame_size_cap_counts_utf8_bytes():
    """A multi-byte string under the char limit can still be over the byte limit."""
    text = "é" * (p.MAX_FRAME_BYTES // 2)
    with pytest.raises(p.ProtocolError, match="too large"):
        p.parse_frame(p.dumps({"t": "msg", "text": text}))


def test_parse_frame_rejects_invalid_utf8_bytes():
    with pytest.raises(p.ProtocolError):
        p.parse_frame(b'{"t":"msg","text":"\xff\xfe"}')


@pytest.mark.parametrize("bad", [42, None, ["t"], {"t": "ping"}])
def test_parse_frame_rejects_wrong_types(bad):
    with pytest.raises(p.ProtocolError):
        p.parse_frame(bad)


# --- envelope -------------------------------------------------------------------------


def test_envelope_round_trip():
    inner = {"t": "msg", "user_id": "abc", "name": "Alice", "text": "hi", "ts": 1.0}
    wire = p.encode_envelope(KEY, inner)
    assert p.decode_envelope(KEY, p.parse_frame(wire)) == inner


def test_envelope_hides_the_plaintext_on_the_wire():
    wire = p.encode_envelope(KEY, {"t": "msg", "text": "CANARY-9F2A-DO-NOT-LEAK"})
    assert "CANARY" not in wire
    assert "msg" not in json.loads(wire).values()
    assert set(json.loads(wire)) == {"t", "n", "ct"}


def test_envelope_is_rejected_under_a_different_key():
    wire = p.parse_frame(p.encode_envelope(KEY, {"t": "ping"}))
    with pytest.raises(InvalidTag):
        p.decode_envelope(OTHER_KEY, wire)


def test_tampered_envelope_raises_invalid_tag():
    frame = p.parse_frame(p.encode_envelope(KEY, {"t": "ping"}))
    raw = bytearray(crypto.b64d(frame["ct"]))
    raw[0] ^= 0x01
    frame["ct"] = crypto.b64e(bytes(raw))
    with pytest.raises(InvalidTag):
        p.decode_envelope(KEY, frame)


@pytest.mark.parametrize(
    "frame",
    [
        {"t": "msg"},  # not an envelope at all
        {"t": "enc"},  # missing fields
        {"t": "enc", "n": "AAAA"},  # missing ct
        {"t": "enc", "n": 1, "ct": "AAAA"},  # wrong types
        {"t": "enc", "n": "AAAA", "ct": None},
        {"t": "enc", "n": "not base64!", "ct": "AAAA"},
    ],
)
def test_decode_envelope_rejects_structural_garbage(frame):
    with pytest.raises(p.ProtocolError):
        p.decode_envelope(KEY, frame)


def test_envelope_carrying_non_json_plaintext_is_a_protocol_error():
    nonce, ct = crypto.seal(KEY, b"this is not json")
    frame = {"t": "enc", "n": crypto.b64e(nonce), "ct": crypto.b64e(ct)}
    with pytest.raises(p.ProtocolError):
        p.decode_envelope(KEY, frame)


# --- display names --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Alice", "Alice"),
        ("  Alice  ", "Alice"),
        ("Alice   Smith", "Alice Smith"),
        ("Alice\tSmith", "Alice Smith"),
        ("Alice\n Smith", "Alice Smith"),
        ("a", "a"),
        ("x" * p.MAX_NAME_CHARS, "x" * p.MAX_NAME_CHARS),
        ("日本語", "日本語"),
        ("Zoë", "Zoë"),
    ],
)
def test_normalize_name_accepts_and_cleans(raw, expected):
    assert p.normalize_name(raw) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "\t\n",
        "x" * (p.MAX_NAME_CHARS + 1),
        "Alice​",  # zero-width space, category Cf
        "Alice‮",  # right-to-left override, a spoofing classic
        "Alice\x00",
        "Alice\x07",
        42,
        None,
        ["Alice"],
    ],
)
def test_normalize_name_rejects(bad):
    with pytest.raises(p.ProtocolError):
        p.normalize_name(bad)


def test_normalize_name_applies_nfc():
    assert p.normalize_name("Zoë") == "Zoë"


# --- builders and inbound validation --------------------------------------------------


def test_server_hello_round_trip():
    salt, nonce = crypto.generate_salt(), crypto.generate_nonce()
    version, got_salt, got_nonce = p.parse_server_hello(p.server_hello(salt, nonce))
    assert (version, got_salt, got_nonce) == (p.PROTOCOL_VERSION, salt, nonce)


@pytest.mark.parametrize(
    "frame",
    [
        {"t": "auth"},
        {"t": "server_hello", "version": "1", "salt": "AA==", "nonce": "AA=="},
        {"t": "server_hello", "version": 1, "salt": "!!", "nonce": "AA=="},
        {
            "t": "server_hello",
            "version": 1,
            "salt": crypto.b64e(b"short"),
            "nonce": crypto.b64e(b"\x00" * 32),
        },
        {
            "t": "server_hello",
            "version": 1,
            "salt": crypto.b64e(b"\x00" * 16),
            "nonce": crypto.b64e(b"short"),
        },
    ],
)
def test_parse_server_hello_rejects(frame):
    with pytest.raises(p.ProtocolError):
        p.parse_server_hello(frame)


def test_auth_round_trip():
    proof = crypto.make_proof(KEY, b"\x00" * 32, "Alice")
    version, name, got_proof = p.parse_auth(p.auth_frame("  Alice  ", proof))
    assert (version, name, got_proof) == (p.PROTOCOL_VERSION, "Alice", proof)


@pytest.mark.parametrize(
    "frame",
    [
        {"t": "msg"},
        {"t": "auth", "version": 1, "name": "", "proof": crypto.b64e(b"\x00" * 32)},
        {"t": "auth", "version": None, "name": "A", "proof": crypto.b64e(b"\x00" * 32)},
        {"t": "auth", "version": 1, "name": "A", "proof": "not base64!"},
        {"t": "auth", "version": 1, "name": "A", "proof": crypto.b64e(b"short")},
        {"t": "auth", "version": 1, "name": "A"},
    ],
)
def test_parse_auth_rejects(frame):
    with pytest.raises(p.ProtocolError):
        p.parse_auth(frame)


def test_parse_client_message():
    assert p.parse_client_message({"t": "msg", "text": "hello"}) == "hello"


@pytest.mark.parametrize("frame", [{"t": "ping"}, {"t": "msg"}, {"t": "msg", "text": 5}])
def test_parse_client_message_rejects(frame):
    with pytest.raises(p.ProtocolError):
        p.parse_client_message(frame)


def test_builders_produce_parseable_frames():
    frames = [
        p.auth_fail(p.REASON_BAD_CREDENTIALS),
        p.auth_ok("id", "Alice", [{"user_id": "id", "name": "Alice"}]),
        p.roster_frame([{"user_id": "id", "name": "Alice"}]),
        p.msg_frame("id", "Alice", "hi", ts=1.5),
        p.system_frame("Alice joined the chat", ts=1.5),
        p.error_frame("message too long"),
    ]
    for frame in frames:
        assert p.parse_frame(p.dumps(frame)) == frame


def test_message_frame_stamps_a_timestamp():
    assert p.msg_frame("id", "Alice", "hi")["ts"] > 0


def test_constants_match_the_specification():
    assert (p.PROTOCOL_VERSION, p.MAX_FRAME_BYTES) == (1, 8192)
    assert (p.MAX_MESSAGE_CHARS, p.MAX_NAME_CHARS, p.MAX_CLIENTS) == (2000, 24, 50)


def test_a_maximum_length_message_fits_in_a_frame():
    """MAX_MESSAGE_CHARS of multi-byte text must still fit under MAX_FRAME_BYTES."""
    inner = {
        "t": "msg",
        "user_id": "0" * 16,
        "name": "x" * 24,
        "text": "a" * p.MAX_MESSAGE_CHARS,
        "ts": 1755000000.123456,
    }
    assert len(p.encode_envelope(KEY, inner).encode()) < p.MAX_FRAME_BYTES


def test_fits_in_frame_flags_multibyte_overflow():
    """The character limit and the byte limit are not the same constraint."""

    def envelope(ch: str) -> str:
        return p.encode_envelope(KEY, {"t": "msg", "text": ch * p.MAX_MESSAGE_CHARS})

    assert p.fits_in_frame(envelope("a"))
    assert not p.fits_in_frame(envelope("😀"))
