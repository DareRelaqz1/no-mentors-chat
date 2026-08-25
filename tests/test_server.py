"""Tests for pychat.server.

The handshake, relay and abuse-limit behaviours are exercised against a real server
listening on a real TLS socket on an ephemeral port — the interesting bugs in this
layer live in the interaction between connections, not inside a single function.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl

import pytest
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve

from pychat import protocol as p
from pychat import server as srv
from pychat.crypto import b64e, derive_key, generate_nonce, make_proof

PASSWORD = "test-room-password"


# --- unit-level pieces ----------------------------------------------------------------


class TestConfig:
    def test_requires_a_password(self):
        with pytest.raises(srv.ConfigError, match="PYCHAT_ROOM_PASSWORD"):
            srv.Config.from_env({})

    def test_rejects_a_short_password(self):
        with pytest.raises(srv.ConfigError, match="too short"):
            srv.Config.from_env({"PYCHAT_ROOM_PASSWORD": "short"})

    def test_accepts_exactly_the_minimum_length(self):
        config = srv.Config.from_env({"PYCHAT_ROOM_PASSWORD": "a" * srv.MIN_PASSWORD_CHARS})
        assert len(config.password) == srv.MIN_PASSWORD_CHARS

    @pytest.mark.parametrize("port", ["nope", "", "1.5", "0", "70000", "-1"])
    def test_rejects_a_bad_port(self, port):
        with pytest.raises(srv.ConfigError, match="PYCHAT_PORT"):
            srv.Config.from_env({"PYCHAT_ROOM_PASSWORD": PASSWORD, "PYCHAT_PORT": port})

    def test_defaults(self):
        config = srv.Config.from_env({"PYCHAT_ROOM_PASSWORD": PASSWORD})
        assert config.port == 8765
        assert config.public_host is None
        assert config.cert_hosts() == ["localhost", "127.0.0.1"]

    def test_public_host_leads_the_cert_sans(self):
        config = srv.Config.from_env(
            {"PYCHAT_ROOM_PASSWORD": PASSWORD, "PYCHAT_PUBLIC_HOST": "18.184.1.2"}
        )
        assert config.cert_hosts() == ["18.184.1.2", "localhost", "127.0.0.1"]

    def test_blank_public_host_is_treated_as_unset(self):
        config = srv.Config.from_env({"PYCHAT_ROOM_PASSWORD": PASSWORD, "PYCHAT_PUBLIC_HOST": "  "})
        assert config.public_host is None


class TestLockout:
    def test_locks_out_after_the_threshold(self):
        tracker = srv.LockoutTracker()
        for i in range(srv.LOCKOUT_THRESHOLD - 1):
            assert tracker.record_failure("1.2.3.4", now=i) is False
            assert not tracker.is_locked("1.2.3.4", now=i)
        assert tracker.record_failure("1.2.3.4", now=srv.LOCKOUT_THRESHOLD) is True
        assert tracker.is_locked("1.2.3.4", now=srv.LOCKOUT_THRESHOLD)

    def test_lockout_expires(self):
        tracker = srv.LockoutTracker()
        for i in range(srv.LOCKOUT_THRESHOLD):
            tracker.record_failure("1.2.3.4", now=i)
        assert tracker.is_locked("1.2.3.4", now=100)
        assert not tracker.is_locked("1.2.3.4", now=srv.LOCKOUT_DURATION + 100)

    def test_failures_outside_the_window_do_not_accumulate(self):
        tracker = srv.LockoutTracker()
        for i in range(srv.LOCKOUT_THRESHOLD * 3):
            # One failure per window-and-a-bit never reaches the threshold.
            assert tracker.record_failure("1.2.3.4", now=i * (srv.LOCKOUT_WINDOW + 1)) is False

    def test_lockout_is_per_ip(self):
        tracker = srv.LockoutTracker()
        for i in range(srv.LOCKOUT_THRESHOLD):
            tracker.record_failure("1.2.3.4", now=i)
        assert tracker.is_locked("1.2.3.4", now=1)
        assert not tracker.is_locked("5.6.7.8", now=1)

    def test_success_clears_the_failure_history(self):
        tracker = srv.LockoutTracker()
        for i in range(srv.LOCKOUT_THRESHOLD - 1):
            tracker.record_failure("1.2.3.4", now=i)
        tracker.record_success("1.2.3.4")
        assert tracker.record_failure("1.2.3.4", now=10) is False


class TestRateLimit:
    def _client(self):
        return srv.Client(user_id="id", name="Alice", ws=None)  # ws unused by rate_limited

    def test_allows_up_to_the_limit_then_blocks(self):
        client = self._client()
        for _ in range(srv.RATE_LIMIT_MESSAGES):
            assert client.rate_limited(now=0.0) is False
        assert client.rate_limited(now=0.0) is True

    def test_window_slides(self):
        client = self._client()
        for _ in range(srv.RATE_LIMIT_MESSAGES):
            client.rate_limited(now=0.0)
        assert client.rate_limited(now=0.0) is True
        assert client.rate_limited(now=srv.RATE_LIMIT_WINDOW + 0.1) is False


# --- live server fixture --------------------------------------------------------------


@pytest.fixture
async def chat(tmp_path):
    """A real pychat server on an ephemeral port, with its own data directory."""
    config = srv.Config(password=PASSWORD, port=0, host="127.0.0.1", data_dir=tmp_path)
    server = srv.ChatServer(config)
    ssl_ctx = srv.build_ssl_context(server.identity.cert_path, server.identity.key_path)
    async with serve(
        server.handle, "127.0.0.1", 0, ssl=ssl_ctx, max_size=p.MAX_FRAME_BYTES
    ) as ws_server:
        port = next(iter(ws_server.sockets)).getsockname()[1]
        server.test_port = port  # type: ignore[attr-defined]
        yield server
        await server.shutdown()


def _client_ssl() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class Peer:
    """A scripted client that drains frames into a queue in the background."""

    def __init__(self, ws, key):
        self.ws, self.key, self.queue = ws, key, asyncio.Queue()
        self._task = asyncio.create_task(self._pump())

    async def _pump(self):
        with contextlib.suppress(Exception):
            async for raw in self.ws:
                frame = p.parse_frame(raw)
                if frame.get("t") == "enc":
                    frame = p.decode_envelope(self.key, frame)
                await self.queue.put(frame)

    async def send(self, inner):
        await self.ws.send(p.encode_envelope(self.key, inner))

    async def expect(self, predicate, timeout=5.0):
        """The first frame satisfying ``predicate``, or None. Others are discarded."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while (remaining := deadline - loop.time()) > 0:
            try:
                frame = await asyncio.wait_for(self.queue.get(), remaining)
            except TimeoutError:
                return None
            if predicate(frame):
                return frame
        return None

    async def close(self):
        await self.ws.close()
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task


async def raw_connect(server, **kwargs):
    return await connect(
        f"wss://127.0.0.1:{server.test_port}",
        ssl=_client_ssl(),
        max_size=p.MAX_FRAME_BYTES,
        **kwargs,
    )


async def handshake(server, name, password=PASSWORD):
    """Full handshake. Returns (websocket, key, first_reply)."""
    ws = await raw_connect(server)
    hello = p.parse_frame(await ws.recv())
    if hello.get("t") == "auth_fail":
        return ws, None, hello
    _, salt, nonce = p.parse_server_hello(hello)
    key = derive_key(password, salt)
    await ws.send(p.dumps(p.auth_frame(name, make_proof(key, nonce, name))))
    reply = p.parse_frame(await ws.recv())
    if reply.get("t") == "auth_fail":
        return ws, key, reply
    return ws, key, p.decode_envelope(key, reply)


async def join(server, name, password=PASSWORD):
    ws, key, reply = await handshake(server, name, password)
    assert reply["t"] == "auth_ok", reply
    return Peer(ws, key), reply


# --- handshake ------------------------------------------------------------------------


class TestHandshake:
    async def test_successful_auth(self, chat):
        peer, reply = await join(chat, "Alice")
        assert reply["name"] == "Alice"
        assert len(reply["user_id"]) == 16
        assert reply["roster"] == [{"user_id": reply["user_id"], "name": "Alice"}]
        await peer.close()

    async def test_wrong_password_is_refused(self, chat):
        ws, _, reply = await handshake(chat, "Mallory", "the-wrong-password")
        assert reply == {"t": "auth_fail", "reason": p.REASON_BAD_CREDENTIALS}
        await ws.close()

    async def test_failure_reason_does_not_distinguish_password_from_name(self, chat):
        _, _, wrong_password = await handshake(chat, "Alice", "the-wrong-password")
        ws = await raw_connect(chat)
        hello = p.parse_frame(await ws.recv())
        p.parse_server_hello(hello)
        await ws.send(p.dumps({"t": "auth", "version": 1, "name": "", "proof": b64e(b"\x00" * 32)}))
        bad_name = p.parse_frame(await ws.recv())
        await ws.close()
        assert wrong_password["reason"] == bad_name["reason"] == p.REASON_BAD_CREDENTIALS

    async def test_version_mismatch(self, chat):
        ws = await raw_connect(chat)
        _, salt, nonce = p.parse_server_hello(p.parse_frame(await ws.recv()))
        key = derive_key(PASSWORD, salt)
        frame = p.auth_frame("Alice", make_proof(key, nonce, "Alice")) | {"version": 99}
        await ws.send(p.dumps(frame))
        assert p.parse_frame(await ws.recv()) == {
            "t": "auth_fail",
            "reason": p.REASON_VERSION_MISMATCH,
        }
        await ws.close()

    async def test_proof_from_a_different_nonce_is_refused(self, chat):
        """A replayed proof must not authenticate a new connection."""
        ws = await raw_connect(chat)
        _, salt, _ = p.parse_server_hello(p.parse_frame(await ws.recv()))
        key = derive_key(PASSWORD, salt)
        stale = make_proof(key, generate_nonce(), "Alice")
        await ws.send(p.dumps(p.auth_frame("Alice", stale)))
        assert p.parse_frame(await ws.recv())["reason"] == p.REASON_BAD_CREDENTIALS
        await ws.close()

    @pytest.mark.parametrize(
        "frame",
        [
            "not json at all",
            '{"t":"auth"}',
            '{"t":"msg","text":"skipping auth"}',
            '{"t":"auth","version":1,"name":"","proof":"AAAA"}',
            '{"t":"auth","version":1,"name":"Alice","proof":"not base64!"}',
        ],
    )
    async def test_malformed_auth_is_refused_without_crashing_the_server(self, chat, frame):
        ws = await raw_connect(chat)
        await ws.recv()
        await ws.send(frame)
        assert p.parse_frame(await ws.recv())["t"] == "auth_fail"
        await ws.close()
        # The server is still healthy afterwards.
        peer, _ = await join(chat, "Alice")
        await peer.close()

    async def test_silent_client_is_dropped_on_the_auth_timeout(self, chat):
        ws = await raw_connect(chat)
        await ws.recv()
        await asyncio.wait_for(ws.wait_closed(), timeout=p.AUTH_TIMEOUT_SECONDS + 3)
        assert ws.close_code is not None

    async def test_repeated_failures_lock_the_ip_out(self, chat):
        for _ in range(srv.LOCKOUT_THRESHOLD):
            ws, _, reply = await handshake(chat, "Mallory", "the-wrong-password")
            assert reply["reason"] == p.REASON_BAD_CREDENTIALS
            await ws.close()
        # Even the correct password is now refused, before the challenge is even sent.
        ws, _, reply = await handshake(chat, "Alice", PASSWORD)
        assert reply == {"t": "auth_fail", "reason": p.REASON_RATE_LIMITED}
        await ws.close()

    async def test_server_full(self, chat, monkeypatch):
        monkeypatch.setattr(p, "MAX_CLIENTS", 1)
        peer, _ = await join(chat, "Alice")
        ws, _, reply = await handshake(chat, "Bob")
        assert reply == {"t": "auth_fail", "reason": p.REASON_SERVER_FULL}
        await ws.close()
        await peer.close()


# --- names ----------------------------------------------------------------------------


class TestNames:
    async def test_duplicate_names_are_suffixed(self, chat):
        a, _ = await join(chat, "Alice")
        b, second = await join(chat, "Alice")
        c, third = await join(chat, "Alice")
        assert (second["name"], third["name"]) == ("Alice#2", "Alice#3")
        for peer in (a, b, c):
            await peer.close()

    async def test_duplicate_detection_is_case_insensitive(self, chat):
        a, _ = await join(chat, "Alice")
        b, reply = await join(chat, "alice")
        assert reply["name"] == "alice#2"
        await a.close()
        await b.close()

    async def test_names_are_normalised_on_the_way_in(self, chat):
        peer, reply = await join(chat, "  Alice   Smith  ")
        assert reply["name"] == "Alice Smith"
        await peer.close()

    async def test_a_suffixed_name_stays_within_the_length_limit(self, chat):
        long_name = "x" * p.MAX_NAME_CHARS
        a, _ = await join(chat, long_name)
        b, reply = await join(chat, long_name)
        assert len(reply["name"]) <= p.MAX_NAME_CHARS
        assert reply["name"].endswith("#2")
        await a.close()
        await b.close()


# --- relay ----------------------------------------------------------------------------


class TestRelay:
    async def test_message_reaches_everyone_including_the_sender(self, chat):
        alice, a_reply = await join(chat, "Alice")
        bob, b_reply = await join(chat, "Bob")

        await alice.send({"t": "msg", "text": "hello everyone"})
        for peer in (alice, bob):
            frame = await peer.expect(lambda f: f["t"] == "msg")
            assert frame["text"] == "hello everyone"
            assert frame["name"] == "Alice"
            assert frame["user_id"] == a_reply["user_id"]
            assert frame["ts"] > 0
        assert b_reply["user_id"] != a_reply["user_id"]
        await alice.close()
        await bob.close()

    async def test_three_clients_all_see_each_other(self, chat):
        peers = [await join(chat, name) for name in ("Alice", "Bob", "Carol")]
        clients = [peer for peer, _ in peers]

        roster = await clients[0].expect(lambda f: f["t"] == "roster" and len(f["users"]) == 3)
        assert [u["name"] for u in roster["users"]] == ["Alice", "Bob", "Carol"]

        await clients[2].send({"t": "msg", "text": "carol speaking"})
        for client in clients:
            frame = await client.expect(lambda f: f["t"] == "msg")
            assert frame["text"] == "carol speaking"
            assert frame["name"] == "Carol"
        for client in clients:
            await client.close()

    async def test_join_and_leave_are_announced(self, chat):
        alice, _ = await join(chat, "Alice")
        bob, _ = await join(chat, "Bob")
        assert await alice.expect(lambda f: f["t"] == "system" and "Bob joined" in f["text"])

        await bob.close()
        assert await alice.expect(lambda f: f["t"] == "system" and "Bob left" in f["text"])
        roster = await alice.expect(lambda f: f["t"] == "roster" and len(f["users"]) == 1)
        assert roster["users"][0]["name"] == "Alice"
        await alice.close()

    async def test_departure_is_announced_when_the_send_itself_fails(self, chat):
        """Regression: a client that dies mid-broadcast still has to leave the roster.

        Previously the failed broadcast removed the client from the registry, so the
        handler's cleanup found nothing to remove and never announced the departure —
        leaving everyone else with a stale roster.
        """
        alice, _ = await join(chat, "Alice")
        bob, _ = await join(chat, "Bob")
        await alice.expect(lambda f: f["t"] == "roster" and len(f["users"]) == 2)

        # Kill Bob's transport abruptly, then force a broadcast that will fail on him.
        bob.ws.transport.abort()
        await asyncio.sleep(0.05)
        await alice.send({"t": "msg", "text": "does bob still exist?"})

        assert await alice.expect(lambda f: f["t"] == "system" and "Bob left" in f["text"])
        roster = await alice.expect(lambda f: f["t"] == "roster" and len(f["users"]) == 1)
        assert [u["name"] for u in roster["users"]] == ["Alice"]
        assert len(chat.clients) == 1
        await alice.close()

    async def test_roster_is_sorted_case_insensitively(self, chat):
        peers = [(await join(chat, name))[0] for name in ("zoe", "Alice", "bob")]
        roster = await peers[0].expect(lambda f: f["t"] == "roster" and len(f["users"]) == 3)
        assert [u["name"] for u in roster["users"]] == ["Alice", "bob", "zoe"]
        for peer in peers:
            await peer.close()

    async def test_ping_is_answered(self, chat):
        alice, _ = await join(chat, "Alice")
        await alice.send({"t": "ping"})
        assert await alice.expect(lambda f: f["t"] == "pong")
        await alice.close()

    async def test_unknown_frame_types_are_ignored_not_fatal(self, chat):
        alice, _ = await join(chat, "Alice")
        await alice.send({"t": "a-type-from-the-future", "payload": [1, 2, 3]})
        await alice.send({"t": "msg", "text": "still here"})
        assert await alice.expect(lambda f: f["t"] == "msg" and f["text"] == "still here")
        await alice.close()

    async def test_empty_and_whitespace_messages_are_dropped(self, chat):
        alice, _ = await join(chat, "Alice")
        await alice.send({"t": "msg", "text": "   "})
        await alice.send({"t": "msg", "text": "real message"})
        frame = await alice.expect(lambda f: f["t"] == "msg")
        assert frame["text"] == "real message"
        await alice.close()

    async def test_message_text_is_stripped(self, chat):
        alice, _ = await join(chat, "Alice")
        await alice.send({"t": "msg", "text": "  padded  "})
        frame = await alice.expect(lambda f: f["t"] == "msg")
        assert frame["text"] == "padded"
        await alice.close()


# --- abuse limits ---------------------------------------------------------------------


class TestAbuseLimits:
    async def test_oversized_message_gets_an_error_not_a_disconnect(self, chat):
        alice, _ = await join(chat, "Alice")
        await alice.send({"t": "msg", "text": "x" * (p.MAX_MESSAGE_CHARS + 1)})
        error = await alice.expect(lambda f: f["t"] == "error")
        assert "too long" in error["text"]
        await alice.send({"t": "msg", "text": "still connected"})
        assert await alice.expect(lambda f: f["t"] == "msg")
        await alice.close()

    async def test_rate_limit_gets_an_error_not_a_disconnect(self, chat):
        alice, _ = await join(chat, "Alice")
        for i in range(srv.RATE_LIMIT_MESSAGES + 3):
            await alice.send({"t": "msg", "text": f"flood {i}"})
        assert await alice.expect(lambda f: f["t"] == "error" and "too quickly" in f["text"])
        assert alice.ws.state.name == "OPEN"
        await alice.close()

    async def test_malformed_json_closes_that_connection_only(self, chat):
        alice, _ = await join(chat, "Alice")
        bob, _ = await join(chat, "Bob")
        await bob.ws.send("this is not json")
        await asyncio.wait_for(bob.ws.wait_closed(), timeout=5)
        assert bob.ws.close_code == 1007

        await alice.send({"t": "msg", "text": "unaffected"})
        assert await alice.expect(lambda f: f["t"] == "msg" and f["text"] == "unaffected")
        await alice.close()

    async def test_three_decryption_failures_close_the_connection(self, chat):
        alice, _ = await join(chat, "Alice")
        garbage = p.dumps({"t": "enc", "n": b64e(b"\x00" * 12), "ct": b64e(b"\x00" * 40)})
        for _ in range(srv.MAX_DECRYPT_FAILURES):
            await alice.ws.send(garbage)
        await asyncio.wait_for(alice.ws.wait_closed(), timeout=5)
        assert alice.ws.close_code == 1008

    async def test_fewer_decryption_failures_are_survivable(self, chat):
        alice, _ = await join(chat, "Alice")
        garbage = p.dumps({"t": "enc", "n": b64e(b"\x00" * 12), "ct": b64e(b"\x00" * 40)})
        for _ in range(srv.MAX_DECRYPT_FAILURES - 1):
            await alice.ws.send(garbage)
        await alice.send({"t": "msg", "text": "recovered"})
        assert await alice.expect(lambda f: f["t"] == "msg" and f["text"] == "recovered")
        await alice.close()

    async def test_oversized_frame_is_rejected_before_decryption(self, chat):
        alice, _ = await join(chat, "Alice")
        await alice.ws.send("x" * (p.MAX_FRAME_BYTES * 2))
        await asyncio.wait_for(alice.ws.wait_closed(), timeout=5)
        assert alice.ws.close_code in (1007, 1009)


# --- shutdown -------------------------------------------------------------------------


class TestShutdown:
    async def test_shutdown_notifies_and_closes_everyone(self, chat):
        alice, _ = await join(chat, "Alice")
        await chat.shutdown()
        assert await alice.expect(lambda f: f["t"] == "system" and "shutting down" in f["text"])
        await asyncio.wait_for(alice.ws.wait_closed(), timeout=5)
        assert alice.ws.close_code == 1001
        assert chat.clients == {}

    async def test_shutdown_is_idempotent(self, chat):
        await chat.shutdown()
        await chat.shutdown()


# --- secret hygiene -------------------------------------------------------------------


class TestSecretHygiene:
    async def test_nothing_sensitive_is_logged(self, chat, caplog):
        import logging

        caplog.set_level(logging.DEBUG, logger="pychat.server")
        alice, _ = await join(chat, "Alice")
        await alice.send({"t": "msg", "text": "CANARY-9F2A-DO-NOT-LEAK"})
        await alice.expect(lambda f: f["t"] == "msg")
        ws, _, _ = await handshake(chat, "Mallory", "the-wrong-password")
        await ws.close()
        await alice.close()

        logged = caplog.text
        assert "CANARY-9F2A-DO-NOT-LEAK" not in logged
        assert PASSWORD not in logged
        assert "the-wrong-password" not in logged
        assert b64e(chat.identity.salt) not in logged
