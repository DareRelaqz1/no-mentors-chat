"""Tests for pychat.net — known-hosts pinning, preferences, and the connection lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import json
import queue
import ssl
import threading
import time

import pytest
from websockets.asyncio.server import serve

from pychat import net
from pychat import protocol as p
from pychat import server as srv

PASSWORD = "test-room-password"


# --- known hosts and preferences ------------------------------------------------------


class TestKnownHosts:
    def test_missing_file_reads_as_empty(self, tmp_path):
        assert net.load_known_hosts(tmp_path / "nope") == {}

    def test_round_trip(self, tmp_path):
        path = tmp_path / "known_hosts"
        net.save_known_host("example.com:8765", "a" * 64, path)
        assert net.load_known_hosts(path) == {"example.com:8765": "a" * 64}

    def test_second_host_is_added_not_replaced(self, tmp_path):
        path = tmp_path / "known_hosts"
        net.save_known_host("one:8765", "a" * 64, path)
        net.save_known_host("two:8765", "b" * 64, path)
        assert set(net.load_known_hosts(path)) == {"one:8765", "two:8765"}

    def test_file_is_owner_only(self, tmp_path):
        path = tmp_path / "known_hosts"
        net.save_known_host("example.com:8765", "a" * 64, path)
        assert path.stat().st_mode & 0o777 == 0o600

    @pytest.mark.parametrize("content", ["not json", "[1,2,3]", '"a string"', ""])
    def test_corrupt_file_does_not_break_the_client(self, tmp_path, content):
        path = tmp_path / "known_hosts"
        path.write_text(content)
        assert net.load_known_hosts(path) == {}

    def test_host_key_format(self):
        assert net.host_key("example.com", 8765) == "example.com:8765"


class TestPrefs:
    def test_round_trip(self, tmp_path):
        path = tmp_path / "config.json"
        net.save_prefs({"host": "example.com", "port": 8765, "name": "Alice"}, path)
        assert net.load_prefs(path)["name"] == "Alice"

    def test_password_is_never_persisted(self, tmp_path):
        path = tmp_path / "config.json"
        net.save_prefs({"host": "example.com", "name": "Alice", "password": "hunter2"}, path)
        assert "password" not in net.load_prefs(path)
        assert "hunter2" not in path.read_text()

    def test_corrupt_file_reads_as_empty(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text("{{{")
        assert net.load_prefs(path) == {}


# --- settings and messages ------------------------------------------------------------


class TestSettings:
    def test_url_and_key(self):
        s = net.Settings(host="example.com", port=8765, name="Alice", password=PASSWORD)
        assert s.url == "wss://example.com:8765"
        assert s.key == "example.com:8765"

    def test_ipv6_literals_are_bracketed(self):
        s = net.Settings(host="::1", port=8765, name="Alice", password=PASSWORD)
        assert s.url == "wss://[::1]:8765"

    def test_password_is_not_in_the_repr(self):
        s = net.Settings(host="h", port=1, name="Alice", password="hunter2")
        assert "hunter2" not in repr(s)


class TestEventMessages:
    @pytest.mark.parametrize(
        ("reason", "fragment"),
        [
            (p.REASON_BAD_CREDENTIALS, "Wrong password"),
            (p.REASON_VERSION_MISMATCH, "versions differ"),
            (p.REASON_SERVER_FULL, "full"),
            (p.REASON_RATE_LIMITED, "Too many failed attempts"),
            ("something_unexpected", "refused"),
        ],
    )
    def test_auth_failure_messages_are_human(self, reason, fragment):
        assert fragment in net.AuthFailed(reason).message

    def test_certificate_prompt_is_human_readable(self):
        event = net.CertificateUnknown(host_key="h:1", fingerprint="aabbcc")
        assert event.readable == "AA:BB:CC"

    def test_tls_context_pins_rather_than_validates(self):
        ctx = net._pinning_ssl_context()
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3


# --- live connection ------------------------------------------------------------------


@pytest.fixture
def live_server(tmp_path):
    """A real server on its own thread and event loop.

    The tests in this module are synchronous on purpose: they consume the network
    layer from a foreign thread exactly as the Tk main loop does. That means the
    server cannot share the test's thread, so it gets its own — which is also how it
    runs in production.
    """
    config = srv.Config(password=PASSWORD, port=0, host="127.0.0.1", data_dir=tmp_path / "data")
    server = srv.ChatServer(config)
    ctx = srv.build_ssl_context(server.identity.cert_path, server.identity.key_path)
    ready = threading.Event()
    state: dict = {}

    def run() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        state["loop"] = loop

        async def main() -> None:
            async with serve(
                server.handle, "127.0.0.1", 0, ssl=ctx, max_size=p.MAX_FRAME_BYTES
            ) as ws:
                server.test_port = next(iter(ws.sockets)).getsockname()[1]  # type: ignore[attr-defined]
                state["stop"] = loop.create_future()
                ready.set()
                await state["stop"]
            await server.shutdown()

        try:
            loop.run_until_complete(main())
        finally:
            loop.close()

    thread = threading.Thread(target=run, name="test-chat-server", daemon=True)
    thread.start()
    assert ready.wait(timeout=20), "the test server did not start"

    yield server

    loop = state["loop"]
    stop = state["stop"]
    with contextlib.suppress(RuntimeError):
        loop.call_soon_threadsafe(lambda: stop.done() or stop.set_result(None))
    thread.join(timeout=10)


def drain(client: net.NetworkClient, kind, timeout=15.0, pred=None, auto_accept=True):
    """Block the calling thread until a matching event arrives, or return None.

    The network layer runs on its own thread, so this is exactly how the UI consumes
    it — just synchronously instead of from a Tk callback.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            event = client.events.get(timeout=0.2)
        except queue.Empty:
            continue
        if auto_accept and isinstance(event, net.CertificateUnknown):
            client.answer_certificate(True)
        if isinstance(event, kind) and (pred is None or pred(event)):
            return event
    return None


@pytest.fixture
def client_factory(live_server, tmp_path):
    """Builds NetworkClients against the live server, and stops them afterwards."""
    created: list[net.NetworkClient] = []

    def make(name: str, password: str = PASSWORD) -> net.NetworkClient:
        client = net.NetworkClient(
            net.Settings(
                host="127.0.0.1", port=live_server.test_port, name=name, password=password
            ),
            known_hosts_path=tmp_path / "known_hosts",
        )
        created.append(client)
        return client

    yield make
    for client in created:
        client.stop(timeout=5)


class TestConnection:
    """These drive the network thread from the test thread, so they are not asyncio tests."""

    def test_connects_pins_and_authenticates(self, client_factory, tmp_path):
        client = client_factory("Alice")
        client.start()

        prompt = drain(client, net.CertificateUnknown, auto_accept=False)
        assert prompt is not None
        assert len(prompt.fingerprint) == 64
        assert not (tmp_path / "known_hosts").exists(), "must not pin before the user accepts"

        client.answer_certificate(True)
        connected = drain(client, net.Connected)
        assert connected is not None
        assert connected.name == "Alice"
        assert net.load_known_hosts(tmp_path / "known_hosts")[connected.host] == prompt.fingerprint

    def test_declining_the_certificate_aborts(self, client_factory, tmp_path):
        client = client_factory("Alice")
        client.start()
        assert drain(client, net.CertificateUnknown, auto_accept=False) is not None
        client.answer_certificate(False)

        failure = drain(client, net.ConnectionFailed)
        assert failure is not None and failure.fatal
        assert not (tmp_path / "known_hosts").exists()

    def test_pinned_mismatch_is_refused_and_not_overwritten(self, client_factory, tmp_path):
        path = tmp_path / "known_hosts"
        client = client_factory("Alice")
        net.save_known_host(client.settings.key, "0" * 64, path)

        client.start()
        mismatch = drain(client, net.CertificateMismatch)
        assert mismatch is not None and mismatch.expected == "0" * 64

        failure = drain(client, net.ConnectionFailed)
        assert failure is not None and failure.fatal and "CHANGED" in failure.message
        assert json.loads(path.read_text())[client.settings.key] == "0" * 64

    def test_wrong_password_reports_auth_failure(self, client_factory):
        client = client_factory("Alice", password="the-wrong-password")
        client.start()
        failure = drain(client, net.AuthFailed)
        assert failure is not None
        assert failure.reason == p.REASON_BAD_CREDENTIALS
        assert "Wrong password" in failure.message

    def test_messages_flow_between_two_clients(self, client_factory):
        alice, bob = client_factory("Alice"), client_factory("Bob")
        alice.start()
        assert drain(alice, net.Connected) is not None
        bob.start()
        assert drain(bob, net.Connected) is not None

        alice.send_message("hello from Alice")
        received = drain(bob, net.Frame, pred=lambda e: e.kind == "msg")
        assert received is not None and received.inner["text"] == "hello from Alice"
        assert received.inner["name"] == "Alice"

        echoed = drain(alice, net.Frame, pred=lambda e: e.kind == "msg")
        assert echoed is not None and echoed.inner["text"] == "hello from Alice"

    def test_roster_and_system_frames_arrive(self, client_factory):
        alice, bob = client_factory("Alice"), client_factory("Bob")
        alice.start()
        assert drain(alice, net.Connected) is not None
        bob.start()
        assert drain(bob, net.Connected) is not None

        joined = drain(alice, net.Frame, pred=lambda e: e.kind == "system")
        assert joined is not None and "Bob joined" in joined.inner["text"]
        roster = drain(
            alice, net.Frame, pred=lambda e: e.kind == "roster" and len(e.inner["users"]) == 2
        )
        assert roster is not None

    def test_oversized_message_is_refused_locally_with_an_explanation(self, client_factory):
        """The byte limit bites before the character limit for non-Latin scripts."""
        alice = client_factory("Alice")
        alice.start()
        assert drain(alice, net.Connected) is not None

        alice.send_message("😀" * p.MAX_MESSAGE_CHARS)
        error = drain(alice, net.Frame, pred=lambda e: e.kind == "error")
        assert error is not None and "too large" in error.inner["text"]

    def test_stop_is_clean_and_leaves_no_thread(self, client_factory):
        alice = client_factory("Alice")
        alice.start()
        assert drain(alice, net.Connected) is not None

        alice.stop(timeout=5)
        assert not alice.running
        assert not [t for t in threading.enumerate() if t.name == "pychat-net" and t.is_alive()]

    def test_stop_before_connecting_is_safe(self, client_factory):
        alice = client_factory("Alice")
        alice.start()
        alice.stop(timeout=5)
        assert not alice.running

    def test_stop_is_idempotent(self, client_factory):
        alice = client_factory("Alice")
        alice.start()
        alice.stop(timeout=5)
        alice.stop(timeout=5)

    def test_sending_while_disconnected_reports_instead_of_raising(self, client_factory):
        alice = client_factory("Alice")
        alice.start()
        assert drain(alice, net.Connected) is not None
        alice.stop(timeout=5)
        alice.send_message("into the void")  # must not raise


class TestBackoff:
    def test_sequence_matches_the_specification(self):
        """1, 2, 4, 8, 16 then capped at 30 — not 0.5 as an off-by-one would give."""
        delays = [net.NetworkClient.backoff_delay(n) for n in range(6)]
        assert delays == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0]

    def test_is_capped(self):
        assert net.NetworkClient.backoff_delay(50) == net.BACKOFF_CAP

    def test_total_retry_window_covers_a_server_reboot(self):
        """The six attempts must span long enough for a small instance to come back."""
        total = sum(net.NetworkClient.backoff_delay(n) for n in range(net.MAX_RECONNECT_ATTEMPTS))
        assert total >= 60
