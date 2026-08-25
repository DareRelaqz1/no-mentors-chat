"""Client-side network layer: TLS, certificate pinning, auth, and reconnection.

This module is deliberately UI-free. It owns an asyncio event loop on a background
daemon thread and communicates with whatever drives it through two channels:

* outward — :class:`NetworkClient.events`, a plain ``queue.Queue`` of :class:`Event`
  objects that the UI thread drains from its own main loop,
* inward — thread-safe methods (:meth:`send_message`, :meth:`answer_certificate`,
  :meth:`stop`) that marshal onto the loop with ``run_coroutine_threadsafe``.

No Tk object is ever touched from here, and the expensive scrypt derivation runs on
this thread so the UI never blocks on it (§6.1).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import queue
import ssl
import threading
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import websockets
from cryptography.exceptions import InvalidTag
from websockets.asyncio.client import connect

from . import protocol as p
from .crypto import derive_key, fingerprint, format_fingerprint, make_proof

log = logging.getLogger("pychat.net")

CONFIG_DIR = Path.home() / ".pychat"
KNOWN_HOSTS_PATH = CONFIG_DIR / "known_hosts"
PREFS_PATH = CONFIG_DIR / "config.json"

CONNECT_TIMEOUT = 10.0
HANDSHAKE_TIMEOUT = 10.0
MAX_RECONNECT_ATTEMPTS = 6
BACKOFF_CAP = 30.0
PING_INTERVAL = 20
PING_TIMEOUT = 20


# --- events -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Event:
    """Base class for everything the network layer reports to the UI."""


@dataclass(frozen=True)
class Connecting(Event):
    attempt: int


@dataclass(frozen=True)
class CertificateUnknown(Event):
    """First contact with this host. The UI must call ``answer_certificate``."""

    host_key: str
    fingerprint: str

    @property
    def readable(self) -> str:
        return format_fingerprint(self.fingerprint)


@dataclass(frozen=True)
class CertificateMismatch(Event):
    """The pinned fingerprint changed. Fatal, and deliberately not overridable."""

    host_key: str
    expected: str
    actual: str


@dataclass(frozen=True)
class Connected(Event):
    user_id: str
    name: str
    roster: list[dict[str, str]]
    host: str
    reconnected: bool = False


@dataclass(frozen=True)
class AuthFailed(Event):
    reason: str

    @property
    def message(self) -> str:
        return {
            p.REASON_BAD_CREDENTIALS: "Wrong password, or the name was rejected by the server.",
            p.REASON_VERSION_MISMATCH: "Client and server versions differ — update one of them.",
            p.REASON_SERVER_FULL: "The room is full. Try again later.",
            p.REASON_RATE_LIMITED: (
                "Too many failed attempts from this address. Wait 15 minutes and try again."
            ),
        }.get(self.reason, "The server refused the connection.")


@dataclass(frozen=True)
class ConnectionFailed(Event):
    """Could not reach or complete a connection. ``fatal`` means do not retry."""

    message: str
    fatal: bool = False


@dataclass(frozen=True)
class Disconnected(Event):
    reason: str
    will_retry: bool


@dataclass(frozen=True)
class Reconnecting(Event):
    attempt: int
    delay: float
    max_attempts: int = MAX_RECONNECT_ATTEMPTS


@dataclass(frozen=True)
class GaveUp(Event):
    attempts: int


@dataclass(frozen=True)
class Frame(Event):
    """An application frame from the server: msg, system, roster, error or pong."""

    inner: dict[str, Any]

    @property
    def kind(self) -> str:
        return self.inner.get("t", "")


@dataclass(frozen=True)
class Stopped(Event):
    """The network thread has finished. Always the last event."""


# --- known hosts (trust on first use, §3.2) ---------------------------------------------


def host_key(host: str, port: int) -> str:
    return f"{host}:{port}"


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        # A corrupt file must not stop the client; treat it as empty.
        return default


def load_known_hosts(path: Path = KNOWN_HOSTS_PATH) -> dict[str, str]:
    data = _read_json(path, {})
    return data if isinstance(data, dict) else {}


def save_known_host(key: str, digest: str, path: Path = KNOWN_HOSTS_PATH) -> None:
    hosts = load_known_hosts(path)
    hosts[key] = digest
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(hosts, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def load_prefs(path: Path = PREFS_PATH) -> dict[str, Any]:
    """Remembered host and name. Never contains the password."""
    data = _read_json(path, {})
    return data if isinstance(data, dict) else {}


def save_prefs(prefs: dict[str, Any], path: Path = PREFS_PATH) -> None:
    prefs.pop("password", None)  # belt and braces: never persist the password
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(prefs, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


# --- connection settings ------------------------------------------------------------------


@dataclass
class Settings:
    host: str
    port: int
    name: str
    password: str = field(repr=False)  # never shown in a traceback

    @property
    def key(self) -> str:
        return host_key(self.host, self.port)

    @property
    def url(self) -> str:
        # Bracket IPv6 literals so the URL stays parseable.
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"wss://{host}:{self.port}"


class PinningError(Exception):
    """The server's certificate was not accepted."""

    def __init__(self, message: str, *, fatal: bool = True) -> None:
        super().__init__(message)
        self.fatal = fatal


# --- the network client -------------------------------------------------------------------


class NetworkClient:
    """Owns the connection lifecycle on a background thread."""

    def __init__(self, settings: Settings, known_hosts_path: Path = KNOWN_HOSTS_PATH) -> None:
        self.settings = settings
        self.known_hosts_path = known_hosts_path
        self.events: queue.Queue[Event] = queue.Queue()

        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ws: Any = None
        self._key: bytes | None = None  # derived once, reused across reconnects
        self._cert_answer: asyncio.Future[bool] | None = None
        self._stopping = threading.Event()
        self._ready = threading.Event()

    # --- thread control -------------------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="pychat-net", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._ready.set()
        try:
            loop.run_until_complete(self._main())
        except Exception:
            log.exception("network thread died")
        finally:
            with contextlib.suppress(Exception):
                _cancel_pending(loop)
            loop.close()
            self._emit(Stopped())

    def stop(self, timeout: float = 5.0) -> None:
        """Ask the loop to close the connection and finish. Safe from any thread."""
        self._stopping.set()
        self._submit(self._close_socket)
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # --- calls from the UI thread ---------------------------------------------------------

    def send_message(self, text: str) -> None:
        self._submit(lambda: self._send_inner({"t": "msg", "text": text}))

    def send_ping(self) -> None:
        self._submit(lambda: self._send_inner({"t": "ping"}))

    def answer_certificate(self, accepted: bool) -> None:
        """Answer a CertificateUnknown prompt. Safe from the UI thread."""
        loop, future = self._loop, self._cert_answer
        if loop is None or future is None or future.done():
            return
        loop.call_soon_threadsafe(lambda: future.done() or future.set_result(accepted))

    def _submit(self, factory: Callable[[], Coroutine[Any, Any, None]]) -> None:
        """Run a coroutine on the network loop from any thread.

        The coroutine object is built on the loop thread, not here. Constructing it
        eagerly and handing it to a loop that has already finished leaves it un-awaited,
        which Python reports as a RuntimeWarning during shutdown.
        """
        loop = self._loop
        if loop is None or loop.is_closed():
            return

        def _start() -> None:
            with contextlib.suppress(Exception):
                asyncio.get_running_loop().create_task(factory())

        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(_start)

    # --- the connection lifecycle ---------------------------------------------------------

    @staticmethod
    def backoff_delay(failures: int) -> float:
        """Seconds to wait before the next attempt: 1, 2, 4, 8, 16, then capped at 30."""
        return min(2.0**failures, BACKOFF_CAP)

    async def _main(self) -> None:
        # Consecutive failed attempts. Kept separate from the attempt *number* on
        # purpose: using one counter for both makes the first retry wait 2**-1 seconds
        # and shortens the whole retry window, which matters when what you are waiting
        # for is a server rebooting.
        failures = 0
        connected_before = False

        while not self._stopping.is_set():
            self._emit(Connecting(attempt=failures + 1))
            try:
                await self._session(reconnected=connected_before)
                connected_before = True
                failures = 0  # a successful session resets the backoff
                if self._stopping.is_set():
                    break
                self._emit(Disconnected("Connection lost.", will_retry=True))
            except PinningError as exc:
                self._emit(ConnectionFailed(str(exc), fatal=True))
                return
            except AuthRefused as exc:
                self._emit(AuthFailed(exc.reason))
                return
            except (OSError, ssl.SSLError, websockets.exceptions.WebSocketException) as exc:
                message = _friendly_error(exc, self.settings)
                if not connected_before:
                    # The very first attempt failing is a setup problem, not a blip:
                    # report it and let the user fix the host, port or password.
                    self._emit(ConnectionFailed(message))
                    return
                failures += 1
                self._emit(Disconnected(message, will_retry=True))
            except asyncio.CancelledError:
                break
            except Exception as exc:  # never let the thread die silently
                log.exception("unexpected error in session")
                if not connected_before:
                    self._emit(ConnectionFailed(f"Unexpected error: {exc}"))
                    return
                failures += 1
                self._emit(Disconnected(f"Unexpected error: {exc}", will_retry=True))

            if self._stopping.is_set():
                break
            if failures >= MAX_RECONNECT_ATTEMPTS:
                self._emit(GaveUp(attempts=failures))
                return

            delay = self.backoff_delay(failures)
            self._emit(Reconnecting(attempt=failures + 1, delay=delay))
            if await self._sleep_or_stop(delay):
                break

    async def _sleep_or_stop(self, delay: float) -> bool:
        """Sleep, waking early if stop() is called. Returns True if we should stop."""
        deadline = time.monotonic() + delay
        while time.monotonic() < deadline:
            if self._stopping.is_set():
                return True
            await asyncio.sleep(0.1)
        return self._stopping.is_set()

    async def _session(self, *, reconnected: bool) -> None:
        """One full connection: TLS, pinning, auth, then the read loop."""
        ws = await asyncio.wait_for(
            connect(
                self.settings.url,
                ssl=_pinning_ssl_context(),
                max_size=p.MAX_FRAME_BYTES,
                ping_interval=PING_INTERVAL,
                ping_timeout=PING_TIMEOUT,
                open_timeout=CONNECT_TIMEOUT,
            ),
            timeout=CONNECT_TIMEOUT + 5,
        )
        self._ws = ws
        try:
            # Pin before any authentication material leaves this process (§3.2).
            await self._verify_certificate(ws)
            await self._authenticate(ws, reconnected=reconnected)
            await self._read_loop(ws)
        finally:
            self._ws = None
            with contextlib.suppress(Exception):
                await ws.close()

    async def _verify_certificate(self, ws: Any) -> None:
        ssl_object = ws.transport.get_extra_info("ssl_object")
        if ssl_object is None:
            raise PinningError("The connection is not using TLS.")
        der = ssl_object.getpeercert(binary_form=True)
        if not der:
            raise PinningError("The server did not present a certificate.")

        digest = fingerprint(der)
        key = self.settings.key
        pinned = load_known_hosts(self.known_hosts_path).get(key)

        if pinned is None:
            self._cert_answer = asyncio.get_running_loop().create_future()
            self._emit(CertificateUnknown(host_key=key, fingerprint=digest))
            try:
                accepted = await self._await_certificate_answer(self._cert_answer)
            finally:
                self._cert_answer = None
            if not accepted:
                raise PinningError("You did not accept the server's certificate.")
            save_known_host(key, digest, self.known_hosts_path)
            log.info("pinned new host %s", key)
            return

        if pinned != digest:
            self._emit(CertificateMismatch(host_key=key, expected=pinned, actual=digest))
            raise PinningError(
                f"The server identity for {key} has CHANGED. This can mean someone is "
                f"intercepting the connection. If you are certain the server was "
                f"legitimately rebuilt, remove the entry for {key} from "
                f"{self.known_hosts_path} and connect again."
            )

    async def _await_certificate_answer(self, future: asyncio.Future[bool]) -> bool:
        """Wait for the user's verdict, but never past a stop().

        Polling the stop flag rather than only relying on stop() resolving the future
        keeps this correct whichever order the two happen in — closing the window while
        the fingerprint prompt is still open used to strand this thread forever.
        """
        while not self._stopping.is_set():
            try:
                return await asyncio.wait_for(asyncio.shield(future), timeout=0.2)
            except TimeoutError:
                continue
        return False

    async def _authenticate(self, ws: Any, *, reconnected: bool) -> None:
        raw = await asyncio.wait_for(ws.recv(), timeout=HANDSHAKE_TIMEOUT)
        hello = p.parse_frame(raw)
        if hello.get("t") == "auth_fail":
            raise AuthRefused(str(hello.get("reason", "")))

        _, salt, nonce = p.parse_server_hello(hello)

        # scrypt costs ~100 ms and runs on this thread by design. Derived once; a
        # reconnect reuses it so the user is never re-prompted for the password.
        if self._key is None:
            self._key = derive_key(self.settings.password, salt)
        key = self._key

        name = p.normalize_name(self.settings.name)
        await ws.send(p.dumps(p.auth_frame(name, make_proof(key, nonce, name))))

        reply_raw = await asyncio.wait_for(ws.recv(), timeout=HANDSHAKE_TIMEOUT)
        reply = p.parse_frame(reply_raw)
        if reply.get("t") == "auth_fail":
            raise AuthRefused(str(reply.get("reason", "")))

        inner = p.decode_envelope(key, reply)
        if inner.get("t") != "auth_ok":
            raise p.ProtocolError(f"expected auth_ok, got {inner.get('t')!r}")

        self._emit(
            Connected(
                user_id=inner["user_id"],
                name=inner["name"],
                roster=inner.get("roster", []),
                host=self.settings.key,
                reconnected=reconnected,
            )
        )

    async def _read_loop(self, ws: Any) -> None:
        assert self._key is not None
        failures = 0
        async for raw in ws:
            try:
                inner = p.decode_envelope(self._key, p.parse_frame(raw))
            except InvalidTag:
                failures += 1
                log.warning("decryption failure %d/3 from server", failures)
                if failures >= 3:
                    raise PinningError(
                        "The server sent data this client could not decrypt. Either the "
                        "room password changed or something is tampering with the traffic.",
                    ) from None
                continue
            except p.ProtocolError as exc:
                log.warning("ignoring malformed frame from server: %s", exc)
                continue
            self._emit(Frame(inner))

    # --- sending --------------------------------------------------------------------------

    async def _send_inner(self, inner: dict[str, Any]) -> None:
        ws, key = self._ws, self._key
        if ws is None or key is None:
            self._emit(Frame(p.error_frame("Not connected — your message was not sent.")))
            return
        wire = p.encode_envelope(key, inner)
        if not p.fits_in_frame(wire):
            self._emit(
                Frame(
                    p.error_frame(
                        "That message is too large to send. Shorten it and try again — "
                        "the limit is a size in bytes, so emoji and non-Latin scripts "
                        "use up more of it than plain letters."
                    )
                )
            )
            return
        try:
            await ws.send(wire)
        except Exception as exc:
            log.info("send failed: %s", exc)
            self._emit(Frame(p.error_frame("Your message could not be sent — reconnecting.")))

    async def _close_socket(self) -> None:
        ws = self._ws
        if ws is not None:
            with contextlib.suppress(Exception):
                await ws.close(1000, "client closing")

    # --- plumbing -------------------------------------------------------------------------

    def _emit(self, event: Event) -> None:
        self.events.put(event)


class AuthRefused(Exception):
    """The server sent auth_fail."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _pinning_ssl_context() -> ssl.SSLContext:
    """A context that skips PKI validation because §3.2 pins the certificate instead.

    Verification is not being *skipped* — it is being done by fingerprint, immediately
    after the handshake and before anything is sent. A self-signed certificate cannot
    chain to a public root, so hostname and chain checks are meaningless here.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def _friendly_error(exc: BaseException, settings: Settings) -> str:
    where = f"{settings.host}:{settings.port}"
    if isinstance(exc, TimeoutError | asyncio.TimeoutError):
        return f"Timed out connecting to {where}."
    if isinstance(exc, ConnectionRefusedError):
        return f"Could not reach the server at {where} — nothing is listening there."
    if isinstance(exc, OSError) and getattr(exc, "errno", None) in (-2, -3, -5):
        return f"Could not look up the host {settings.host!r}."
    if isinstance(exc, ssl.SSLError):
        return f"TLS handshake with {where} failed: {exc}"
    if isinstance(exc, websockets.exceptions.InvalidMessage | websockets.exceptions.InvalidStatus):
        return f"{where} answered, but it does not look like a pychat server."
    if isinstance(exc, websockets.exceptions.ConnectionClosed):
        return "The server closed the connection."
    if isinstance(exc, OSError):
        return f"Could not reach the server at {where}: {exc.strerror or exc}"
    return f"Could not connect to {where}: {exc}"


def _cancel_pending(loop: asyncio.AbstractEventLoop) -> None:
    pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
    for task in pending:
        task.cancel()
    if pending:
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
