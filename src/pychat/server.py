"""pychat server — headless, async, relays encrypted frames between room members.

Run with ``python -m pychat.server``. Configuration comes from the environment only;
see the README for the full table. The one hard requirement is PYCHAT_ROOM_PASSWORD.

Design notes worth knowing before changing anything here:

* The server holds the room key. This is not end-to-end encryption (§3.5) — it decrypts
  each inbound frame and re-encrypts on relay.
* Nothing here ever logs the password, the key, the salt, or message plaintext.
* A connection handler must never take the process down with it: every one is wrapped,
  and every malformed input is an expected input.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import ssl
import sys
import time
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import websockets
from cryptography.exceptions import InvalidTag
from websockets.asyncio.server import ServerConnection, serve

from . import protocol as p
from .crypto import (
    derive_key,
    generate_nonce,
    load_or_create_identity,
    new_user_id,
    verify_proof,
)

log = logging.getLogger("pychat.server")

# --- tunables not covered by the protocol constants ------------------------------------

MIN_PASSWORD_CHARS = 8
RATE_LIMIT_MESSAGES = 10
RATE_LIMIT_WINDOW = 5.0
MAX_DECRYPT_FAILURES = 3
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW = 300.0  # 5 minutes of failures...
LOCKOUT_DURATION = 900.0  # ...earns 15 minutes of refusal
PING_INTERVAL = 20
PING_TIMEOUT = 20


class ConfigError(Exception):
    """The server cannot start with the configuration it was given."""


@dataclass(slots=True)
class Config:
    password: str
    port: int = 8765
    # A chat server is meant to be reachable, so it binds all interfaces by default.
    host: str = "0.0.0.0"
    data_dir: Path = Path("/data")
    public_host: str | None = None
    log_level: str = "INFO"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Config:
        env = dict(os.environ if env is None else env)

        password = env.get("PYCHAT_ROOM_PASSWORD", "")
        if not password:
            raise ConfigError(
                "PYCHAT_ROOM_PASSWORD is not set. The server refuses to start without a "
                "room password. Set it in the environment (see .env.example); never put "
                "it in a file that git tracks."
            )
        if len(password) < MIN_PASSWORD_CHARS:
            raise ConfigError(
                f"PYCHAT_ROOM_PASSWORD is too short: it must be at least "
                f"{MIN_PASSWORD_CHARS} characters."
            )

        raw_port = env.get("PYCHAT_PORT", "8765")
        try:
            port = int(raw_port)
        except ValueError as exc:
            raise ConfigError(f"PYCHAT_PORT must be an integer, got {raw_port!r}") from exc
        if not 1 <= port <= 65535:
            raise ConfigError(f"PYCHAT_PORT must be between 1 and 65535, got {port}")

        return cls(
            password=password,
            port=port,
            host=env.get("PYCHAT_BIND_HOST", "0.0.0.0"),
            data_dir=Path(env.get("PYCHAT_DATA_DIR", "/data")),
            public_host=(env.get("PYCHAT_PUBLIC_HOST") or "").strip() or None,
            log_level=env.get("PYCHAT_LOG_LEVEL", "INFO").upper(),
        )

    def cert_hosts(self) -> list[str]:
        """Names to place in the certificate SAN."""
        hosts = ["localhost", "127.0.0.1"]
        if self.public_host and self.public_host not in hosts:
            hosts.insert(0, self.public_host)
        return hosts


@dataclass(slots=True)
class Client:
    """One authenticated connection."""

    user_id: str
    name: str
    ws: ServerConnection
    sent_at: deque[float] = field(default_factory=deque)
    # Set once the room has been told this client left, so the two paths that can
    # notice a departure — a failed broadcast and the handler's finally — announce once.
    departed: bool = False

    def roster_entry(self) -> dict[str, str]:
        return {"user_id": self.user_id, "name": self.name}

    def rate_limited(self, now: float) -> bool:
        """Sliding window of RATE_LIMIT_MESSAGES per RATE_LIMIT_WINDOW seconds."""
        while self.sent_at and now - self.sent_at[0] > RATE_LIMIT_WINDOW:
            self.sent_at.popleft()
        if len(self.sent_at) >= RATE_LIMIT_MESSAGES:
            return True
        self.sent_at.append(now)
        return False


class LockoutTracker:
    """Per-IP failed-authentication lockout, kept in memory (§3.3.6)."""

    def __init__(self) -> None:
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}

    def is_locked(self, ip: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        until = self._locked_until.get(ip)
        if until is None:
            return False
        if now >= until:
            del self._locked_until[ip]
            self._failures.pop(ip, None)
            return False
        return True

    def record_failure(self, ip: str, now: float | None = None) -> bool:
        """Record a failed attempt. Returns True if this triggered a lockout."""
        now = time.monotonic() if now is None else now
        failures = self._failures.setdefault(ip, deque())
        failures.append(now)
        while failures and now - failures[0] > LOCKOUT_WINDOW:
            failures.popleft()
        if len(failures) >= LOCKOUT_THRESHOLD:
            self._locked_until[ip] = now + LOCKOUT_DURATION
            failures.clear()
            return True
        return False

    def record_success(self, ip: str) -> None:
        self._failures.pop(ip, None)


class ChatServer:
    """Holds the room state. One instance per process."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.identity = load_or_create_identity(config.data_dir, config.cert_hosts())
        # Derived once at startup: scrypt is deliberately expensive.
        self._key = derive_key(config.password, self.identity.salt)
        self.clients: dict[str, Client] = {}
        self.lockouts = LockoutTracker()
        self._shutting_down = False

    # --- sending ----------------------------------------------------------------------

    async def _send(self, client: Client, inner: dict) -> None:
        """Send one encrypted frame. Failure is the caller's problem, not a crash."""
        await client.ws.send(p.encode_envelope(self._key, inner))

    async def send_to(self, client: Client, inner: dict) -> None:
        with contextlib.suppress(Exception):
            await self._send(client, inner)

    async def broadcast(self, inner: dict, *, targets: Iterable[Client] | None = None) -> None:
        """Fan out to every authenticated client, including the sender.

        One slow or dead peer must never stall or kill the loop, so sends run
        concurrently and failures are collected rather than raised.
        """
        recipients = list(self.clients.values() if targets is None else targets)
        if not recipients:
            return
        results = await asyncio.gather(
            *(self._send(c, inner) for c in recipients), return_exceptions=True
        )
        failed = [
            c for c, r in zip(recipients, results, strict=True) if isinstance(r, BaseException)
        ]
        if failed:
            # Drop them all before announcing, so the roster we send is already correct.
            for client in failed:
                self.clients.pop(client.user_id, None)
            await asyncio.gather(
                *(self.depart(c, "send failed") for c in failed), return_exceptions=True
            )

    async def depart(self, client: Client, reason: str) -> None:
        """Remove a client and tell the room. Idempotent, and safe to call from anywhere.

        Two things can notice a departure: a broadcast whose send raised, and the
        connection handler unwinding. Both call this; the ``departed`` flag makes the
        second call a no-op so nobody gets two leave notices.
        """
        if client.departed:
            return
        client.departed = True
        self.clients.pop(client.user_id, None)
        with contextlib.suppress(Exception):
            await client.ws.close(1011, reason)
        log.info("left id=%s name=%s reason=%s", client.user_id, client.name, reason)
        if not self._shutting_down:
            await self.broadcast(p.system_frame(f"{client.name} left the chat"))
            await self.broadcast_roster()

    async def broadcast_roster(self) -> None:
        await self.broadcast(p.roster_frame(self.roster()))

    def roster(self) -> list[dict[str, str]]:
        return sorted(
            (c.roster_entry() for c in self.clients.values()), key=lambda e: e["name"].casefold()
        )

    # --- names ------------------------------------------------------------------------

    def unique_name(self, name: str) -> str:
        """Append #2, #3, … until the name is free (§5.3)."""
        taken = {c.name.casefold() for c in self.clients.values()}
        if name.casefold() not in taken:
            return name
        for suffix in range(2, p.MAX_CLIENTS + 3):
            candidate = f"{name}#{suffix}"
            # Keep the result inside the length limit by trimming the base, not the tag.
            if len(candidate) > p.MAX_NAME_CHARS:
                candidate = f"{name[: p.MAX_NAME_CHARS - len(str(suffix)) - 1]}#{suffix}"
            if candidate.casefold() not in taken:
                return candidate
        return f"user-{new_user_id()[:6]}"

    # --- connection lifecycle ---------------------------------------------------------

    async def handle(self, ws: ServerConnection) -> None:
        """Top-level per-connection handler. Must never raise."""
        peer_ip = _peer_ip(ws)
        client: Client | None = None
        try:
            client = await self._authenticate(ws, peer_ip)
            if client is None:
                return
            await self._serve_client(client)
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception:
            log.exception("connection handler failed (ip=%s)", peer_ip)
            with contextlib.suppress(Exception):
                await ws.close(1011, "internal error")
        finally:
            if client is not None:
                await self.depart(client, "disconnected")

    async def _authenticate(self, ws: ServerConnection, peer_ip: str) -> Client | None:
        """Run the challenge-response handshake. Returns None if the client was refused."""
        if self.lockouts.is_locked(peer_ip):
            log.warning("refused locked-out ip=%s", peer_ip)
            await _send_plain(ws, p.auth_fail(p.REASON_RATE_LIMITED))
            await ws.close(1008, "rate limited")
            return None

        if len(self.clients) >= p.MAX_CLIENTS:
            log.warning("refused connection from ip=%s: server full", peer_ip)
            await _send_plain(ws, p.auth_fail(p.REASON_SERVER_FULL))
            await ws.close(1013, "server full")
            return None

        challenge = generate_nonce()
        await _send_plain(ws, p.server_hello(self.identity.salt, challenge))

        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=p.AUTH_TIMEOUT_SECONDS)
        except TimeoutError:
            log.info("auth timeout ip=%s", peer_ip)
            await ws.close(1008, "auth timeout")
            return None

        try:
            version, raw_name, display_name, proof = p.parse_auth(p.parse_frame(raw))
        except p.ProtocolError as exc:
            log.info("malformed auth from ip=%s: %s", peer_ip, exc)
            await _send_plain(ws, p.auth_fail(p.REASON_BAD_CREDENTIALS))
            await ws.close(1008, "bad auth frame")
            return None

        if version != p.PROTOCOL_VERSION:
            log.info("version mismatch ip=%s client_version=%s", peer_ip, version)
            await _send_plain(ws, p.auth_fail(p.REASON_VERSION_MISMATCH))
            await ws.close(1008, "version mismatch")
            return None

        # Verified against the name as sent, not the normalised one — see parse_auth.
        if not verify_proof(self._key, challenge, raw_name, proof):
            # Never log the attempted material, and never tell the client which part failed.
            locked = self.lockouts.record_failure(peer_ip)
            log.warning("auth failure ip=%s%s", peer_ip, " (ip now locked out)" if locked else "")
            await _send_plain(ws, p.auth_fail(p.REASON_BAD_CREDENTIALS))
            await ws.close(1008, "auth failed")
            return None

        self.lockouts.record_success(peer_ip)
        client = Client(user_id=new_user_id(), name=self.unique_name(display_name), ws=ws)
        self.clients[client.user_id] = client

        await self._send(client, p.auth_ok(client.user_id, client.name, self.roster()))
        log.info("joined id=%s name=%s ip=%s", client.user_id, client.name, peer_ip)
        await self.broadcast(
            p.system_frame(f"{client.name} joined the chat"),
            targets=[c for c in self.clients.values() if c.user_id != client.user_id],
        )
        await self.broadcast_roster()
        return client

    async def _serve_client(self, client: Client) -> None:
        """Read frames until the peer goes away."""
        decrypt_failures = 0
        async for raw in client.ws:
            try:
                envelope = p.parse_frame(raw)
            except p.ProtocolError as exc:
                log.info("malformed frame id=%s: %s", client.user_id, exc)
                await client.ws.close(1007, "malformed frame")
                return

            try:
                inner = p.decode_envelope(self._key, envelope)
            except InvalidTag:
                decrypt_failures += 1
                log.warning(
                    "decryption failure %d/%d id=%s",
                    decrypt_failures,
                    MAX_DECRYPT_FAILURES,
                    client.user_id,
                )
                if decrypt_failures >= MAX_DECRYPT_FAILURES:
                    await client.ws.close(1008, "too many decryption failures")
                    return
                continue
            except p.ProtocolError as exc:
                log.info("bad envelope id=%s: %s", client.user_id, exc)
                await client.ws.close(1007, "malformed envelope")
                return

            await self._dispatch(client, inner)

    async def _dispatch(self, client: Client, inner: dict) -> None:
        kind = inner.get("t")
        if kind == "msg":
            await self._on_message(client, inner)
        elif kind == "ping":
            await self.send_to(client, {"t": "pong"})
        else:
            # Unknown frame types are ignored on purpose — forward compatibility.
            log.debug("ignoring unknown frame type %r from id=%s", kind, client.user_id)

    async def _on_message(self, client: Client, inner: dict) -> None:
        try:
            text = p.parse_client_message(inner)
        except p.ProtocolError:
            await self.send_to(client, p.error_frame("Malformed message, ignored."))
            return

        text = text.strip()
        if not text:
            return

        if len(text) > p.MAX_MESSAGE_CHARS:
            await self.send_to(
                client, p.error_frame(f"Message too long (limit {p.MAX_MESSAGE_CHARS} characters).")
            )
            return

        if client.rate_limited(time.monotonic()):
            log.info("rate limited id=%s", client.user_id)
            await self.send_to(client, p.error_frame("You are sending messages too quickly."))
            return

        log.info("msg id=%s name=%s bytes=%d", client.user_id, client.name, len(text.encode()))
        await self.broadcast(p.msg_frame(client.user_id, client.name, text))

    # --- shutdown ---------------------------------------------------------------------

    async def shutdown(self) -> None:
        """Tell everyone, then close every connection politely (§5.1)."""
        if self._shutting_down:
            return
        self._shutting_down = True
        log.info("shutting down, notifying %d client(s)", len(self.clients))
        await self.broadcast(p.system_frame("Server is shutting down."))
        leaving = list(self.clients.values())
        for client in leaving:
            client.departed = True
        closers = [c.ws.close(1001, "server shutting down") for c in leaving]
        if closers:
            await asyncio.gather(*closers, return_exceptions=True)
        self.clients.clear()


# --- helpers ---------------------------------------------------------------------------


def _peer_ip(ws: ServerConnection) -> str:
    try:
        return ws.remote_address[0]
    except (AttributeError, IndexError, TypeError):
        return "unknown"


async def _send_plain(ws: ServerConnection, frame: dict) -> None:
    """Send an unencrypted handshake frame; a dead peer here is not an error."""
    with contextlib.suppress(Exception):
        await ws.send(p.dumps(frame))


def build_ssl_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )


async def run(config: Config) -> None:
    configure_logging(config.log_level)
    server = ChatServer(config)
    ssl_ctx = build_ssl_context(server.identity.cert_path, server.identity.key_path)

    stop = asyncio.get_running_loop().create_future()

    def _request_stop(signame: str) -> None:
        log.info("received %s", signame)
        if not stop.done():
            stop.set_result(None)

    loop = asyncio.get_running_loop()
    for signame in ("SIGINT", "SIGTERM"):
        with contextlib.suppress(NotImplementedError, AttributeError):
            loop.add_signal_handler(getattr(signal, signame), _request_stop, signame)

    async with serve(
        server.handle,
        config.host,
        config.port,
        ssl=ssl_ctx,
        ping_interval=PING_INTERVAL,
        ping_timeout=PING_TIMEOUT,
        max_size=p.MAX_FRAME_BYTES,
    ):
        log.info(
            "pychat server listening on wss://%s:%d (protocol v%d, data dir %s)",
            config.host,
            config.port,
            p.PROTOCOL_VERSION,
            config.data_dir,
        )
        log.info("certificate fingerprint: %s", server.identity.fingerprint)
        await stop

    await server.shutdown()
    log.info("goodbye")


def main() -> int:
    try:
        config = Config.from_env()
    except ConfigError as exc:
        print(f"pychat: {exc}", file=sys.stderr)
        return 2
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(run(config))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
