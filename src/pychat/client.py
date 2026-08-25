"""pychat client entrypoint.

``python -m pychat.client`` opens the desktop GUI. ``--headless`` runs the same
network layer with a terminal interface instead, which is useful for debugging a
server, for smoke-testing on a machine with no display, and for verifying the
protocol without Tk in the way.
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import queue
import sys
import threading
import time
from datetime import datetime

from . import net
from . import protocol as p


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="pychat.client", description="pychat desktop client")
    parser.add_argument(
        "--headless",
        action="store_true",
        help="run a terminal client instead of the GUI (debugging aid)",
    )
    parser.add_argument("--host", default=None, help="server host (headless mode)")
    parser.add_argument("--port", type=int, default=None, help="server port (headless mode)")
    parser.add_argument("--name", default=None, help="display name (headless mode)")
    parser.add_argument(
        "--accept-new-cert",
        action="store_true",
        help="headless mode: trust an unknown certificate without prompting. A changed "
        "certificate is still refused.",
    )
    parser.add_argument("--verbose", action="store_true", help="debug logging")
    return parser.parse_args(argv)


# --- headless mode ------------------------------------------------------------------------


def _format_event(event: net.Event, own_id: str | None) -> str | None:
    """Render one event as a terminal line, or None if it should stay quiet."""
    stamp = datetime.now().strftime("%H:%M")
    match event:
        case net.Connecting(attempt=attempt):
            return f"· connecting (attempt {attempt})…"
        case net.CertificateUnknown():
            return None  # handled interactively
        case net.CertificateMismatch(host_key=host, expected=exp, actual=act):
            return (
                f"!! SERVER IDENTITY CHANGED for {host}\n"
                f"   pinned: {net.format_fingerprint(exp)}\n"
                f"   now:    {net.format_fingerprint(act)}"
            )
        case net.Connected(name=name, roster=roster, reconnected=again):
            who = ", ".join(sorted(u["name"] for u in roster)) or "just you"
            verb = "reconnected" if again else "connected"
            return f"· {verb} as {name} — online: {who}"
        case net.AuthFailed():
            return f"!! {event.message}"
        case net.ConnectionFailed(message=message):
            return f"!! {message}"
        case net.Disconnected(reason=reason):
            return f"· disconnected: {reason}"
        case net.Reconnecting(attempt=attempt, delay=delay, max_attempts=cap):
            return f"· reconnecting in {delay:.0f}s (attempt {attempt} of {cap})…"
        case net.GaveUp(attempts=attempts):
            return f"!! gave up after {attempts} attempts"
        case net.Frame(inner=inner):
            match inner.get("t"):
                case "msg":
                    marker = "*" if inner.get("user_id") == own_id else " "
                    return f"{stamp} {marker}{inner['name']}: {inner['text']}"
                case "system":
                    return f"{stamp} -- {inner['text']} --"
                case "roster":
                    names = ", ".join(u["name"] for u in inner["users"])
                    return f"· online ({len(inner['users'])}): {names}"
                case "error":
                    return f"!! {inner['text']}"
                case _:
                    return None
        case _:
            return None


def run_headless(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)-7s %(name)s: %(message)s",
    )
    prefs = net.load_prefs()
    host = args.host or prefs.get("host") or "localhost"
    port = args.port or int(prefs.get("port") or 8765)
    name = args.name or prefs.get("name") or getpass.getuser()

    password = os.environ.get("PYCHAT_ROOM_PASSWORD")
    if not password:
        password = getpass.getpass(f"Room password for {host}:{port}: ")
    if not password:
        print("pychat: a room password is required.", file=sys.stderr)
        return 2

    try:
        name = p.normalize_name(name)
    except p.ProtocolError as exc:
        print(f"pychat: {exc}", file=sys.stderr)
        return 2

    client = net.NetworkClient(net.Settings(host=host, port=port, name=name, password=password))
    client.start()

    stop = threading.Event()
    state: dict[str, str | None] = {"own_id": None}

    def pump() -> None:
        while not stop.is_set():
            try:
                event = client.events.get(timeout=0.2)
            except queue.Empty:
                continue

            if isinstance(event, net.CertificateUnknown):
                print(f"\nUnknown server {event.host_key}")
                print(f"  SHA-256 fingerprint: {event.readable}")
                if args.accept_new_cert:
                    print("  accepting (--accept-new-cert)")
                    client.answer_certificate(True)
                else:
                    answer = input("  Trust this server and remember it? [y/N] ").strip().lower()
                    client.answer_certificate(answer in ("y", "yes"))
                continue

            if isinstance(event, net.Connected):
                state["own_id"] = event.user_id

            line = _format_event(event, state["own_id"])
            if line:
                print(line)

            if isinstance(event, net.AuthFailed | net.GaveUp | net.Stopped | net.ConnectionFailed):
                stop.set()
                return

    reader = threading.Thread(target=pump, name="pychat-print", daemon=True)
    reader.start()

    print("Type a message and press Enter. Ctrl-D or /quit to leave.")
    try:
        while not stop.is_set():
            try:
                text = input()
            except EOFError:
                break
            if text.strip() in ("/quit", "/exit"):
                break
            if text.strip():
                client.send_message(text)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        client.stop()
        time.sleep(0.1)
    print("· goodbye")
    return 0


# --- gui mode ---------------------------------------------------------------------------


def run_gui(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)-7s %(name)s: %(message)s",
    )
    try:
        from .ui.app import launch
    except ImportError as exc:
        print(
            f"pychat: the GUI needs customtkinter and Tk ({exc}).\n"
            "  pip install 'pychat[client]'   and on Ubuntu: sudo apt install python3-tk\n"
            "Or run the terminal client with: python -m pychat.client --headless",
            file=sys.stderr,
        )
        return 3
    return launch()


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return run_headless(args) if args.headless else run_gui(args)


if __name__ == "__main__":
    raise SystemExit(main())
