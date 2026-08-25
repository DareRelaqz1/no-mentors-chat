#!/usr/bin/env python3
"""Connect once, send the canary, disconnect. Used by scripts/sniff_test.sh."""

from __future__ import annotations

import os
import queue
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pychat import net


def main() -> int:
    settings = net.Settings(
        host="127.0.0.1",
        port=int(os.environ.get("PYCHAT_SNIFF_PORT", "8820")),
        name=os.environ.get("PYCHAT_SNIFF_NAME", "ZeldaCanary7Q"),
        password=os.environ["PYCHAT_ROOM_PASSWORD"],
    )
    known_hosts = Path(os.environ.get("PYCHAT_SNIFF_KNOWN_HOSTS", "build/sniff-known-hosts"))
    known_hosts.unlink(missing_ok=True)

    client = net.NetworkClient(settings, known_hosts_path=known_hosts)
    client.start()

    connected = False
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not connected:
        try:
            event = client.events.get(timeout=0.2)
        except queue.Empty:
            continue
        if isinstance(event, net.CertificateUnknown):
            client.answer_certificate(True)
        elif isinstance(event, net.Connected):
            connected = True
        elif isinstance(event, net.AuthFailed | net.ConnectionFailed):
            print(f"sniff client failed: {event}", file=sys.stderr)
            client.stop()
            return 1

    if not connected:
        print("sniff client timed out connecting", file=sys.stderr)
        client.stop()
        return 1

    text = os.environ.get("PYCHAT_SNIFF_TEXT", "CANARY-9F2A-DO-NOT-LEAK")
    for index in range(3):
        client.send_message(f"{text} #{index}")
        time.sleep(0.4)
    time.sleep(1.5)
    client.stop()
    print("sniff client sent the canary and disconnected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
