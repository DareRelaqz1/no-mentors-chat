#!/usr/bin/env python3
"""Prove that nothing sensitive appears on the wire — without needing root.

A transparent TCP relay sits between a real client and a real server and appends every
byte of both directions to a file. What it records is byte-for-byte what a passive
sniffer on the path would capture, so searching it answers the same question as the
tcpdump check in the README, and it can run anywhere (CI included).

A positive control runs first: the same detector is pointed at an *unencrypted*
connection carrying the same canary and must find it. A check that cannot fail proves
nothing, so the run is only considered meaningful if the control trips.

Usage:  python scripts/wire_proof.py [work_dir]
Exit code 0 means: control tripped, session succeeded, and nothing leaked.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import queue
import subprocess
import sys
import time
from pathlib import Path

CANARY = "CANARY-9F2A-DO-NOT-LEAK"
CANARY_NAME = "ZeldaCanary7Q"
TEST_PASSWORD = "wire-proof-throwaway-password"

SERVER_PORT = 8810
RELAY_PORT = 8811
CONTROL_PORT = 8812
ECHO_PORT = 8813


async def record(listen_port: int, target_port: int, dump_path: Path, stop: asyncio.Future) -> None:
    """Forward TCP between two ports, writing every byte seen to ``dump_path``."""
    dump = dump_path.open("wb")

    async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await reader.read(65536):
                dump.write(data)
                dump.flush()
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def handle(client_reader, client_writer) -> None:
        try:
            server_reader, server_writer = await asyncio.open_connection("127.0.0.1", target_port)
        except OSError:
            client_writer.close()
            return
        await asyncio.gather(
            pipe(client_reader, server_writer),
            pipe(server_reader, client_writer),
            return_exceptions=True,
        )

    server = await asyncio.start_server(handle, "127.0.0.1", listen_port)
    async with server:
        await stop
    dump.close()


def count_in(path: Path, needles: dict[str, str]) -> dict[str, int]:
    raw = path.read_bytes()
    return {label: raw.count(needle.encode("utf-8")) for label, needle in needles.items()}


async def positive_control(work: Path) -> tuple[bool, dict[str, int]]:
    """Send the canary in the clear through the same recorder. It must be found."""
    loop = asyncio.get_running_loop()
    stop = loop.create_future()

    async def echo(reader, writer) -> None:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
        writer.close()

    echo_server = await asyncio.start_server(echo, "127.0.0.1", ECHO_PORT)
    dump = work / "control.bin"
    task = asyncio.create_task(record(CONTROL_PORT, ECHO_PORT, dump, stop))
    await asyncio.sleep(0.4)

    _, writer = await asyncio.open_connection("127.0.0.1", CONTROL_PORT)
    writer.write(f"name={CANARY_NAME} text={CANARY}\n".encode())
    await writer.drain()
    await asyncio.sleep(0.3)
    writer.close()
    await asyncio.sleep(0.3)

    stop.set_result(None)
    echo_server.close()
    await task

    found = count_in(dump, {"canary": CANARY, "name": CANARY_NAME})
    return found["canary"] > 0 and found["name"] > 0, found


async def live_session(work: Path) -> tuple[bool, int, dict[str, int]]:
    """Run a real client against a real server, through the recorder."""
    data_dir = work / "server-data"
    data_dir.mkdir(parents=True, exist_ok=True)
    log_path = work / "server.log"

    env = dict(
        os.environ,
        PYCHAT_ROOM_PASSWORD=TEST_PASSWORD,
        PYCHAT_PORT=str(SERVER_PORT),
        PYCHAT_DATA_DIR=str(data_dir),
        PYCHAT_LOG_LEVEL="INFO",
    )
    with log_path.open("w") as log_file:
        server = subprocess.Popen(
            [sys.executable, "-m", "pychat.server"], env=env, stdout=log_file, stderr=log_file
        )
        try:
            for _ in range(120):
                if log_path.exists() and "listening" in log_path.read_text():
                    break
                await asyncio.sleep(0.25)
            else:
                raise RuntimeError("the server did not start")

            stop = asyncio.get_running_loop().create_future()
            dump = work / "wire.bin"
            recorder = asyncio.create_task(record(RELAY_PORT, SERVER_PORT, dump, stop))
            await asyncio.sleep(0.5)

            from pychat import net

            known_hosts = work / "known_hosts"
            known_hosts.unlink(missing_ok=True)
            client = net.NetworkClient(
                net.Settings(
                    host="127.0.0.1", port=RELAY_PORT, name=CANARY_NAME, password=TEST_PASSWORD
                ),
                known_hosts_path=known_hosts,
            )
            client.start()

            # Drain without blocking: the recorder shares this event loop, and a blocking
            # queue.get() here would starve it and stall the traffic being recorded.
            connected = False
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not connected:
                try:
                    event = client.events.get_nowait()
                except queue.Empty:
                    await asyncio.sleep(0.05)
                    continue
                if isinstance(event, net.CertificateUnknown):
                    client.answer_certificate(True)
                elif isinstance(event, net.Connected):
                    connected = True

            for index in range(3):
                client.send_message(f"{CANARY} #{index}")
                await asyncio.sleep(0.4)
            await asyncio.sleep(1.5)
            client.stop()
        finally:
            server.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                server.wait(timeout=15)

    await asyncio.sleep(0.5)
    stop.set_result(None)
    await recorder

    found = count_in(dump, {"canary": CANARY, "name": CANARY_NAME, "password": TEST_PASSWORD})
    return connected, dump.stat().st_size, found


async def main() -> int:
    work = Path(sys.argv[1] if len(sys.argv) > 1 else "build/wire-proof")
    work.mkdir(parents=True, exist_ok=True)

    print("=== positive control: the same detector on unencrypted traffic ===")
    control_ok, control = await positive_control(work)
    print(f"  canary found {control['canary']} time(s), name found {control['name']} time(s)")
    print(f"  detector proven able to find plaintext: {control_ok}")

    print("\n=== live pychat session through the recorder ===")
    connected, size, found = await live_session(work)
    print(f"  client connected: {connected}")
    print(f"  bytes recorded:   {size}")
    print(f"  message text  '{CANARY}': {found['canary']} (must be 0)")
    print(f"  display name  '{CANARY_NAME}': {found['name']} (must be 0)")
    print(f"  room password: {found['password']} (must be 0)")

    leak_free = all(count == 0 for count in found.values())
    ok = control_ok and connected and leak_free and size > 2000
    print()
    print("PASS — no plaintext content, display name or password on the wire" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
