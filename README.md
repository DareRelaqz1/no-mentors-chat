# pychat

An encrypted group chat you can actually run: an async Python WebSocket server that
lives in a container, and a desktop client that looks like a real application.

Traffic is TLS 1.3 with client-side certificate pinning, and every application frame is
*additionally* sealed with AES-256-GCM under a key derived from the shared room
password. A packet capture of a live session shows TLS records and nothing else — no
message text, no display names, no password material. That claim is
[verified, not assumed](#does-it-actually-encrypt-anything).

![status](https://img.shields.io/badge/tests-200%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.12-blue)
![license](https://img.shields.io/badge/license-MIT-blue)

---

## Contents

- [What it looks like](#what-it-looks-like)
- [Architecture](#architecture)
- [Security design](#security-design)
- [What this is *not*](#what-this-is-not)
- [Quickstart](#quickstart)
- [Running with Docker](#running-with-docker)
- [Deploying to AWS](#deploying-to-aws)
- [Configuration reference](#configuration-reference)
- [Does it actually encrypt anything?](#does-it-actually-encrypt-anything)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

---

## What it looks like

```
┌──────────────────────────────────────────────────────────────┐
│  pychat   connected to 18.184.1.2:8765     ● Connected  [◐]  │
├───────────────────┬──────────────────────────────────────────┤
│  ONLINE — 3       │        —  Bob joined the chat  —         │
│                   │                                          │
│  (A) Alice        │  (A) Alice  10:24                        │
│  (B) Bob          │      Hey everyone                        │
│  (C) Carol (You)  │                                          │
│                   │  (B) Bob  10:24                          │
│                   │      morning                             │
│                   │                                          │
│                   │  (C) Carol  10:25        ← your messages  │
│                   │      hello                  are tinted    │
│                   ├──────────────────────────────────────────┤
│                   │  [ Type a message…            ] [ Send ]  │
└───────────────────┴──────────────────────────────────────────┘
```

Each person gets an avatar colour derived deterministically from their user id, so the
same person is the same colour in the roster and in the log. Consecutive messages from
one sender within 60 seconds group under a single header. The log sticks to the bottom
only if you are already at the bottom — scroll up and it leaves you alone, showing a
"↓ New messages" pill instead.

## Architecture

```
        ┌────────────────────────────┐            ┌────────────────────────────┐
        │      client (desktop)      │            │      client (desktop)      │
        │                            │            │                            │
        │  ┌──────────────────────┐  │            │  ┌──────────────────────┐  │
        │  │  Tk main thread      │  │            │  │  Tk main thread      │  │
        │  │  ui/app.py           │  │            │  │  ui/app.py           │  │
        │  └──────────┬───────────┘  │            │  └──────────┬───────────┘  │
        │   queue.Queue│  ▲ run_coro  │            │             │              │
        │      (events)│  │threadsafe │            │             │              │
        │  ┌──────────▼──┴────────┐  │            │  ┌──────────▼───────────┐  │
        │  │  asyncio thread      │  │            │  │  asyncio thread      │  │
        │  │  net.py              │  │            │  │  net.py              │  │
        │  └──────────┬───────────┘  │            │  └──────────┬───────────┘  │
        └─────────────┼──────────────┘            └─────────────┼──────────────┘
                      │                                         │
                      │      wss:// — TLS 1.3, pinned cert      │
                      │      payloads sealed with AES-256-GCM   │
                      └────────────────┬────────────────────────┘
                                       │
                        ┌──────────────▼───────────────┐
                        │   server (Docker, EC2)       │
                        │   server.py — asyncio        │
                        │                              │
                        │   • challenge/response auth  │
                        │   • in-memory roster         │
                        │   • decrypt → re-encrypt →   │
                        │     fan out to everyone      │
                        │   • rate limits, lockout     │
                        │                              │
                        │   /data (volume, mode 600)   │
                        │   ├── server.crt             │
                        │   ├── server.key             │
                        │   └── salt.bin               │
                        └──────────────────────────────┘
```

No database and no message history: a client that joins sees only what is sent from
that moment on. That is a deliberate choice, not a missing feature — there is no
transcript on the server to leak.

### The client's threading model

Tk and asyncio cannot share a thread, so they don't:

- the network layer runs an asyncio loop on a **background daemon thread**,
- network → UI goes through a `queue.Queue`, drained by `root.after(50, …)`,
- UI → network goes through `asyncio.run_coroutine_threadsafe`,
- **no Tk widget is ever touched from the network thread**, and the ~100 ms scrypt
  derivation runs on the network thread so the interface never freezes.

## Security design

Three layers, each doing a job the others cannot.

### Layer 1 — TLS 1.3 transport

The server generates a self-signed ECDSA P-256 certificate on first start and persists
it, with the private key, to its data directory at mode `600`. Validity is two years.
The SAN covers `localhost` and `127.0.0.1`, plus the public host from
`PYCHAT_PUBLIC_HOST` when set.

### Layer 2 — certificate pinning (trust on first use)

A self-signed certificate alone stops a passive eavesdropper but not an active
machine-in-the-middle, so the client pins it the way SSH does:

1. Connect with chain validation disabled — a self-signed certificate cannot chain to a
   public root, so hostname and chain checks are meaningless here.
2. **Before sending anything**, take the peer certificate and compute its SHA-256
   fingerprint.
3. Compare against `~/.pychat/known_hosts` (JSON, `{host:port → fingerprint}`):
   - **unknown host** → show the fingerprint and ask,
   - **known and matching** → proceed silently,
   - **known and different** → abort, loudly.

That last case has no "ignore once" button on purpose. If the server was legitimately
rebuilt, you delete the entry from `known_hosts` by hand.

### Layer 3 — password authentication, and payload encryption

**The room password is never transmitted, in any form, in either direction.**

```
  server                                                   client
    │                                                        │
    │──  server_hello { version, salt(16B), nonce(32B) }  ──▶│
    │                                                        │  key = scrypt(password, salt,
    │                                                        │        n=2^15, r=8, p=1) → 32B
    │                                                        │  (~100 ms, derived once, cached)
    │◀──  auth { version, name, proof }  ─────────────────────│
    │                                                        │  proof = HMAC-SHA256(
    │  recompute, compare with hmac.compare_digest            │      key, nonce ‖ name)
    │                                                        │
    │══  everything from here is AES-256-GCM sealed  ════════│
```

Every subsequent frame is an envelope — `{"t":"enc","n":<12B nonce>,"ct":<ciphertext>}` —
using AES-256-GCM with the room key, a fresh random nonce per message, and the AAD
`pychat/1`. A frame that fails to decrypt is dropped; three failures close the
connection.

### Abuse limits

| Limit | Value |
|---|---|
| Time to complete authentication | 5 seconds, then dropped |
| Failed auths before an IP is locked out | 5 within 5 minutes → 15 minute refusal |
| Messages per connection | 10 per 5-second sliding window |
| Message length | 2000 characters |
| Frame size | 8192 bytes |
| Concurrent clients | 50 |

Opening the chat port to the world is required for a public chat server. These limits
are what make that acceptable.

### What is never logged or written

The password, the derived key, and message plaintext never reach a log, a file, or a
traceback. Server logs carry event type, connection id, display name, and byte counts.
A failed authentication is logged without the attempted material, and the client is
told only `bad_credentials` — never whether it was the password or the name that was
wrong.

## What this is *not*

Please read this before trusting it with anything that matters.

- **This is not end-to-end encrypted.** The server holds the room key. It decrypts each
  message and re-encrypts it to relay. The threat model is a passive or active observer
  *on the network path* — not a malicious server operator. Anyone who controls the
  server can read everything.
- **The password is the only access control.** There are no accounts, no per-user keys,
  no roles, no invitations. Anyone who knows the password is in the room.
- **Display names are self-asserted.** They are normalised and de-duplicated, but past
  "you know the room password" they are not authenticated. Two people can be Alice and
  Alice#2.
- **No message history.** Nothing is persisted. Join late and you missed it.
- **It has not been audited.** The primitives come from `cryptography` and nothing is
  hand-rolled, but this is a personal project, not a reviewed security product.

## Quickstart

Requires Python 3.12+. On Ubuntu the GUI also needs Tk, which pip cannot provide:

```bash
sudo apt install python3-tk
```

```bash
git clone https://github.com/DareRelaqz1/no-mentors-chat.git
cd no-mentors-chat
make install                 # venv + dependencies

cp .env.example .env
# edit .env and set PYCHAT_ROOM_PASSWORD (at least 8 characters)

make run-server              # terminal 1
make run-client              # terminal 2
```

The client asks for the server, your display name, and the room password. On the first
connection it shows the server's fingerprint — compare it with the one the server
printed at startup, then accept.

No display? There is a terminal client over the same network layer:

```bash
make run-client-headless
```

## Running with Docker

Images are on Docker Hub as [`darerelaqz1/chat-app`](https://hub.docker.com/r/darerelaqz1/chat-app),
tagged `server-latest` / `server-0.1.0` and `client-latest` / `client-0.1.0`.

### Server

```bash
docker run -d --name pychat \
  --restart unless-stopped \
  -p 8765:8765 \
  -v pychat-data:/data \
  -e PYCHAT_ROOM_PASSWORD='your-room-password' \
  darerelaqz1/chat-app:server-latest
```

Keep the `/data` volume. It holds the certificate, key and salt — lose it and every
client sees a fingerprint change and has to re-pin. The server refuses to start without
`PYCHAT_ROOM_PASSWORD`, and refuses a password shorter than 8 characters.

For local development, `docker/docker-compose.yml` reads the password from your
environment or a `.env` file:

```bash
docker compose -f docker/docker-compose.yml up --build
```

### Client

Running the client natively is the recommended path — the image exists for
completeness. A GUI container needs the host's X11 socket:

```bash
xhost +local:docker
docker run --rm \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -v $HOME/.pychat:/home/appuser/.pychat \
  darerelaqz1/chat-app:client-latest
xhost -local:docker
```

Mounting `~/.pychat` keeps your pinned hosts and preferences across runs.

## Deploying to AWS

`deploy/aws_deploy.sh` puts the server on a single EC2 instance in `eu-central-1`. It is
idempotent — re-running reuses what it already created — and tags everything
`Project=pychat`.

```bash
./deploy/aws_deploy.sh        # or: make deploy
```

It resolves the current Ubuntu 24.04 AMI from the SSM public parameter rather than
hard-coding a region-specific id, creates the `pychat-key` key pair (saved to
`deploy/pychat-key.pem`, mode 400, gitignored), creates the `pychat-sg` security group
with the chat port open to the world and **SSH restricted to your current public IP**,
launches a `t3.micro` with an encrypted gp3 root volume, attaches an Elastic IP so the
address survives a stop/start, then writes `/etc/pychat.env` over SSH and starts a
`pychat` systemd unit that survives reboots.

The room password is read from `.env` or prompted for, then piped over the SSH channel
on **stdin**. It is never passed as a command-line argument — that would put it in shell
history and in `ps` output — and never baked into user-data, which is readable through
the instance metadata service.

### Why EC2 and not Elastic Beanstalk

Beanstalk can run a container, but it fights this design in three places. The server
generates and must *keep* its own TLS identity, and EB replaces instances on deploys and
autohealing — every replacement would change the fingerprint and trip the
identity-changed warning on every client. TLS terminates in the application, so the ALB
that EB reaches for by default is unusable (it would terminate TLS itself, leaving the
pinning meaningless); you would need single-instance or an NLB doing TCP passthrough.
And EB's health model assumes HTTP on port 80, which pychat does not speak. EC2 with a
persistent volume and an Elastic IP is what this workload actually wants.

### Tearing it down

An idle instance and its Elastic IP still cost money — roughly **$12–13/month** if left
running (t3.micro ≈ $8.30, 8 GB gp3 ≈ $0.72, public IPv4 ≈ $3.60, since AWS bills IPv4
addresses even while attached).

```bash
./deploy/aws_teardown.sh      # or: make teardown
```

It lists what it will delete and requires you to type `destroy`.

## Configuration reference

### Server (environment variables only)

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `PYCHAT_ROOM_PASSWORD` | **yes** | — | Shared room password, minimum 8 characters. The server exits with status 2 without it. |
| `PYCHAT_PORT` | no | `8765` | Listening port. |
| `PYCHAT_DATA_DIR` | no | `/data` | Where the certificate, key and salt live. |
| `PYCHAT_PUBLIC_HOST` | no | — | Added to the certificate SAN. Set it to the public IP or DNS name. |
| `PYCHAT_BIND_HOST` | no | `0.0.0.0` | Interface to bind. |
| `PYCHAT_LOG_LEVEL` | no | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. |

### Client files

| Path | Contents |
|---|---|
| `~/.pychat/known_hosts` | Pinned certificate fingerprints, `{host:port → sha256}`. |
| `~/.pychat/config.json` | Remembered host, port and display name. **Never the password.** |

### Protocol constants

`PROTOCOL_VERSION 1` · `MAX_FRAME_BYTES 8192` · `MAX_MESSAGE_CHARS 2000` ·
`MAX_NAME_CHARS 24` · `MAX_CLIENTS 50`

> **A note on the two limits.** `MAX_MESSAGE_CHARS` counts characters while
> `MAX_FRAME_BYTES` counts bytes, and base64 inflates ciphertext by a third. A
> 2000-character ASCII message is ~2.9 kB on the wire; 2000 emoji would be ~10.9 kB and
> exceed the frame limit. The client checks the sealed envelope before sending and tells
> you plainly, rather than letting the frame be dropped in silence.

## Does it actually encrypt anything?

A design is only as good as its verification, so this is checked two ways. Both start by
pointing the detector at *unencrypted* traffic carrying the same canary and requiring it
to be found — a check that cannot fail proves nothing.

### Without root

```bash
make wire-proof
```

A transparent TCP relay records every byte of a real client/server session. What it
records is byte-for-byte what a passive sniffer on the path would capture.

```
=== positive control: the same detector on unencrypted traffic ===
  canary found 2 time(s), name found 2 time(s)
  detector proven able to find plaintext: True

=== live pychat session through the recorder ===
  client connected: True
  bytes recorded:   4011
  message text  'CANARY-9F2A-DO-NOT-LEAK': 0 (must be 0)
  display name  'ZeldaCanary7Q': 0 (must be 0)
  room password: 0 (must be 0)

PASS — no plaintext content, display name or password on the wire
```

### With tcpdump

```bash
make sniff-test          # runs sudo ./scripts/sniff_test.sh
```

This is the literal capture check: `tcpdump -i lo -s 0 -w pychat.pcap "tcp port 8820"`
while a client sends the canary, then

```bash
strings pychat.pcap | grep -c "CANARY-9F2A-DO-NOT-LEAK"   # must be 0
strings pychat.pcap | grep -ci "ZeldaCanary7Q"            # must be 0
```

<!-- SNIFF-RESULT -->
**Result — run on 2026-08-25, loopback capture of a live session:**

```
capture: build/sniff-test/pychat.pcap  (7147 bytes, 37 packets)

strings pychat.pcap | grep -c  "CANARY-9F2A-DO-NOT-LEAK"   ->  0
strings pychat.pcap | grep -ci "ZeldaCanary7Q"             ->  0
strings pychat.pcap | grep -c  "<room password>"           ->  0
```

The capture contains a complete TCP handshake and TLS records — including the 225-byte
ClientHello — and 73 printable strings, none of which is the message text, the display
name, or the password. The same `strings | grep` finds the canary immediately in a
plaintext control file, so the check is capable of failing.
<!-- /SNIFF-RESULT -->

## Development

```bash
make install     # venv and dependencies
make test        # pytest
make lint        # ruff check + ruff format --check
make fmt         # apply fixes
make check       # lint + test
```

```
src/pychat/
├── protocol.py       version, constants, frame builders, strict parsing
├── crypto.py         scrypt KDF, AES-GCM seal/open, certificates, fingerprints
├── server.py         entrypoint: python -m pychat.server
├── client.py         entrypoint: python -m pychat.client  (--headless available)
├── net.py            client asyncio layer: TLS, pinning, auth, reconnect
└── ui/
    ├── app.py            main window and the network→Tk event pump
    ├── connect_dialog.py launch dialog
    ├── widgets.py        avatars, roster rows, message rows, status pill
    └── theme.py          colours, spacing, fonts

tests/                200 tests: crypto, protocol, server, network layer
scripts/              wire_proof.py (no root) and sniff_test.sh (tcpdump)
```

Everything arriving from the network is treated as hostile input. Malformed JSON,
truncated frames, wrong types, missing keys, invalid base64 and abrupt disconnects are
all *expected* inputs with explicit handling, and the server is designed never to let
one connection take the process down.

## Troubleshooting

**"Server identity changed" and the client refuses to connect.**
Working as designed. The fingerprint for that host no longer matches what you pinned.
If you know why — you redeployed, or the `/data` volume was recreated — remove that
host's line from `~/.pychat/known_hosts` and reconnect. If you *don't* know why, do not
remove it.

**"Wrong password, or the name was rejected by the server."**
Deliberately ambiguous: the server never reveals which part failed. Check the password
first, then that your display name is 1–24 characters and free of control characters.

**Five failed attempts and now everything is refused.**
Per-IP lockout: 15 minutes. It clears on its own, or immediately if you restart the
server (the state is in memory).

**`ModuleNotFoundError: No module named 'tkinter'`**
Tk is a system package: `sudo apt install python3-tk`. `pip install customtkinter` is
not enough.

**The client window never appears / `no display name and no $DISPLAY`.**
You are on a headless machine. Use `python -m pychat.client --headless`.

**The server exits immediately with status 2.**
It is telling you why on stderr — almost always `PYCHAT_ROOM_PASSWORD` unset or shorter
than 8 characters. This is intentional: there is no default password anywhere in this
project.

**Messages stop arriving and the status pill turns amber.**
The client is reconnecting with backoff (1, 2, 4, 8, 16, 30 s), reusing the cached key
so you are not asked for the password again. After 6 attempts it gives up and offers a
Reconnect button.

**A long message is rejected as "too large to send".**
The byte limit, not the character limit — see the note under
[Configuration reference](#configuration-reference). Non-Latin scripts and emoji use
several bytes each.

**Certificate errors after moving the server to a new IP.**
The SAN must cover the address clients dial. Set `PYCHAT_PUBLIC_HOST` and delete
`server.crt` / `server.key` from the data directory so a fresh certificate is generated.
`deploy/aws_deploy.sh` does this automatically when the Elastic IP changes.

## License

MIT — see [LICENSE](LICENSE).
