# CLAUDE.md — Encrypted Group Chat (Python)

This file is the complete specification and operating manual for the agent building this
project. Read it fully before writing any code. Work through the phases **in order**, and
do not skip the verification step at the end of each phase.

---

## 0. Configuration

These values are final. Use them exactly as written; do not substitute, abbreviate, or
invent alternatives.

| Key                 | Value                                                    |
| ------------------- | -------------------------------------------------------- |
| `PROJECT_NAME`      | `pychat`                                                  |
| `DOCKERHUB_USER`    | `darerelaqz1`                                             |
| `DOCKERHUB_REPO`    | `darerelaqz1/chat-app`                                    |
| `GITHUB_REPO_URL`   | `https://github.com/DareRelaqz1/no-mentors-chat.git`      |
| `GITHUB_REPO_NAME`  | `no-mentors-chat`                                         |
| `GITHUB_VISIBILITY` | public (the repository already exists — see Phase 1)      |
| `AWS_REGION`        | `eu-central-1` (Frankfurt)                                |
| `AWS_INSTANCE_TYPE` | `t3.micro`                                                |
| `CHAT_PORT`         | `8765`                                                    |
| `PYTHON_VERSION`    | `3.12`                                                    |

`t3.micro` is the default because it comfortably runs this workload. Free-tier eligibility
varies by account age and region — the operator should check current AWS free-tier terms for
`eu-central-1` before leaving the instance running, and `deploy/aws_teardown.sh` (Phase 9)
exists precisely so it can be shut down cleanly when not in use.

Note that the Docker Hub target is a **single repository** (`darerelaqz1/chat-app`), so the
server and client images are distinguished by tag prefix (`server-*`, `client-*`), not by
separate repositories. See Phase 8.

**Secrets are never written to any file in the repo.** The room password lives only in a
gitignored `.env` file locally and in an environment variable on the AWS instance.

---

## 1. Mission

Build a self-contained group chat application in Python with two executables:

- **Server** — headless, async, runs in Docker on an AWS EC2 instance. Accepts client
  connections, authenticates them against a shared room password, relays messages, and
  maintains the roster of connected users.
- **Client** — a desktop GUI application. On launch it asks for server address, display
  name, and room password; once connected it shows the live roster and the chat log.

All traffic between client and server must be unreadable to a passive observer running
Wireshark, tcpdump, or any other packet capture on the path. A capture must show only TLS
records; no display names, no message text, no password material in plaintext at any point.

### Definition of done

The project is complete only when **every** item below is true:

- [ ] `python -m pychat.server` runs locally and accepts connections.
- [ ] `python -m pychat.client` opens the GUI, connects, and chats successfully.
- [ ] Three clients connected simultaneously all see each other in the roster and receive
      each other's messages.
- [ ] A `tcpdump`/Wireshark capture of a live session contains no plaintext message
      content, display names, or password material. This is verified, not assumed.
- [ ] `pytest` passes with the full test suite green.
- [ ] Both Docker images build and are pushed to Docker Hub with `latest` and a version tag.
- [ ] The server is running on AWS, reachable from the public internet on `CHAT_PORT`, and
      survives an instance reboot.
- [ ] A client on the user's laptop connects to the AWS server and chats successfully.
- [ ] The git repo is initialized, committed in logical steps, and pushed to GitHub.
- [ ] `README.md` documents setup, local run, Docker run, AWS deploy, and teardown.
- [ ] No secret, private key, or certificate is present anywhere in git history.

---

## 2. Fixed technical decisions

Do not substitute these without asking the user first.

| Concern        | Decision                                                              |
| -------------- | --------------------------------------------------------------------- |
| Python         | 3.12                                                                   |
| Transport      | WebSockets over TLS 1.3 (`wss://`), library: `websockets` (>=12)       |
| Async model    | `asyncio` on both sides                                                |
| Crypto         | `cryptography` — AES-256-GCM, scrypt KDF, X.509 self-signed cert       |
| GUI            | `customtkinter` (Tk-based, themed) + stdlib `tkinter`                  |
| Tests          | `pytest` + `pytest-asyncio`                                            |
| Formatting     | `ruff format` and `ruff check` — must pass clean                       |
| Packaging      | `pyproject.toml`, source layout under `src/pychat/`                    |
| Container base | `python:3.12-slim`                                                     |

---

## 3. Security design

Read this whole section before implementing anything crypto-related. Implement it exactly.
Do not invent your own scheme, do not hand-roll primitives, do not use `random` for
anything security-relevant (use `os.urandom` / `secrets`).

### 3.1 Layer 1 — TLS transport

- The server generates a **self-signed X.509 certificate** on first start using
  `cryptography.x509`, and persists cert + key to its data directory (`/data` in the
  container, a mounted volume). It reuses them on subsequent starts.
- Key: ECDSA P-256. Validity: 2 years. SAN: the server's public DNS/IP if provided via
  `PYCHAT_PUBLIC_HOST`, otherwise `localhost` + `127.0.0.1`.
- Cert and key files are `chmod 600` and **must never** enter git or a Docker image layer.
- The server serves `wss://` with `ssl.PROTOCOL_TLS_SERVER`, minimum version TLS 1.3.

### 3.2 Client certificate pinning (trust on first use)

A self-signed cert alone does not stop an active MITM, so the client pins it SSH-style:

1. Client connects with `check_hostname=False`, `verify_mode=CERT_NONE`.
2. Immediately after the handshake, before sending anything, it retrieves the peer
   certificate in binary form (`ssl_object.getpeercert(binary_form=True)`) and computes its
   SHA-256 fingerprint.
3. It looks up the host in `~/.pychat/known_hosts` (JSON: `{host:port -> fingerprint}`).
   - Unknown host → show a dialog with the fingerprint, ask the user to accept, then store.
   - Known and matching → proceed silently.
   - Known and **not** matching → abort the connection and show a prominent warning that
     the server identity changed. Do not offer a one-click "ignore"; require the user to
     manually delete the entry from `known_hosts`.
4. Only after pinning succeeds does the client send any authentication material.

### 3.3 Layer 2 — password authentication (challenge–response)

The password is **never transmitted**, in any form, in either direction.

1. Server sends `server_hello` containing: protocol version, a 16-byte `salt` (generated
   once at first start and persisted alongside the cert), and a fresh 32-byte `nonce`.
2. Both sides derive the room key:
   `key = scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, dklen=32)`
   Derive it once and cache it; scrypt at this cost takes ~100 ms and must not run per message.
3. Client sends `auth` with the display name and `proof = HMAC-SHA256(key, nonce || display_name)`.
4. Server recomputes the HMAC and compares with `hmac.compare_digest`. Mismatch → send
   `auth_fail` with a generic reason and close. Never reveal whether the failure was the
   password, the name, or the version.
5. A connection that does not complete auth within **5 seconds** is dropped.
6. After **5 failed attempts from one IP within 5 minutes**, refuse new connections from
   that IP for 15 minutes. Keep this state in memory; log the event without logging the
   attempted material.

### 3.4 Layer 3 — payload encryption

Every frame after `server_hello` / `auth` is an encrypted envelope, so message content
stays confidential to password holders even if TLS were terminated by an intermediary:

```json
{ "t": "enc", "n": "<base64 12-byte nonce>", "ct": "<base64 ciphertext>" }
```

- Cipher: AES-256-GCM with the derived room key. AAD: `b"pychat/1"`.
- The 12-byte nonce is fresh random per message (`os.urandom(12)`).
- The plaintext is the UTF-8 JSON of the inner frame (see §4.2).
- Decryption failure (`InvalidTag`) → drop the frame, increment a per-connection error
  counter, and close the connection after 3 such failures.

### 3.5 Explicit non-goals — document these in the README

- **This is not end-to-end encrypted.** The server holds the room key and can read
  messages; it decrypts and re-encrypts on relay. The threat model is a passive or active
  network observer, not a malicious server operator.
- Password strength is the only access control. There are no accounts, no per-user keys,
  and no message persistence.
- Display names are self-asserted and not authenticated beyond room membership.

### 3.6 Hard rules for the agent

- Never log, print, or write to disk: the password, the derived key, the salt+key pair, or
  message plaintext. Server logs get event type, connection id, display name, and byte
  counts — nothing else.
- Never commit `.env`, `*.pem`, `*.key`, `*.crt`, or `known_hosts`.
- Never embed a default password in code, Dockerfile, compose file, or user-data script.
  If `PYCHAT_ROOM_PASSWORD` is unset, the server exits immediately with a clear error.
- Reject a password shorter than 8 characters at server startup with a clear message.

---

## 4. Protocol

### 4.1 Constants

- `PROTOCOL_VERSION = 1` — defined once in `src/pychat/protocol.py` and imported by both
  sides. On mismatch the server sends `auth_fail` with reason `version_mismatch` and the
  client shows "Client and server versions differ — update one of them."
- `MAX_FRAME_BYTES = 8192` — frames larger than this are rejected before decryption.
- `MAX_MESSAGE_CHARS = 2000`
- `MAX_NAME_CHARS = 24`
- `MAX_CLIENTS = 50`

### 4.2 Inner frame types

Handshake frames are sent in clear (inside TLS); all others are wrapped per §3.4.

**Server → client, unencrypted:**

- `server_hello` — `{ "t": "server_hello", "version": 1, "salt": b64, "nonce": b64 }`
- `auth_fail` — `{ "t": "auth_fail", "reason": "bad_credentials" | "version_mismatch" | "server_full" | "rate_limited" }`

**Client → server, unencrypted:**

- `auth` — `{ "t": "auth", "version": 1, "name": str, "proof": b64 }`

**Encrypted, server → client:**

- `auth_ok` — `{ "t": "auth_ok", "user_id": str, "name": str, "roster": [{"user_id", "name"}] }`
  (`name` is echoed because the server may have de-duplicated it, see §5.3)
- `roster` — `{ "t": "roster", "users": [{"user_id", "name"}] }` — sent on every join/leave
- `msg` — `{ "t": "msg", "user_id": str, "name": str, "text": str, "ts": float }`
- `system` — `{ "t": "system", "text": str, "ts": float }` — joins, leaves, notices
- `error` — `{ "t": "error", "text": str }` — e.g. rate limit hit, message too long
- `pong` — `{ "t": "pong" }`

**Encrypted, client → server:**

- `msg` — `{ "t": "msg", "text": str }` — server stamps `user_id`, `name`, `ts`
- `ping` — `{ "t": "ping" }`

Unknown `t` values are ignored, not fatal. Malformed JSON closes the connection.

---

## 5. Server requirements — `src/pychat/server.py`

### 5.1 Behaviour

- `asyncio` + `websockets.serve`, bound to `0.0.0.0:$PYCHAT_PORT` (default `8765`).
- Configuration comes from environment variables only:
  `PYCHAT_ROOM_PASSWORD` (required), `PYCHAT_PORT`, `PYCHAT_DATA_DIR` (default `/data`),
  `PYCHAT_PUBLIC_HOST` (optional, for the cert SAN), `PYCHAT_LOG_LEVEL`.
- Keeps an in-memory registry of connected clients. No database, no message history — a
  client that joins sees only messages sent from that point on. State it in the README.
- Broadcast is fan-out to all authenticated clients including the sender (so the sender's
  own message is rendered from the authoritative server copy, keeping ordering consistent).
- Broadcast must be resilient: one slow or dead client must never block or crash the loop.
  Use `asyncio.gather(..., return_exceptions=True)` and drop clients that raise.
- Application-level keepalive: rely on the `websockets` built-in ping (`ping_interval=20`,
  `ping_timeout=20`) and also handle the explicit `ping`/`pong` frames.
- Graceful shutdown on SIGTERM/SIGINT: send a `system` notice, close all connections with a
  normal close code, then exit. This matters for `docker stop`.

### 5.2 Abuse limits

- Rate limit: max 10 messages per 5-second sliding window per connection. On breach, send
  `error` and ignore the message; do not disconnect for a first offence.
- Reject messages over `MAX_MESSAGE_CHARS` with an `error` frame.
- Refuse connections beyond `MAX_CLIENTS` with `auth_fail` / `server_full`.

### 5.3 Display name rules

- Strip leading/trailing whitespace; collapse internal runs of whitespace to one space.
- Length 1–24 characters after stripping. Reject empty.
- Reject control characters and any character in `Cc`/`Cf` Unicode categories.
- If the name is already taken, append `#2`, `#3`, … and return the final name in `auth_ok`
  so the client can display what it actually got.
- Assign each connection a random `user_id` (`secrets.token_hex(8)`) — the roster and
  messages key on this, not on the name.

### 5.4 Robustness

The server must not crash. Ever. Wrap each connection handler in a broad `try/except`,
log the exception with traceback, and close only that connection. Malformed frames,
truncated JSON, wrong types, missing keys, invalid base64, and unexpected disconnects are
all expected inputs — handle each explicitly.

---

## 6. Client requirements — `src/pychat/client.py` + `src/pychat/ui/`

### 6.1 Threading model — get this right first

Tk and asyncio cannot share a thread. Use this structure, and do not deviate:

- The asyncio event loop runs the network layer in a **daemon background thread**.
- Network → UI: the network thread pushes events onto a `queue.Queue`. The Tk main loop
  drains it via `root.after(50, self._drain_queue)`, rescheduling itself each time.
- UI → network: the UI calls `asyncio.run_coroutine_threadsafe(coro, loop)`.
- **No Tk widget is ever touched from the network thread.** No blocking call (including
  `scrypt`) ever runs on the Tk thread — derive the key in the network thread and show a
  "Connecting…" state meanwhile.

### 6.2 Connection dialog

Shown at launch, centered, non-resizable:

- Server host (default `localhost`), port (default `8765`).
- Display name.
- Room password, masked, with a show/hide toggle.
- "Remember host and name" checkbox → persists to `~/.pychat/config.json`
  (**never** the password).
- Connect button, plus Enter-to-submit. Inline validation errors under the offending field.
- While connecting: disable the form, show a spinner/progress state, allow Cancel.
- On failure: a clear, human message — "Wrong password or name rejected by the server",
  "Could not reach the server at host:port", "Server identity changed" — and return the
  user to the form with values preserved.

### 6.3 Main window

Layout, using CustomTkinter, dark theme by default with a light/dark toggle:

```
┌──────────────────────────────────────────────────────────────┐
│  pychat — connected to <host>            ● Connected   [⚙]   │
├───────────────────┬──────────────────────────────────────────┤
│  ONLINE — 3       │  10:24  Alice   Hey everyone              │
│                   │  10:24  Bob     morning                   │
│  ● Alice          │  ── Carol joined the chat ──              │
│  ● Bob            │  10:25  You     hello                     │
│  ● You (Carol)    │                                           │
│                   │                                           │
│                   ├──────────────────────────────────────────┤
│                   │  [ Type a message…             ] [ Send ] │
└───────────────────┴──────────────────────────────────────────┘
```

Required behaviours:

- **Roster panel**: live count in the header, one row per user, own entry marked "(You)".
  Each user gets a small circular avatar with their initial, filled with a colour derived
  deterministically from `user_id` (hash → hue) so the same person is the same colour in
  the roster and in the log. Sort alphabetically, case-insensitive.
- **Chat log**: read-only, scrollable, selectable and copyable text. Timestamps in local
  `HH:MM`. Consecutive messages from the same sender within 60 s are grouped under one name
  header. Own messages visually distinguished (accent colour on the name, subtle background).
  System messages centered, muted, italic.
- **Auto-scroll**: stick to the bottom only when the user is already at the bottom. If they
  have scrolled up, do not yank the view; show a "↓ New messages" pill that jumps to the
  bottom when clicked.
- **Input**: multi-line capable. `Enter` sends, `Shift+Enter` inserts a newline. A character
  counter appears past 80% of `MAX_MESSAGE_CHARS` and the Send button disables past the
  limit. Input is focused on launch and refocused after every send.
- **Status indicator**: green "Connected", amber "Reconnecting…", red "Disconnected", with
  the reason on hover.
- **Reconnect**: on unexpected disconnect, retry automatically with exponential backoff
  (1, 2, 4, 8, capped at 30 s), reusing the cached key so the user is not re-prompted.
  Show each attempt as a system line. Give up after 6 attempts and offer a Reconnect button.
- **Window**: sensible default size (1000×640), minimum size enforced, panes resize
  correctly, no widget clipping at minimum size. Title reflects connection state.
- **Shortcuts**: `Ctrl+Q` quit, `Ctrl+L` clear local log view, `Esc` closes dialogs.
- **Clean exit**: closing the window sends a proper WebSocket close, stops the loop, and
  joins the thread — no orphaned threads, no traceback on exit.

### 6.4 Design quality bar

Consistent 8 px spacing scale, one accent colour, one font family at 2–3 sizes, adequate
contrast in both themes. No stock grey Tk widgets, no default `tkinter` button styling
leaking through. Take a screenshot of the running client and inspect it before declaring
the UI done — if it looks like an unstyled Tk demo, iterate.

---

## 7. Repository layout

```
<repo>/
├── CLAUDE.md
├── README.md
├── LICENSE                     # MIT unless the user says otherwise
├── .gitignore
├── .env.example                # keys only, no values
├── pyproject.toml
├── Makefile
├── src/pychat/
│   ├── __init__.py
│   ├── protocol.py             # version, frame builders/parsers, constants
│   ├── crypto.py               # scrypt KDF, AES-GCM seal/open, cert generation, fingerprints
│   ├── server.py               # entrypoint: python -m pychat.server
│   ├── client.py               # entrypoint: python -m pychat.client
│   ├── net.py                  # client-side asyncio websocket layer + reconnect
│   └── ui/
│       ├── __init__.py
│       ├── app.py              # main window
│       ├── connect_dialog.py
│       ├── widgets.py          # roster row, message row, avatar, status pill
│       └── theme.py            # colours, spacing, fonts
├── tests/
│   ├── test_crypto.py
│   ├── test_protocol.py
│   └── test_server.py
├── docker/
│   ├── Dockerfile.server
│   ├── Dockerfile.client
│   └── docker-compose.yml      # local dev convenience
└── deploy/
    ├── aws_deploy.sh
    ├── aws_teardown.sh
    └── user_data.sh
```

`.gitignore` must include at minimum: `.env`, `*.pem`, `*.key`, `*.crt`, `known_hosts`,
`data/`, `__pycache__/`, `*.pyc`, `.venv/`, `.pytest_cache/`, `.ruff_cache/`, `*.log`,
`.DS_Store`, `deploy/*.pem`.

---

## 8. Execution phases

Complete each phase, run its verification, then `git commit` with a clear message before
moving on. If a verification fails, fix it before continuing — never carry a known failure
into the next phase.

### Phase 0 — Environment check

Run and report the result of each:

```bash
python3 --version                 # need 3.12+
docker version                    # daemon must be reachable
gh auth status                    # must be authenticated
git --version
aws --version && aws sts get-caller-identity
```

Handle the AWS CLI yourself where you can:

- If `aws` is **not installed**, install it (Ubuntu 24.04, x86_64):
  ```bash
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp && sudo /tmp/aws/install
  ```
- If it is installed but `aws sts get-caller-identity` fails, the user's credentials are
  missing or expired. That is the one thing you cannot do for them: ask them to run
  `aws configure` (or set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) and continue with
  Phases 1–8 in the meantime. Do not block the whole build on it.
- Set the region for the session so every later command is unambiguous:
  ```bash
  export AWS_DEFAULT_REGION=eu-central-1
  ```
  and pass `--region eu-central-1` explicitly in `deploy/aws_deploy.sh` regardless.

### Phase 1 — Scaffold and git

- Create the directory tree, `pyproject.toml`, `.gitignore`, `.env.example`, `LICENSE`.
- `python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"`
- `git init -b main`, initial commit.
- The GitHub repository **already exists** and is public. Do not run `gh repo create`.
  Wire it up and push:
  ```bash
  git remote add origin https://github.com/DareRelaqz1/no-mentors-chat.git
  git fetch origin
  ```
  - If `origin/main` exists and has commits (e.g. an auto-created README), rebase onto it:
    `git pull --rebase origin main`, resolve any trivial conflict in favour of the local
    files, then `git push -u origin main`.
  - If the remote is empty, `git push -u origin main` directly.
  - Never `push --force` to `main`. If the histories are unrelated and a rebase is not
    clean, stop and ask.
- **Verify:** `git log` shows the commit; `gh repo view DareRelaqz1/no-mentors-chat` resolves
  and shows the pushed files; `git status` is clean; `git remote -v` points at the URL above.

### Phase 2 — Crypto and protocol modules

Build `crypto.py` and `protocol.py` first, with tests, before any networking. These are
pure functions and must be fully covered.

- **Verify:** `pytest tests/test_crypto.py tests/test_protocol.py -v` green, including a
  seal→open round trip, a tampered-ciphertext rejection, a wrong-key rejection, KDF
  determinism, and cert generation producing a parseable X.509 with the expected SAN.

### Phase 3 — Server

- **Verify:** start it with a test password; connect with a throwaway `websockets` script
  that performs the full handshake; confirm auth success, auth failure on a wrong password,
  and a broadcast reaching two concurrent scripted clients.

### Phase 4 — Client networking (`net.py`)

Headless first — no UI. A small CLI harness that connects and prints frames.

- **Verify:** the harness connects to the local server, authenticates, sends and receives
  messages, and reconnects when the server is restarted under it.

### Phase 5 — Client UI

- **Verify:** launch two clients against the local server. Both appear in each other's
  roster, messages flow both ways, join/leave notices appear, closing one updates the
  other's roster within a second. Take a screenshot and review it against §6.4.

### Phase 6 — Test suite and capture proof

- Full `pytest` run, `ruff check`, `ruff format --check`.
- **Sniff test:** with the server running locally, capture loopback traffic while sending a
  known unique string (e.g. `CANARY-9F2A-DO-NOT-LEAK`) from a client:

  ```bash
  sudo tcpdump -i lo -s 0 -w /tmp/pychat.pcap "tcp port 8765"
  # send the canary from a client, then stop tcpdump
  strings /tmp/pychat.pcap | grep -c "CANARY-9F2A-DO-NOT-LEAK"   # must be 0
  strings /tmp/pychat.pcap | grep -ci "<the display name used>"  # must be 0
  ```

  Record the result in the README. If either count is non-zero, the design is not correctly
  implemented — find and fix the leak before proceeding.

### Phase 7 — Docker images

`docker/Dockerfile.server`:
- Base `python:3.12-slim`, multi-stage (builder installs deps into a venv, runtime copies it).
- Server dependencies only — **do not** install `customtkinter` or any Tk package here.
- Create and run as a non-root user (`appuser`, UID 10001).
- `VOLUME /data`, `EXPOSE 8765`, `HEALTHCHECK` doing a TCP connect to the port.
- `ENTRYPOINT ["python", "-m", "pychat.server"]`.
- Build explicitly for `linux/amd64` — the EC2 instance is x86_64.

`docker/Dockerfile.client`:
- Same base, plus the Tk system packages (`python3-tk`, `libx11-6`, `libxft2`, `libxss1`,
  `tk`) via `apt-get` with `--no-install-recommends` and a cleaned apt cache.
- Document in the README that the GUI container needs an X11 socket on Linux:
  ```bash
  xhost +local:docker
  docker run --rm -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix \
    -v $HOME/.pychat:/home/appuser/.pychat darerelaqz1/chat-app:client-latest
  ```
  and note that running the client natively (`pip install -e . && python -m pychat.client`)
  is the recommended path — the image exists for completeness and reproducibility.

- **Verify:** both images build clean; the server image runs and accepts a connection;
  `docker run --rm <server-image>` without `PYCHAT_ROOM_PASSWORD` exits non-zero with the
  intended error message.

### Phase 8 — Docker Hub

**Gate: report to the user and get a go-ahead before pushing.**

- Confirm the push target first: `docker login` (the user is already authenticated via
  Docker Desktop; if the push is rejected, report it rather than trying other credentials).
- Tag all four, with `<version>` read from `pyproject.toml` (starts at `0.1.0`):
  ```
  darerelaqz1/chat-app:server-latest
  darerelaqz1/chat-app:server-<version>
  darerelaqz1/chat-app:client-latest
  darerelaqz1/chat-app:client-<version>
  ```
- `docker push` each tag.
- **Verify:** remove the local image, `docker pull darerelaqz1/chat-app:server-latest`, and
  run it — it must start and accept a connection.

### Phase 9 — AWS deployment

**Gate: this creates billable resources. Show the user the exact resources and the plan,
and get explicit approval before running anything that creates infrastructure.**

Write `deploy/aws_deploy.sh` — idempotent, `set -euo pipefail`, every resource tagged
`Project=pychat`:

1. Resolve the latest Ubuntu 24.04 LTS x86_64 AMI in `eu-central-1` via the SSM public
   parameter — never hard-code an AMI id, they are region-specific and rotate:
   ```bash
   aws ssm get-parameter --region eu-central-1 \
     --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
     --query 'Parameter.Value' --output text
   ```
2. Create key pair `pychat-key` if absent; save the `.pem` to `deploy/` with `chmod 400`
   (gitignored).
3. Create security group `pychat-sg` in the default VPC:
   - inbound TCP `$CHAT_PORT` from `0.0.0.0/0`
   - inbound TCP 22 **from the operator's current public IP only** (`curl -s ifconfig.me`)
   - all outbound
4. Launch one `$AWS_INSTANCE_TYPE` instance with `deploy/user_data.sh`, which installs
   Docker from the official repo, enables it, and creates a `pychat` systemd unit.
5. Allocate and associate an Elastic IP so the address survives stop/start. Print it.
6. Wait for `instance-status-ok`.
7. Over SSH, write `/etc/pychat.env` (mode 600, containing `PYCHAT_ROOM_PASSWORD` and
   `PYCHAT_PUBLIC_HOST=<elastic ip>`) — read the password from the local `.env` or prompt
   for it; **never** pass it as a command-line argument (it would land in shell history and
   in `ps` output) and never bake it into user-data.
8. Start the container:
   ```
   docker run -d --name pychat --restart unless-stopped \
     -p 8765:8765 -v /var/lib/pychat:/data --env-file /etc/pychat.env \
     darerelaqz1/chat-app:server-latest
   ```
9. Print the connection details: public IP, port, and a reminder that the first client
   connection will show a certificate fingerprint to accept.

Write `deploy/aws_teardown.sh` that deletes the instance, EIP, security group, and key pair
by tag, with a confirmation prompt. Tell the user it exists — an idle EC2 instance costs
money.

- **Verify:** connect a local client to the Elastic IP and exchange messages. Then
  `sudo reboot` the instance, wait, and confirm the client reconnects automatically without
  manual intervention on the server.

### Phase 10 — Documentation and wrap-up

- `README.md`: what it is, architecture diagram (ASCII is fine), security design and the
  §3.5 non-goals, prerequisites, local dev quickstart, running via Docker, AWS deploy and
  teardown, configuration reference table, the packet-capture verification result, and a
  troubleshooting section.
- `Makefile` targets: `install`, `run-server`, `run-client`, `test`, `lint`, `fmt`,
  `docker-build`, `docker-push`, `deploy`, `teardown`.
- Final `git push`. Confirm the working tree is clean and no secret ever entered history
  (`git log -p | grep -iE "password|BEGIN .*PRIVATE KEY"` should return nothing meaningful).
- Walk the §1 checklist and report the status of every item honestly.

---

## 9. Working agreement

- **Ask, don't assume.** §0 is complete — do not ask about repositories, region, or naming.
  For anything genuinely ambiguous that §0 does not cover, pick the option most consistent
  with the rest of this document, note the decision in `PROGRESS.md`, and keep going. Stop
  only for the two things that truly require the user: the room password and AWS credentials.
- **Gates.** Pause for explicit user approval before: pushing to Docker Hub (Phase 8),
  creating AWS resources (Phase 9), and any destructive operation (deleting resources,
  force-pushing, rewriting history).
- **Commit granularity.** One commit per phase minimum, conventional-commit style messages
  (`feat:`, `fix:`, `docs:`, `chore:`). Never commit broken code to `main`.
- **Test before claiming.** Do not report a phase as complete based on reading the code.
  Run it. If something cannot be verified in the current environment, say so plainly rather
  than implying it passed.
- **No silent scope changes.** If a fixed decision in §2 turns out to be wrong, explain why
  and propose the alternative — don't just swap it.
- **Keep a running `PROGRESS.md`** (gitignored) with the current phase, what's done, what's
  blocked, and any decisions taken. Update it as you go so work can resume after an
  interruption.

## 10. Known sharp edges

- `customtkinter` needs a real display. In a headless environment the UI cannot be tested —
  say so rather than pretending. `xvfb-run` can be used for smoke tests but not visual review.
- On Ubuntu, `python3-tk` is a system package; `pip install customtkinter` alone is not
  enough. `sudo apt install python3-tk` may be required on the host.
- `websockets` changed its API across major versions. Pin `websockets>=12,<16` and use the
  modern `asyncio` interface consistently; do not mix the legacy and new client APIs.
- Deriving the scrypt key on the Tk thread will freeze the UI for ~100 ms. Do it in the
  network thread (§6.1).
- The certificate's SAN must include the Elastic IP, or Python's TLS layer may complain even
  with hostname checking disabled in some configurations. Set `PYCHAT_PUBLIC_HOST` on deploy
  and regenerate the cert if the IP changes.
- Opening port 8765 to `0.0.0.0/0` is required for a public chat server but means anyone can
  reach the auth endpoint. The rate limiting and lockout in §5.2 and §3.3 are what make this
  acceptable — do not omit them.
