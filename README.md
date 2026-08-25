# pychat

Encrypted group chat: an async Python WebSocket server and a CustomTkinter desktop client.
Traffic is TLS 1.3 with client-side certificate pinning, and every application frame is
additionally sealed with AES-256-GCM under a key derived from the shared room password.

Full documentation is written in Phase 10 of the build.
