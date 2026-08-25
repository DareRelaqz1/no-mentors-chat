#!/usr/bin/env bash
# EC2 user-data: install Docker and prepare the pychat systemd unit.
#
# This runs once, as root, at first boot. It deliberately contains NO secret: the room
# password is written to /etc/pychat.env over SSH afterwards, because user-data is
# readable by anything that can reach the instance metadata service.
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y ca-certificates curl gnupg

# Docker from the official repository, not the distro's older package.
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable --now docker
usermod -aG docker ubuntu || true

# The container runs as uid 10001 (appuser). A bind mount keeps the *host's* ownership,
# unlike a named volume which inherits the image's, so the host directory has to be
# owned by that uid or the server cannot write its certificate and salt.
mkdir -p /var/lib/pychat
chown 10001:10001 /var/lib/pychat
chmod 700 /var/lib/pychat

# Placeholder so the unit can start even before the real env file is written.
# It contains no password, so the server will refuse to start until one is supplied.
touch /etc/pychat.env
chmod 600 /etc/pychat.env

cat > /etc/systemd/system/pychat.service <<'UNIT'
[Unit]
Description=pychat encrypted group chat server
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=exec
Restart=always
RestartSec=10
TimeoutStartSec=300
EnvironmentFile=/etc/pychat.env

# Always start from a clean slate: --rm plus an explicit pre-stop removal keeps a
# stale container from blocking the name after an unclean shutdown.
ExecStartPre=-/usr/bin/docker stop pychat
ExecStartPre=-/usr/bin/docker rm pychat
ExecStartPre=/usr/bin/docker pull darerelaqz1/chat-app:server-latest
ExecStart=/usr/bin/docker run --rm --name pychat \
  -p 8765:8765 \
  -v /var/lib/pychat:/data \
  --env-file /etc/pychat.env \
  darerelaqz1/chat-app:server-latest
ExecStop=/usr/bin/docker stop pychat

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable pychat.service

echo "user-data finished" > /var/log/pychat-user-data-done
