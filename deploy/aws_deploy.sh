#!/usr/bin/env bash
# Deploy the pychat server to a single EC2 instance in eu-central-1.
#
# Idempotent: re-running reuses the key pair, security group, instance and Elastic IP
# it created before, and only fills in what is missing. Every resource is tagged
# Project=pychat so aws_teardown.sh can find it.
#
# The room password is read from ../.env or prompted for, then written to
# /etc/pychat.env on the instance over SSH. It is never passed as a command-line
# argument (which would land in shell history and in ps output) and never baked into
# user-data (which is readable through the instance metadata service).
set -euo pipefail

REGION="eu-central-1"
PROJECT="pychat"
INSTANCE_TYPE="${AWS_INSTANCE_TYPE:-t3.micro}"
CHAT_PORT="${CHAT_PORT:-8765}"
KEY_NAME="pychat-key"
SG_NAME="pychat-sg"
IMAGE="darerelaqz1/chat-app:server-latest"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KEY_FILE="$SCRIPT_DIR/${KEY_NAME}.pem"

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '\n\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

aws_() { aws --region "$REGION" "$@"; }

command -v aws >/dev/null || die "the AWS CLI is not installed"
aws_ sts get-caller-identity >/dev/null 2>&1 \
  || die "AWS credentials are missing or expired. Run 'aws configure' and try again."

log "Account and region"
info "account: $(aws_ sts get-caller-identity --query Account --output text)"
info "region:  $REGION"

# --- room password ---------------------------------------------------------------------
ROOM_PASSWORD="${PYCHAT_ROOM_PASSWORD:-}"
if [[ -z "$ROOM_PASSWORD" && -f "$REPO_ROOT/.env" ]]; then
  ROOM_PASSWORD="$(grep -E '^PYCHAT_ROOM_PASSWORD=' "$REPO_ROOT/.env" | head -1 | cut -d= -f2- || true)"
fi
if [[ -z "$ROOM_PASSWORD" ]]; then
  read -rsp "Room password (min 8 chars, not echoed): " ROOM_PASSWORD
  echo
fi
[[ ${#ROOM_PASSWORD} -ge 8 ]] || die "the room password must be at least 8 characters"

# --- AMI -------------------------------------------------------------------------------
log "Resolving the latest Ubuntu 24.04 LTS AMI"
AMI_ID="$(aws_ ssm get-parameter \
  --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
  --query 'Parameter.Value' --output text)"
[[ -n "$AMI_ID" && "$AMI_ID" != "None" ]] || die "could not resolve the Ubuntu AMI"
info "ami: $AMI_ID"

# --- key pair --------------------------------------------------------------------------
log "Key pair '$KEY_NAME'"
if aws_ ec2 describe-key-pairs --key-names "$KEY_NAME" >/dev/null 2>&1; then
  info "already exists in AWS"
  [[ -f "$KEY_FILE" ]] || die "the key pair exists in AWS but $KEY_FILE is missing locally.
   Delete the key pair with:
     aws --region $REGION ec2 delete-key-pair --key-name $KEY_NAME
   then re-run this script to create a fresh one."
else
  info "creating and saving to $KEY_FILE"
  umask 077
  aws_ ec2 create-key-pair --key-name "$KEY_NAME" \
    --tag-specifications "ResourceType=key-pair,Tags=[{Key=Project,Value=$PROJECT}]" \
    --query 'KeyMaterial' --output text > "$KEY_FILE"
  chmod 400 "$KEY_FILE"
fi

# --- security group --------------------------------------------------------------------
log "Security group '$SG_NAME'"
VPC_ID="$(aws_ ec2 describe-vpcs --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text)"
[[ -n "$VPC_ID" && "$VPC_ID" != "None" ]] || die "no default VPC found in $REGION"
info "vpc: $VPC_ID"

SG_ID="$(aws_ ec2 describe-security-groups \
  --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")"

if [[ "$SG_ID" == "None" || -z "$SG_ID" ]]; then
  SG_ID="$(aws_ ec2 create-security-group --group-name "$SG_NAME" \
    --description "pychat chat server" --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Project,Value=$PROJECT}]" \
    --query 'GroupId' --output text)"
  info "created: $SG_ID"
else
  info "exists: $SG_ID"
fi

MY_IP="$(curl -fsS --max-time 10 https://checkip.amazonaws.com || true)"
MY_IP="${MY_IP//[$'\t\r\n ']/}"
[[ -n "$MY_IP" ]] || die "could not determine this machine's public IP for the SSH rule"
info "your public IP: $MY_IP (SSH will be restricted to it)"

# Chat port open to the world: a public chat server has to be reachable. The auth
# rate limiting and per-IP lockout are what make that acceptable.
aws_ ec2 authorize-security-group-ingress --group-id "$SG_ID" \
  --ip-permissions "IpProtocol=tcp,FromPort=$CHAT_PORT,ToPort=$CHAT_PORT,IpRanges=[{CidrIp=0.0.0.0/0,Description=pychat}]" \
  >/dev/null 2>&1 && info "opened tcp/$CHAT_PORT to 0.0.0.0/0" || info "tcp/$CHAT_PORT rule already present"

aws_ ec2 authorize-security-group-ingress --group-id "$SG_ID" \
  --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$MY_IP/32,Description=operator}]" \
  >/dev/null 2>&1 && info "opened tcp/22 to $MY_IP/32" || info "tcp/22 rule for $MY_IP/32 already present"

# --- instance --------------------------------------------------------------------------
log "Instance"
INSTANCE_ID="$(aws_ ec2 describe-instances \
  --filters "Name=tag:Project,Values=$PROJECT" \
            "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null || echo "None")"

if [[ "$INSTANCE_ID" == "None" || -z "$INSTANCE_ID" ]]; then
  info "launching a $INSTANCE_TYPE"
  INSTANCE_ID="$(aws_ ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --user-data "file://$SCRIPT_DIR/user_data.sh" \
    --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
    --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=8,VolumeType=gp3,DeleteOnTermination=true,Encrypted=true}' \
    --tag-specifications \
      "ResourceType=instance,Tags=[{Key=Project,Value=$PROJECT},{Key=Name,Value=pychat-server}]" \
      "ResourceType=volume,Tags=[{Key=Project,Value=$PROJECT}]" \
    --query 'Instances[0].InstanceId' --output text)"
  info "launched: $INSTANCE_ID"
else
  info "reusing: $INSTANCE_ID"
  STATE="$(aws_ ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].State.Name' --output text)"
  if [[ "$STATE" == "stopped" ]]; then
    info "instance is stopped; starting it"
    aws_ ec2 start-instances --instance-ids "$INSTANCE_ID" >/dev/null
  fi
fi

log "Waiting for the instance to be running"
aws_ ec2 wait instance-running --instance-ids "$INSTANCE_ID"
info "running"

# --- elastic IP ------------------------------------------------------------------------
log "Elastic IP"
ALLOC_ID="$(aws_ ec2 describe-addresses --filters "Name=tag:Project,Values=$PROJECT" \
  --query 'Addresses[0].AllocationId' --output text 2>/dev/null || echo "None")"
if [[ "$ALLOC_ID" == "None" || -z "$ALLOC_ID" ]]; then
  ALLOC_ID="$(aws_ ec2 allocate-address --domain vpc \
    --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Project,Value=$PROJECT}]" \
    --query 'AllocationId' --output text)"
  info "allocated: $ALLOC_ID"
else
  info "reusing: $ALLOC_ID"
fi
aws_ ec2 associate-address --instance-id "$INSTANCE_ID" --allocation-id "$ALLOC_ID" >/dev/null
PUBLIC_IP="$(aws_ ec2 describe-addresses --allocation-ids "$ALLOC_ID" \
  --query 'Addresses[0].PublicIp' --output text)"
info "public IP: $PUBLIC_IP"

log "Waiting for status checks to pass (this takes a few minutes)"
aws_ ec2 wait instance-status-ok --instance-ids "$INSTANCE_ID"
info "status ok"

# --- configure over SSH ------------------------------------------------------------------
SSH_OPTS=(-i "$KEY_FILE" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10
          -o UserKnownHostsFile="$SCRIPT_DIR/known_hosts_ec2")

log "Waiting for SSH"
for attempt in $(seq 1 40); do
  if ssh "${SSH_OPTS[@]}" "ubuntu@$PUBLIC_IP" true 2>/dev/null; then
    info "ssh is up"
    break
  fi
  [[ $attempt -eq 40 ]] && die "could not reach the instance over SSH at $PUBLIC_IP"
  sleep 10
done

log "Waiting for cloud-init to finish installing Docker"
ssh "${SSH_OPTS[@]}" "ubuntu@$PUBLIC_IP" \
  'sudo cloud-init status --wait >/dev/null 2>&1 || true; until command -v docker >/dev/null; do sleep 5; done; docker --version'

log "Writing /etc/pychat.env (mode 600)"
# The password travels over the SSH channel on stdin, so it never appears in an
# argument list, in the instance's shell history, or in ps output.
printf 'PYCHAT_ROOM_PASSWORD=%s\nPYCHAT_PUBLIC_HOST=%s\nPYCHAT_PORT=8765\nPYCHAT_LOG_LEVEL=INFO\n' \
  "$ROOM_PASSWORD" "$PUBLIC_IP" \
  | ssh "${SSH_OPTS[@]}" "ubuntu@$PUBLIC_IP" \
      'sudo install -m 600 /dev/stdin /etc/pychat.env && echo "written"'

# The certificate SAN must contain the Elastic IP. If the IP changed since the cert was
# generated, the old identity is stale, so it is regenerated and clients re-pin.
log "Ensuring the certificate matches $PUBLIC_IP"
ssh "${SSH_OPTS[@]}" "ubuntu@$PUBLIC_IP" bash -s -- "$PUBLIC_IP" <<'REMOTE'
set -euo pipefail
IP="$1"
if sudo test -f /var/lib/pychat/server.crt; then
  if sudo openssl x509 -in /var/lib/pychat/server.crt -noout -text \
       | grep -q "IP Address:$IP"; then
    echo "certificate already covers $IP"
  else
    echo "certificate does not cover $IP - regenerating (clients will need to re-accept)"
    sudo rm -f /var/lib/pychat/server.crt /var/lib/pychat/server.key
  fi
else
  echo "no certificate yet - the server will generate one"
fi
REMOTE

log "Starting the pychat service"
ssh "${SSH_OPTS[@]}" "ubuntu@$PUBLIC_IP" \
  'sudo systemctl daemon-reload && sudo systemctl enable pychat.service && sudo systemctl restart pychat.service && sleep 12 && sudo systemctl is-active pychat.service'

log "Server log"
ssh "${SSH_OPTS[@]}" "ubuntu@$PUBLIC_IP" 'sudo journalctl -u pychat.service -n 20 --no-pager' || true

FINGERPRINT="$(ssh "${SSH_OPTS[@]}" "ubuntu@$PUBLIC_IP" \
  'sudo journalctl -u pychat.service --no-pager | grep -o "certificate fingerprint: [0-9a-f]*" | tail -1 | cut -d" " -f3' || true)"

cat <<SUMMARY

================================================================
 pychat is deployed
================================================================
  Host          : $PUBLIC_IP
  Port          : $CHAT_PORT
  Instance      : $INSTANCE_ID ($INSTANCE_TYPE)
  Security group: $SG_ID
  Elastic IP    : $ALLOC_ID
  SSH           : ssh -i $KEY_FILE ubuntu@$PUBLIC_IP

  Connect with:  python -m pychat.client
                 server $PUBLIC_IP, port $CHAT_PORT

  On first connection the client shows a certificate fingerprint
  and asks you to accept it. It must match:

    ${FINGERPRINT:-<check: sudo journalctl -u pychat.service | grep fingerprint>}

  This instance costs money while it runs. Tear it down with:
    ./deploy/aws_teardown.sh
================================================================
SUMMARY
