#!/usr/bin/env bash
# Remove every AWS resource tagged Project=pychat in eu-central-1.
#
# An idle EC2 instance and its Elastic IP cost money, so this is the counterpart to
# aws_deploy.sh. It lists exactly what it will delete and asks before touching anything.
set -euo pipefail

REGION="eu-central-1"
PROJECT="pychat"
KEY_NAME="pychat-key"
SG_NAME="pychat-sg"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_FILE="$SCRIPT_DIR/${KEY_NAME}.pem"

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '\n\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
aws_() { aws --region "$REGION" "$@"; }

command -v aws >/dev/null || die "the AWS CLI is not installed"
aws_ sts get-caller-identity >/dev/null 2>&1 || die "AWS credentials are missing or expired"

log "Looking for resources tagged Project=$PROJECT in $REGION"

INSTANCE_IDS="$(aws_ ec2 describe-instances \
  --filters "Name=tag:Project,Values=$PROJECT" \
            "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[].Instances[].InstanceId' --output text || true)"
ALLOC_IDS="$(aws_ ec2 describe-addresses --filters "Name=tag:Project,Values=$PROJECT" \
  --query 'Addresses[].AllocationId' --output text || true)"
SG_ID="$(aws_ ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")"
KEY_EXISTS="no"
aws_ ec2 describe-key-pairs --key-names "$KEY_NAME" >/dev/null 2>&1 && KEY_EXISTS="yes"

echo
echo "  instances      : ${INSTANCE_IDS:-<none>}"
echo "  elastic IPs    : ${ALLOC_IDS:-<none>}"
echo "  security group : ${SG_ID:-<none>}"
echo "  key pair       : $KEY_NAME ($KEY_EXISTS)"
echo

if [[ -z "$INSTANCE_IDS" && -z "$ALLOC_IDS" && ( "$SG_ID" == "None" || -z "$SG_ID" ) && "$KEY_EXISTS" == "no" ]]; then
  log "Nothing to remove."
  exit 0
fi

echo "This permanently deletes the resources listed above, including the server's"
echo "certificate and any state on its disk. Chat history is not stored, so nothing"
echo "else is lost."
read -rp "Type 'destroy' to continue: " CONFIRM
[[ "$CONFIRM" == "destroy" ]] || { echo "Aborted; nothing was changed."; exit 1; }

if [[ -n "$INSTANCE_IDS" ]]; then
  log "Terminating instances"
  # shellcheck disable=SC2086
  aws_ ec2 terminate-instances --instance-ids $INSTANCE_IDS >/dev/null
  info "waiting for termination"
  # shellcheck disable=SC2086
  aws_ ec2 wait instance-terminated --instance-ids $INSTANCE_IDS
  info "terminated"
fi

if [[ -n "$ALLOC_IDS" ]]; then
  log "Releasing Elastic IPs"
  for alloc in $ALLOC_IDS; do
    ASSOC="$(aws_ ec2 describe-addresses --allocation-ids "$alloc" \
      --query 'Addresses[0].AssociationId' --output text 2>/dev/null || echo "None")"
    [[ "$ASSOC" != "None" && -n "$ASSOC" ]] && aws_ ec2 disassociate-address --association-id "$ASSOC" >/dev/null 2>&1 || true
    aws_ ec2 release-address --allocation-id "$alloc" && info "released $alloc"
  done
fi

if [[ "$SG_ID" != "None" && -n "$SG_ID" ]]; then
  log "Deleting security group $SG_ID"
  # A group stays in use for a short while after its instance dies.
  for attempt in $(seq 1 12); do
    if aws_ ec2 delete-security-group --group-id "$SG_ID" 2>/dev/null; then
      info "deleted"
      break
    fi
    [[ $attempt -eq 12 ]] && info "could not delete $SG_ID (still in use?) - delete it manually"
    sleep 10
  done
fi

if [[ "$KEY_EXISTS" == "yes" ]]; then
  log "Deleting key pair $KEY_NAME"
  aws_ ec2 delete-key-pair --key-name "$KEY_NAME" && info "deleted from AWS"
  if [[ -f "$KEY_FILE" ]]; then
    rm -f "$KEY_FILE"
    info "removed $KEY_FILE"
  fi
fi

rm -f "$SCRIPT_DIR/known_hosts_ec2"

log "Teardown complete."
echo
echo "  Clients still have the old server pinned in ~/.pychat/known_hosts."
echo "  If you deploy again the fingerprint will differ and the client will refuse to"
echo "  connect until you remove that host's entry from that file. That refusal is the"
echo "  pinning working as designed, not a bug."
