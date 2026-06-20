#!/bin/bash
set -euo pipefail

# =============================================================================
# Bring up ONE cross-cloud SEV-SNP TEE pair (tee_k + tee_t split across GCP and
# AWS) wired to the isolated TEST router, concurrently with any existing pair.
# Images are assumed pre-built (build them separately with snp-gcp-image.sh /
# snp-aws-image.sh); this script only creates VMs, injects per-deployment env
# (tee-env on GCP, user-data on AWS), and waits for both to serve /health.
#
#   ./deploy/snp-pair.sh up       create + wire both TEEs, poll health
#   ./deploy/snp-pair.sh status   show both VMs + /health
#   ./deploy/snp-pair.sh down     delete both VMs, release the EIP
#
# Role x cloud is configurable (default: tee_k@GCP + tee_t@AWS, the mirror of
# the first pair). Override via GCP_ROLE / AWS_ROLE (k|t). Everything else has
# defaults below and may be overridden inline or in deploy/.env.
#
# IP wiring (no reserved/idle charges): GCP self-IP is auto-discovered by the
# app; AWS gets one Elastic IP (free while associated). GCP is created first so
# AWS boots last with both SELF (its EIP) and PEER (GCP's IP) already correct.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then set -a; source "${SCRIPT_DIR}/.env"; set +a; fi
source "${SCRIPT_DIR}/_lib.sh"

# ---- configuration (env-overridable) ----------------------------------------
PAIR_NAME="${SNP_PAIR_NAME:-snp-pair2}"
GCP_PROJECT="${GCP_PROJECT:?set GCP_PROJECT (or put it in deploy/.env)}"
GCP_ZONE="${SNP_PAIR_GCP_ZONE:?set SNP_PAIR_GCP_ZONE in deploy/.env}"
AWS_REGION="${SNP_PAIR_AWS_REGION:?set SNP_PAIR_AWS_REGION in deploy/.env}"
AWS_TYPE="${SNP_PAIR_AWS_TYPE:-c6a.large}"
AWS_IAM_PROFILE="${SNP_AWS_IAM_PROFILE:-snp-tee-logger}"

GCP_ROLE="${GCP_ROLE:-k}"
AWS_ROLE="${AWS_ROLE:-t}"

ROUTER_URL="${SNP_ROUTER_URL:?set SNP_ROUTER_URL in deploy/.env}"
JWT_ISSUER="${SNP_JWT_ISSUER:?set SNP_JWT_ISSUER in deploy/.env}"
PORT="${SNP_PORT:-8081}"
LOG_LEVEL="${SNP_LOG_LEVEL:-debug}"
STATIC_OPRF="${SNP_TEST_STATIC_OPRF:-1}"

# Cross-cloud-stable app-bundle digests (snp-app:<hash>), one per role. Same
# bundle on either cloud, so the switched pair reuses these unchanged.
K_DIGEST="${SNP_K_DIGEST:?set SNP_K_DIGEST in deploy/.env}"
T_DIGEST="${SNP_T_DIGEST:?set SNP_T_DIGEST in deploy/.env}"

# Pre-built images: GCP image name + AWS AMI tag (resolved to an AMI by name
# 'snp-<tag>', mirroring snp-aws-image.sh). Must match the role on that cloud.
GCP_IMAGE="${SNP_GCP_IMAGE:-snp-teek-gcp}"
AWS_IMAGE_TAG="${SNP_AWS_IMAGE_TAG:-teet-aws}"

SIGNKEY="${SCRIPT_DIR}/.test-router-signing-key"
PEM="${SCRIPT_DIR}/snp-img-key.pem"
KEYNAME="snp-img-key"
GCP_VM="${PAIR_NAME}-${GCP_ROLE}-gcp"
AWS_TAG="${PAIR_NAME}-${AWS_ROLE}-aws"
SGNAME="${PAIR_NAME}-sg"

# ---- cloud wrappers (gcloud wants the proxy unset; aws wants it kept) --------
g() { ( unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true; gcloud_retry gcloud "$@" --project="${GCP_PROJECT}" ); }
awsq() { aws --region "${AWS_REGION}" "$@"; }

role_digest() { [[ "$1" == "k" ]] && echo "${K_DIGEST}" || echo "${T_DIGEST}"; }

jwt_pubkey() {
    [[ -f "${SIGNKEY}" ]] || { echo "missing ${SIGNKEY} (the test router signing key)" >&2; exit 1; }
    printf '%b' "$(cat "${SIGNKEY}")" | openssl ec -pubout 2>/dev/null | awk 'NR>1{printf "\\n"}{printf "%s",$0}'
}

find_ami() {
    awsq ec2 describe-images --owners self \
        --filters "Name=name,Values=snp-${AWS_IMAGE_TAG}" "Name=state,Values=available" \
        --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text 2>/dev/null
}

# ---- up ----------------------------------------------------------------------
cmd_up() {
    local jwt; jwt="$(jwt_pubkey)"
    local gcp_peer_digest; gcp_peer_digest="$(role_digest "${AWS_ROLE}")"
    local aws_peer_digest; aws_peer_digest="$(role_digest "${GCP_ROLE}")"
    local ami; ami="$(find_ami)"
    [[ -n "${ami}" && "${ami}" != "None" ]] || { echo "no AMI snp-${AWS_IMAGE_TAG} in ${AWS_REGION}; build it first (snp-aws-image.sh image ${AWS_IMAGE_TAG})" >&2; exit 1; }
    g compute images describe "${GCP_IMAGE}" --format='value(name)' >/dev/null 2>&1 \
        || { echo "no GCP image ${GCP_IMAGE}; build it first (snp-gcp-image.sh image <tag>)" >&2; exit 1; }
    echo "[up] pair ${PAIR_NAME}: ${GCP_ROLE}@gcp (${GCP_IMAGE}) + ${AWS_ROLE}@aws (${ami})"

    echo "[up] allocating AWS Elastic IP..."
    local alloc eip
    alloc="$(awsq ec2 allocate-address --domain vpc \
        --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=${AWS_TAG}}]" \
        --query 'AllocationId' --output text)"
    eip="$(awsq ec2 describe-addresses --allocation-ids "${alloc}" --query 'Addresses[0].PublicIp' --output text)"
    echo "[up] EIP ${eip} (${alloc})"

    echo "[up] ensuring GCP firewall tcp:${PORT}..."
    g compute firewall-rules create "snp-test-allow-${PORT}" --network=default \
        --direction=INGRESS --action=ALLOW --rules="tcp:${PORT}" --source-ranges=0.0.0.0/0 \
        --quiet >/dev/null 2>&1 || true

    echo "[up] creating GCP ${GCP_VM} (peer = AWS EIP, self auto-discovered)..."
    local genv; genv="$(mktemp)"
    cat > "${genv}" <<EOF
ROUTER_URL=${ROUTER_URL}
PEER_ADDR=${eip}:${PORT}
EXPECTED_PEER_IMAGE_DIGEST=${gcp_peer_digest}
JWT_PUBLIC_KEY=${jwt}
EXPECTED_JWT_ISSUER=${JWT_ISSUER}
SNP_TEST_STATIC_OPRF=${STATIC_OPRF}
PORT=${PORT}
LOG_LEVEL=${LOG_LEVEL}
GCP_PROJECT_ID=${GCP_PROJECT}
EOF
    g compute instances delete "${GCP_VM}" --zone="${GCP_ZONE}" --quiet >/dev/null 2>&1 || true
    g compute instances create "${GCP_VM}" --zone="${GCP_ZONE}" \
        --machine-type=n2d-standard-2 \
        --confidential-compute-type=SEV_SNP --min-cpu-platform="AMD Milan" \
        --maintenance-policy=TERMINATE \
        --no-shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
        --image="${GCP_IMAGE}" --image-project="${GCP_PROJECT}" \
        --metadata-from-file "tee-env=${genv}" --quiet >/dev/null
    rm -f "${genv}"

    local gip
    gip="$(g compute instances describe "${GCP_VM}" --zone="${GCP_ZONE}" \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null)"
    [[ -n "${gip}" && "${gip}" != "None" ]] || { echo "[up] GCP VM has no external IP" >&2; exit 1; }
    echo "[up] GCP ${GCP_VM} IP ${gip}"

    echo "[up] creating AWS ${AWS_TAG} (self = EIP, peer = GCP IP)..."
    local sgid; sgid="$(ensure_sg)"
    local aenv; aenv="$(mktemp)"
    cat > "${aenv}" <<EOF
ROUTER_URL=${ROUTER_URL}
SELF_ADDR=${eip}:${PORT}
PEER_ADDR=${gip}:${PORT}
EXPECTED_PEER_IMAGE_DIGEST=${aws_peer_digest}
JWT_PUBLIC_KEY=${jwt}
EXPECTED_JWT_ISSUER=${JWT_ISSUER}
SNP_TEST_STATIC_OPRF=${STATIC_OPRF}
PORT=${PORT}
LOG_LEVEL=${LOG_LEVEL}
CLOUDWATCH_LOG_GROUP=/reclaim-tee/snp
AWS_REGION=${AWS_REGION}
EOF
    local iid
    iid="$(awsq ec2 run-instances --image-id "${ami}" --instance-type "${AWS_TYPE}" \
        --cpu-options AmdSevSnp=enabled \
        --key-name "${KEYNAME}" --security-group-ids "${sgid}" \
        --iam-instance-profile "Name=${AWS_IAM_PROFILE}" \
        --user-data "file://${aenv}" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${AWS_TAG}}]" \
        --query 'Instances[0].InstanceId' --output text)"
    rm -f "${aenv}"
    echo "[up] AWS instance ${iid}; waiting for running..."
    awsq ec2 wait instance-running --instance-ids "${iid}"
    awsq ec2 associate-address --instance-id "${iid}" --allocation-id "${alloc}" >/dev/null
    echo "[up] EIP ${eip} associated to ${iid}"

    echo "[up] polling /health on both (gcp ${gip}, aws ${eip})..."
    poll_health "${gip}" "${eip}"
}

ensure_sg() {
    local sgid
    sgid="$(awsq ec2 describe-security-groups --group-names "${SGNAME}" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
    if [[ -z "${sgid}" || "${sgid}" == "None" ]]; then
        sgid="$(awsq ec2 create-security-group --group-name "${SGNAME}" --description "${PAIR_NAME}" --query 'GroupId' --output text)"
    fi
    awsq ec2 authorize-security-group-ingress --group-id "${sgid}" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
    awsq ec2 authorize-security-group-ingress --group-id "${sgid}" --protocol tcp --port "${PORT}" --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
    echo "${sgid}"
}

poll_health() {
    local gip="$1" eip="$2" gok="" aok=""
    for i in $(seq 1 48); do
        [[ -z "${gok}" ]] && curl -fksS --max-time 4 "https://${gip}:${PORT}/health" >/dev/null 2>&1 && { gok=1; echo "  [${i}] gcp ${gip} healthy"; }
        [[ -z "${aok}" ]] && curl -fksS --max-time 4 "https://${eip}:${PORT}/health" >/dev/null 2>&1 && { aok=1; echo "  [${i}] aws ${eip} healthy"; }
        [[ -n "${gok}" && -n "${aok}" ]] && { echo "[up] both TEEs healthy. Pair registers with ${ROUTER_URL} on boot."; return 0; }
        sleep 10
    done
    echo "[up] not both healthy yet (gcp=${gok:-no} aws=${aok:-no}). Check logs (Cloud Logging / CloudWatch)." >&2
}

# ---- status ------------------------------------------------------------------
cmd_status() {
    echo "=== GCP ${GCP_VM} (${GCP_ZONE}) ==="
    local gip
    gip="$(g compute instances describe "${GCP_VM}" --zone="${GCP_ZONE}" \
        --format='value(status,networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || echo "absent")"
    echo "  ${gip}"
    [[ "${gip}" != "absent" ]] && { gip="${gip##*$'\t'}"; curl -ks -o /dev/null -w "  https://${gip}:${PORT}/health -> %{http_code}\n" --max-time 6 "https://${gip}:${PORT}/health" || true; }
    echo "=== AWS ${AWS_TAG} (${AWS_REGION}) ==="
    awsq ec2 describe-instances --filters "Name=tag:Name,Values=${AWS_TAG}" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
        --query 'Reservations[].Instances[].[InstanceId,State.Name,PublicIpAddress]' --output text 2>/dev/null || echo "  absent"
}

# ---- down --------------------------------------------------------------------
cmd_down() {
    echo "[down] deleting GCP ${GCP_VM}..."
    g compute instances delete "${GCP_VM}" --zone="${GCP_ZONE}" --quiet >/dev/null 2>&1 || true
    echo "[down] terminating AWS ${AWS_TAG}..."
    local iid
    iid="$(awsq ec2 describe-instances --filters "Name=tag:Name,Values=${AWS_TAG}" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
        --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || true)"
    if [[ -n "${iid}" && "${iid}" != "None" ]]; then
        awsq ec2 terminate-instances --instance-ids "${iid}" >/dev/null
        awsq ec2 wait instance-terminated --instance-ids "${iid}"
    fi
    echo "[down] releasing EIP tagged ${AWS_TAG}..."
    local alloc
    alloc="$(awsq ec2 describe-addresses --filters "Name=tag:Name,Values=${AWS_TAG}" --query 'Addresses[0].AllocationId' --output text 2>/dev/null || true)"
    [[ -n "${alloc}" && "${alloc}" != "None" ]] && awsq ec2 release-address --allocation-id "${alloc}" >/dev/null 2>&1 || true
    awsq ec2 delete-security-group --group-name "${SGNAME}" >/dev/null 2>&1 || true
    echo "[down] pair ${PAIR_NAME} torn down (images kept)."
}

case "${1:-}" in
    up)     cmd_up ;;
    status) cmd_status ;;
    down)   cmd_down ;;
    *) echo "usage: $0 {up|status|down}" >&2; exit 1 ;;
esac
