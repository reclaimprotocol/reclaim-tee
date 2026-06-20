#!/bin/bash
set -euo pipefail

# =============================================================================
# Bring up BOTH TEEs on AWS (tee_k + tee_t, same region) wired to the test
# router. Unlike snp-pair.sh (one GCP + one AWS), this stands up two AWS
# SEV-SNP instances cross-referenced as peers. Purpose: validate that both
# roles concurrently load their real MPC OPRF share from AWS Secrets Manager
# (KMS_ENCLAVE_DOMAIN_KEY set, SNP_TEST_STATIC_OPRF deliberately UNSET).
#
#   ./deploy/snp-aws-pair.sh up       create + wire both AWS TEEs, poll health
#   ./deploy/snp-aws-pair.sh status   show both instances + /health
#   ./deploy/snp-aws-pair.sh down     terminate both, release both EIPs
#
# Prereqs: both AMIs built (snp-teek-aws, snp-teet-aws); the per-role OPRF
# shares already imported to Secrets Manager; the instance profile can read
# both secrets + kms:Decrypt the CMK. Run with the proxy SET (AWS CLI needs it).
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then set -a; source "${SCRIPT_DIR}/.env"; set +a; fi

AWS_REGION="${SNP_PAIR_AWS_REGION:?set SNP_PAIR_AWS_REGION in deploy/.env}"
AWS_TYPE="${SNP_PAIR_AWS_TYPE:-c6a.large}"
PROFILE="${SNP_AWS_IAM_PROFILE:-snp-tee-logger}"
KEYNAME="${SNP_AWS_KEYNAME:-snp-img-key}"
SGNAME="${SNP_AWS_PAIR_SG:-snp-aws-pair-sg}"

ROUTER_URL="${SNP_ROUTER_URL:?set SNP_ROUTER_URL in deploy/.env}"
JWT_ISSUER="${SNP_JWT_ISSUER:?set SNP_JWT_ISSUER in deploy/.env}"
PORT="${SNP_PORT:-8081}"
LOG_LEVEL="${SNP_LOG_LEVEL:-debug}"

# New (rebuilt) cross-cloud app digests, one per role. Required by `up` for the
# peer EXPECTED_PEER_IMAGE_DIGEST cross-check; status/down don't need them.
K_DIGEST="${SNP_K_DIGEST:-}"
T_DIGEST="${SNP_T_DIGEST:-}"

# Same deployment keys as prod CS so the secret names + share values match.
K_DEPLOY_KEY="${TEE_K_DEPLOYMENT_KEY:?set TEE_K_DEPLOYMENT_KEY in deploy/.env}"
T_DEPLOY_KEY="${TEE_T_DEPLOYMENT_KEY:?set TEE_T_DEPLOYMENT_KEY in deploy/.env}"

K_TAG="${SNP_AWS_PAIR_K_TAG:-snp-awspair-k}"
T_TAG="${SNP_AWS_PAIR_T_TAG:-snp-awspair-t}"
K_AMI_NAME="${SNP_K_AMI:-snp-teek-aws}"
T_AMI_NAME="${SNP_T_AMI:-snp-teet-aws}"
SIGNKEY="${SCRIPT_DIR}/.test-router-signing-key"

awsq() { aws --region "${AWS_REGION}" "$@"; }

jwt_pubkey() {
    [[ -f "${SIGNKEY}" ]] || { echo "missing ${SIGNKEY}" >&2; exit 1; }
    printf '%b' "$(cat "${SIGNKEY}")" | openssl ec -pubout 2>/dev/null | awk 'NR>1{printf "\\n"}{printf "%s",$0}'
}

find_ami() {
    awsq ec2 describe-images --owners self \
        --filters "Name=name,Values=$1" "Name=state,Values=available" \
        --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text 2>/dev/null
}

ensure_sg() {
    local sgid
    sgid="$(awsq ec2 describe-security-groups --group-names "${SGNAME}" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
    if [[ -z "${sgid}" || "${sgid}" == "None" ]]; then
        sgid="$(awsq ec2 create-security-group --group-name "${SGNAME}" --description snp-aws-pair --query 'GroupId' --output text)"
    fi
    awsq ec2 authorize-security-group-ingress --group-id "${sgid}" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
    awsq ec2 authorize-security-group-ingress --group-id "${sgid}" --protocol tcp --port "${PORT}" --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
    echo "${sgid}"
}

alloc_eip() {
    local tag="$1" alloc
    alloc="$(awsq ec2 allocate-address --domain vpc \
        --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=${tag}}]" \
        --query 'AllocationId' --output text)"
    echo "${alloc}"
}

eip_of() { awsq ec2 describe-addresses --allocation-ids "$1" --query 'Addresses[0].PublicIp' --output text; }

# launch <tag> <ami> <self_eip> <peer_eip> <peer_digest> <deploy_key> <sgid> <jwt>
launch() {
    local tag="$1" ami="$2" self_eip="$3" peer_eip="$4" peer_digest="$5" deploy_key="$6" sgid="$7" jwt="$8"
    local env; env="$(mktemp)"
    cat > "${env}" <<EOF
ROUTER_URL=${ROUTER_URL}
SELF_ADDR=${self_eip}:${PORT}
PEER_ADDR=${peer_eip}:${PORT}
EXPECTED_PEER_IMAGE_DIGEST=${peer_digest}
JWT_PUBLIC_KEY=${jwt}
EXPECTED_JWT_ISSUER=${JWT_ISSUER}
KMS_ENCLAVE_DOMAIN_KEY=${deploy_key}
PORT=${PORT}
LOG_LEVEL=${LOG_LEVEL}
CLOUDWATCH_LOG_GROUP=/reclaim-tee/snp
AWS_REGION=${AWS_REGION}
EOF
    awsq ec2 run-instances --image-id "${ami}" --instance-type "${AWS_TYPE}" \
        --cpu-options AmdSevSnp=enabled \
        --key-name "${KEYNAME}" --security-group-ids "${sgid}" \
        --iam-instance-profile "Name=${PROFILE}" \
        --user-data "file://${env}" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${tag}}]" \
        --query 'Instances[0].InstanceId' --output text
    rm -f "${env}"
}

cmd_up() {
    [[ -n "${K_DIGEST}" && -n "${T_DIGEST}" ]] || { echo "set SNP_K_DIGEST + SNP_T_DIGEST (snp-app:<hex> from the build)" >&2; exit 1; }
    local jwt; jwt="$(jwt_pubkey)"
    local kami tami; kami="$(find_ami "${K_AMI_NAME}")"; tami="$(find_ami "${T_AMI_NAME}")"
    [[ -n "${kami}" && "${kami}" != "None" ]] || { echo "no AMI ${K_AMI_NAME}" >&2; exit 1; }
    [[ -n "${tami}" && "${tami}" != "None" ]] || { echo "no AMI ${T_AMI_NAME}" >&2; exit 1; }
    local sgid; sgid="$(ensure_sg)"

    echo "[up] allocating EIPs..."
    local kalloc talloc keip teip
    kalloc="$(alloc_eip "${K_TAG}")"; talloc="$(alloc_eip "${T_TAG}")"
    keip="$(eip_of "${kalloc}")"; teip="$(eip_of "${talloc}")"
    echo "[up] k EIP ${keip}  t EIP ${teip}"

    echo "[up] launching tee_k@aws (${kami}) + tee_t@aws (${tami})..."
    local kiid tiid
    kiid="$(launch "${K_TAG}" "${kami}" "${keip}" "${teip}" "${T_DIGEST}" "${K_DEPLOY_KEY}" "${sgid}" "${jwt}")"
    tiid="$(launch "${T_TAG}" "${tami}" "${teip}" "${keip}" "${K_DIGEST}" "${T_DEPLOY_KEY}" "${sgid}" "${jwt}")"
    echo "[up] k=${kiid} t=${tiid}; waiting for running..."
    awsq ec2 wait instance-running --instance-ids "${kiid}" "${tiid}"
    awsq ec2 associate-address --instance-id "${kiid}" --allocation-id "${kalloc}" >/dev/null
    awsq ec2 associate-address --instance-id "${tiid}" --allocation-id "${talloc}" >/dev/null
    echo "[up] EIPs associated. Polling /health (k ${keip}, t ${teip})..."
    poll_health "${keip}" "${teip}"
}

poll_health() {
    local keip="$1" teip="$2" kok="" tok=""
    for i in $(seq 1 48); do
        [[ -z "${kok}" ]] && curl -fksS --max-time 4 "https://${keip}:${PORT}/health" >/dev/null 2>&1 && { kok=1; echo "  [${i}] k ${keip} healthy"; }
        [[ -z "${tok}" ]] && curl -fksS --max-time 4 "https://${teip}:${PORT}/health" >/dev/null 2>&1 && { tok=1; echo "  [${i}] t ${teip} healthy"; }
        [[ -n "${kok}" && -n "${tok}" ]] && { echo "[up] both AWS TEEs healthy; pair registers on boot."; return 0; }
        sleep 10
    done
    echo "[up] not both healthy (k=${kok:-no} t=${tok:-no}). Check CloudWatch /reclaim-tee/snp." >&2
}

cmd_status() {
    for tag in "${K_TAG}" "${T_TAG}"; do
        echo "=== ${tag} ==="
        awsq ec2 describe-instances --filters "Name=tag:Name,Values=${tag}" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
            --query 'Reservations[].Instances[].[InstanceId,State.Name,PublicIpAddress]' --output text 2>/dev/null || echo "  absent"
    done
}

cmd_down() {
    for tag in "${K_TAG}" "${T_TAG}"; do
        local iid; iid="$(awsq ec2 describe-instances --filters "Name=tag:Name,Values=${tag}" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
            --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || true)"
        if [[ -n "${iid}" && "${iid}" != "None" ]]; then
            echo "[down] terminating ${tag} (${iid})..."
            awsq ec2 terminate-instances --instance-ids ${iid} >/dev/null
            awsq ec2 wait instance-terminated --instance-ids ${iid}
        fi
        local alloc; alloc="$(awsq ec2 describe-addresses --filters "Name=tag:Name,Values=${tag}" --query 'Addresses[0].AllocationId' --output text 2>/dev/null || true)"
        [[ -n "${alloc}" && "${alloc}" != "None" ]] && { echo "[down] releasing ${tag} EIP..."; awsq ec2 release-address --allocation-id "${alloc}" >/dev/null 2>&1 || true; }
    done
    awsq ec2 delete-security-group --group-name "${SGNAME}" >/dev/null 2>&1 || true
    echo "[down] AWS pair torn down."
}

case "${1:-}" in
    up)     cmd_up ;;
    status) cmd_status ;;
    down)   cmd_down ;;
    *) echo "usage: $0 {up|status|down}" >&2; exit 1 ;;
esac
