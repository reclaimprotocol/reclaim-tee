#!/bin/bash
set -euo pipefail

# The flaky local WSL proxy (127.0.0.1:10808) breaks the AWS CLI; bypass it.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true

# =============================================================================
# AWS SEV-SNP proof-of-concept: launch the cheapest SEV-SNP EC2 instance
# (c6a.large, --cpu-options AmdSevSnp=enabled), pu/bsh the snp-poc binary, run it,
# and print the raw SEV-SNP report + AMD-chain verification. Answers the gating
# AWS question: does AWS expose /dev/sev-guest, and what does its MEASUREMENT
# cover (AMD-rooted code vs firmware-only, as on GCP)?
#
#   ./deploy/snp-aws-poc.sh up     # create instance, push binary, run
#   ./deploy/snp-aws-poc.sh run    # re-run the binary on the existing instance
#   ./deploy/snp-aws-poc.sh ssh    # interactive ssh
#   ./deploy/snp-aws-poc.sh down   # terminate instance (+ sg/key)
#
# Env: AWS_SNP_REGION (default us-east-2 — has SEV-SNP types), AWS_SNP_TYPE.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

REGION="${AWS_SNP_REGION:?set AWS_SNP_REGION in deploy/.env}"
ITYPE="${AWS_SNP_TYPE:-c6a.large}"
KEYNAME="snp-poc-key"
PEM="${SCRIPT_DIR}/${KEYNAME}.pem"
SGNAME="snp-poc-sg"
TAG="snp-aws-poc"

awsq() { aws --region "${REGION}" "$@"; }
ssh_opts=(-i "${PEM}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10)

find_instance() {
    awsq ec2 describe-instances \
        --filters "Name=tag:Name,Values=${TAG}" "Name=instance-state-name,Values=pending,running" \
        --query 'Reservations[].Instances[0].InstanceId' --output text 2>/dev/null
}
instance_ip() {
    awsq ec2 describe-instances --instance-ids "$1" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null
}

build_binary() {
    echo "[aws-poc] building snp-poc (linux/amd64)..."
    ( cd "${REPO_DIR}/snp-poc" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o snp-poc . )
}

ensure_key() {
    if [[ ! -f "${PEM}" ]]; then
        echo "[aws-poc] creating key pair ${KEYNAME}..."
        awsq ec2 delete-key-pair --key-name "${KEYNAME}" >/dev/null 2>&1 || true
        awsq ec2 create-key-pair --key-name "${KEYNAME}" --query 'KeyMaterial' --output text > "${PEM}"
        chmod 600 "${PEM}"
    fi
}

ensure_sg() {
    local sgid
    sgid="$(awsq ec2 describe-security-groups --group-names "${SGNAME}" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
    if [[ -z "${sgid}" || "${sgid}" == "None" ]]; then
        echo "[aws-poc] creating security group ${SGNAME}..." >&2
        sgid="$(awsq ec2 create-security-group --group-name "${SGNAME}" --description "snp poc ssh" --query 'GroupId' --output text)"
    fi
    # Always ensure the SSH ingress rule (a reused/leftover SG may lack it —
    # that caused a no-SSH hang). Idempotent: ignore the duplicate-rule error.
    awsq ec2 authorize-security-group-ingress --group-id "${sgid}" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
    echo "${sgid}"
}

resolve_ami() {
    awsq ec2 describe-images --owners 099720109477 \
        --filters 'Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*' 'Name=state,Values=available' \
        --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text
}

wait_ssh() {
    local ip="$1"
    echo "[aws-poc] waiting for SSH at ${ip}..."
    for i in {1..40}; do
        ssh "${ssh_opts[@]}" "ubuntu@${ip}" true >/dev/null 2>&1 && { echo "[aws-poc] SSH up."; return 0; }
        sleep 5
    done
    echo "[aws-poc] SSH never came up" >&2; return 1
}

run_probe() {
    local ip="$1"
    echo "[aws-poc] pushing binary + running (needs root for /dev/sev-guest)..."
    scp "${ssh_opts[@]}" "${REPO_DIR}/snp-poc/snp-poc" "ubuntu@${ip}:~/snp-poc" >/dev/null
    ssh "${ssh_opts[@]}" "ubuntu@${ip}" '
        echo "--- dmesg sev ---"; sudo dmesg | grep -i -E "sev-snp|SEV-SNP|sev-guest|Memory Encryption" | head;
        echo "--- /dev/sev-guest ---"; ls -l /dev/sev-guest 2>&1 || echo "MISSING /dev/sev-guest";
        chmod +x ~/snp-poc;
        echo "--- run (verify) ---"; sudo ~/snp-poc -dump=/tmp/att.bin || true;
        echo "--- run (skip-verify) ---"; sudo ~/snp-poc -skip-verify || true;
        sudo chmod 644 /tmp/att.bin 2>/dev/null || true;
    '
    # Pull the marshaled attestation back as an offline test fixture, via
    # base64 over the ssh channel (robust — avoids scp pull quirks).
    local fixture="${REPO_DIR}/shared/testdata/aws_vlek_attestation.bin"
    mkdir -p "$(dirname "${fixture}")"
    ssh "${ssh_opts[@]}" "ubuntu@${ip}" "base64 -w0 /tmp/att.bin 2>/dev/null" | base64 -d > "${fixture}" 2>/dev/null || true
    if [[ -s "${fixture}" ]]; then
        echo "[aws-poc] captured fixture: ${fixture} ($(stat -c%s "${fixture}") bytes)"
    else
        echo "[aws-poc] WARN: fixture capture failed"; rm -f "${fixture}"
    fi
}

case "${1:-up}" in
    up)
        build_binary
        ensure_key
        SGID="$(ensure_sg)"
        AMI="$(resolve_ami)"
        echo "[aws-poc] launching ${ITYPE} (AmdSevSnp=enabled) AMI=${AMI} in ${REGION}..."
        IID="$(awsq ec2 run-instances --image-id "${AMI}" --instance-type "${ITYPE}" \
            --cpu-options AmdSevSnp=enabled \
            --key-name "${KEYNAME}" --security-group-ids "${SGID}" \
            --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${TAG}}]" \
            --query 'Instances[0].InstanceId' --output text)"
        echo "[aws-poc] instance ${IID}; waiting for running..."
        awsq ec2 wait instance-running --instance-ids "${IID}"
        IP="$(instance_ip "${IID}")"
        echo "[aws-poc] public IP: ${IP}"
        wait_ssh "${IP}"
        run_probe "${IP}"
        echo "[aws-poc] done. './deploy/snp-aws-poc.sh down' to terminate."
        ;;
    run)
        build_binary
        IID="$(find_instance)"; [[ -n "${IID}" && "${IID}" != "None" ]] || { echo "no running instance"; exit 1; }
        run_probe "$(instance_ip "${IID}")"
        ;;
    ssh)
        IID="$(find_instance)"; ssh "${ssh_opts[@]}" "ubuntu@$(instance_ip "${IID}")"
        ;;
    down)
        IID="$(find_instance)"
        [[ -n "${IID}" && "${IID}" != "None" ]] && { echo "[aws-poc] terminating ${IID}..."; awsq ec2 terminate-instances --instance-ids "${IID}" >/dev/null; awsq ec2 wait instance-terminated --instance-ids "${IID}"; }
        awsq ec2 delete-security-group --group-name "${SGNAME}" >/dev/null 2>&1 || true
        awsq ec2 delete-key-pair --key-name "${KEYNAME}" >/dev/null 2>&1 || true
        rm -f "${PEM}"
        echo "[aws-poc] cleaned up"
        ;;
    *) echo "usage: $0 {up|run|ssh|down}" >&2; exit 1 ;;
esac
