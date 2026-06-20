#!/bin/bash
set -euo pipefail

# NOTE: the AWS CLI on this WSL box NEEDS the local proxy (127.0.0.1:10808) to
# reach AWS — do NOT unset it here (unsetting makes aws hang/time out). The
# go/docker build steps are delegated to snp-build-image.sh, which unsets the
# proxy for itself (go wants it unset). See memory [[wsl-proxy]].

# =============================================================================
# Package a locally-built two-tier SEV-SNP image (deploy/snp-image/snp-tier.raw,
# built with CLOUD=aws so the loader bundles sev-guest.ko) as an EC2 AMI via VM
# Import/Export, then boot it on a SEV-SNP instance (--cpu-options AmdSevSnp) and
# read the serial console / :8081 health.
#
#   ./deploy/snp-aws-image.sh build <TAG>   rebuild the raw with CLOUD=aws
#   ./deploy/snp-aws-image.sh image <TAG>   raw -> S3 -> import-snapshot -> register AMI
#   ./deploy/snp-aws-image.sh test  <TAG>   launch SEV-SNP instance, poll console/8081
#   ./deploy/snp-aws-image.sh down          terminate the test instance
#
# Env: AWS_SNP_REGION (default us-east-2), AWS_SNP_TYPE (default c6a.large),
#      SNP_S3_BUCKET (default snp-vmimport-<acct>).
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

REGION="${AWS_SNP_REGION:?set AWS_SNP_REGION in deploy/.env}"
ITYPE="${AWS_SNP_TYPE:-c6a.large}"
RAW="${SCRIPT_DIR}/snp-image/snp-tier.raw"
ACCT="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="${SNP_S3_BUCKET:-snp-vmimport-${ACCT}}"
KEYNAME="snp-img-key"
PEM="${SCRIPT_DIR}/${KEYNAME}.pem"
SGNAME="snp-img-sg"
TEST_TAG="snp-image-test"

awsq() { aws --region "${REGION}" "$@"; }
ssh_opts=(-i "${PEM}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10)

find_ami() {
    local image="snp-${1}"
    awsq ec2 describe-images --owners self \
        --filters "Name=name,Values=${image}" "Name=state,Values=available" \
        --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text 2>/dev/null
}

cmd_build() {
    local tag="${1:?usage: build <TAG>}"
    echo "[build] rebuilding two-tier raw with CLOUD=aws (sev-guest.ko bundled)..."
    CLOUD=aws "${SCRIPT_DIR}/snp-build-image.sh" tee "${tag}"
}

cmd_image() {
    local tag="${1:?usage: image <TAG>}"
    local image="snp-${tag}"
    [[ -f "${RAW}" ]] || { echo "missing ${RAW}; run '$0 build ${tag}' first" >&2; exit 1; }
    local key="${image}.vmdk"
    local tmp; tmp="$(mktemp -d)"; local vmdk="${tmp}/disk.vmdk"

    # Deterministic streamOptimized VMDK: a FIXED basename (disk.vmdk) keeps the
    # descriptor's embedded filename constant and we pin the CID; the rest of the
    # qemu stream is reproducible -> byte-identical run-to-run (verified). ~38M vs
    # ~610M raw. The earlier "VMDK is non-deterministic" was just CID + basename.
    echo "[image] converting raw -> deterministic streamOptimized VMDK..."
    qemu-img convert -f raw -O vmdk -o subformat=streamOptimized "${RAW}" "${vmdk}"
    python3 - "${vmdk}" <<'PY'
import re,sys
p=sys.argv[1]; b=bytearray(open(p,'rb').read())
m=re.search(rb'CID=[0-9a-f]{8}', b)
b[m.start():m.end()]=b'CID=00000001'
open(p,'wb').write(b)
PY
    echo "[image] vmdk: $(du -h "${vmdk}" | cut -f1)  sha256: $(sha256sum "${vmdk}" | cut -d' ' -f1)"
    echo "[image] uploading -> s3://${BUCKET}/${key}..."
    aws s3 cp "${vmdk}" "s3://${BUCKET}/${key}" --no-progress
    rm -rf "${tmp}"

    echo "[image] starting import-snapshot (VMDK)..."
    local task
    task="$(awsq ec2 import-snapshot --description "${image}" \
        --disk-container "Format=VMDK,UserBucket={S3Bucket=${BUCKET},S3Key=${key}}" \
        --query 'ImportTaskId' --output text)"
    echo "[image] import task ${task}; waiting (this can take 5-15 min)..."

    local snap="" status detail
    for i in $(seq 1 90); do
        status="$(awsq ec2 describe-import-snapshot-tasks --import-task-ids "${task}" \
            --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.Status' --output text 2>/dev/null || true)"
        detail="$(awsq ec2 describe-import-snapshot-tasks --import-task-ids "${task}" \
            --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.[Progress,StatusMessage]' --output text 2>/dev/null || true)"
        echo "  [${i}] status=${status} ${detail}"
        case "${status}" in
            completed) snap="$(awsq ec2 describe-import-snapshot-tasks --import-task-ids "${task}" \
                            --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.SnapshotId' --output text)"; break ;;
            deleted|deleting) echo "[image] import failed: ${detail}" >&2; exit 1 ;;
        esac
        sleep 20
    done
    [[ -n "${snap}" && "${snap}" != "None" ]] || { echo "[image] no snapshot produced" >&2; exit 1; }
    echo "[image] snapshot ${snap}"

    echo "[image] registering AMI ${image} (UEFI, no secure-boot, ENA, NitroTPM v2.0)..."
    awsq ec2 deregister-image --image-id "$(find_ami "${tag}")" >/dev/null 2>&1 || true
    local ami
    ami="$(awsq ec2 register-image --name "${image}" \
        --architecture x86_64 --virtualization-type hvm \
        --boot-mode uefi --ena-support --sriov-net-support simple \
        --tpm-support v2.0 \
        --root-device-name /dev/xvda \
        --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=${snap},DeleteOnTermination=true,VolumeType=gp3}" \
        --query 'ImageId' --output text)"
    echo "[image] AMI ${ami} registered. Next: $0 test ${tag}"
}

ensure_key() {
    if [[ ! -f "${PEM}" ]]; then
        awsq ec2 delete-key-pair --key-name "${KEYNAME}" >/dev/null 2>&1 || true
        awsq ec2 create-key-pair --key-name "${KEYNAME}" --query 'KeyMaterial' --output text > "${PEM}"
        chmod 600 "${PEM}"
    fi
}
ensure_sg() {
    local sgid
    sgid="$(awsq ec2 describe-security-groups --group-names "${SGNAME}" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
    if [[ -z "${sgid}" || "${sgid}" == "None" ]]; then
        sgid="$(awsq ec2 create-security-group --group-name "${SGNAME}" --description "snp image test" --query 'GroupId' --output text)"
    fi
    awsq ec2 authorize-security-group-ingress --group-id "${sgid}" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
    awsq ec2 authorize-security-group-ingress --group-id "${sgid}" --protocol tcp --port 8081 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
    echo "${sgid}"
}

cmd_test() {
    local tag="${1:?usage: test <TAG>}"
    local ami; ami="$(find_ami "${tag}")"
    [[ -n "${ami}" && "${ami}" != "None" ]] || { echo "no AMI snp-${tag}; run '$0 image ${tag}'" >&2; exit 1; }
    ensure_key
    local sgid; sgid="$(ensure_sg)"

    echo "[test] launching ${ITYPE} (AmdSevSnp=enabled) from ${ami} in ${REGION}..."
    local iid
    iid="$(awsq ec2 run-instances --image-id "${ami}" --instance-type "${ITYPE}" \
        --cpu-options AmdSevSnp=enabled \
        --key-name "${KEYNAME}" --security-group-ids "${sgid}" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${TEST_TAG}}]" \
        --query 'Instances[0].InstanceId' --output text)"
    echo "[test] instance ${iid}; waiting for running..."
    awsq ec2 wait instance-running --instance-ids "${iid}"
    local ip
    ip="$(awsq ec2 describe-instances --instance-ids "${iid}" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
    echo "[test] public IP: ${ip}"

    echo "[test] polling (:8081/health for tee_t, or console for SNP-PROBE)..."
    for i in $(seq 1 48); do
        if [[ -n "${ip}" && "${ip}" != "None" ]] && curl -fsS --max-time 4 "http://${ip}:8081/health" 2>/dev/null | grep -q .; then
            echo "===== REACHABLE: GET http://${ip}:8081/health ====="
            curl -fsS --max-time 4 "http://${ip}:8081/health"; echo
            return 0
        fi
        out="$(awsq ec2 get-console-output --instance-id "${iid}" --query Output --output text 2>/dev/null | base64 -d 2>/dev/null || true)"
        if echo "${out}" | grep -q "SNP-PROBE"; then
            echo "===== prober output ====="; echo "${out}" | grep -A8 "SNP-PROBE ====" | head -12; return 0
        fi
        echo "${out}" | grep -E "net up:|MPCLDIR|standalone server|loaded module|DHCP" | tail -3 || true
        sleep 10
    done
    echo "[test] not reachable yet. Console:"
    echo "  aws --region ${REGION} ec2 get-console-output --instance-id ${iid} --output text"
}

cmd_down() {
    local iid
    iid="$(awsq ec2 describe-instances --filters "Name=tag:Name,Values=${TEST_TAG}" \
        "Name=instance-state-name,Values=pending,running" \
        --query 'Reservations[].Instances[0].InstanceId' --output text 2>/dev/null)"
    [[ -n "${iid}" && "${iid}" != "None" ]] && { echo "[down] terminating ${iid}..."; awsq ec2 terminate-instances --instance-ids "${iid}" >/dev/null; awsq ec2 wait instance-terminated --instance-ids "${iid}"; }
    awsq ec2 delete-security-group --group-name "${SGNAME}" >/dev/null 2>&1 || true
    echo "[down] test instance terminated (AMI + snapshot kept)"
}

case "${1:-}" in
    build) cmd_build "${2:-}" ;;
    image) cmd_image "${2:-}" ;;
    test)  cmd_test "${2:-}" ;;
    down)  cmd_down ;;
    *) echo "usage: $0 {build <TAG>|image <TAG>|test <TAG>|down}" >&2; exit 1 ;;
esac
