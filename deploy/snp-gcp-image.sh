#!/bin/bash
set -euo pipefail

# The flaky local WSL proxy (127.0.0.1:10808) breaks gcloud; bypass it.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true

# =============================================================================
# Package a locally-built two-tier SEV-SNP image (deploy/snp-image/snp-tier.raw
# or snp-mini.raw) as a GCP image, boot it on a SEV-SNP CVM (vTPM on, secure-boot
# off since the UKI is unsigned), and read the actual vTPM PCRs + SEV-SNP report
# from the serial console.
#
#   ./deploy/snp-gcp-image.sh image <TAG>   tar raw -> GCS -> create GCP image
#   ./deploy/snp-gcp-image.sh test  <TAG>   boot SEV-SNP CVM, poll serial
#   ./deploy/snp-gcp-image.sh down          delete the test VM
#
# Env (deploy/.env or inline): GCP_PROJECT (required), SNP_ZONE.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then set -a; source "${SCRIPT_DIR}/.env"; set +a; fi
source "${SCRIPT_DIR}/_lib.sh"

: "${GCP_PROJECT:?set GCP_PROJECT (or put it in deploy/.env)}"
ZONE="${SNP_ZONE:?set SNP_ZONE in deploy/.env}"
# Which local raw to package: the two-tier image by default (base UKI + app),
# or the minimal no-rootfs UKI image via SNP_RAW=snp-mini.raw.
RAW="${SCRIPT_DIR}/snp-image/${SNP_RAW:-snp-tier.raw}"
BUCKET="gs://${GCP_PROJECT}-snp-images"
TEST_VM="snp-test"

g() { gcloud_retry gcloud "$@"; }

cmd_image() {
    local tag="${1:?usage: image <TAG>}"
    local image="snp-${tag}"
    [[ -f "${RAW}" ]] || { echo "missing ${RAW}; build it first" >&2; exit 1; }

    echo "[image] packaging ${RAW} as disk.raw tarball..."
    local tmp; tmp="$(mktemp -d)"
    # GCP requires the file inside the tarball to be named exactly 'disk.raw'.
    cp --reflink=auto "${RAW}" "${tmp}/disk.raw"
    tar --format=oldgnu -C "${tmp}" -Sczf "${tmp}/${image}.tar.gz" disk.raw

    echo "[image] ensuring bucket ${BUCKET}..."
    g storage buckets create "${BUCKET}" --location=US >/dev/null 2>&1 || true
    echo "[image] uploading..."
    # gsutil, not `gcloud storage cp` — the latter crashes with a local
    # PermissionError on this WSL box; gsutil uploads fine.
    gsutil -q cp "${tmp}/${image}.tar.gz" "${BUCKET}/${image}.tar.gz"

    echo "[image] creating GCP image ${image}..."
    g compute images delete "${image}" --project="${GCP_PROJECT}" --quiet >/dev/null 2>&1 || true
    g compute images create "${image}" --project="${GCP_PROJECT}" \
        --source-uri="${BUCKET}/${image}.tar.gz" \
        --guest-os-features=UEFI_COMPATIBLE,SEV_SNP_CAPABLE,VIRTIO_SCSI_MULTIQUEUE
    rm -rf "${tmp}"
    echo "[image] ${image} created. Next: $0 test ${tag}"
}

cmd_test() {
    local tag="${1:?usage: test <TAG>}"
    local image="snp-${tag}"

    # Allow inbound tcp:8081 so a server app (tee_t) is reachable from outside.
    g compute firewall-rules create snp-test-allow-8081 --project="${GCP_PROJECT}" \
        --network=default --direction=INGRESS --action=ALLOW --rules=tcp:8081 \
        --source-ranges=0.0.0.0/0 --quiet >/dev/null 2>&1 || true

    echo "[test] launching SEV-SNP CVM from ${image} (vtpm on, secure-boot off)..."
    g compute instances delete "${TEST_VM}" --project="${GCP_PROJECT}" --zone="${ZONE}" --quiet >/dev/null 2>&1 || true
    g compute instances create "${TEST_VM}" --project="${GCP_PROJECT}" --zone="${ZONE}" \
        --machine-type=n2d-standard-2 \
        --confidential-compute-type=SEV_SNP --min-cpu-platform="AMD Milan" \
        --maintenance-policy=TERMINATE \
        --no-shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
        --image="${image}" --image-project="${GCP_PROJECT}" --quiet >/dev/null

    local ext
    ext="$(g compute instances describe "${TEST_VM}" --project="${GCP_PROJECT}" --zone="${ZONE}" \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || true)"
    echo "[test] external IP: ${ext:-<none>}"

    echo "[test] polling (serial banner for prober, or :8081/health for tee_t)..."
    for i in {1..36}; do
        if [[ -n "${ext}" ]] && curl -fsS --max-time 4 "http://${ext}:8081/health" 2>/dev/null | grep -q .; then
            echo "===== REACHABLE: GET http://${ext}:8081/health ====="
            curl -fsS --max-time 4 "http://${ext}:8081/health"; echo
            echo "--- serial 'net up' line ---"
            g compute instances get-serial-port-output "${TEST_VM}" --project="${GCP_PROJECT}" --zone="${ZONE}" --port=1 2>/dev/null | grep -E "net up:|MPCLDIR|standalone server" | tail -5
            return 0
        fi
        out="$(g compute instances get-serial-port-output "${TEST_VM}" \
            --project="${GCP_PROJECT}" --zone="${ZONE}" --port=1 2>/dev/null || true)"
        if echo "${out}" | grep -q "SNP-PROBE"; then
            echo "===== prober output ====="
            echo "${out}" | grep -A8 "SNP-PROBE ====" | head -12
            return 0
        fi
        sleep 5
    done
    echo "[test] not reachable / no banner yet. Check serial:"
    echo "  gcloud compute instances get-serial-port-output ${TEST_VM} --zone=${ZONE} --port=1"
}

cmd_down() {
    g compute instances delete "${TEST_VM}" --project="${GCP_PROJECT}" --zone="${ZONE}" --quiet >/dev/null 2>&1 || true
    echo "[down] test VM deleted (image + bucket kept)"
}

case "${1:-}" in
    image) cmd_image "${2:-}" ;;
    test)  cmd_test "${2:-}" ;;
    down)  cmd_down ;;
    *) echo "usage: $0 {image <TAG>|test <TAG>|down}" >&2; exit 1 ;;
esac
