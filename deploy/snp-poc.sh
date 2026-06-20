#!/bin/bash
set -euo pipefail

# The system-wide WSL2 proxy causes flaky TLS to GCP / package mirrors; bypass it.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true

# =============================================================================
# SEV-SNP proof-of-concept: boot the cheapest GCP N2D SEV-SNP Confidential VM
# (plain CVM, NOT Confidential Space), push the snp-poc binary, run it, and
# print the raw SEV-SNP report + AMD-chain verification result.
#
# This is throwaway exploration tooling for the `snp` branch. It does NOT touch
# the router, allowlist, or any prod resource. It creates one VM you can delete.
#
# Usage:
#   ./deploy/snp-poc.sh up        # create VM, push binary, run, leave VM up
#   ./deploy/snp-poc.sh run       # re-run the binary on an existing VM
#   ./deploy/snp-poc.sh ssh       # interactive ssh to poke around
#   ./deploy/snp-poc.sh down      # delete the VM
#
# Env (override inline or via deploy/.env):
#   GCP_PROJECT  required
#   SNP_ZONE     default us-central1-a  (must offer N2D SEV-SNP)
#   SNP_VM       default snp-poc
#   SNP_MACHINE  default n2d-standard-2  (cheapest N2D)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    set -a; source "${SCRIPT_DIR}/.env"; set +a
fi

: "${GCP_PROJECT:?set GCP_PROJECT (or put it in deploy/.env)}"
ZONE="${SNP_ZONE:?set SNP_ZONE in deploy/.env}"
VM="${SNP_VM:-snp-poc}"
MACHINE="${SNP_MACHINE:-n2d-standard-2}"
# Stock Ubuntu 24.04: 6.8 kernel ships the sev-guest module + /dev/sev-guest.
IMAGE_FAMILY="ubuntu-2404-lts-amd64"
IMAGE_PROJECT="ubuntu-os-cloud"

cmd="${1:-up}"

build_binary() {
    echo "[snp-poc] building static linux/amd64 binary..."
    ( cd "${REPO_DIR}/snp-poc" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o snp-poc . )
}

create_vm() {
    echo "[snp-poc] creating ${VM} (${MACHINE}, SEV_SNP) in ${ZONE}..."
    gcloud compute instances create "${VM}" \
        --project="${GCP_PROJECT}" --zone="${ZONE}" \
        --machine-type="${MACHINE}" \
        --confidential-compute-type=SEV_SNP \
        --min-cpu-platform="AMD Milan" \
        --maintenance-policy=TERMINATE \
        --shielded-secure-boot \
        --shielded-vtpm \
        --shielded-integrity-monitoring \
        --image-family="${IMAGE_FAMILY}" \
        --image-project="${IMAGE_PROJECT}" \
        --quiet
}

wait_ssh() {
    echo "[snp-poc] waiting for SSH..."
    for i in {1..30}; do
        if gcloud compute ssh "${VM}" --project="${GCP_PROJECT}" --zone="${ZONE}" \
            --command="true" --quiet >/dev/null 2>&1; then
            echo "[snp-poc] SSH up."
            return 0
        fi
        sleep 5
    done
    echo "[snp-poc] SSH never came up" >&2
    return 1
}

push_and_run() {
    echo "[snp-poc] pushing binary..."
    gcloud compute scp "${REPO_DIR}/snp-poc/snp-poc" "${VM}:~/snp-poc" \
        --project="${GCP_PROJECT}" --zone="${ZONE}" --quiet
    echo "[snp-poc] checking SEV-SNP guest device + running (needs root for /dev/sev-guest)..."
    gcloud compute ssh "${VM}" --project="${GCP_PROJECT}" --zone="${ZONE}" --quiet --command='
        echo "--- dmesg sev ---"; sudo dmesg | grep -i -E "sev-snp|SEV-SNP|sev-guest|Memory Encryption" | head;
        echo "--- /dev/sev-guest ---"; ls -l /dev/sev-guest 2>&1 || echo "MISSING /dev/sev-guest";
        chmod +x ~/snp-poc;
        echo "--- run (verify) ---"; sudo ~/snp-poc || true;
        echo "--- run (skip-verify, offline) ---"; sudo ~/snp-poc -skip-verify || true;
    '
}

case "${cmd}" in
    up)
        build_binary
        create_vm
        wait_ssh
        push_and_run
        echo "[snp-poc] done. VM left up. './deploy/snp-poc.sh down' to delete."
        ;;
    run)
        build_binary
        push_and_run
        ;;
    ssh)
        gcloud compute ssh "${VM}" --project="${GCP_PROJECT}" --zone="${ZONE}"
        ;;
    down)
        gcloud compute instances delete "${VM}" --project="${GCP_PROJECT}" --zone="${ZONE}" --quiet
        ;;
    *)
        echo "usage: $0 {up|run|ssh|down}" >&2
        exit 1
        ;;
esac
