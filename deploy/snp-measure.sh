#!/bin/bash
set -euo pipefail

# The system-wide WSL2 proxy causes flaky TLS to GCP / package mirrors; bypass it.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true

# =============================================================================
# SEV-SNP measurement probe. For each given image family, boots a SEV-SNP CVM,
# reads BOTH the SEV-SNP launch MEASUREMENT (via snp-poc) AND the vTPM PCRs
# (via tpm2-tools), deletes the VM, and prints a side-by-side comparison.
#
# Purpose: determine empirically what the SEV-SNP MEASUREMENT covers on GCP. If
# MEASUREMENT is identical across two different OS images while the vTPM PCRs
# differ, then on GCP the SEV-SNP report measures only firmware/launch state and
# CODE integrity must be anchored in the vTPM PCRs (the dm-verity root hash has
# to be carried into a PCR via measured boot), not in the SEV-SNP report.
#
# Crash-safe: any VM it creates is deleted on exit (including on error), and
# all gcloud calls go through gcloud_retry to ride out transient API hiccups.
#
# Usage:
#   ./deploy/snp-measure.sh                      # defaults: ubuntu-2404 vs ubuntu-2204
#   ./deploy/snp-measure.sh ubuntu-2404-lts-amd64 debian-12
#
# Env (override or via deploy/.env): GCP_PROJECT (required), SNP_ZONE, SNP_MACHINE.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then set -a; source "${SCRIPT_DIR}/.env"; set +a; fi
source "${SCRIPT_DIR}/_lib.sh"

: "${GCP_PROJECT:?set GCP_PROJECT (or put it in deploy/.env)}"
ZONE="${SNP_ZONE:?set SNP_ZONE in deploy/.env}"
MACHINE="${SNP_MACHINE:-n2d-standard-2}"
IMAGE_PROJECT_DEFAULT="ubuntu-os-cloud"

IMAGES=("$@")
if [[ ${#IMAGES[@]} -eq 0 ]]; then
    IMAGES=("ubuntu-2404-lts-amd64" "ubuntu-2204-lts")
fi

# Delete any VM we are mid-probe on, even if the script crashes. CURRENT_VM is
# set before create and cleared after a clean delete.
CURRENT_VM=""
cleanup() {
    if [[ -n "${CURRENT_VM}" ]]; then
        echo "[probe] cleanup: deleting ${CURRENT_VM}..." >&2
        gcloud_retry gcloud compute instances delete "${CURRENT_VM}" \
            --project="${GCP_PROJECT}" --zone="${ZONE}" --quiet >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "[probe] building snp-poc binary..."
( cd "${REPO_DIR}/snp-poc" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o snp-poc . )

OUT_DIR="$(mktemp -d)"

image_project_for() {
    case "$1" in
        debian-*) echo "debian-cloud" ;;
        *)        echo "${IMAGE_PROJECT_DEFAULT}" ;;
    esac
}

probe_image() {
    local family=$1
    local vm="snp-measure-${family//[^a-z0-9]/-}"
    local img_project; img_project="$(image_project_for "${family}")"
    echo "[probe] === ${family} (vm=${vm}) ==="

    CURRENT_VM="${vm}"
    echo "[probe] creating SEV-SNP VM..."
    gcloud_retry gcloud compute instances create "${vm}" \
        --project="${GCP_PROJECT}" --zone="${ZONE}" \
        --machine-type="${MACHINE}" \
        --confidential-compute-type=SEV_SNP \
        --min-cpu-platform="AMD Milan" \
        --maintenance-policy=TERMINATE \
        --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
        --image-family="${family}" --image-project="${img_project}" --quiet >/dev/null

    echo "[probe] waiting for SSH..."
    local ssh_ok=0
    for i in {1..40}; do
        if gcloud compute ssh "${vm}" --project="${GCP_PROJECT}" --zone="${ZONE}" \
            --command="true" --quiet >/dev/null 2>&1; then ssh_ok=1; break; fi
        sleep 5
    done
    if [[ "${ssh_ok}" -ne 1 ]]; then
        echo "[probe] SSH never came up for ${vm}; skipping." >&2
        cleanup; CURRENT_VM=""; return 0
    fi

    gcloud_retry gcloud compute scp "${REPO_DIR}/snp-poc/snp-poc" "${vm}:~/snp-poc" \
        --project="${GCP_PROJECT}" --zone="${ZONE}" --quiet

    echo "[probe] reading SEV-SNP MEASUREMENT + vTPM PCRs..."
    gcloud_retry gcloud compute ssh "${vm}" --project="${GCP_PROJECT}" --zone="${ZONE}" --quiet --command='
        set -e
        chmod +x ~/snp-poc
        echo "### SEV-SNP MEASUREMENT ###"
        sudo ~/snp-poc -skip-verify 2>/dev/null | grep -E "^measurement" || true
        echo "### vTPM PCRs (sha256) ###"
        if ! command -v tpm2_pcrread >/dev/null 2>&1; then
            sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tpm2-tools >/dev/null 2>&1 || true
        fi
        sudo tpm2_pcrread sha256 2>/dev/null || echo "tpm2_pcrread unavailable"
        echo "### kernel ###"
        uname -r
        echo "### cmdline ###"
        cat /proc/cmdline
    ' | tee "${OUT_DIR}/${family}.txt"

    echo "[probe] deleting VM..."
    gcloud_retry gcloud compute instances delete "${vm}" \
        --project="${GCP_PROJECT}" --zone="${ZONE}" --quiet >/dev/null
    CURRENT_VM=""
}

for family in "${IMAGES[@]}"; do
    probe_image "${family}"
done

echo
echo "================== COMPARISON =================="
for family in "${IMAGES[@]}"; do
    echo "----- ${family} -----"
    cat "${OUT_DIR}/${family}.txt" 2>/dev/null || echo "(no output captured)"
    echo
done
echo "If 'measurement' is identical across images but PCRs differ => SEV-SNP"
echo "report measures firmware/launch only; code integrity lives in the vTPM."
echo "Raw outputs: ${OUT_DIR}"
