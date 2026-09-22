#!/bin/bash
set -euo pipefail

# Verify a recorded base using its public signature, without R.key or cloud access:
#   ./deploy/snp-base.sh verify <gcp|aws>
# Record an existing signed release only after reproducing it byte for byte:
#   ./deploy/snp-base.sh record <gcp|aws> <source-commit> <signed-uki>
# sourceCommit selects the loader, pins, Dockerfile, and historical tier recipe.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
HISTORY="${SCRIPT_DIR}/image-history.json"
source "${SCRIPT_DIR}/snp-image/source-commit.sh"
ACTION="${1:?usage: $0 verify <gcp|aws> OR $0 record <gcp|aws> <source-commit> <signed-uki>}"
CLOUD="${2:?cloud required}"
case "${CLOUD}" in gcp|aws) ;; *) echo 'ERROR: cloud must be gcp or aws' >&2; exit 1 ;; esac
case "${ACTION}:${#}" in verify:2|record:4) ;; *) echo 'ERROR: invalid base command or arguments' >&2; exit 1 ;; esac

BASE_DIR="$(mktemp -d)"
trap 'rm -rf "${BASE_DIR}"' EXIT
mkdir "${BASE_DIR}/evidence"
EVIDENCE="${BASE_DIR}/evidence"
if [[ "${ACTION}" == verify ]]; then
    python3 "${SCRIPT_DIR}/snp-image/base-history.py" extract "${HISTORY}" "${CLOUD}" "${EVIDENCE}"
    COMMIT="$(cat "${EVIDENCE}/commit")"
else
    COMMIT="$3"
    cp -- "$4" "${EVIDENCE}/released.efi"
    printf '%s' "${COMMIT}" >"${EVIDENCE}/commit"
    cp "${HISTORY}" "${EVIDENCE}/original-history.json"
fi
snp_checkout_source_commit "${REPO_ROOT}" "${COMMIT}" "${BASE_DIR}/source"
IMAGE_DIR="${BASE_DIR}/source/deploy/snp-image"
source "${IMAGE_DIR}/pins.env"
DOCKER="${DOCKER:-docker}"
CERT="${SCRIPT_DIR}/secure-boot/R.crt.pem"
# The certificate is public, but it must contain the verifier's pinned R key.
openssl x509 -in "${CERT}" -pubkey -noout | cmp - "${REPO_ROOT}/shared/secure_boot_release_pub.pem"

case "${CLOUD}" in
    gcp) KERNEL="${SNP_GCP_KERNEL_PKG}"; MODULES=gve; BANK=sha256 ;;
    aws) KERNEL="${SNP_AWS_KERNEL_PKG}"; MODULES='ena tsm_report sev-guest'; BANK=sha384 ;;
esac
echo "[base] Rebuilding ${CLOUD} from ${COMMIT}"
mkdir -p "${IMAGE_DIR}/mkosi.extra/usr/local/bin"
(
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY ftp_proxy FTP_PROXY
    cd "${IMAGE_DIR}/loader"
    GOTOOLCHAIN="${SNP_LOADER_GO_TOOLCHAIN}" GOFLAGS=-mod=readonly GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath -buildvcs=false -ldflags '-buildid=' \
        -o "${IMAGE_DIR}/mkosi.extra/usr/local/bin/snp-loader" .
    "${DOCKER}" build --iidfile "${BASE_DIR}/builder.id" \
        --build-arg KERNEL_PKG="${KERNEL}" --build-arg CA_IMAGE="${SNP_CA_IMAGE}" \
        --build-arg APT_SNAPSHOT="${SNP_APT_SNAPSHOT}" --build-arg UBUNTU_DIGEST="${SNP_UBUNTU_DIGEST}" \
        --build-arg SYSTEMD_BOOT_VER="${SNP_SYSTEMD_BOOT_VER}" --build-arg SYSTEMD_UKIFY_VER="${SNP_SYSTEMD_UKIFY_VER}" \
        --build-arg SYSTEMD_VER="${SNP_SYSTEMD_VER}" --build-arg ZSTD_VER="${SNP_ZSTD_VER}" \
        --build-arg CPIO_VER="${SNP_CPIO_VER}" --build-arg BINUTILS_VER="${SNP_BINUTILS_VER}" \
        --build-arg http_proxy= --build-arg https_proxy= --build-arg HTTP_PROXY= --build-arg HTTPS_PROXY= --build-arg no_proxy= \
        "${IMAGE_DIR}"
)
BUILDER="$(cat "${BASE_DIR}/builder.id")"

# Only the public certificate is mounted. The historical recipe needs an app
# file for its diagnostics; the loader is a placeholder, never packaged or run
# as an app. SNP_IDENTITY_ONLY disables disk assembly and needs no host devices.
"${DOCKER}" run --rm -i --network=none \
    --mount "type=bind,src=${IMAGE_DIR},dst=/work" \
    --mount "type=bind,src=${EVIDENCE},dst=/evidence" \
    --mount "type=bind,src=${CERT},dst=/R.crt.pem,readonly" \
    -e BASE_ACTION="${ACTION}" -e MODULES="${MODULES}" -e SNP_PCR_BANK="${BANK}" \
    -e SNP_IDENTITY_ONLY=1 -e APP_BIN=/work/mkosi.extra/usr/local/bin/snp-loader \
    "${BUILDER}" bash -s <<'BUILD'
set -euo pipefail
if [[ "${BASE_ACTION}" == record ]]; then
    sbverify --cert /R.crt.pem /evidence/released.efi
    sbattach --detach /evidence/base-signature.pk7 /evidence/released.efi
    objcopy -O binary --only-section=.cmdline /evidence/released.efi /evidence/cmdline.raw
    python3 - <<'PY'
from pathlib import Path
Path('/evidence/cmdline').write_bytes(Path('/evidence/cmdline.raw').read_bytes().rstrip(b'\0'))
PY
fi
export SNP_CMDLINE="$(cat /evidence/cmdline)"
# Successful historical build output stays in the evidence directory. This
# includes legacy app diagnostics, which do not participate in base verification.
if ! bash /work/tier-build.sh >/evidence/build.log 2>&1; then
    tail -30 /evidence/build.log >&2
    exit 1
fi
sbverify --cert /R.crt.pem --detached /evidence/base-signature.pk7 /work/snp-base.efi
sbattach --attach /evidence/base-signature.pk7 /work/snp-base.efi
sbverify --cert /R.crt.pem /work/snp-base.efi
sha256sum /work/snp-base.efi | cut -d' ' -f1 >/evidence/actual-sha256
sed -n 's/^\[tier\] snp-base (PCR11 [^)]*) = \(snp-base:[0-9a-f]*\)$/\1/p' /evidence/build.log >/evidence/actual-pcr
if [[ "${BASE_ACTION}" == record ]]; then
    cmp /evidence/released.efi /work/snp-base.efi
else
    [[ "$(cat /evidence/actual-sha256)" == "$(cat /evidence/expected-sha256)" ]] || {
        echo 'ERROR: reconstructed signed base SHA-256 does not match history' >&2; exit 1;
    }
    [[ "$(cat /evidence/actual-pcr)" == "$(cat /evidence/expected-pcr)" ]] || {
        echo 'ERROR: reconstructed base PCR 11 does not match history' >&2; exit 1;
    }
fi
BUILD

ACTUAL_SHA="$(cat "${EVIDENCE}/actual-sha256")"
[[ "${ACTUAL_SHA}" =~ ^[0-9a-f]{64}$ ]] || { echo 'ERROR: base build produced no valid SHA-256' >&2; exit 1; }
if [[ "${ACTION}" == record ]]; then
    python3 "${SCRIPT_DIR}/snp-image/base-history.py" record "${HISTORY}" "${CLOUD}" "${EVIDENCE}"
    echo "[base] Recorded verified ${CLOUD} base in image-history.json"
fi
echo "[base] VERIFIED ${CLOUD}: ${ACTUAL_SHA}"
