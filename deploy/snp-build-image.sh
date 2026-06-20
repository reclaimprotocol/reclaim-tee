#!/bin/bash
set -euo pipefail

# Bypass the flaky local WSL proxy (127.0.0.1:10808) for the host-side steps.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true

# Build a two-tier SEV-SNP image (stable base UKI + app partition measured into
# PCR 8) inside a self-contained Docker container (ukify + systemd-repart; no
# host installs). The loader/app binaries compile on the host with the Go cache.
#
#   ./deploy/snp-build-image.sh mini [TAG]    minimal no-rootfs UKI (prober in initrd)
#   ./deploy/snp-build-image.sh tier [TAG]    base UKI + prober as the app
#   ./deploy/snp-build-image.sh tee  [TAG]    base UKI + real tee_t as the app
#   ./deploy/snp-build-image.sh clean         remove build outputs
#
# Set DOCKER="sudo docker" if your Docker needs root.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMG_DIR="${SCRIPT_DIR}/snp-image"
PROBER_SRC="${IMG_DIR}/prober"
PROBER_DST="${IMG_DIR}/mkosi.extra/usr/local/bin/snp-prober"
TEET_DST="${IMG_DIR}/mkosi.extra/usr/local/bin/snp-teet"
DOCKER="${DOCKER:-docker}"

# Target cloud selects the kernel + which non-builtin modules the loader must
# bundle+insert. GCP: gve (NIC) is a module; sev-guest/tpm/nvme are builtin.
# AWS: ena (NIC)/nvme/tpm are builtin, but sev-guest IS a module.
CLOUD="${CLOUD:-gcp}"
case "${CLOUD}" in
    gcp) KERNEL_PKG=linux-image-gcp; MODULES=gve ;;
    aws) KERNEL_PKG="linux-image-6.17.0-1017-aws=6.17.0-1017.17~24.04.1"; MODULES="tsm_report sev-guest" ;;
    *)   echo "unknown CLOUD=${CLOUD} (use gcp|aws)" >&2; exit 1 ;;
esac
BUILDER_IMG="snp-img-builder-${CLOUD}"

build_prober() {
    local tag=$1
    echo "[build] compiling prober (tag=${tag}) with host Go..."
    mkdir -p "$(dirname "${PROBER_DST}")"
    ( cd "${PROBER_SRC}" && GOFLAGS=-mod=mod GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath -ldflags "-X main.buildTag=${tag} -buildid=" -o "${PROBER_DST}" . )
    chmod 0755 "${PROBER_DST}"
    echo "[build] prober sha256: $(sha256sum "${PROBER_DST}" | cut -d' ' -f1)"
}

build_loader() {
    local dst="${IMG_DIR}/mkosi.extra/usr/local/bin/snp-loader"
    echo "[build] compiling loader (stable base init) with host Go..."
    mkdir -p "$(dirname "${dst}")"
    ( cd "${IMG_DIR}/loader" && GOFLAGS=-mod=mod GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath -ldflags "-buildid=" -o "${dst}" . )
    chmod 0755 "${dst}"
    echo "[build] loader sha256: $(sha256sum "${dst}" | cut -d' ' -f1)"
}

# build_tee compiles tee_k or tee_t (role = k|t) into TEE_DST.
TEE_DST=""
build_tee() {
    local role="$1"
    TEE_DST="${IMG_DIR}/mkosi.extra/usr/local/bin/snp-tee${role}"
    echo "[build] compiling the real tee_${role} (main module) as the app..."
    mkdir -p "$(dirname "${TEE_DST}")"
    # Match the prod enclave build tags (no-ops for file selection here, but
    # faithful to Dockerfile.enclave). CGO off gives osusergo/netgo for free.
    ( cd "${REPO_ROOT}" && GOFLAGS=-mod=mod GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath -tags 'enclave osusergo netgo static_build' \
        -ldflags "-s -w -buildid= -extldflags=-static" -o "${TEE_DST}" "./tee_${role}" )
    chmod 0755 "${TEE_DST}"
    echo "[build] tee_${role} sha256: $(sha256sum "${TEE_DST}" | cut -d' ' -f1) ($(du -h "${TEE_DST}" | cut -f1))"
}

# make_bundle tars a staging dir into a deterministic app bundle. The loader
# measures the whole bundle into PCR 8 and extracts it, so the app identity
# covers the binary AND its runtime files (mpcl/, certs).
BUNDLE_HOST="${IMG_DIR}/app-bundle.tar"
make_bundle() {
    local stage="$1"
    tar --sort=name --format=gnu --mtime="@1735689600" \
        --owner=0 --group=0 --numeric-owner -C "${stage}" -cf "${BUNDLE_HOST}" .
    echo "[build] app bundle: $(du -h "${BUNDLE_HOST}" | cut -f1)  sha256: $(sha256sum "${BUNDLE_HOST}" | cut -d' ' -f1)"
}

run_in_container() {
    echo "[build] cloud=${CLOUD} kernel=${KERNEL_PKG} modules=${MODULES}"
    ${DOCKER} build \
        --build-arg KERNEL_PKG="${KERNEL_PKG}" \
        --build-arg http_proxy= --build-arg https_proxy= \
        --build-arg HTTP_PROXY= --build-arg HTTPS_PROXY= --build-arg no_proxy= \
        -t "${BUILDER_IMG}" "${IMG_DIR}"
    ${DOCKER} run --rm --privileged \
        -e http_proxy= -e https_proxy= -e HTTP_PROXY= -e HTTPS_PROXY= \
        -e APP_BIN="${APP_BIN:-}" -e MODULES="${MODULES}" -e SNP_CMDLINE="${SNP_CMDLINE:-}" \
        -v /dev:/dev -v "${IMG_DIR}:/work" \
        "${BUILDER_IMG}" bash "/work/$1"
}

case "${1:-}" in
    mini)
        build_prober "${2:-mini}"
        echo "[mini] building minimal no-rootfs UKI image..."
        run_in_container mini-build.sh
        ;;
    tier)
        build_loader
        build_prober "${2:-tier}"
        stage="$(mktemp -d)"; cp "${PROBER_DST}" "${stage}/app"
        make_bundle "${stage}"; rm -rf "${stage}"
        echo "[tier] building two-tier image (prober as the app bundle)..."
        APP_BIN=/work/app-bundle.tar run_in_container tier-build.sh
        ;;
    tee)
        role="${2:-t}"
        case "${role}" in k|t) ;; *) echo "usage: $0 tee <k|t> [TAG]" >&2; exit 1 ;; esac
        build_loader
        build_tee "${role}"
        echo "[tee] assembling app bundle (tee_${role} + mpcl circuits + CA certs)..."
        stage="$(mktemp -d)"
        cp "${TEE_DST}" "${stage}/app"
        mpcdir="$(cd "${REPO_ROOT}" && GOFLAGS=-mod=mod go list -m -f '{{.Dir}}' github.com/markkurossi/mpc)"
        mkdir -p "${stage}/mpcl"; cp -r "${mpcdir}/pkg" "${stage}/mpcl/pkg"
        mkdir -p "${stage}/etc/ssl/certs"
        cp /etc/ssl/certs/ca-certificates.crt "${stage}/etc/ssl/certs/" 2>/dev/null || echo "[tee] warn: no host CA bundle"
        make_bundle "${stage}"; rm -rf "${stage}"
        echo "[tee] building two-tier image with the real tee_${role} as the app..."
        APP_BIN=/work/app-bundle.tar run_in_container tier-build.sh
        ;;
    clean)
        echo "[clean] removing build outputs (may need sudo for root-owned files)..."
        rm -rf "${IMG_DIR}"/*.raw "${IMG_DIR}/app-bundle.tar" "${IMG_DIR}/mkosi.extra/usr/local/bin" 2>/dev/null || \
            sudo rm -rf "${IMG_DIR}"/*.raw "${IMG_DIR}/app-bundle.tar" "${IMG_DIR}/mkosi.extra/usr/local/bin"
        echo "[clean] done"
        ;;
    *) echo "usage: $0 {mini [TAG]|tier [TAG]|tee <k|t> [TAG]|clean}" >&2; exit 1 ;;
esac
