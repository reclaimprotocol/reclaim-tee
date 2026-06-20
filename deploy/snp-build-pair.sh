#!/bin/bash
set -euo pipefail

# =============================================================================
# Build a SEV-SNP two-tier image for a given role x cloud and package it as a
# GCP image / AWS AMI, ready for snp-pair.sh. Wraps the primitives:
#   snp-build-image.sh tee <role>  -> snp-tier.raw + app-bundle.tar (the bundle
#       sha256 IS the cross-cloud snp-app: digest; printed at the end)
#   snp-gcp-image.sh image / snp-aws-image.sh image  -> cloud image / AMI
#
#   ./deploy/snp-build-pair.sh <k|t> <gcp|aws> [TAG]   build one image
#   ./deploy/snp-build-pair.sh switched                build tee_k@gcp + tee_t@aws
#
# Default TAG is tee<role>-<cloud>; the GCP image / AMI is named snp-<TAG>, which
# matches snp-pair.sh's SNP_GCP_IMAGE / SNP_AWS_IMAGE_TAG defaults. Run with the
# proxy as the AWS CLI needs it (set); the build/gcp steps unset it themselves.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE="${SCRIPT_DIR}/snp-image/app-bundle.tar"

build_one() {
    local role="$1" cloud="$2" tag="${3:-tee${1}-${2}}"
    case "${role}" in k|t) ;; *) echo "role must be k|t" >&2; exit 1 ;; esac
    case "${cloud}" in gcp|aws) ;; *) echo "cloud must be gcp|aws" >&2; exit 1 ;; esac

    echo "[build-pair] === tee_${role}@${cloud} (tag ${tag}) ==="
    CLOUD="${cloud}" "${SCRIPT_DIR}/snp-build-image.sh" tee "${role}" "${tag}"
    local digest; digest="$(sha256sum "${BUNDLE}" | cut -d' ' -f1)"

    case "${cloud}" in
        gcp) "${SCRIPT_DIR}/snp-gcp-image.sh" image "${tag}" ;;
        aws) "${SCRIPT_DIR}/snp-aws-image.sh" image "${tag}" ;;
    esac

    echo "[build-pair] DONE tee_${role}@${cloud}"
    echo "[build-pair]   image/AMI name : snp-${tag}"
    echo "[build-pair]   app digest     : snp-app:${digest}"
    if [[ "${cloud}" == "gcp" ]]; then
        echo "[build-pair]   -> snp-pair.sh: SNP_GCP_IMAGE=snp-${tag}"
    else
        echo "[build-pair]   -> snp-pair.sh: SNP_AWS_IMAGE_TAG=${tag}"
    fi
    echo "[build-pair]   -> if digest changed, set SNP_${role^^}_DIGEST=snp-app:${digest}"
}

case "${1:-}" in
    k|t)      build_one "$1" "${2:?usage: $0 <k|t> <gcp|aws> [TAG]}" "${3:-}" ;;
    switched) build_one k gcp; build_one t aws ;;
    *) echo "usage: $0 {<k|t> <gcp|aws> [TAG] | switched}" >&2; exit 1 ;;
esac
