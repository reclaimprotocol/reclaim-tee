#!/bin/bash
set -euo pipefail

# Bypass any inherited WSL proxy.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true

# Runs inside the privileged mkosi builder container, in the mounted image dir.
# Builds the bootable dm-verity + UKI image, then reads the verity roothash out
# of the UKI's measured .cmdline so the binary -> roothash -> measured-cmdline
# chain (and build reproducibility) is verifiable before booting on GCP.

TAG="${1:-dev}"
cd /work

echo "[mkosi] $(mkosi --version)"
mkosi --force

RAW=/work/snp-verity.raw
UKI=/work/snp-verity.efi
[[ -f "${RAW}" ]] || { echo "[mkosi] ${RAW} not produced" >&2; ls -la /work; exit 1; }
[[ -f "${UKI}" ]] || { echo "[mkosi] ${UKI} not produced" >&2; exit 1; }
echo "[mkosi] image: ${RAW} ($(du -h "${RAW}" | cut -f1)) [tag=${TAG}]"

cmd="$(objcopy -O binary --only-section=.cmdline "${UKI}" /dev/stdout 2>/dev/null | tr -d '\0')"
[[ -n "${cmd}" ]] || cmd="$(strings "${UKI}" | grep -m1 -E 'roothash=' || true)"
echo "[cmdline] ${cmd}"
echo "[roothash] $(echo "${cmd}" | grep -oE 'roothash=[0-9a-f]+' | head -1 || echo '(none)')"
echo "[raw_sha256] $(sha256sum "${RAW}" | cut -d' ' -f1)"
