#!/bin/bash
set -euo pipefail
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true

# Builds the MINIMAL no-rootfs image inside the container: a UKI whose initrd is
# just the static prober (as /init) + CA certs, wrapped in an ESP-only GPT disk.
# No systemd userland, no distro rootfs. The binary is measured
# directly into PCR 11 (it is part of the UKI's .initrd section). Reproducible:
# fixed SOURCE_DATE_EPOCH + cpio --reproducible + fixed repart seed.

export SOURCE_DATE_EPOCH=1735689600
cd /work

PROBER=/work/mkosi.extra/usr/local/bin/snp-prober
[[ -f "${PROBER}" ]] || { echo "prober missing at ${PROBER}" >&2; exit 1; }
KERNEL="$(ls /boot/vmlinuz-*-gcp 2>/dev/null | sort | tail -1)"
[[ -n "${KERNEL}" ]] || { echo "no gcp kernel in container /boot" >&2; exit 1; }
STUB=/usr/lib/systemd/boot/efi/linuxx64.efi.stub
CMDLINE="console=ttyS0,115200"
SEED=b5f8a3c2-1d4e-4a6b-9c8d-7e0f1a2b3c4d

echo "[mini] kernel: ${KERNEL}"

# 1) Reproducible initrd: prober as /init + CA certs + empty pseudo-fs mountpoints.
rm -rf /tmp/ir; mkdir -p /tmp/ir/proc /tmp/ir/sys /tmp/ir/dev /tmp/ir/etc/ssl/certs
cp "${PROBER}" /tmp/ir/init; chmod 0755 /tmp/ir/init
cp /etc/ssl/certs/ca-certificates.crt /tmp/ir/etc/ssl/certs/
# cpio --reproducible does NOT zero mtimes; clamp them so the initrd is stable.
find /tmp/ir -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
( cd /tmp/ir && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort \
    | cpio --reproducible --quiet -o -H newc -R 0:0 ) | zstd -q -19 -f -o /work/initrd.zst

# 2) UKI = kernel + initrd + cmdline, measured by sd-stub into PCR 11.
ukify build --linux="${KERNEL}" --initrd=/work/initrd.zst \
    --cmdline="${CMDLINE}" --stub "${STUB}" --output /work/snp-mini.efi

# 3) ESP-only bootable GPT disk (512M ESP => valid FAT32). No rootfs.
rm -rf /tmp/sysroot; mkdir -p /tmp/sysroot/EFI/BOOT
cp /work/snp-mini.efi /tmp/sysroot/EFI/BOOT/BOOTX64.EFI
mkdir -p /tmp/defs
cat > /tmp/defs/00-esp.conf <<'EOF'
[Partition]
Type=esp
Format=vfat
CopyFiles=/EFI:/EFI
SizeMinBytes=512M
SizeMaxBytes=512M
EOF
rm -f /work/snp-mini.raw
systemd-repart --empty=create --size=auto --seed="${SEED}" \
    --definitions=/tmp/defs --root=/tmp/sysroot --dry-run=no /work/snp-mini.raw

echo "[mini] UKI: $(du -h /work/snp-mini.efi | cut -f1)  raw: $(du -h /work/snp-mini.raw | cut -f1)"
echo "[mini] prober_sha256 = $(sha256sum "${PROBER}" | cut -d' ' -f1)"
echo "[mini] initrd_sha256 = $(sha256sum /work/initrd.zst | cut -d' ' -f1)"
echo "[mini] uki_sha256    = $(sha256sum /work/snp-mini.efi | cut -d' ' -f1)"

# 4) Predicted PCR 11 (sd-stub measurement) — what the vTPM should report.
MEASURE=/usr/lib/systemd/systemd-measure
if [[ -x "${MEASURE}" ]]; then
    echo "[mini] predicted PCR 11:"
    "${MEASURE}" calculate --linux="${KERNEL}" --initrd=/work/initrd.zst \
        --cmdline="${CMDLINE}" --stub "${STUB}" 2>/dev/null | grep -iE '11:|pcr 11|sha256' | head -3 || echo "  (systemd-measure produced no PCR 11 line)"
fi
